package main

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	formatClaude    = "claude"
	formatOpenAI    = "openai"
	formatResponses = "openai-response"
	formatGemini    = "gemini"
)

// requestState carries one request from the before-auth hook to its response:
// the placeholders sent upstream, and the stream reassembly buffers.
type requestState struct {
	mu      sync.Mutex
	created time.Time
	model   string
	r       *restorer

	channels map[string]*channelState
	order    []string
	// held is an SSE "event:" line whose "data:" line has not arrived yet.
	held     []byte
	restored int
}

type channelKind uint8

const (
	chClaude channelKind = iota + 1
	chOpenAIContent
	chOpenAITool
	chGeminiText
	chResponses
)

// channelState is one independently streamed string: a Claude content block,
// an OpenAI choice's content or tool-call arguments, a Responses item.
type channelState struct {
	kind      channelKind
	mode      escMode
	tail      string
	index     int64
	tool      int64
	deltaType string
	event     string
	template  []byte
}

func (st *requestState) resetStream() {
	st.channels = nil
	st.order = nil
	st.held = nil
}

func (st *requestState) channel(key string, kind channelKind, mode escMode) *channelState {
	if ch := st.channels[key]; ch != nil {
		return ch
	}
	if st.channels == nil {
		st.channels = make(map[string]*channelState, 4)
	}
	ch := &channelState{kind: kind, mode: mode}
	st.channels[key] = ch
	st.order = append(st.order, key)
	return ch
}

func (st *requestState) dropChannel(key string) {
	delete(st.channels, key)
	for i, k := range st.order {
		if k == key {
			st.order = append(st.order[:i], st.order[i+1:]...)
			return
		}
	}
}

// applyDelta restores the string at path in js, carrying ch's tail in and out.
// It returns the rewritten event, or nil when the bytes are unchanged.
func (st *requestState) applyDelta(js []byte, path string, ch *channelState, final bool) []byte {
	current := gjson.GetBytes(js, path)
	if current.Type != gjson.String {
		return nil
	}
	fragment := current.String()
	emit, tail, n := st.r.delta(ch.tail, fragment, ch.mode, final)
	ch.tail = tail
	st.restored += n
	if emit == fragment {
		return nil
	}
	out, err := sjson.SetRawBytes(js, path, appendJSONString(nil, emit))
	if err != nil {
		return nil
	}
	return out
}

// processChunk rewrites one stream chunk. It returns nil when the chunk is
// unchanged, and drop when the chunk must be held back entirely.
func (st *requestState) processChunk(format string, body []byte) (out []byte, drop bool) {
	data := body
	merged := false
	if len(st.held) > 0 {
		joined := make([]byte, 0, len(st.held)+1+len(body))
		joined = append(joined, st.held...)
		if !bytes.HasSuffix(joined, []byte("\n")) {
			joined = append(joined, '\n')
		}
		data = append(joined, body...)
		st.held = nil
		merged = true
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return keepIf(merged, data), false
	}

	// A bare JSON payload. OpenAI chat and Gemini handlers add the SSE
	// framing themselves, so their channels merge held tails into the next
	// payload. The Responses WebSocket forwarder splits a chunk into one JSON
	// payload per line, so flushed Responses deltas go out as extra lines.
	if trimmed[0] == '{' || trimmed[0] == '[' {
		var ev eventResult
		if trimmed[0] == '{' {
			ev = st.handleEvent(format, trimmed, format == formatResponses)
		} else {
			ev.out = st.restoreWhole(trimmed)
		}
		if ev.out == nil && len(ev.synth) == 0 {
			return keepIf(merged, data), false
		}
		out := make([]byte, 0, len(data)+64)
		for _, synth := range ev.synth {
			out = append(append(out, synth.js...), '\n')
		}
		out = append(out, data[:len(data)-len(trimmed)]...)
		if ev.out != nil {
			return append(out, ev.out...), false
		}
		return append(out, trimmed...), false
	}

	if format == formatResponses && !hasSSEField(data, "data:") {
		if hasSSEField(data, "event:") {
			st.held = append([]byte(nil), data...)
			return nil, true
		}
		return keepIf(merged, data), false
	}

	lines := splitLines(data)
	parts := make([][]byte, 0, len(lines)+1)
	blockStart := 0
	modified := merged
	for _, line := range lines {
		content := bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(content)) == 0 {
			parts = append(parts, line)
			blockStart = len(parts)
			continue
		}
		if bytes.HasPrefix(content, []byte("data:")) {
			lead := 5
			if len(content) > lead && content[lead] == ' ' {
				lead++
			}
			payload := content[lead:]
			if len(payload) > 0 && payload[0] == '{' {
				ev := st.handleEvent(format, payload, true)
				for _, synth := range ev.synth {
					parts = append(parts, nil)
					copy(parts[blockStart+1:], parts[blockStart:])
					parts[blockStart] = sseEvent(synth.name, synth.js)
					blockStart++
					modified = true
				}
				if ev.out != nil {
					rebuilt := make([]byte, 0, lead+len(ev.out)+len(line)-len(content))
					rebuilt = append(rebuilt, content[:lead]...)
					rebuilt = append(rebuilt, ev.out...)
					rebuilt = append(rebuilt, line[len(content):]...)
					line = rebuilt
					modified = true
				}
			}
		}
		parts = append(parts, line)
	}
	if !modified {
		return nil, false
	}
	return bytes.Join(parts, nil), false
}

func keepIf(changed bool, data []byte) []byte {
	if changed {
		return data
	}
	return nil
}

func splitLines(data []byte) [][]byte {
	lines := make([][]byte, 0, 4)
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			lines = append(lines, data)
			break
		}
		lines = append(lines, data[:i+1])
		data = data[i+1:]
	}
	return lines
}

func hasSSEField(data []byte, field string) bool {
	for _, line := range splitLines(data) {
		if bytes.HasPrefix(bytes.TrimLeft(line, " \t"), []byte(field)) {
			return true
		}
	}
	return false
}

type eventResult struct {
	// out is the rewritten event payload, nil when unchanged.
	out []byte
	// synth holds events to emit before this one.
	synth []synthEvent
}

// synthEvent is a flushed delta, framed by the caller.
type synthEvent struct {
	name string
	js   []byte
}

// handleEvent restores one event payload. canSynth reports whether extra SSE
// events may be emitted in front of it; formats that need that to flush a
// held tail restore without holding when it is false.
func (st *requestState) handleEvent(format string, js []byte, canSynth bool) eventResult {
	switch format {
	case formatClaude:
		return st.claudeEvent(js, canSynth)
	case formatResponses:
		return st.responsesEvent(js, canSynth)
	case formatOpenAI:
		return eventResult{out: st.openaiChunk(js)}
	case formatGemini:
		return eventResult{out: st.geminiChunk(js)}
	default:
		out, n := st.r.restoreJSON(js)
		st.restored += n
		return eventResult{out: out}
	}
}

func (st *requestState) restoreWhole(js []byte) []byte {
	out, n := st.r.restoreJSON(js)
	st.restored += n
	return out
}

// flush emits synthetic delta events for the held tails of the SSE-framed
// channels selected by keep, and forgets those channels.
func (st *requestState) flush(canSynth bool, selected func(key string, ch *channelState) bool) []synthEvent {
	if len(st.order) == 0 {
		return nil
	}
	var out []synthEvent
	for _, key := range append([]string(nil), st.order...) {
		ch := st.channels[key]
		if ch == nil || (ch.kind != chClaude && ch.kind != chResponses) || !selected(key, ch) {
			continue
		}
		if ch.tail != "" && canSynth {
			if ev, ok := st.synthesize(ch); ok {
				out = append(out, ev)
			}
		}
		st.dropChannel(key)
	}
	return out
}

func (st *requestState) synthesize(ch *channelState) (synthEvent, bool) {
	var js []byte
	switch ch.kind {
	case chClaude:
		field := "text"
		if ch.deltaType == "input_json_delta" {
			field = "partial_json"
		}
		js = []byte(`{"type":"content_block_delta","index":` + strconv.FormatInt(ch.index, 10) +
			`,"delta":{"type":"` + ch.deltaType + `","` + field + `":`)
		js = appendJSONString(js, ch.tail)
		js = append(js, "}}"...)
		return synthEvent{name: "content_block_delta", js: js}, true
	case chResponses:
		rewritten, err := sjson.SetRawBytes(ch.template, "delta", appendJSONString(nil, ch.tail))
		if err != nil {
			return synthEvent{}, false
		}
		return synthEvent{name: ch.event, js: rewritten}, true
	}
	return synthEvent{}, false
}

func sseEvent(name string, js []byte) []byte {
	out := make([]byte, 0, len(name)+len(js)+16)
	out = append(out, "event: "...)
	out = append(out, name...)
	out = append(out, "\ndata: "...)
	out = append(out, js...)
	return append(out, "\n\n"...)
}

func all(string, *channelState) bool { return true }

// claudeEvent handles Anthropic Messages stream events.
func (st *requestState) claudeEvent(js []byte, canSynth bool) eventResult {
	switch gjson.GetBytes(js, "type").String() {
	case "content_block_delta":
		index := gjson.GetBytes(js, "index").Int()
		deltaType := gjson.GetBytes(js, "delta.type").String()
		path, mode := "", modeRaw
		switch deltaType {
		case "text_delta":
			path = "delta.text"
		case "input_json_delta":
			path, mode = "delta.partial_json", modeJSON
		default:
			return eventResult{} // thinking, signature, citations
		}
		key := "c:" + strconv.FormatInt(index, 10)
		res := eventResult{synth: st.flush(canSynth, func(k string, _ *channelState) bool { return k != key })}
		ch := st.channel(key, chClaude, mode)
		ch.index, ch.deltaType = index, deltaType
		res.out = st.applyDelta(js, path, ch, !canSynth)
		return res
	case "content_block_start":
		res := eventResult{synth: st.flush(canSynth, all)}
		block := gjson.GetBytes(js, "content_block")
		if block.Get("type").String() == "text" && block.Get("text").String() != "" {
			index := gjson.GetBytes(js, "index").Int()
			key := "c:" + strconv.FormatInt(index, 10)
			ch := st.channel(key, chClaude, modeRaw)
			ch.index, ch.deltaType = index, "text_delta"
			res.out = st.applyDelta(js, "content_block.text", ch, !canSynth)
			return res
		}
		res.out = st.restoreWhole(js)
		return res
	case "content_block_stop":
		key := "c:" + strconv.FormatInt(gjson.GetBytes(js, "index").Int(), 10)
		return eventResult{synth: st.flush(canSynth, func(k string, _ *channelState) bool { return k == key })}
	case "ping":
		return eventResult{}
	case "message_delta", "message_stop", "error":
		return eventResult{synth: st.flush(canSynth, all)}
	default:
		return eventResult{out: st.restoreWhole(js)}
	}
}

// responsesEvent handles OpenAI Responses stream events.
func (st *requestState) responsesEvent(js []byte, canSynth bool) eventResult {
	eventType := gjson.GetBytes(js, "type").String()
	itemID := gjson.GetBytes(js, "item_id").String()
	var key string
	mode := modeRaw
	switch eventType {
	case "response.output_text.delta", "response.refusal.delta":
		key = "r:" + itemID + ":" + gjson.GetBytes(js, "content_index").Raw
	case "response.function_call_arguments.delta":
		key, mode = "r:"+itemID, modeJSON
	case "response.custom_tool_call_input.delta":
		key = "r:" + itemID
	default:
		if strings.HasPrefix(eventType, "response.reasoning") {
			return eventResult{}
		}
		return eventResult{synth: st.flush(canSynth, all), out: st.restoreWhole(js)}
	}
	res := eventResult{synth: st.flush(canSynth, func(k string, _ *channelState) bool { return k != key })}
	ch := st.channel(key, chResponses, mode)
	ch.event = eventType
	ch.template = append(ch.template[:0], js...)
	res.out = st.applyDelta(js, "delta", ch, !canSynth)
	return res
}

// openaiChunk handles OpenAI chat completion chunks. A held tail is merged into
// the next chunk of the same choice that carries anything else, or into the
// chunk with the finish reason.
func (st *requestState) openaiChunk(js []byte) []byte {
	choices := gjson.GetBytes(js, "choices")
	if !choices.IsArray() {
		return st.restoreWhole(js)
	}
	out := js
	changed := false
	apply := func(rewritten []byte) {
		if rewritten != nil {
			out, changed = rewritten, true
		}
	}
	for pos, choice := range choices.Array() {
		delta := choice.Get("delta")
		if !delta.Exists() {
			continue
		}
		choiceIndex := int64(pos)
		if idx := choice.Get("index"); idx.Exists() {
			choiceIndex = idx.Int()
		}
		finish := choice.Get("finish_reason")
		final := finish.Exists() && finish.Type != gjson.Null
		base := "choices." + strconv.Itoa(pos) + ".delta"
		touched := map[string]bool{}

		if delta.Get("content").Type == gjson.String {
			key := "o:" + strconv.FormatInt(choiceIndex, 10) + ":c"
			ch := st.channel(key, chOpenAIContent, modeRaw)
			ch.index = choiceIndex
			apply(st.applyDelta(out, base+".content", ch, final))
			touched[key] = true
		}
		for toolPos, call := range delta.Get("tool_calls").Array() {
			if call.Get("function.arguments").Type != gjson.String {
				continue
			}
			toolIndex := int64(toolPos)
			if idx := call.Get("index"); idx.Exists() {
				toolIndex = idx.Int()
			}
			key := "o:" + strconv.FormatInt(choiceIndex, 10) + ":t:" + strconv.FormatInt(toolIndex, 10)
			ch := st.channel(key, chOpenAITool, modeJSON)
			ch.index, ch.tool = choiceIndex, toolIndex
			apply(st.applyDelta(out, base+".tool_calls."+strconv.Itoa(toolPos)+".function.arguments", ch, final))
			touched[key] = true
		}

		if len(touched) == 0 && !final {
			continue
		}
		for _, key := range append([]string(nil), st.order...) {
			ch := st.channels[key]
			if ch == nil || ch.index != choiceIndex || (ch.kind != chOpenAIContent && ch.kind != chOpenAITool) {
				continue
			}
			if touched[key] {
				if final {
					st.dropChannel(key)
				}
				continue
			}
			if ch.tail != "" {
				tail := ch.tail
				ch.tail = ""
				var err error
				var rewritten []byte
				if ch.kind == chOpenAIContent {
					rewritten, err = sjson.SetRawBytes(out, base+".content", appendJSONString(nil, tail))
				} else {
					call := []byte(`{"index":` + strconv.FormatInt(ch.tool, 10) + `,"function":{"arguments":`)
					call = appendJSONString(call, tail)
					call = append(call, "}}"...)
					rewritten, err = sjson.SetRawBytes(out, base+".tool_calls.-1", call)
				}
				if err == nil {
					apply(rewritten)
				}
			}
			if final {
				st.dropChannel(key)
			}
		}
	}
	if rewritten := st.restoreWhole(out); rewritten != nil {
		out, changed = rewritten, true
	}
	if !changed {
		return nil
	}
	return out
}

// geminiChunk handles Gemini generateContent stream chunks, including the
// {"response": {...}} envelope of the CLI flavour.
func (st *requestState) geminiChunk(js []byte) []byte {
	prefix := ""
	if gjson.GetBytes(js, "response.candidates").Exists() {
		prefix = "response."
	}
	candidates := gjson.GetBytes(js, prefix+"candidates")
	if !candidates.IsArray() {
		return st.restoreWhole(js)
	}
	out := js
	changed := false
	for pos, candidate := range candidates.Array() {
		candidateIndex := int64(pos)
		if idx := candidate.Get("index"); idx.Exists() {
			candidateIndex = idx.Int()
		}
		final := candidate.Get("finishReason").Exists()
		key := "g:" + strconv.FormatInt(candidateIndex, 10)
		ch := st.channel(key, chGeminiText, modeRaw)
		partsPath := prefix + "candidates." + strconv.Itoa(pos) + ".content.parts"

		var textParts []int
		nonText := false
		for partPos, part := range candidate.Get("content.parts").Array() {
			if part.Get("thought").Bool() {
				continue
			}
			if part.Get("text").Type == gjson.String {
				textParts = append(textParts, partPos)
			} else {
				nonText = true
			}
		}
		for i, partPos := range textParts {
			last := i == len(textParts)-1
			if rewritten := st.applyDelta(out, partsPath+"."+strconv.Itoa(partPos)+".text", ch, last && (final || nonText)); rewritten != nil {
				out, changed = rewritten, true
			}
		}
		if len(textParts) == 0 && ch.tail != "" && (final || nonText) {
			part := appendJSONString([]byte(`{"text":`), ch.tail)
			part = append(part, '}')
			ch.tail = ""
			var parts []byte
			if existing := gjson.GetBytes(out, partsPath); existing.IsArray() && strings.TrimSpace(existing.Raw[1:len(existing.Raw)-1]) != "" {
				parts = append(append(append([]byte{'['}, part...), ','), existing.Raw[1:]...)
			} else {
				parts = append(append([]byte{'['}, part...), ']')
			}
			if rewritten, err := sjson.SetRawBytes(out, partsPath, parts); err == nil {
				out, changed = rewritten, true
			}
		}
		if final {
			st.dropChannel(key)
		}
	}
	if rewritten := st.restoreWhole(out); rewritten != nil {
		out, changed = rewritten, true
	}
	if !changed {
		return nil
	}
	return out
}

// stateRegistry holds request states between the before-auth hook and the
// response hooks.
type stateRegistry struct {
	mu        sync.Mutex
	states    map[string]*requestState
	lastSweep time.Time
	ttl       time.Duration
}

func newStateRegistry() *stateRegistry {
	return &stateRegistry{states: make(map[string]*requestState, 64), ttl: 2 * time.Hour}
}

func (reg *stateRegistry) put(id string, st *requestState) {
	if id == "" || st == nil {
		return
	}
	now := time.Now()
	if st.created.IsZero() {
		st.created = now
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.states[id] = st
	if now.Sub(reg.lastSweep) > time.Minute {
		reg.lastSweep = now
		for key, candidate := range reg.states {
			if now.Sub(candidate.created) > reg.ttl {
				delete(reg.states, key)
			}
		}
	}
}

func (reg *stateRegistry) get(id string) *requestState {
	if id == "" {
		return nil
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.states[id]
}

func (reg *stateRegistry) take(id string) *requestState {
	if id == "" {
		return nil
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	st := reg.states[id]
	delete(reg.states, id)
	return st
}

func (reg *stateRegistry) len() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return len(reg.states)
}
