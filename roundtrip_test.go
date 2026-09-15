package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/tidwall/gjson"
)

const (
	samplePassword = "Zq8#vLp2!mRx"
	sampleAWSKey   = "AKIAIOSFODNN7EXAMPLE"
)

// redactFor runs the before-auth hook and returns the rewritten body plus the
// placeholders it references.
func redactFor(t *testing.T, p *privacyFilterPlugin, id, format, body string) (string, map[string]string) {
	t.Helper()
	resp, err := p.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{
		RequestID: id, SourceFormat: format, Model: "m", Body: []byte(body),
	})
	if err != nil {
		t.Fatalf("before-auth: %v", err)
	}
	out := body
	if resp.Body != nil {
		out = string(resp.Body)
	}
	if !gjson.Valid(out) {
		t.Fatalf("rewritten body is not valid JSON: %s", out)
	}
	values := map[string]string{}
	if st := p.states.get(id); st != nil && st.r != nil {
		values = st.r.values
	}
	return out, values
}

func placeholderFor(t *testing.T, values map[string]string, value string) string {
	t.Helper()
	for placeholder, v := range values {
		if v == value {
			return placeholder
		}
	}
	t.Fatalf("no placeholder for %q in %v", value, values)
	return ""
}

// stream feeds chunks through the stream hook the way CPA does: one header
// init call, then every payload chunk in order.
func stream(t *testing.T, p *privacyFilterPlugin, id, format string, chunks []string) string {
	t.Helper()
	if _, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: id, SourceFormat: format, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex,
	}); err != nil {
		t.Fatalf("header init: %v", err)
	}
	var out bytes.Buffer
	for i, chunk := range chunks {
		resp, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
			RequestID: id, SourceFormat: format, ChunkIndex: i, Body: []byte(chunk),
		})
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		if resp.DropChunk {
			continue
		}
		body := chunk
		if len(resp.Body) > 0 {
			body = string(resp.Body)
		}
		// Mirror the bare-JSON handlers, which add the SSE framing themselves.
		if strings.HasPrefix(strings.TrimSpace(body), "{") {
			body = "data: " + body + "\n\n"
		} else if format == formatResponses && !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		out.WriteString(body)
	}
	return out.String()
}

// sseData returns every data payload of an SSE transcript, in order.
func sseData(transcript string) []gjson.Result {
	var out []gjson.Result
	for _, line := range strings.Split(transcript, "\n") {
		if payload, ok := strings.CutPrefix(line, "data: "); ok && gjson.Valid(payload) {
			out = append(out, gjson.Parse(payload))
		}
	}
	return out
}

// chop splits s into pieces of n bytes, the worst case for placeholders that
// must be reassembled across deltas.
func chop(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func TestPlaceholdersAreDeterministicPerKey(t *testing.T) {
	a := newTestPlugin(t)
	b := newTestPlugin(t)
	body := `{"messages":[{"role":"user","content":"token ` + sampleToken + `"}]}`
	outA, _ := redactFor(t, a, "a", formatClaude, body)
	outB, _ := redactFor(t, b, "b", formatClaude, body)
	if outA != outB {
		t.Fatalf("same key, same value must render the same placeholder:\n%s\n%s", outA, outB)
	}
	format, _ := newPlaceholderFormat("", "")
	other := format.render([]byte("another key another key another!"), sampleToken, typeKey, 0)
	if strings.Contains(outA, other) {
		t.Fatal("a different key must render a different placeholder")
	}
}

func TestClaudeNonStreamRoundTrip(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"GITHUB_TOKEN=` + sampleToken + `\nOWNER=` + sampleEmail + `"}]}]}`
	redacted, values := redactFor(t, p, "r1", formatClaude, body)
	if strings.Contains(redacted, sampleToken) || strings.Contains(redacted, sampleEmail) {
		t.Fatalf("secret went upstream: %s", redacted)
	}
	token := placeholderFor(t, values, sampleToken)
	email := placeholderFor(t, values, sampleEmail)

	response := `{"id":"msg_1","type":"message","content":[` +
		`{"type":"thinking","thinking":"use ` + token + `","signature":"sig"},` +
		`{"type":"text","text":"Pushing as ` + email + `."},` +
		`{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"git push https://` + token + `@github.com/o/r"}}]}`
	resp, err := p.InterceptResponse(nil, pluginapi.ResponseInterceptRequest{RequestID: "r1", SourceFormat: formatClaude, Body: []byte(response)})
	if err != nil {
		t.Fatal(err)
	}
	got := gjson.ParseBytes(resp.Body)
	if text := got.Get("content.1.text").String(); text != "Pushing as "+sampleEmail+"." {
		t.Fatalf("text not restored: %q", text)
	}
	if cmd := got.Get("content.2.input.command").String(); cmd != "git push https://"+sampleToken+"@github.com/o/r" {
		t.Fatalf("tool input not restored: %q", cmd)
	}
	if thinking := got.Get("content.0.thinking").String(); thinking != "use "+token {
		t.Fatalf("signed thinking must keep its placeholder, got %q", thinking)
	}
}

// TestRestoredValueIsReplacedAgainAnywhere is the security property of the
// literal pass: once the model has used a placeholder and the client ran the
// restored command, the value comes back in a context no detector recognises,
// and it must still not go upstream.
func TestRestoredValueIsReplacedAgainAnywhere(t *testing.T) {
	p := newTestPlugin(t)
	first := `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"DB_PASSWORD: ` + samplePassword + `"}]}]}`
	_, values := redactFor(t, p, "r1", formatClaude, first)
	placeholder := placeholderFor(t, values, samplePassword)

	second := `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"mysql -u app -p` + "'" + samplePassword + "'" + ` db"}}]}]}`
	redacted, values2 := redactFor(t, p, "r2", formatClaude, second)
	if strings.Contains(redacted, samplePassword) {
		t.Fatalf("known value leaked in a new context: %s", redacted)
	}
	if !strings.Contains(redacted, placeholder) || values2[placeholder] != samplePassword {
		t.Fatalf("expected the same placeholder %s: %s", placeholder, redacted)
	}
}

func TestLiteralPassBoundaries(t *testing.T) {
	p := newTestPlugin(t)
	p.notice = ""
	_, values := redactFor(t, p, "r1", formatClaude, `{"messages":[{"role":"user","content":"password: `+samplePassword+` host 10.20.30.40"}]}`)
	placeholder := placeholderFor(t, values, samplePassword)
	placeholderFor(t, values, "10.20.30.40")

	// The model writes `-p<placeholder>`; once restored and replayed, the
	// value sits mid-word and must still be replaced.
	redacted, _ := redactFor(t, p, "r2", formatClaude, `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Bash","input":{"command":"mysql -uroot -p`+samplePassword+` app"}}]}]}`)
	if strings.Contains(redacted, samplePassword) || !strings.Contains(redacted, "-p"+placeholder+" app") {
		t.Fatalf("a long key glued to a flag leaked: %s", redacted)
	}
	// Structured values keep word boundaries: digits glued on both sides
	// make it a different number, which the IP detector skips too.
	redacted, _ = redactFor(t, p, "r3", formatClaude, `{"messages":[{"role":"user","content":"serial 110.20.30.401"}]}`)
	if !strings.Contains(redacted, "110.20.30.401") {
		t.Fatalf("an IP inside a longer token must not be replaced: %s", redacted)
	}
}

// TestRestoredValuesInUnscannedFieldsAreReplaced covers every place the
// restore side writes to that the detectors do not read: Responses custom
// tools, keys the collector skips, and tool input with scan_tool_input off.
func TestRestoredValuesInUnscannedFieldsAreReplaced(t *testing.T) {
	off := false
	p := newTestPlugin(t, func(c *privacyFilterConfig) { c.ScanToolInput = &off })
	p.notice = ""
	_, values := redactFor(t, p, "r1", formatResponses, `{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"TOKEN=`+sampleToken+`"}]}]}`)
	placeholder := placeholderFor(t, values, sampleToken)

	bodies := []string{
		`{"input":[{"type":"custom_tool_call","call_id":"c","name":"apply_patch","input":"+TOKEN=` + sampleToken + `"}]}`,
		`{"input":[{"type":"local_shell_call","call_id":"c","action":{"type":"exec","command":["git","push","https://` + sampleToken + `@github.com/o/r"]}}]}`,
		`{"input":[{"type":"function_call","call_id":"c","name":"run","arguments":"{\"cmd\":\"echo ` + sampleToken + `\"}"}]}`,
		`{"input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_text","text":"` + sampleToken + `"}]}]}`,
		`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Upload","input":{"data":"` + sampleToken + `"}}]}]}`,
		`{"unknown_shape":{"deeply":["nested ` + sampleToken + `"]}}`,
	}
	for i, body := range bodies {
		redacted, got := redactFor(t, p, fmt.Sprintf("u%d", i), formatResponses, body)
		if strings.Contains(redacted, sampleToken) || got[placeholder] != sampleToken {
			t.Fatalf("body %d leaked or lost its restore entry: %s", i, redacted)
		}
	}
	thinking := `{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"` + sampleToken + `","signature":"s"}]}]}`
	if redacted, _ := redactFor(t, p, "think", formatClaude, thinking); redacted != thinking {
		t.Fatalf("signed thinking must stay byte-identical: %s", redacted)
	}
}

func TestNoticeRequiresRestore(t *testing.T) {
	off := false
	p := newTestPlugin(t, func(c *privacyFilterConfig) { c.RestoreResponses = &off })
	redacted, _ := redactFor(t, p, "n1", formatClaude, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	if strings.Contains(redacted, noticeMarker) || strings.Contains(redacted, sampleToken) {
		t.Fatalf("one-way mode must replace without promising restoration: %s", redacted)
	}
}

func TestResponsesWebsocketStream(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "w1", formatResponses, `{"input":"key `+sampleToken+`"}`)
	token := placeholderFor(t, values, sampleToken)
	full := "token=" + token + " ok p"
	var chunks []string
	for i, piece := range chop(full, 4) {
		chunks = append(chunks, `{"type":"response.output_text.delta","item_id":"msg","output_index":0,"content_index":0,"sequence_number":`+fmt.Sprint(i)+`,"delta":`+jsonString(piece)+`}`)
	}
	chunks = append(chunks, `{"type":"response.output_text.done","item_id":"msg","output_index":0,"content_index":0,"text":`+jsonString(full)+`}`)

	if _, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{RequestID: "w1", SourceFormat: formatResponses, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex}); err != nil {
		t.Fatal(err)
	}
	var deltas strings.Builder
	var done string
	for i, chunk := range chunks {
		resp, _ := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{RequestID: "w1", SourceFormat: formatResponses, ChunkIndex: i, Body: []byte(chunk)})
		body := chunk
		if len(resp.Body) > 0 {
			body = string(resp.Body)
		}
		// The WebSocket forwarder sends one message per JSON line.
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if !gjson.Valid(line) {
				t.Fatalf("chunk %d produced an invalid line %q", i, line)
			}
			ev := gjson.Parse(line)
			switch ev.Get("type").String() {
			case "response.output_text.delta":
				deltas.WriteString(ev.Get("delta").String())
			case "response.output_text.done":
				done = ev.Get("text").String()
			}
		}
	}
	want := "token=" + sampleToken + " ok p"
	if deltas.String() != want || done != want {
		t.Fatalf("deltas %q done %q want %q", deltas.String(), done, want)
	}
}

func TestContextDetectorSkipsCode(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"messages":[{"role":"user","content":"password = os.getenv(\"DB_PASS\")\ntoken: config.auth.token\npassword: null"}]}`
	redacted, values := redactFor(t, p, "r1", formatClaude, body)
	if len(values) != 0 {
		t.Fatalf("code must not become vault entries: %v\n%s", values, redacted)
	}
}

func TestBenignIPsAndSkipTypes(t *testing.T) {
	p := newTestPlugin(t)
	redacted, _ := redactFor(t, p, "r1", formatClaude, `{"messages":[{"role":"user","content":"curl http://127.0.0.1:8317 and ssh 10.20.30.40"}]}`)
	if !strings.Contains(redacted, "127.0.0.1") || strings.Contains(redacted, "10.20.30.40") {
		t.Fatalf("loopback must stay, private address must go: %s", redacted)
	}
	q := newTestPlugin(t, func(c *privacyFilterConfig) { c.SkipTypes = []string{"ip"} })
	redacted, _ = redactFor(t, q, "r1", formatClaude, `{"messages":[{"role":"user","content":"ssh 10.20.30.40"}]}`)
	if !strings.Contains(redacted, "10.20.30.40") {
		t.Fatalf("skip_types ip must leave addresses alone: %s", redacted)
	}
}

func TestAlreadyRedactedBodyIsStable(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"messages":[{"role":"user","content":"key ` + sampleToken + ` mail ` + sampleEmail + `"}]}`
	once, values := redactFor(t, p, "r1", formatClaude, body)
	p.notice = ""
	twice, values2 := redactFor(t, p, "r2", formatClaude, once)
	if twice != once {
		t.Fatalf("redacting twice must be a no-op:\n%s\n%s", once, twice)
	}
	if len(values2) != len(values) {
		t.Fatalf("existing placeholders must stay restorable: %v vs %v", values2, values)
	}
}

// TestHistoryReplayIsByteStable checks the prompt-cache property: the client
// stores the restored reply, sends it back next turn, and the upstream bytes
// for the earlier turns must not change.
func TestHistoryReplayIsByteStable(t *testing.T) {
	p := newTestPlugin(t)
	p.notice = ""
	user := `{"role":"user","content":"deploy with ` + sampleToken + `"}`
	turn1, values := redactFor(t, p, "r1", formatClaude, `{"messages":[`+user+`]}`)
	token := placeholderFor(t, values, sampleToken)

	reply := `{"content":[{"type":"tool_use","id":"t","name":"Bash","input":{"command":"gh auth login --with-token ` + token + `"}}]}`
	resp, _ := p.InterceptResponse(nil, pluginapi.ResponseInterceptRequest{RequestID: "r1", SourceFormat: formatClaude, Body: []byte(reply)})
	assistant := `{"role":"assistant","content":` + gjson.GetBytes(resp.Body, "content").Raw + `}`
	if strings.Contains(assistant, token) {
		t.Fatalf("client should hold the real value: %s", assistant)
	}

	turn2, _ := redactFor(t, p, "r2", formatClaude, `{"messages":[`+user+`,`+assistant+`]}`)
	prefix := strings.TrimSuffix(turn1, "]}")
	if !strings.HasPrefix(turn2, prefix) {
		t.Fatalf("earlier turns changed upstream:\n%s\n%s", turn1, turn2)
	}
	if !strings.Contains(turn2, "--with-token "+token) {
		t.Fatalf("replayed tool call must carry the same placeholder: %s", turn2)
	}
}

func TestClaudeStream(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "s1", formatClaude, `{"messages":[{"role":"user","content":"GITHUB_TOKEN=`+sampleToken+` mail `+sampleEmail+`"}]}`)
	token := placeholderFor(t, values, sampleToken)
	email := placeholderFor(t, values, sampleEmail)

	event := func(name, js string) string { return "event: " + name + "\ndata: " + js + "\n\n" }
	var chunks []string
	chunks = append(chunks, event("message_start", `{"type":"message_start","message":{"id":"m","content":[]}}`))
	chunks = append(chunks, event("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`))
	chunks = append(chunks, event("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"`+token+`"}}`))
	chunks = append(chunks, event("content_block_stop", `{"type":"content_block_stop","index":0}`))
	chunks = append(chunks, event("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`))
	text := "Token " + token + " belongs to " + email + ", ends with p"
	for _, piece := range chop(text, 3) {
		chunks = append(chunks, event("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":`+jsonString(piece)+`}}`))
	}
	chunks = append(chunks, event("content_block_stop", `{"type":"content_block_stop","index":1}`))
	chunks = append(chunks, event("content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu","name":"Bash","input":{}}}`))
	args := `{"command":"echo ` + token + `"}`
	for _, piece := range chop(args, 2) {
		chunks = append(chunks, event("content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":`+jsonString(piece)+`}}`))
	}
	chunks = append(chunks, event("content_block_stop", `{"type":"content_block_stop","index":2}`))
	chunks = append(chunks, event("message_stop", `{"type":"message_stop"}`))

	transcript := stream(t, p, "s1", formatClaude, chunks)
	var thinking, gotText, gotArgs strings.Builder
	for _, ev := range sseData(transcript) {
		if ev.Get("type").String() != "content_block_delta" {
			continue
		}
		switch ev.Get("index").Int() {
		case 0:
			thinking.WriteString(ev.Get("delta.thinking").String())
		case 1:
			gotText.WriteString(ev.Get("delta.text").String())
		case 2:
			gotArgs.WriteString(ev.Get("delta.partial_json").String())
		}
	}
	if want := "Token " + sampleToken + " belongs to " + sampleEmail + ", ends with p"; gotText.String() != want {
		t.Fatalf("text:\n got %q\nwant %q", gotText.String(), want)
	}
	if cmd := gjson.Get(gotArgs.String(), "command").String(); cmd != "echo "+sampleToken {
		t.Fatalf("tool args %q decode to %q", gotArgs.String(), cmd)
	}
	if thinking.String() != token {
		t.Fatalf("thinking must not be restored: %q", thinking.String())
	}
	// The trailing "p" is a prefix of every placeholder, so it was held and
	// must be flushed as its own delta right before content_block_stop.
	stop := strings.Index(transcript, `{"type":"content_block_stop","index":1}`)
	if stop < 0 || !strings.Contains(transcript[:stop], `"text":"p"}}`) {
		t.Fatalf("held tail was not flushed before the block stop:\n%s", transcript)
	}
}

func TestClaudeStreamRestoresJSONEscapedValues(t *testing.T) {
	p := newTestPlugin(t)
	value := `abc"def\ghi-jkl-mnop`
	placeholder := p.vault.put(value, typeKey)
	st := &requestState{r: newRestorer(p.format, map[string]string{placeholder: value})}
	p.states.put("s2", st)
	args := `{"path":"/tmp/x","content":"` + placeholder + `"}`
	var chunks []string
	for _, piece := range chop(args, 5) {
		chunks = append(chunks, "event: content_block_delta\ndata: "+`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+jsonString(piece)+`}}`+"\n\n")
	}
	chunks = append(chunks, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	var joined strings.Builder
	for _, ev := range sseData(stream(t, p, "s2", formatClaude, chunks)) {
		joined.WriteString(ev.Get("delta.partial_json").String())
	}
	if got := gjson.Get(joined.String(), "content").String(); got != value {
		t.Fatalf("partial_json %q decodes to %q, want %q", joined.String(), got, value)
	}
}

func TestOpenAIChatStream(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "o1", formatOpenAI, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	token := placeholderFor(t, values, sampleToken)

	var chunks []string
	chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`)
	for _, piece := range chop("use "+token+" now p", 4) {
		chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{"content":`+jsonString(piece)+`}}]}`)
	}
	chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call","type":"function","function":{"name":"run","arguments":""}}]}}]}`)
	for _, piece := range chop(`{"cmd":"echo `+token+`"}`, 3) {
		chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+jsonString(piece)+`}}]}}]}`)
	}
	chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)

	var content, args strings.Builder
	for _, ev := range sseData(stream(t, p, "o1", formatOpenAI, chunks)) {
		content.WriteString(ev.Get("choices.0.delta.content").String())
		ev.Get("choices.0.delta.tool_calls").ForEach(func(_, call gjson.Result) bool {
			args.WriteString(call.Get("function.arguments").String())
			return true
		})
	}
	if want := "use " + sampleToken + " now p"; content.String() != want {
		t.Fatalf("content %q, want %q", content.String(), want)
	}
	if cmd := gjson.Get(args.String(), "cmd").String(); cmd != "echo "+sampleToken {
		t.Fatalf("arguments %q decode to %q", args.String(), cmd)
	}
}

func TestResponsesStreamWithSplitEventLines(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "x1", formatResponses, `{"input":"key `+sampleToken+`"}`)
	token := placeholderFor(t, values, sampleToken)

	var chunks []string
	add := func(name, js string) {
		// The codex passthrough forwards SSE line by line.
		chunks = append(chunks, "event: "+name, "data: "+js+"\n")
	}
	add("response.output_item.added", `{"type":"response.output_item.added","output_index":0,"item":{"id":"msg","type":"message","content":[]}}`)
	full := "token=" + token + " p"
	for i, piece := range chop(full, 4) {
		add("response.output_text.delta", `{"type":"response.output_text.delta","item_id":"msg","output_index":0,"content_index":0,"sequence_number":`+jsonString(string(rune('a'+i)))+`,"delta":`+jsonString(piece)+`}`)
	}
	add("response.output_text.done", `{"type":"response.output_text.done","item_id":"msg","output_index":0,"content_index":0,"text":`+jsonString(full)+`}`)
	add("response.completed", `{"type":"response.completed","response":{"output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"`+token+`"}]},{"type":"message","content":[{"type":"output_text","text":`+jsonString(full)+`}]}]}}`)

	transcript := stream(t, p, "x1", formatResponses, chunks)
	var deltas strings.Builder
	var done, completed, reasoning string
	for _, ev := range sseData(transcript) {
		switch ev.Get("type").String() {
		case "response.output_text.delta":
			deltas.WriteString(ev.Get("delta").String())
		case "response.output_text.done":
			done = ev.Get("text").String()
		case "response.completed":
			completed = ev.Get("response.output.1.content.0.text").String()
			reasoning = ev.Get("response.output.0.summary.0.text").String()
		}
	}
	want := "token=" + sampleToken + " p"
	if deltas.String() != want || done != want || completed != want {
		t.Fatalf("deltas=%q done=%q completed=%q want %q\n%s", deltas.String(), done, completed, want, transcript)
	}
	if reasoning != token {
		t.Fatalf("reasoning summary must keep its placeholder: %q", reasoning)
	}
	// Every data line must still sit right under its own event line.
	lines := strings.Split(transcript, "\n")
	for i, line := range lines {
		if payload, ok := strings.CutPrefix(line, "data: "); ok {
			if i == 0 || lines[i-1] != "event: "+gjson.Get(payload, "type").String() {
				t.Fatalf("event/data pairing broken at line %d:\n%s", i, transcript)
			}
		}
	}
}

func TestGeminiStream(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "g1", formatGemini, `{"contents":[{"role":"user","parts":[{"text":"mail `+sampleEmail+`"}]}]}`)
	email := placeholderFor(t, values, sampleEmail)
	var chunks []string
	chunks = append(chunks, `{"candidates":[{"content":{"role":"model","parts":[{"text":"`+email+`","thought":true}]}}]}`)
	for _, piece := range chop("write to "+email+" p", 5) {
		chunks = append(chunks, `{"candidates":[{"content":{"role":"model","parts":[{"text":`+jsonString(piece)+`}]}}]}`)
	}
	chunks = append(chunks, `{"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"STOP"}]}`)
	var text, thought strings.Builder
	for _, ev := range sseData(stream(t, p, "g1", formatGemini, chunks)) {
		ev.Get("candidates.0.content.parts").ForEach(func(_, part gjson.Result) bool {
			if part.Get("thought").Bool() {
				thought.WriteString(part.Get("text").String())
			} else {
				text.WriteString(part.Get("text").String())
			}
			return true
		})
	}
	if want := "write to " + sampleEmail + " p"; text.String() != want {
		t.Fatalf("text %q, want %q", text.String(), want)
	}
	if thought.String() != email {
		t.Fatalf("thought parts must keep placeholders: %q", thought.String())
	}
}

func TestStreamWithoutPlaceholdersIsUntouched(t *testing.T) {
	p := newTestPlugin(t)
	redactFor(t, p, "c1", formatClaude, `{"messages":[{"role":"user","content":"hello"}]}`)
	resp, _ := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: "c1", SourceFormat: formatClaude, ChunkIndex: 0,
		Body: []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"pf-key-000000000000\"}}\n\n"),
	})
	if resp.Body != nil || resp.DropChunk {
		t.Fatalf("a clean request must stream untouched: %+v", resp)
	}
}

func TestHeaderInitFallsBackToOriginalRequest(t *testing.T) {
	p := newTestPlugin(t)
	redacted, values := redactFor(t, p, "first", formatClaude, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	token := placeholderFor(t, values, sampleToken)
	p.states.take("first")
	if _, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: "unseen", SourceFormat: formatClaude, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex,
		OriginalRequest: []byte(redacted),
	}); err != nil {
		t.Fatal(err)
	}
	resp, _ := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: "unseen", SourceFormat: formatClaude, ChunkIndex: 0,
		Body: []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + token + " \"}}\n\n"),
	})
	if !strings.Contains(string(resp.Body), sampleToken) {
		t.Fatalf("expected restore from OriginalRequest, got %q", string(resp.Body))
	}
}

func TestResponseCannotPullForeignValues(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "owner", formatClaude, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	token := placeholderFor(t, values, sampleToken)
	redactFor(t, p, "other", formatClaude, `{"messages":[{"role":"user","content":"hello"}]}`)
	resp, _ := p.InterceptResponse(nil, pluginapi.ResponseInterceptRequest{
		RequestID: "other", SourceFormat: formatClaude,
		Body: []byte(`{"content":[{"type":"text","text":"` + token + `"}]}`),
	})
	if resp.Body != nil {
		t.Fatalf("another request's placeholder must not be restored: %s", string(resp.Body))
	}
}

func TestNoticeInjection(t *testing.T) {
	format, _ := newPlaceholderFormat("", "")
	notice := noticeText(format)
	cases := []struct {
		name, format, body, path string
	}{
		{"claude array", formatClaude, `{"system":[{"type":"text","text":"a","cache_control":{"type":"ephemeral"}}],"messages":[]}`, "system.1.text"},
		{"claude string", formatClaude, `{"system":"a","messages":[]}`, "system"},
		{"claude missing", formatClaude, `{"messages":[]}`, "system.0.text"},
		{"openai system", formatOpenAI, `{"messages":[{"role":"system","content":"a"},{"role":"user","content":"b"}]}`, "messages.0.content"},
		{"openai no system", formatOpenAI, `{"messages":[{"role":"user","content":"b"}]}`, "messages.0.content"},
		{"responses", formatResponses, `{"instructions":"a","input":"b"}`, "instructions"},
		{"responses missing", formatResponses, `{"input":"b"}`, "instructions"},
		{"gemini", formatGemini, `{"contents":[],"systemInstruction":{"parts":[{"text":"a"}]}}`, "systemInstruction.parts.1.text"},
		{"gemini missing", formatGemini, `{"contents":[]}`, "systemInstruction.parts.0.text"},
	}
	for _, tc := range cases {
		out := injectNotice([]byte(tc.body), tc.format, notice)
		if out == nil || !gjson.ValidBytes(out) {
			t.Fatalf("%s: injection failed: %s", tc.name, string(out))
		}
		if got := gjson.GetBytes(out, tc.path).String(); !strings.HasSuffix(got, notice) {
			t.Fatalf("%s: notice not at %s: %s", tc.name, tc.path, string(out))
		}
		if again := injectNotice(out, tc.format, notice); again != nil {
			t.Fatalf("%s: notice injected twice", tc.name)
		}
	}
	if got := injectNotice([]byte(`{"messages":[{"role":"user","content":"b"}]}`), formatOpenAI, notice); gjson.GetBytes(got, "messages.1.content").String() != "b" {
		t.Fatalf("inserting a system message must keep the conversation: %s", string(got))
	}
}

func TestUUIDStyle(t *testing.T) {
	p := newTestPlugin(t, func(c *privacyFilterConfig) { c.PlaceholderStyle = "uuid" })
	_, values := redactFor(t, p, "u1", formatClaude, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	placeholder := placeholderFor(t, values, sampleToken)
	if !p.format.re.MatchString(placeholder) || len(placeholder) != 36 {
		t.Fatalf("not a v8 uuid: %q", placeholder)
	}
	resp, _ := p.InterceptResponse(nil, pluginapi.ResponseInterceptRequest{
		RequestID: "u1", SourceFormat: formatClaude,
		Body: []byte(`{"content":[{"type":"text","text":"use ` + placeholder + `"}]}`),
	})
	if gjson.GetBytes(resp.Body, "content.0.text").String() != "use "+sampleToken {
		t.Fatalf("uuid placeholder not restored: %s", string(resp.Body))
	}
}

func TestStreamFastPathSkipsDecoding(t *testing.T) {
	plugin, err := buildPlugin([]byte("data_dir: "+t.TempDir()+"\n"), ".")
	if err != nil {
		t.Fatal(err)
	}
	privacyFilterABIState.Lock()
	privacyFilterABIState.plugin = plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()
	// Not even valid JSON past the peeked fields: only the fast path can
	// answer this.
	raw, err := handlePrivacyFilterABIMethod(context.Background(), "response.intercept_stream_chunk", []byte(`{"RequestID":"nobody","ChunkIndex":3,"Body":!!!}`))
	if err != nil || !bytes.Equal(raw, emptyStreamChunkEnvelope) {
		t.Fatalf("fast path not taken: %s %v", string(raw), err)
	}
}

func TestKeyNamesStayVisible(t *testing.T) {
	p := newTestPlugin(t)
	redacted, _ := redactFor(t, p, "k1", formatClaude, `{"messages":[{"role":"user","content":"GITHUB_TOKEN=`+sampleToken+`\nAWS_ACCESS_KEY_ID=`+sampleAWSKey+`\napi_key: \"sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z\""}]}`)
	for _, want := range []string{`GITHUB_TOKEN=pf-key-`, `AWS_ACCESS_KEY_ID=pf-key-`, `api_key: \"pf-key-`} {
		if !strings.Contains(redacted, want) {
			t.Fatalf("expected %q in %s", want, redacted)
		}
	}
}

func TestStreamEdgeCases(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "e1", formatOpenAI, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	token := placeholderFor(t, values, sampleToken)

	// OpenAI: an empty-delta chunk between two halves of a placeholder must
	// not release the held half early.
	half := len(token) / 2
	chunks := []string{
		`{"choices":[{"index":0,"delta":{"content":"x ` + token[:half] + `"}}]}`,
		`{"choices":[{"index":0,"delta":{}}]}`,
		`{"choices":[{"index":0,"delta":{"content":"` + token[half:] + ` y"}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
	}
	var content strings.Builder
	for _, ev := range sseData(stream(t, p, "e1", formatOpenAI, chunks)) {
		content.WriteString(ev.Get("choices.0.delta.content").String())
	}
	if content.String() != "x "+sampleToken+" y" {
		t.Fatalf("openai content %q", content.String())
	}

	// A bootstrap retry re-runs header init: a tail held from the failed
	// attempt must not leak into the new stream.
	p.states.put("e2", &requestState{r: newRestorer(p.format, values)})
	evt := func(text string) string {
		return "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":" + jsonString(text) + "}}\n\n"
	}
	stream(t, p, "e2", formatClaude, []string{evt("abandoned " + token[:5])})
	transcript := stream(t, p, "e2", formatClaude, []string{evt("fresh"), "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"})
	if strings.Contains(transcript, "abandoned") || strings.Contains(transcript, token[:5]) {
		t.Fatalf("state from the abandoned attempt leaked: %s", transcript)
	}

	// Gemini: text ending in a placeholder prefix followed by a function
	// call part in the same chunk must flush the tail into that chunk.
	p.states.put("e3", &requestState{r: newRestorer(p.format, values)})
	gem := stream(t, p, "e3", formatGemini, []string{
		`{"candidates":[{"content":{"parts":[{"text":"run p"},{"functionCall":{"name":"sh","args":{"cmd":"echo ` + token + `"}}}]}}]}`,
		`{"candidates":[{"content":{"parts":[{"text":"done"}]},"finishReason":"STOP"}]}`,
	})
	var text strings.Builder
	var args string
	for _, ev := range sseData(gem) {
		ev.Get("candidates.0.content.parts").ForEach(func(_, part gjson.Result) bool {
			text.WriteString(part.Get("text").String())
			if call := part.Get("functionCall.args.cmd"); call.Exists() {
				args = call.String()
			}
			return true
		})
	}
	if text.String() != "run pdone" || args != "echo "+sampleToken {
		t.Fatalf("gemini text %q args %q", text.String(), args)
	}
}
