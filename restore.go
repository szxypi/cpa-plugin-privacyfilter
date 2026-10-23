package main

import (
	"strings"

	"github.com/tidwall/gjson"
)

// escMode says how a restored value is spliced into the decoded string that
// held its placeholder.
type escMode uint8

const (
	// modeRaw inserts the value as-is: the string is plain text.
	modeRaw escMode = iota
	// modeJSON escapes the value for a JSON string literal first: the string
	// is itself JSON text (tool-call arguments), and the placeholder sat
	// inside one of its string literals.
	modeJSON
)

// restorer swaps the placeholders of one request back to their values. Only
// placeholders present in that request's upstream body are honoured, so a
// provider cannot make a response pull in a value from another conversation
// by emitting its placeholder.
type restorer struct {
	format *placeholderFormat
	values map[string]string
	// prefixes holds every proper prefix of every placeholder in values. A
	// streamed delta ending in one of them is held back until the next delta.
	prefixes map[string]struct{}
	// unknown counts placeholder-shaped strings in responses that this request
	// never sent. The model made them up or copied them from elsewhere. They
	// stay as they are; the count shows up in the completion log line.
	unknown int
}

func newRestorer(format *placeholderFormat, values map[string]string) *restorer {
	if len(values) == 0 {
		return nil
	}
	return &restorer{format: format, values: values}
}

func (r *restorer) ensurePrefixes() {
	if r.prefixes != nil {
		return
	}
	r.prefixes = make(map[string]struct{}, len(r.values)*8)
	for placeholder := range r.values {
		for n := 1; n < len(placeholder); n++ {
			r.prefixes[placeholder[:n]] = struct{}{}
		}
	}
}

// replace restores every known placeholder in s.
func (r *restorer) replace(s string, mode escMode) (string, int) {
	locs := r.format.find(s)
	if len(locs) == 0 {
		return s, 0
	}
	var b strings.Builder
	prev, count := 0, 0
	for _, loc := range locs {
		value, ok := r.values[s[loc[0]:loc[1]]]
		if !ok {
			r.unknown++
			continue
		}
		if count == 0 {
			b.Grow(len(s) + len(value))
		}
		b.WriteString(s[prev:loc[0]])
		if mode == modeJSON {
			b.Write(appendJSONStringBody(nil, value))
		} else {
			b.WriteString(value)
		}
		prev = loc[1]
		count++
	}
	if count == 0 {
		return s, 0
	}
	b.WriteString(s[prev:])
	return b.String(), count
}

// delta restores one streamed fragment. pending is the tail held back from the
// previous fragment of the same channel. When final is false, a suffix that
// could still grow into a placeholder is returned as the new tail instead of
// being emitted.
func (r *restorer) delta(pending, fragment string, mode escMode, final bool) (emit, tail string, count int) {
	s := pending + fragment
	if !final {
		r.ensurePrefixes()
		lastEnd := 0
		if locs := r.format.find(s); len(locs) > 0 {
			lastEnd = locs[len(locs)-1][1]
		}
		limit := min(len(s)-lastEnd, r.format.maxLen-1)
		for n := limit; n > 0; n-- {
			if _, ok := r.prefixes[s[len(s)-n:]]; ok {
				tail = s[len(s)-n:]
				s = s[:len(s)-n]
				break
			}
		}
	}
	emit, count = r.replace(s, mode)
	return emit, tail, count
}

// Keys and object types the restore walk never enters. Thinking and reasoning
// content is replayed verbatim under a provider signature, so it keeps its
// placeholders: editing it would invalidate the next turn.
var (
	restoreSkipKeys = map[string]bool{
		"signature": true, "thinking": true, "redacted_thinking": true,
		"encrypted_content": true, "reasoning_content": true, "reasoning": true,
		"reasoning_text": true, "thoughtSignature": true, "thought_signature": true,
	}
	restoreSkipTypes = map[string]bool{
		"thinking": true, "redacted_thinking": true, "reasoning": true,
		"reasoning_text": true, "summary_text": true,
	}
	jsonTextKeys = map[string]bool{"arguments": true, "partial_json": true}
)

// restoreJSON restores placeholders in every model-output string of a JSON
// document and returns the rewritten document, or nil when nothing changed.
func (r *restorer) restoreJSON(body []byte) ([]byte, int) {
	if r == nil || !r.format.mayContainBytes(body) || !gjson.ValidBytes(body) {
		return nil, 0
	}
	w := restoreWalker{r: r}
	w.walk(gjson.ParseBytes(body), "", 0)
	if len(w.edits) == 0 {
		return nil, 0
	}
	return spliceBody(body, w.edits), w.count
}

type restoreWalker struct {
	r     *restorer
	edits []edit
	count int
}

func (w *restoreWalker) walk(v gjson.Result, key string, depth int) {
	if depth > 64 {
		return
	}
	switch {
	case v.Type == gjson.String:
		if v.Index <= 0 || !w.r.format.mayContain(v.Raw) {
			return
		}
		mode := modeRaw
		if jsonTextKeys[key] {
			mode = modeJSON
		}
		restored, n := w.r.replace(v.String(), mode)
		if n == 0 {
			return
		}
		w.count += n
		w.edits = append(w.edits, edit{
			index:       v.Index,
			rawLen:      len(v.Raw),
			replacement: appendJSONString(make([]byte, 0, len(restored)+8), restored),
		})
	case v.IsObject():
		if !w.r.format.mayContain(v.Raw) {
			return
		}
		if restoreSkipTypes[v.Get("type").String()] || v.Get("thought").Bool() {
			return
		}
		v.ForEach(func(k, item gjson.Result) bool {
			name := k.String()
			if !restoreSkipKeys[name] {
				w.walk(item, name, depth+1)
			}
			return true
		})
	case v.IsArray():
		if !w.r.format.mayContain(v.Raw) {
			return
		}
		v.ForEach(func(_, item gjson.Result) bool {
			w.walk(item, key, depth+1)
			return true
		})
	}
}
