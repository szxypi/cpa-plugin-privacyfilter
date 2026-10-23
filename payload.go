package main

import (
	"github.com/tidwall/gjson"
)

// textRef points at one JSON string literal inside a request body: where its
// raw form starts, the raw form itself (quotes included), and the decoded
// value handed to the scanner.
type textRef struct {
	index int
	raw   string
	value string
	// jsonText marks a string that itself holds JSON text (tool-call
	// arguments). A bare number replaced there must stay valid JSON.
	jsonText bool
}

// walkOptions tunes which fields are collected.
type walkOptions struct {
	// ScanToolInput includes tool-call arguments and tool results carrying
	// structured JSON (Claude tool_use.input, OpenAI function arguments,
	// Gemini functionCall.args / functionResponse.response).
	ScanToolInput bool
}

const (
	// maxWalkDepth bounds the recursion into free-form tool arguments.
	maxWalkDepth = 12
	// binaryProbeBytes is the length past which a string with no whitespace
	// and a pure base64 alphabet is treated as an encoded blob (inline
	// images, audio, PDFs) and skipped.
	binaryProbeBytes = 2048
)

type collector struct {
	opts walkOptions
	refs []textRef
	seen map[int]struct{}
}

// collectTexts gathers every model-visible text field of a request body. The
// supported shapes are Claude Messages, OpenAI chat completions, OpenAI
// Responses and Gemini generateContent; unknown shapes contribute nothing and
// the body is passed through untouched.
func collectTexts(body []byte, opts walkOptions) []textRef {
	if !gjson.ValidBytes(body) {
		return nil
	}
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return nil
	}
	c := &collector{opts: opts, seen: make(map[int]struct{}, 64)}

	// Claude: system is a string or an array of content blocks.
	c.content(root.Get("system"), 0)
	// OpenAI Responses: top-level instructions string.
	c.add(root.Get("instructions"))

	// Claude Messages and OpenAI chat completions.
	if messages := root.Get("messages"); messages.IsArray() {
		messages.ForEach(func(_, message gjson.Result) bool {
			c.message(message)
			return true
		})
	}

	// OpenAI Responses: input is a string or an array of typed items.
	if input := root.Get("input"); input.Exists() {
		if input.Type == gjson.String {
			c.add(input)
		} else if input.IsArray() {
			input.ForEach(func(_, item gjson.Result) bool {
				c.responsesItem(item)
				return true
			})
		}
	}

	// Gemini generateContent.
	if contents := root.Get("contents"); contents.IsArray() {
		contents.ForEach(func(_, content gjson.Result) bool {
			c.geminiContent(content)
			return true
		})
	}
	c.geminiContent(root.Get("systemInstruction"))
	c.geminiContent(root.Get("system_instruction"))

	// Legacy completions.
	if prompt := root.Get("prompt"); prompt.Type == gjson.String {
		c.add(prompt)
	}

	return c.refs
}

func (c *collector) message(message gjson.Result) {
	if !message.IsObject() {
		return
	}
	c.content(message.Get("content"), 0)
	if !c.opts.ScanToolInput {
		return
	}
	// OpenAI chat: assistant tool calls carry their arguments as a JSON string.
	message.Get("tool_calls").ForEach(func(_, call gjson.Result) bool {
		c.addJSONText(call.Get("function.arguments"))
		return true
	})
	c.addJSONText(message.Get("function_call.arguments"))
}

// content handles the "content" field in both of its shapes: a bare string, or
// an array of typed blocks.
func (c *collector) content(content gjson.Result, depth int) {
	if !content.Exists() || depth > maxWalkDepth {
		return
	}
	if content.Type == gjson.String {
		c.add(content)
		return
	}
	if !content.IsArray() {
		return
	}
	content.ForEach(func(_, block gjson.Result) bool {
		c.block(block, depth+1)
		return true
	})
}

func (c *collector) block(block gjson.Result, depth int) {
	if depth > maxWalkDepth {
		return
	}
	if block.Type == gjson.String {
		c.add(block)
		return
	}
	if !block.IsObject() {
		return
	}
	switch block.Get("type").String() {
	case "text", "input_text", "output_text", "summary_text":
		c.add(block.Get("text"))
	case "tool_result", "function_call_output", "custom_tool_call_output", "local_shell_call_output", "mcp_call_output":
		c.content(block.Get("content"), depth)
		c.content(block.Get("output"), depth)
	case "tool_use", "function_call", "server_tool_use", "mcp_tool_use", "custom_tool_call", "local_shell_call", "mcp_call":
		if c.opts.ScanToolInput {
			if input := block.Get("input"); input.Type == gjson.String {
				c.add(input) // Responses custom tools (apply_patch) take free text
			} else {
				c.free(input, depth)
			}
			c.addJSONText(block.Get("arguments"))
			c.free(block.Get("action"), depth)
			c.add(block.Get("output"))
		}
	case "thinking", "redacted_thinking", "reasoning":
		// Extended-thinking blocks are replayed verbatim: they carry a
		// signature the provider verifies, so any edit invalidates the turn.
	case "image", "input_image", "document", "input_audio", "input_file":
		// Binary payloads (base64 or a URL), nothing to scan.
	default:
		// Forward compatibility: an unknown block that still exposes text.
		c.add(block.Get("text"))
		c.content(block.Get("content"), depth)
	}
}

func (c *collector) responsesItem(item gjson.Result) {
	if item.Type == gjson.String {
		c.add(item)
		return
	}
	if !item.IsObject() {
		return
	}
	switch item.Get("type").String() {
	case "message", "":
		c.content(item.Get("content"), 0)
	default:
		c.block(item, 0)
	}
}

func (c *collector) geminiContent(content gjson.Result) {
	if !content.IsObject() && !content.IsArray() {
		return
	}
	if content.IsArray() {
		content.ForEach(func(_, item gjson.Result) bool {
			c.geminiContent(item)
			return true
		})
		return
	}
	parts := content.Get("parts")
	if !parts.IsArray() {
		// systemInstruction may be given as {"text": "..."}.
		c.add(content.Get("text"))
		return
	}
	parts.ForEach(func(_, part gjson.Result) bool {
		c.add(part.Get("text"))
		if c.opts.ScanToolInput {
			c.free(part.Get("functionCall.args"), 0)
			c.free(part.Get("function_call.args"), 0)
			c.free(part.Get("functionResponse.response"), 0)
			c.free(part.Get("function_response.response"), 0)
		}
		return true
	})
}

// free walks free-form JSON (tool arguments and tool responses) and collects
// every string it finds, skipping keys that hold encoded binary.
func (c *collector) free(value gjson.Result, depth int) {
	if !value.Exists() || depth > maxWalkDepth {
		return
	}
	switch {
	case value.Type == gjson.String:
		c.add(value)
	case value.IsArray():
		value.ForEach(func(_, item gjson.Result) bool {
			c.free(item, depth+1)
			return true
		})
	case value.IsObject():
		value.ForEach(func(key, item gjson.Result) bool {
			if isBinaryKey(key.String()) {
				return true
			}
			c.free(item, depth+1)
			return true
		})
	}
}

func isBinaryKey(key string) bool {
	switch key {
	case "data", "b64_json", "base64", "bytes", "inlineData", "inline_data", "fileData", "file_data":
		return true
	}
	return false
}

// remainingStrings returns every other string literal in the body that a
// restored value could have been written into: fields outside the collector's
// shapes, keys the collector skips, tool arguments when scan_tool_input is off.
// They get no detection, only the known-value pass, so a value restored into a
// response never goes back upstream in clear text. Signed thinking and
// reasoning content is skipped for the same reason the restore side skips it.
func remainingStrings(body []byte, seen map[int]struct{}, minBytes int) []textRef {
	var out []textRef
	var walk func(v gjson.Result, depth int)
	walk = func(v gjson.Result, depth int) {
		if depth > 64 {
			return
		}
		switch {
		case v.Type == gjson.String:
			if v.Index <= 0 || len(v.Raw) < minBytes+2 {
				return
			}
			if _, ok := seen[v.Index]; ok {
				return
			}
			text := v.String()
			if len(text) >= minBytes && !looksBinary(text) {
				out = append(out, textRef{index: v.Index, raw: v.Raw, value: text})
			}
		case v.IsObject():
			if restoreSkipTypes[v.Get("type").String()] {
				return
			}
			v.ForEach(func(k, item gjson.Result) bool {
				if !restoreSkipKeys[k.String()] {
					walk(item, depth+1)
				}
				return true
			})
		case v.IsArray():
			v.ForEach(func(_, item gjson.Result) bool {
				walk(item, depth+1)
				return true
			})
		}
	}
	if gjson.ValidBytes(body) {
		walk(gjson.ParseBytes(body), 0)
	}
	return out
}

// addJSONText records a string field that holds JSON text.
func (c *collector) addJSONText(value gjson.Result) {
	c.add(value)
	if n := len(c.refs); n > 0 && c.refs[n-1].index == value.Index {
		c.refs[n-1].jsonText = true
	}
}

// add records a string field, skipping empties, duplicates and blobs.
func (c *collector) add(value gjson.Result) {
	if value.Type != gjson.String || value.Index <= 0 || len(value.Raw) < 2 {
		return
	}
	if _, ok := c.seen[value.Index]; ok {
		return
	}
	text := value.String()
	if text == "" || looksBinary(text) {
		return
	}
	c.seen[value.Index] = struct{}{}
	c.refs = append(c.refs, textRef{index: value.Index, raw: value.Raw, value: text})
}

// looksBinary reports whether a long string is an unbroken run of base64,
// which in these payloads means an inline image, audio clip or file.
func looksBinary(s string) bool {
	if len(s) < binaryProbeBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// edit replaces the raw JSON string literal at index with replacement.
type edit struct {
	index       int
	rawLen      int
	replacement []byte
}

// spliceBody rewrites only the string literals that changed and copies every
// other byte verbatim, so field order, whitespace and the original escaping of
// untouched fields survive intact.
func spliceBody(body []byte, edits []edit) []byte {
	if len(edits) == 0 {
		return nil
	}
	extra := 0
	for _, e := range edits {
		extra += len(e.replacement) - e.rawLen
	}
	out := make([]byte, 0, len(body)+extra+16)
	prev := 0
	for _, e := range edits {
		if e.index < prev || e.index+e.rawLen > len(body) {
			return nil // overlapping or out-of-range edit: refuse to rewrite
		}
		out = append(out, body[prev:e.index]...)
		out = append(out, e.replacement...)
		prev = e.index + e.rawLen
	}
	out = append(out, body[prev:]...)
	return out
}

const hexDigits = "0123456789abcdef"

// appendJSONString writes s as a JSON string literal. It matches
// encoding/json with SetEscapeHTML(false): only the characters JSON requires
// are escaped, so rewritten text stays as close to the original bytes as
// possible.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	dst = appendJSONStringBody(dst, s)
	return append(dst, '"')
}

// appendJSONStringBody writes the escaped body of a JSON string literal,
// without the surrounding quotes.
func appendJSONStringBody(dst []byte, s string) []byte {
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		dst = append(dst, s[start:i]...)
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		}
		start = i + 1
	}
	return append(dst, s[start:]...)
}
