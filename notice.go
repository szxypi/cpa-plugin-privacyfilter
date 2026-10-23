package main

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const noticeMarker = "[privacyfilter]"

// noticeText tells the model what placeholders are, so it uses them like the
// values they stand for. The wording is deliberately matter-of-fact: framing
// them as protected secrets makes models refuse to put them into commands,
// which is exactly the workflow this plugin exists to keep working.
func noticeText(format *placeholderFormat) string {
	return noticeMarker + " Some literal values in this conversation (for example API keys, tokens, " +
		"passwords, email addresses and IP addresses) appear as value references such as " + format.example() +
		". A reference is a drop-in stand-in for its value: the user's local tooling substitutes the actual " +
		"value wherever your output is used, including text, code, files, commands and tool arguments. " +
		"Use each reference verbatim exactly where the value itself belongs, just as you would use the value. " +
		"The user already has these values and has authorised their use, so there is no need to ask for them, " +
		"describe them as missing, or avoid using them. Copy a reference whole and unchanged. Do not alter, " +
		"split or invent references, do not compute on them (hash, encode, measure, slice), and do not swap " +
		"in sample values such as localhost or test keys. Tasks that do not depend on the value carry on as usual."
}

// injectNotice appends the notice to the system prompt of a request body. It
// returns nil when the format is unknown, the body has no usable system slot,
// or the notice is already present. The notice goes at the end of the system
// prompt so the cached prefix before it is untouched.
func injectNotice(body []byte, format, notice string) []byte {
	if bytes.Contains(body, []byte(noticeMarker)) || !gjson.ValidBytes(body) {
		return nil
	}
	textBlock := func(typ string) []byte {
		block := []byte(`{`)
		if typ != "" {
			block = append(block, `"type":"`+typ+`",`...)
		}
		block = append(block, `"text":`...)
		block = appendJSONString(block, notice)
		return append(block, '}')
	}
	appendText := func(existing string) []byte {
		return appendJSONString(nil, existing+"\n\n"+notice)
	}
	set := func(path string, raw []byte) []byte {
		out, err := sjson.SetRawBytes(body, path, raw)
		if err != nil {
			return nil
		}
		return out
	}

	switch format {
	case formatClaude:
		system := gjson.GetBytes(body, "system")
		switch {
		case system.Type == gjson.String:
			return set("system", appendText(system.String()))
		case system.IsArray():
			return set("system.-1", textBlock("text"))
		case !system.Exists():
			return set("system", append(append([]byte{'['}, textBlock("text")...), ']'))
		}
	case formatOpenAI:
		messages := gjson.GetBytes(body, "messages")
		if !messages.IsArray() {
			return nil
		}
		first := messages.Get("0")
		if role := first.Get("role").String(); role == "system" || role == "developer" {
			content := first.Get("content")
			switch {
			case content.Type == gjson.String:
				return set("messages.0.content", appendText(content.String()))
			case content.IsArray():
				return set("messages.0.content.-1", textBlock("text"))
			}
			return nil
		}
		message := []byte(`{"role":"system","content":`)
		message = appendJSONString(message, notice)
		message = append(message, '}')
		rest := strings.TrimSpace(messages.Raw[1 : len(messages.Raw)-1])
		rebuilt := append([]byte{'['}, message...)
		if rest != "" {
			rebuilt = append(append(rebuilt, ','), messages.Raw[1:]...)
		} else {
			rebuilt = append(rebuilt, ']')
		}
		return set("messages", rebuilt)
	case formatResponses:
		instructions := gjson.GetBytes(body, "instructions")
		switch {
		case instructions.Type == gjson.String:
			return set("instructions", appendText(instructions.String()))
		case !instructions.Exists() || instructions.Type == gjson.Null:
			return set("instructions", appendJSONString(nil, notice))
		}
	case formatGemini:
		for _, key := range []string{"systemInstruction", "system_instruction"} {
			instruction := gjson.GetBytes(body, key)
			if !instruction.Exists() {
				continue
			}
			if instruction.Get("parts").IsArray() {
				return set(key+".parts.-1", textBlock(""))
			}
			return nil
		}
		if gjson.GetBytes(body, "contents").IsArray() {
			return set("systemInstruction", append(append([]byte(`{"parts":[`), textBlock("")...), "]}"...))
		}
	}
	return nil
}
