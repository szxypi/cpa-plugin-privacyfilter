package main

import (
	"encoding/json"

	"privacyfilter/filter"
)

// legacyPlugin reproduces the v0.2.0 pipeline (upstream privacy-filter, whole
// body Unmarshal/Marshal, messages/input only) so the benchmarks can measure
// the same corpus through both implementations.
type legacyPlugin struct {
	filter *filter.Filter
}

func (p *legacyPlugin) redactRequestBody(body []byte) ([]byte, int) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, 0
	}
	field := "messages"
	items, ok := payload[field]
	if !ok {
		field = "input"
		items, ok = payload[field]
	}
	if !ok {
		return nil, 0
	}
	scanned := 0
	changed := false
	if inputText, isString := items.(string); isString {
		changed = p.editText(&inputText, &scanned)
		if changed {
			payload[field] = inputText
		}
	} else if itemSlice, isSlice := items.([]any); isSlice {
		changed = p.editContentItems(itemSlice, &scanned)
		if changed {
			payload[field] = itemSlice
		}
	} else {
		return nil, scanned
	}
	if !changed {
		return nil, scanned
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, scanned
	}
	return out, scanned
}

func (p *legacyPlugin) editContentItems(items []any, scanned *int) bool {
	changed := false
	for _, item := range items {
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content, ok := itemMap["content"]
		if !ok {
			continue
		}
		if p.editContent(&content, scanned) {
			itemMap["content"] = content
			changed = true
		}
	}
	return changed
}

func (p *legacyPlugin) editContent(content *any, scanned *int) bool {
	changed := false
	switch v := (*content).(type) {
	case string:
		if p.editText(&v, scanned) {
			*content = v
			changed = true
		}
	case []any:
		for j, part := range v {
			partMap, ok := part.(map[string]any)
			if !ok {
				continue
			}
			text, ok := partMap["text"].(string)
			if !ok {
				continue
			}
			if p.editText(&text, scanned) {
				partMap["text"] = text
				v[j] = partMap
				changed = true
			}
		}
	}
	return changed
}

func (p *legacyPlugin) editText(text *string, scanned *int) bool {
	*scanned += len(*text)
	result := p.filter.Redact(*text)
	if !result.Hit {
		return false
	}
	*text = result.Redacted
	return true
}
