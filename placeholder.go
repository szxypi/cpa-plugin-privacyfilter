package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Placeholder styles. A placeholder stands for exactly one sensitive value; the
// value itself never leaves this process.
const (
	// styleShort renders "<prefix>-<type>-<12 hex>", e.g. pf-key-3a7f9c21d0b4.
	// It is the default: short references are copied back far more reliably
	// by models than UUIDs, and the fixed prefix lets the response side skip
	// any text that cannot contain one.
	styleShort = "short"
	// styleUUID renders a version-8 UUID derived from the same HMAC.
	styleUUID = "uuid"
)

const shortIDHexLen = 12

// Placeholder types, derived from the upstream detector labels.
const (
	typeKey    = "key"
	typeEmail  = "email"
	typePhone  = "phone"
	typeIDCard = "idcard"
	typeIP     = "ip"
	typeCard   = "card"
)

var knownTypes = []string{typeKey, typeEmail, typePhone, typeIDCard, typeIP, typeCard}

// typeForLabel maps an upstream detector label to a placeholder type.
func typeForLabel(label string) string {
	switch label {
	case "[邮箱]":
		return typeEmail
	case "[电话]":
		return typePhone
	case "[身份证]":
		return typeIDCard
	case "[IP]":
		return typeIP
	case "[银行卡]":
		return typeCard
	default:
		return typeKey
	}
}

// placeholderFormat renders placeholders and finds them again in text.
type placeholderFormat struct {
	style  string
	prefix string
	re     *regexp.Regexp
	// marker is a literal every placeholder contains; texts without it are
	// skipped without running the regex.
	marker string
	// maxLen is the length of the longest placeholder this format renders.
	maxLen int
}

func newPlaceholderFormat(style, prefix string) (*placeholderFormat, error) {
	style = strings.ToLower(strings.TrimSpace(style))
	if style == "" {
		style = styleShort
	}
	switch style {
	case styleShort:
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix == "" {
			prefix = defaultPlaceholderPrefix
		}
		if !regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`).MatchString(prefix) {
			return nil, fmt.Errorf("placeholder_prefix %q must be 1-16 lowercase letters or digits starting with a letter", prefix)
		}
		longest := 0
		for _, t := range knownTypes {
			longest = max(longest, len(t))
		}
		return &placeholderFormat{
			style:  style,
			prefix: prefix,
			re: regexp.MustCompile(regexp.QuoteMeta(prefix) + `-(?:` + strings.Join(knownTypes, "|") +
				`)-[0-9a-f]{` + fmt.Sprint(shortIDHexLen) + `}`),
			marker: prefix + "-",
			maxLen: len(prefix) + 1 + longest + 1 + shortIDHexLen,
		}, nil
	case styleUUID:
		return &placeholderFormat{
			style:  style,
			re:     regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`),
			marker: "-8",
			maxLen: 36,
		}, nil
	default:
		return nil, fmt.Errorf("placeholder_style %q is not one of %q, %q", style, styleShort, styleUUID)
	}
}

// render derives the placeholder for value. salt is bumped only to resolve a
// collision with a different value that already owns the first choice.
func (f *placeholderFormat) render(key []byte, value, typ string, salt int) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	if salt > 0 {
		fmt.Fprintf(mac, "\x00%d", salt)
	}
	sum := mac.Sum(nil)
	if f.style == styleUUID {
		b := sum[:16]
		b[6] = (b[6] & 0x0f) | 0x80 // version 8
		b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
		h := hex.EncodeToString(b)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	}
	return f.prefix + "-" + typ + "-" + hex.EncodeToString(sum)[:shortIDHexLen]
}

// mayContain is a cheap necessary condition for find to return anything.
func (f *placeholderFormat) mayContain(s string) bool {
	return strings.Contains(s, f.marker)
}

// mayContainBytes is mayContain for a byte slice, without copying it.
func (f *placeholderFormat) mayContainBytes(b []byte) bool {
	return bytes.Contains(b, []byte(f.marker))
}

// find returns the [start, end) offsets of every placeholder-shaped substring.
func (f *placeholderFormat) find(s string) [][]int {
	if !f.mayContain(s) {
		return nil
	}
	return f.re.FindAllStringIndex(s, -1)
}

// example is a well-formed placeholder that no value will ever own, used in
// the notice shown to the model.
func (f *placeholderFormat) example() string {
	if f.style == styleUUID {
		return "3f2a9c1e-7b4d-8e21-a5c3-9d0f6b2e4a17"
	}
	return f.prefix + "-key-1a2b3c4d5e6f"
}
