package main

import (
	"container/list"
	"crypto/sha256"
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/scan"
)

// interval is a half-open byte range [start, end).
type interval struct{ start, end int }

// secretSpan is one value to replace, after filtering and merging.
type secretSpan struct {
	start, end int
	typ        string
}

// textAnalysis is everything about one text that depends only on the text and
// the configuration, so it can be cached by content hash. It stores offsets,
// never copies of the sensitive values.
type textAnalysis struct {
	secrets []secretSpan
	// placeholders are placeholder-shaped substrings already in the text.
	placeholders []interval
}

func (a *textAnalysis) size() int {
	return len(a.secrets)*40 + len(a.placeholders)*16 + 48
}

// analyzer runs the detectors and the plugin-level filters.
type analyzer struct {
	scanner        *scan.Scanner
	format         *placeholderFormat
	skipTypes      map[string]bool
	allowRegexes   []*regexp.Regexp
	allowStopwords *scan.KeywordMatcher
}

func findIntervals(format *placeholderFormat, text string) []interval {
	var out []interval
	for _, loc := range format.find(text) {
		out = append(out, interval{loc[0], loc[1]})
	}
	return out
}

func (az *analyzer) isUserAllowlisted(value string) bool {
	if az.allowStopwords != nil && az.allowStopwords.ContainsAny(value) {
		return true
	}
	for _, re := range az.allowRegexes {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func (az *analyzer) analyze(text string) textAnalysis {
	out := textAnalysis{placeholders: findIntervals(az.format, text)}
	raw := az.scanner.Detect(text)
	extra := detectExtra(text, az.skipTypes)
	if len(raw) == 0 && len(extra) == 0 {
		return out
	}
	kept := make([]scan.Span, 0, len(raw)+len(extra))
	for _, sp := range raw {
		orig := sp
		var ok bool
		if sp.Start, sp.End, ok = narrowValue(text, sp); !ok {
			continue
		}
		typ := typeForLabel(sp.Label)
		if az.skipTypes[typ] {
			continue
		}
		if orig.Source != scan.SourcePII && az.scanner.Allowlisted(text, orig, sp.Start, sp.End) {
			continue
		}
		if az.isUserAllowlisted(text[sp.Start:sp.End]) {
			continue
		}
		switch typ {
		case typeIP:
			if isBenignIP(text, sp.Start, sp.End) {
				continue
			}
		case typeCard:
			if !plausibleCard(text, sp.Start, sp.End) {
				continue
			}
		case typeIDCard:
			if !plausibleIDCard(text, sp.Start, sp.End) {
				continue
			}
		case typePhone:
			if !plausiblePhone(text, sp.Start, sp.End) {
				continue
			}
		case typeEmail:
			if isBenignEmail(text, sp.Start, sp.End) {
				continue
			}
		}
		if overlapsAny(sp.Start, sp.End, out.placeholders) {
			continue
		}
		kept = append(kept, sp)
	}
	for _, sp := range extra {
		typ := typeForLabel(sp.Label)
		if az.skipTypes[typ] {
			continue
		}
		if az.isUserAllowlisted(text[sp.Start:sp.End]) {
			continue
		}
		if overlapsAny(sp.Start, sp.End, out.placeholders) {
			continue
		}
		kept = append(kept, sp)
	}
	for _, sp := range scan.Merge(kept) {
		out.secrets = append(out.secrets, secretSpan{sp.Start, sp.End, typeForLabel(sp.Label)})
	}
	return out
}

func overlapsAny(start, end int, sorted []interval) bool {
	for _, iv := range sorted {
		if iv.start >= end {
			return false
		}
		if iv.end > start {
			return true
		}
	}
	return false
}

var (
	reAssignName    = regexp.MustCompile(`^-{0,2}[A-Za-z_][A-Za-z0-9_.-]*$`)
	reTrailingParam = regexp.MustCompile(`[&;][A-Za-z_][A-Za-z0-9_.-]*=`)
)

// narrowValue shrinks a detection to the value a placeholder should stand for.
// Upstream matches often include the key name ("GITHUB_TOKEN=ghp_...",
// "token: abc123"); with an irreversible label that did not matter, but a
// placeholder that swallows the name hides from the model what the value is.
// ok is false when the narrowed value no longer looks secret.
func narrowValue(text string, sp scan.Span) (start, end int, ok bool) {
	start, end = sp.ValueStart, sp.ValueEnd
	switch sp.Source {
	case scan.SourceContext:
		end = trimContextValue(text, start, end)
		return start, end, end-start >= 4 && !looksLikeCode(text[start:end])
	case scan.SourceRule:
		if start != sp.Start || end != sp.End {
			value := text[start:end]
			if sp.MinEntropy > 0 && scan.Entropy(value) < sp.MinEntropy {
				return start, end, false
			}
			if sp.Rule == "generic-api-key" && looksLikeIdentifier(value) {
				return start, end, false
			}
			return start, end, true
		}
		return narrowAssignment(text, start, end, false)
	case scan.SourceEntropy:
		var narrowed bool
		start, end, narrowed = narrowAssignment(text, start, end, true)
		if !narrowed || looksLikeIdentifier(text[start:end]) {
			return start, end, false
		}
		return start, end, true
	}
	return start, end, true
}

// narrowAssignment strips a leading "NAME=" from a token run. For the entropy
// fallback the remaining value must still be long and random enough on its
// own, otherwise "SOME_LONG_SETTING_NAME=enabled" would become a placeholder.
func narrowAssignment(text string, start, end int, recheck bool) (int, int, bool) {
	eq := strings.IndexByte(text[start:end], '=')
	if eq <= 0 || !reAssignName.MatchString(text[start:start+eq]) {
		return start, end, true
	}
	value := text[start+eq+1 : end]
	if len(value) < 8 || value[0] == '=' {
		return start, end, true
	}
	if recheck && (len(value) < 12 || scan.Entropy(value) < 3.0) {
		return start, end, false
	}
	return start + eq + 1, end, true
}

// trimContextValue drops trailing query/connection parameters
// ("password=secret&sslmode=require" -> "secret") and closing punctuation the
// sentence detector swallows ("token: abc123)," -> "abc123").
func trimContextValue(text string, start, end int) int {
	if loc := reTrailingParam.FindStringIndex(text[start:end]); loc != nil && loc[0] > 0 {
		end = start + loc[0]
	}
	for end > start && strings.IndexByte(",)]}>`", text[end-1]) >= 0 {
		end--
	}
	return end
}

// analysisCache memoises analyses by content hash. Coding agents replay the
// whole conversation every turn, so in steady state only new text is scanned.
type analysisCache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int64
	entries    map[[32]byte]*list.Element
	order      *list.List
	bytes      int64

	hits, misses uint64
}

type analysisEntry struct {
	key      [32]byte
	analysis textAnalysis
	size     int
}

func newAnalysisCache(maxEntries int, maxBytes int64) *analysisCache {
	if maxEntries <= 0 {
		return nil
	}
	return &analysisCache{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		entries:    make(map[[32]byte]*list.Element, maxEntries),
		order:      list.New(),
	}
}

func (c *analysisCache) get(az *analyzer, text string) textAnalysis {
	if c == nil || text == "" {
		return az.analyze(text)
	}
	// sha256 neither retains nor mutates its input, so hash the string in place.
	key := sha256.Sum256(unsafe.Slice(unsafe.StringData(text), len(text)))
	c.mu.Lock()
	if element, ok := c.entries[key]; ok {
		c.order.MoveToFront(element)
		c.hits++
		result := element.Value.(*analysisEntry).analysis
		c.mu.Unlock()
		return result
	}
	c.misses++
	c.mu.Unlock()

	result := az.analyze(text)
	entry := &analysisEntry{key: key, analysis: result, size: result.size()}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		return result
	}
	c.entries[key] = c.order.PushFront(entry)
	c.bytes += int64(entry.size)
	for (len(c.entries) > c.maxEntries || c.bytes > c.maxBytes) && c.order.Len() > 0 {
		evicted := c.order.Remove(c.order.Back()).(*analysisEntry)
		delete(c.entries, evicted.key)
		c.bytes -= int64(evicted.size)
	}
	return result
}

func (c *analysisCache) stats() (hits, misses uint64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}
