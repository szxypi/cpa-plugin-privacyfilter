// Package scan detects and redacts secrets and PII in request text.
//
// It is a performance-oriented port of github.com/packyme/privacy-filter with
// identical matching semantics (guaranteed by parity_test.go) and a different
// execution plan:
//
//   - one Aho-Corasick pass replaces ~290 strings.Contains keyword probes,
//   - the same pass derives byte-class signals ('@', digit runs, token runs)
//     that let whole PII / entropy regex passes be skipped,
//   - no lower-cased copy of the text is allocated,
//   - rule compilation happens once per configuration load, never per request.
package scan

import (
	"strings"
	"sync"
)

// Result is the outcome of one Redact call.
type Result struct {
	Redacted string
	Hit      bool
	Count    int
	// Labels counts hits per placeholder ("[密钥]", "[邮箱]", ...). Only
	// populated when Hit is true.
	Labels map[string]int
}

// Scanner holds the compiled rule set. It is read-only after construction and
// safe for concurrent use.
type Scanner struct {
	rules   []Rule
	skipped int

	matcher *matcher
	// ruleKeywordIDs[i] lists matcher pattern ids for rules[i]; empty means
	// the rule always runs.
	ruleKeywordIDs [][]int32
	// contextIDs are the pattern ids that gate reContextSecret.
	contextIDs []int32
	patterns   int

	scratch sync.Pool
}

type signals struct {
	maxDigitRun int
	hasAt       bool
	hasIPv4     bool
	hasContext  bool
	hasAssign   bool
	// tokenRuns are the maximal runs of [A-Za-z0-9+/=_-] at least 20 bytes
	// long -- exactly what the high-entropy fallback regex would find, so the
	// prescan hands them over and the regex never runs.
	tokenRuns []span
}

type scratch struct {
	patHit    []bool
	spans     []span
	tokenRuns []span
}

// class table: bit 0 = ASCII digit, bit 1 = member of the entropy-token charset
// [A-Za-z0-9+/=_-].
var byteClass = func() [256]uint8 {
	var t [256]uint8
	for c := 0; c < 256; c++ {
		b := byte(c)
		var v uint8
		if b >= '0' && b <= '9' {
			v |= 1 | 2
		} else if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			b == '+' || b == '/' || b == '=' || b == '_' || b == '-' {
			v |= 2
		}
		t[c] = v
	}
	return t
}()

// New compiles rules into a Scanner. skipped reports how many rules in the
// source document had a regex Go's RE2 engine rejected.
func New(rules []Rule, skipped int) *Scanner {
	s := &Scanner{rules: rules, skipped: skipped}

	ids := make(map[string]int32)
	var patterns []string
	intern := func(keyword string) int32 {
		if id, ok := ids[keyword]; ok {
			return id
		}
		id := int32(len(patterns))
		ids[keyword] = id
		patterns = append(patterns, keyword)
		return id
	}

	s.ruleKeywordIDs = make([][]int32, len(rules))
	for i := range rules {
		for _, keyword := range rules[i].Keywords {
			s.ruleKeywordIDs[i] = append(s.ruleKeywordIDs[i], intern(keyword))
		}
	}
	for _, keyword := range contextKeywords {
		s.contextIDs = append(s.contextIDs, intern(keyword))
	}

	s.patterns = len(patterns)
	s.matcher = newMatcher(patterns)
	s.scratch.New = func() any {
		return &scratch{
			patHit:    make([]bool, s.patterns),
			spans:     make([]span, 0, 16),
			tokenRuns: make([]span, 0, 16),
		}
	}
	return s
}

// Stats reports the loaded and skipped rule counts.
func (s *Scanner) Stats() (rules, skipped int) { return len(s.rules), s.skipped }

// RuleIDs returns the ids of the loaded rules, in load order.
func (s *Scanner) RuleIDs() []string {
	out := make([]string, 0, len(s.rules))
	for i := range s.rules {
		out = append(out, s.rules[i].ID)
	}
	return out
}

// Redact detects and masks secrets and PII. It is safe for concurrent use.
func (s *Scanner) Redact(text string) Result {
	if text == "" {
		return Result{Redacted: text}
	}
	work := s.scratch.Get().(*scratch)
	defer func() {
		work.spans = work.spans[:0]
		work.tokenRuns = work.tokenRuns[:0]
		s.scratch.Put(work)
	}()
	if len(work.patHit) < s.patterns {
		work.patHit = make([]bool, s.patterns)
	}
	patHit := work.patHit[:s.patterns]
	clear(patHit)

	sig := s.prescan(text, patHit, work.tokenRuns[:0])
	work.tokenRuns = sig.tokenRuns

	spans := work.spans[:0]
	spans = detectPII(text, &sig, spans)
	spans = s.detectSecrets(text, &sig, patHit, spans)
	work.spans = spans

	merged := mergeSpans(spans)
	if len(merged) == 0 {
		return Result{Redacted: text}
	}

	var b strings.Builder
	b.Grow(len(text))
	labels := make(map[string]int, 4)
	prev := 0
	for _, sp := range merged {
		b.WriteString(text[prev:sp.start])
		b.WriteString(sp.label)
		labels[sp.label]++
		prev = sp.end
	}
	b.WriteString(text[prev:])
	return Result{Redacted: b.String(), Hit: true, Count: len(merged), Labels: labels}
}

// prescan walks the text once, driving the keyword automaton and collecting
// the byte-class signals that gate the structured detectors. Every signal is a
// necessary condition of the detector it gates, so skipping is loss-free.
func (s *Scanner) prescan(text string, patHit []bool, tokenRuns []span) signals {
	sig := signals{tokenRuns: tokenRuns}
	next := s.matcher.next
	emit := s.matcher.emit
	state := int32(0)
	digitRun, tokenRun, dottedGroups := 0, 0, 0

	for i := 0; i < len(text); i++ {
		c := text[i]
		class := byteClass[c]

		if class&1 != 0 {
			digitRun++
			if digitRun > sig.maxDigitRun {
				sig.maxDigitRun = digitRun
			}
			// IPv4 needs four digit groups joined by three dots.
			if dottedGroups >= 3 {
				sig.hasIPv4 = true
			}
		} else {
			if c == '.' {
				if digitRun > 0 {
					dottedGroups++
				} else {
					dottedGroups = 0
				}
			} else {
				dottedGroups = 0
				switch {
				case c == '@':
					sig.hasAt = true
				case c == ':' || c == '=' || c >= 0x80:
					// ':' '=' and the lead byte of 是 / 为 / ： -- the
					// assignment separators reContextSecret requires.
					sig.hasAssign = true
				}
			}
			digitRun = 0
		}

		if class&2 != 0 {
			tokenRun++
		} else {
			if tokenRun >= 20 {
				sig.tokenRuns = append(sig.tokenRuns, span{i - tokenRun, i, ""})
			}
			tokenRun = 0
		}

		folded := c
		if folded >= 'A' && folded <= 'Z' {
			folded += 'a' - 'A'
		}
		state = next[int(state)<<8|int(folded)]
		if hits := emit[state]; len(hits) != 0 {
			for _, id := range hits {
				patHit[id] = true
			}
		}
	}
	if tokenRun >= 20 {
		sig.tokenRuns = append(sig.tokenRuns, span{len(text) - tokenRun, len(text), ""})
	}

	if sig.hasAssign {
		for _, id := range s.contextIDs {
			if patHit[id] {
				sig.hasContext = true
				break
			}
		}
	}
	return sig
}

func (s *Scanner) ruleApplies(index int, patHit []bool) bool {
	keywords := s.ruleKeywordIDs[index]
	if len(keywords) == 0 {
		return true
	}
	for _, id := range keywords {
		if patHit[id] {
			return true
		}
	}
	return false
}

func (s *Scanner) detectSecrets(text string, sig *signals, patHit []bool, spans []span) []span {
	for i := range s.rules {
		if !s.ruleApplies(i, patHit) {
			continue
		}
		rule := &s.rules[i]
		for _, m := range rule.Re.FindAllStringSubmatchIndex(text, -1) {
			start, end := m[0], m[1]
			if g := rule.SecretGroup; g > 0 && 2*g+1 < len(m) && m[2*g] >= 0 {
				start, end = m[2*g], m[2*g+1]
			}
			if start < 0 || start >= end {
				continue
			}
			if rule.Entropy > 0 && shannonEntropy(text[start:end]) < rule.Entropy {
				continue
			}
			candidate := text[start:end]
			if looksLikeURLMatch(candidate) ||
				isTemplateVar(candidate) || isHexHash(candidate) || isUUID(candidate) ||
				isBusinessIDAssignment(candidate) ||
				isLikelyPlaceholder(candidate) || hasJSONNoise(candidate) {
				continue
			}
			spans = append(spans, span{start, end, "[密钥]"})
		}
	}

	if sig.hasContext {
		for _, m := range reContextSecret.FindAllStringSubmatchIndex(text, -1) {
			if len(m) >= 6 && m[4] >= 0 {
				value := text[m[4]:m[5]]
				if isTemplateVar(value) {
					continue
				}
				if len(value) <= 16 && shannonEntropy(value) < 3.0 {
					continue
				}
				spans = append(spans, span{m[4], m[5], "[密钥]"})
			}
		}
	}

	// The prescan already carved out the maximal [A-Za-z0-9+/=_-]{20,} runs,
	// which is exactly the match set of reEntropyToken.
	for _, run := range sig.tokenRuns {
		start, end := run.start, run.end
		candidate := text[start:end]

		strong := hasStrongSecretContext(text, start, end)
		if !strong && isOnPathOrURLBoundary(text, start, end) {
			continue
		}
		if isTemplateVar(candidate) || isHexHash(candidate) || isUUID(candidate) || isBusinessIDAssignment(candidate) {
			continue
		}
		threshold := entropyMin
		if !hasSecretContext(text, start, end) {
			threshold = entropyMinStrict
		}
		if shannonEntropy(candidate) >= threshold {
			spans = append(spans, span{start, end, "[密钥]"})
		}
	}
	return spans
}
