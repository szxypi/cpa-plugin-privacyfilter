package scan

import (
	"regexp"
	"strings"
)

type allowTarget uint8

const (
	allowTargetSecret allowTarget = iota
	allowTargetMatch
	allowTargetLine
)

type tomlAllowlist struct {
	Description string   `toml:"description"`
	RegexTarget string   `toml:"regexTarget"`
	Condition   string   `toml:"condition"`
	Regexes     []string `toml:"regexes"`
	Stopwords   []string `toml:"stopwords"`
	Paths       []string `toml:"paths"`
}

// allowlist is one compiled Gitleaks allowlist clause. Stopwords are matched
// against the candidate secret with a single Aho-Corasick pass; regexes run
// against the configured target (secret, full match, or enclosing line).
type allowlist struct {
	target    allowTarget
	andCond   bool
	regexes   []*regexp.Regexp
	stopwords *matcher
}

func compileAllowlists(rawList []tomlAllowlist) []allowlist {
	if len(rawList) == 0 {
		return nil
	}
	out := make([]allowlist, 0, len(rawList))
	for _, raw := range rawList {
		andCond := strings.EqualFold(strings.TrimSpace(raw.Condition), "AND")
		if andCond && len(raw.Paths) > 0 {
			// Request payloads carry no file path, so a path-gated AND clause
			// can never be satisfied.
			continue
		}
		var regexes []*regexp.Regexp
		for _, expr := range raw.Regexes {
			if expr == "" {
				continue
			}
			// Upstream gitleaks.toml carries `(?i)^true|false|null$` without
			// grouping, which RE2 parses as `(^true)|(false)|(null$)` and would
			// allowlist any secret containing "false" or starting with "true".
			if expr == "(?i)^true|false|null$" {
				expr = "(?i)^(?:true|false|null)$"
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				continue
			}
			regexes = append(regexes, re)
		}
		if andCond && len(raw.Regexes) > 0 && len(regexes) == 0 {
			continue
		}
		var words []string
		for _, w := range raw.Stopwords {
			if w != "" {
				words = append(words, strings.ToLower(w))
			}
		}
		var sw *matcher
		if len(words) > 0 {
			sw = newMatcher(words)
		}
		if len(regexes) == 0 && sw == nil {
			continue
		}
		target := allowTargetSecret
		switch strings.ToLower(strings.TrimSpace(raw.RegexTarget)) {
		case "match":
			target = allowTargetMatch
		case "line":
			target = allowTargetLine
		}
		out = append(out, allowlist{
			target:    target,
			andCond:   andCond,
			regexes:   regexes,
			stopwords: sw,
		})
	}
	return out
}

func (a *allowlist) matches(secret, fullMatch string, lineFn func() string) bool {
	reHit := false
	if len(a.regexes) > 0 {
		candidate := secret
		switch a.target {
		case allowTargetMatch:
			candidate = fullMatch
		case allowTargetLine:
			candidate = lineFn()
		}
		for _, re := range a.regexes {
			if re.MatchString(candidate) {
				reHit = true
				break
			}
		}
	}
	if a.andCond {
		if len(a.regexes) > 0 && !reHit {
			return false
		}
		if a.stopwords != nil && !a.stopwords.containsAny(secret) {
			return false
		}
		return true
	}
	if reHit {
		return true
	}
	return a.stopwords != nil && a.stopwords.containsAny(secret)
}

func enclosingLine(text string, start, end int) string {
	lo := strings.LastIndexByte(text[:start], '\n') + 1
	hi := len(text)
	if nl := strings.IndexByte(text[end:], '\n'); nl >= 0 {
		hi = end + nl
	}
	return text[lo:hi]
}
