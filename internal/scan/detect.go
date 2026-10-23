package scan

// Detection logic ported from github.com/packyme/privacy-filter (MIT,
// Copyright (c) 2026 PackyMe). The matching semantics are kept byte-for-byte
// identical -- parity_test.go diffs this implementation against the upstream
// library on every run. What changed is how the work is scheduled: the
// per-keyword strings.Contains prescreen and the unconditional PII passes are
// replaced by a single Aho-Corasick + byte-class prescan (see scan.go).

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

const (
	entropyMin       = 4.0 // high-entropy fallback default threshold
	entropyMinStrict = 4.8 // used when no secret-ish keyword sits nearby
	contextLookback  = 30  // bytes hasSecretContext looks back
)

// span is one detected region. start/end are UTF-8 byte offsets.
type span struct {
	start, end int
	label      string
	source     Source
	// valueStart/valueEnd narrow a rule match without a secretGroup to its
	// first capturing group; Redact ignores them (upstream semantics), the
	// plugin uses them to keep key names out of placeholders.
	valueStart, valueEnd int
	minEntropy           float64
	rule                 string
}

var (
	// Structured PII. Go's RE2 has no look-around, so digit boundaries are
	// verified after the match by digitBounded / ipBounded.
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	rePhoneCN  = regexp.MustCompile(`(?:\+?86[-\s]?)?1[3-9][0-9]{9}`)
	reIDCard   = regexp.MustCompile(`[1-9][0-9]{16}[0-9Xx]`)
	reBankCard = regexp.MustCompile(`[0-9]{13,19}`)
	reIPv4     = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])`)

	// Passwords hidden inside a sentence: "我的密码是 hunter2", "api_key: xxx".
	reContextSecret = regexp.MustCompile(
		`(?i)(密码|口令|密钥|password|passwd|pwd|secret|token|api[_\s-]?key)\s*(?:是|为|:|：|=)\s*['"]?([^\s'"，。；;]{4,})`)
	// High-entropy fallback for random strings matching no known format.
	reEntropyToken = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{20,}`)
	// Secret-ish vocabulary near a candidate keeps the looser entropy bar.
	reSecretContext = regexp.MustCompile(
		`(?i)(?:password|passwd|pwd|secret|token|api[_\s-]?key|access[_\s-]?key|bearer|authorization|credential|jwt|密码|口令|密钥|凭证|令牌|鉴权)`)
	reAuthHeaderPrefix = regexp.MustCompile(
		`(?i)\bauthorization\s*:\s*(?:basic|bearer|digest|ntlm|hmac|token)\s+$`)

	reTemplateVar    = regexp.MustCompile(`^(?:\{\{[^{}]+\}\}|\$\{[^{}]+\}|%\{[^{}]+\}|<[^<>]+>)$`)
	reUUID           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHexOnly        = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reHostPortPrefix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9-]+:`)
)

// contextKeywords are the literals reContextSecret can start from. Any real
// match contains one of them, so the regex only has to run when the prescan
// saw at least one. "api" stands in for the api[_\s-]?key alternative.
var contextKeywords = []string{"密码", "口令", "密钥", "password", "passwd", "pwd", "secret", "token", "api"}

// Remote-shell prefixes: user@host after these is an SSH target, not an email.
var sshCommands = []string{"ssh ", "scp ", "rsync ", "sftp ", "ssh-copy-id ", "ssh-keygen "}

const (
	pathBoundaryChars = `/\:.@?=`
	pathInternalChars = `/\:`
	assignmentChars   = " \t\r\n=:'\""
)

var urlPrefixes = []string{
	"http://", "https://", "ftp://", "ssh://",
	"s3://", "gs://", "oss://",
	"git@", "sha256:", "sha1:", "md5:",
}

var benignIDSuffixes = []string{"_id", "_uuid", "_uid", "_oid", "_no", "_seq"}

var commonPlaceholders = []string{
	"REPLACE_ME", "REPLACE_THIS", "REPLACE_WITH",
	"YOUR_KEY", "YOUR_TOKEN", "YOUR_SECRET", "YOUR_API_KEY", "YOUR_PASSWORD",
	"INSERT_HERE", "INSERT_KEY", "INSERT_TOKEN",
	"PLACEHOLDER", "EXAMPLE_KEY", "EXAMPLE_TOKEN",
	"TODO", "FIXME", "XXXX",
}

func isLikelyPlaceholder(s string) bool {
	upper := strings.ToUpper(s)
	for _, p := range commonPlaceholders {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

// hasJSONNoise flags a match containing "," -- a single-token secret never
// does, but gitleaks' looser rules often swallow several tokens at once.
func hasJSONNoise(s string) bool { return strings.IndexByte(s, ',') >= 0 }

func looksLikeURLMatch(s string) bool {
	if strings.Contains(s, "://") {
		return true
	}
	return reHostPortPrefix.MatchString(s)
}

func isInSSHCommandContext(text string, emailStart int) bool {
	lineStart := strings.LastIndexByte(text[:emailStart], '\n') + 1
	line := text[lineStart:emailStart]
	for _, cmd := range sshCommands {
		if strings.Contains(line, cmd) {
			return true
		}
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func digitBounded(text string, start, end int) bool {
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	if end < len(text) && isDigit(text[end]) {
		return false
	}
	return true
}

func ipBounded(text string, start, end int) bool {
	if start > 0 && (isDigit(text[start-1]) || text[start-1] == '.') {
		return false
	}
	if end < len(text) && (isDigit(text[end]) || text[end] == '.') {
		return false
	}
	return true
}

func luhnValid(num string) bool {
	sum := 0
	double := false
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// detectPII appends structured PII spans. The sig gates skip whole regex
// passes that provably cannot match: an email needs '@', the three numeric
// detectors need a digit run of their minimum length, and IPv4 needs a
// digit-dot-digit sequence somewhere in the text.
func detectPII(text string, sig *signals, spans []span) []span {
	if sig.hasAt {
		for _, m := range reEmail.FindAllStringIndex(text, -1) {
			// SSH-style URL user@host:path is not an email address.
			if m[1] < len(text) && text[m[1]] == ':' &&
				m[1]+1 < len(text) && text[m[1]+1] != ' ' && text[m[1]+1] != '\t' {
				continue
			}
			if isInSSHCommandContext(text, m[0]) {
				continue
			}
			spans = append(spans, span{start: m[0], end: m[1], label: "[邮箱]", source: SourcePII})
		}
	}
	if sig.maxDigitRun >= 11 {
		for _, m := range rePhoneCN.FindAllStringIndex(text, -1) {
			if digitBounded(text, m[0], m[1]) {
				spans = append(spans, span{start: m[0], end: m[1], label: "[电话]", source: SourcePII})
			}
		}
	}
	if sig.maxDigitRun >= 17 {
		for _, m := range reIDCard.FindAllStringIndex(text, -1) {
			if digitBounded(text, m[0], m[1]) {
				spans = append(spans, span{start: m[0], end: m[1], label: "[身份证]", source: SourcePII})
			}
		}
	}
	if sig.hasIPv4 {
		for _, m := range reIPv4.FindAllStringIndex(text, -1) {
			if ipBounded(text, m[0], m[1]) {
				spans = append(spans, span{start: m[0], end: m[1], label: "[IP]", source: SourcePII})
			}
		}
	}
	if sig.maxDigitRun >= 13 {
		for _, m := range reBankCard.FindAllStringIndex(text, -1) {
			if digitBounded(text, m[0], m[1]) && luhnValid(text[m[0]:m[1]]) {
				spans = append(spans, span{start: m[0], end: m[1], label: "[银行卡]", source: SourcePII})
			}
		}
	}
	return spans
}

func isOnPathOrURLBoundary(text string, start, end int) bool {
	if strings.ContainsAny(text[start:end], pathInternalChars) {
		return true
	}
	if start > 0 && strings.IndexByte(pathBoundaryChars, text[start-1]) >= 0 {
		return true
	}
	if end < len(text) && strings.IndexByte(pathBoundaryChars, text[end]) >= 0 {
		return true
	}
	lo := start - 8
	if lo < 0 {
		lo = 0
	}
	look := text[lo:start]
	for _, p := range urlPrefixes {
		if strings.Contains(look, p) {
			return true
		}
	}
	return false
}

func hasSecretContext(text string, start, end int) bool {
	lo := start - contextLookback
	if lo < 0 {
		lo = 0
	}
	return reSecretContext.MatchString(text[lo:end])
}

func hasStrongSecretContext(text string, start, end int) bool {
	lo := start - contextLookback
	if lo < 0 {
		lo = 0
	}
	if reAuthHeaderPrefix.MatchString(text[lo:start]) {
		return true
	}
	region := text[lo:end]
	locs := reSecretContext.FindAllStringIndex(region, -1)
	if len(locs) == 0 {
		return false
	}
	last := locs[len(locs)-1]
	candStartInRegion := start - lo
	if last[0] >= candStartInRegion {
		return true
	}
	// A keyword alternative with a non-token byte inside it ("api key",
	// "access key") can start before the candidate and end inside it. Then no
	// byte separates keyword and candidate, which is the empty-gap case below.
	if last[1] > candStartInRegion {
		return true
	}
	between := region[last[1]:candStartInRegion]
	for i := 0; i < len(between); i++ {
		if strings.IndexByte(assignmentChars, between[i]) < 0 {
			return false
		}
	}
	return true
}

func isTemplateVar(s string) bool { return reTemplateVar.MatchString(s) }

func isHexHash(s string) bool {
	n := len(s)
	return (n == 32 || n == 40 || n == 64) && reHexOnly.MatchString(s)
}

func isUUID(s string) bool { return reUUID.MatchString(s) }

func isBusinessIDAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	name := strings.ToLower(s[:eq])
	for _, k := range []string{"key", "secret", "token", "auth", "password", "credential"} {
		if strings.Contains(name, k) {
			return false
		}
	}
	for _, suf := range benignIDSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	ent := 0.0
	for _, c := range freq {
		if c > 0 {
			p := c / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// mergeSpans drops invalid and overlapping regions: sorted by start ascending,
// longest first on ties, then greedily kept if disjoint.
func mergeSpans(spans []span) []span {
	valid := spans[:0]
	for _, s := range spans {
		if s.start >= 0 && s.start < s.end {
			valid = append(valid, s)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].start != valid[j].start {
			return valid[i].start < valid[j].start
		}
		return valid[i].end > valid[j].end
	})
	merged := valid[:0]
	lastEnd := -1
	for _, s := range valid {
		if s.start >= lastEnd {
			merged = append(merged, s)
			lastEnd = s.end
		}
	}
	return merged
}
