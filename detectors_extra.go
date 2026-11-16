package main

import (
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/scan"
)

// Extra detectors covering Microsoft Security Utilities identifiable keys
// (CASK, Entra ID, Azure services, NuGet, SAS, connection strings), modern AI
// gateway keys, URI userinfo credentials, database/cache CLI flags, full PEM
// private key blocks, and allocated IPv6 host addresses.
//
// A single Aho-Corasick pass over the text gates every regex below, so clean
// fields pay no regex execution cost.

const (
	kwCASK = iota
	kwAAD7
	kwAAD8
	kwAzFu
	kwAzSe
	kwACR
	kwARm
	kwAEh
	kwASb
	kwAIoT
	kwAzCa
	kwAZEG
	kwASt
	kwACDb
	kwABa
	kwAMC
	kwAPIM
	kwNuGet
	kwAccountKey
	kwStorageKey
	kwSharedAccessKey
	kwSigEq
	kwDsasSecret
	kwSK
	kwXAI
	kwGSK
	kwSchemeSep
	kwMySQL
	kwMariaDB
	kwLongPass
	kwRedisCLI
	kwPasswordEq
	kwPwdEq
	kwPrivateKey
	kwTotal
)

var extraKeywords = [kwTotal]string{
	kwCASK:            "jqqj9",
	kwAAD7:            "7q~",
	kwAAD8:            "8q~",
	kwAzFu:            "azfu",
	kwAzSe:            "azse",
	kwACR:             "+acr",
	kwARm:             "+arm",
	kwAEh:             "+aeh",
	kwASb:             "+asb",
	kwAIoT:            "aiot",
	kwAzCa:            "azca",
	kwAZEG:            "azeg",
	kwASt:             "+ast",
	kwACDb:            "acdb",
	kwABa:             "+aba",
	kwAMC:             "+amc",
	kwAPIM:            "apim",
	kwNuGet:           "oy2",
	kwAccountKey:      "accountkey",
	kwStorageKey:      "storagekey",
	kwSharedAccessKey: "sharedaccesskey",
	kwSigEq:           "sig=",
	kwDsasSecret:      "dsas_secret=",
	kwSK:              "sk-",
	kwXAI:             "xai-",
	kwGSK:             "gsk_",
	kwSchemeSep:       "://",
	kwMySQL:           "mysql",
	kwMariaDB:         "mariadb",
	kwLongPass:        "--pass",
	kwRedisCLI:        "redis-cli",
	kwPasswordEq:      "password=",
	kwPwdEq:           "pwd=",
	kwPrivateKey:      "private key",
}

var (
	extraMatcher = scan.NewKeywordMatcher(extraKeywords[:])
	extraHitPool = sync.Pool{
		New: func() any {
			buf := make([]bool, kwTotal)
			return &buf
		},
	}

	// Microsoft Security Utilities: Common Annotated Security Key (SEC101/200)
	// and Azure / Entra ID / NuGet identifiable secrets.
	reMSCASK    = regexp.MustCompile(`[A-Za-z0-9]{52}JQQJ9(?:9|D|H)[A-Za-z0-9][A-L][A-Za-z0-9]{16}[A-Za-z][A-Za-z0-9]{7}(?:[A-Za-z0-9]{2}==)?`)
	reMSAAD     = regexp.MustCompile(`[~.A-Za-z0-9_\-]{3}[78]Q~[~.A-Za-z0-9_\-]{31,34}`)
	reMSAzFu    = regexp.MustCompile(`[A-Za-z0-9_\-]{44}AzFu[A-Za-z0-9_\-]{5}[AQgw]==`)
	reMSAz52    = regexp.MustCompile(`[A-Za-z0-9+/]{42}(?:AzSe|\+ACR)[A-P][A-Za-z0-9+/]{5}`)
	reMSAz44    = regexp.MustCompile(`[A-Za-z0-9+/]{33}(?:\+ARm|\+AEh|\+ASb|AIoT|AzCa|AZEG)[A-P][A-Za-z0-9+/]{5}=`)
	reMSAz88    = regexp.MustCompile(`[A-Za-z0-9+/]{76}(?:\+ASt|ACDb|\+ABa|\+AMC|APIM)[A-Za-z0-9+/]{5}[AQgw]==`)
	reMSNuGet   = regexp.MustCompile(`(?i)\boy2[a-z2-7]{43}\b`)
	reMSConnKey = regexp.MustCompile(`(?i)\b(?:AccountKey|StorageKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/]{43,86}={1,2})`)
	reMSSASSig  = regexp.MustCompile(`(?i)(?:[?&;])(?:sig|dsas_secret)=([A-Za-z0-9%+/]{43,129}(?:=|%3d))`)

	// AI and LLM gateway API keys not covered by upstream Gitleaks rules.
	reAISKKey   = regexp.MustCompile(`\b(sk-(?:or-v1-[0-9a-f]{64}|[A-Za-z0-9_\-]{16,256}))\b`)
	reAIXAIKey  = regexp.MustCompile(`\b(xai-[A-Za-z0-9_\-]{32,128})\b`)
	reAIGroqKey = regexp.MustCompile(`\b(gsk_[A-Za-z0-9]{32,128})\b`)

	// URI userinfo credentials (SEC101/127) and database/cache CLI passwords.
	// The username part may be empty (e.g. "redis://:password@host:6379/0").
	reURICreds  = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.\-]{1,31}://[^/\s?#:@'"<>()\[\],;=]*:([^/\s'"<>,;]{3,128})@`)
	rePortQuery = regexp.MustCompile(`^[0-9]{1,5}[?#]`)
	reMySQLCLI = regexp.MustCompile(`\b(?:mysql(?:dump|admin|check|import|show)?|mariadb(?:-dump|-admin)?)\b[^\n;|&]*?\s-p(?:'([^'\n]{4,128})'|"([^"\n]{4,128})"|([^\s'"\\;|&)` + "`" + `]{4,128}))`)
	reLongPass = regexp.MustCompile(`(?:^|\s)--pass(?:word)?(?:=|\s+)(?:'([^'\n]{4,128})'|"([^"\n]{4,128})"|([^\s'"\\;|&` + "`" + `\-][^\s'"\\;|&)` + "`" + `]{3,127}))`)
	reRedisCLI = regexp.MustCompile(`\bredis-cli\b[^\n;|&]*?\s-a\s+(?:'([^'\n]{4,128})'|"([^"\n]{4,128})"|([^\s'"\\;|&` + "`" + `\-][^\s'"\\;|&)` + "`" + `]{3,127}))`)
	reConnPass = regexp.MustCompile(`(?i)(?:^|[;&?])(?:password|pwd)\s*=\s*(?:'([^'\n]{4,128})'|"([^"\n]{4,128})"|([^;&\s'")` + "`" + `]{4,128}))`)

	skKnownSubprefixes = []string{
		"proj-", "svcacct-", "admin-", "ant-api03-", "ant-admin01-", "ant-sid01-", "or-v1-", "live-",
	}
	dummyPasswords = map[string]bool{
		"password": true, "pass": true, "passwd": true, "secret": true,
		"changeme": true, "changeit": true, "example": true, "placeholder": true,
		"your_password": true, "your-password": true, "xxxx": true, "****": true,
		"true": true, "false": true, "null": true, "none": true,
	}
)

func detectExtra(text string, skipTypes map[string]bool) []scan.Span {
	if len(text) < 6 {
		return nil
	}
	hitBuf := extraHitPool.Get().(*[]bool)
	hit := *hitBuf
	clear(hit)
	defer extraHitPool.Put(hitBuf)

	extraMatcher.Scan(text, hit)

	var spans []scan.Span
	if !skipTypes[typeKey] {
		spans = detectExtraKeys(text, hit, spans)
	}
	if !skipTypes[typeIP] && hasAtLeastTwoColons(text) {
		spans = detectIPv6(text, spans)
	}
	return spans
}

func detectExtraKeys(text string, hit []bool, spans []scan.Span) []scan.Span {
	addBounded := func(re *regexp.Regexp, leftCharset, rightCharset func(byte) bool) {
		for _, m := range re.FindAllStringIndex(text, -1) {
			if m[0] > 0 && leftCharset(text[m[0]-1]) {
				continue
			}
			if m[1] < len(text) && rightCharset(text[m[1]]) {
				continue
			}
			spans = append(spans, scan.Span{
				Start: m[0], End: m[1], ValueStart: m[0], ValueEnd: m[1],
				Label: "[密钥]", Source: scan.SourceRule, RuleIndex: -1,
			})
		}
	}
	addGroup := func(re *regexp.Regexp, check func(string) bool) {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			start, end := firstMatchedGroup(m)
			if start < 0 || start >= end {
				continue
			}
			val := text[start:end]
			if check != nil && !check(val) {
				continue
			}
			spans = append(spans, scan.Span{
				Start: start, End: end, ValueStart: start, ValueEnd: end,
				Label: "[密钥]", Source: scan.SourceRule, RuleIndex: -1,
			})
		}
	}

	if hit[kwCASK] {
		addBounded(reMSCASK, isBase62Byte, isBase62Byte)
	}
	if hit[kwAAD7] || hit[kwAAD8] {
		addBounded(reMSAAD, isAADLeftByte, isAADSecretByte)
	}
	if hit[kwAzFu] {
		addBounded(reMSAzFu, isBase64URLByte, isBase64TokenByte)
	}
	if hit[kwAzSe] || hit[kwACR] {
		addBounded(reMSAz52, isBase64BodyByte, isBase64TokenByte)
	}
	if hit[kwARm] || hit[kwAEh] || hit[kwASb] || hit[kwAIoT] || hit[kwAzCa] || hit[kwAZEG] {
		addBounded(reMSAz44, isBase64BodyByte, isBase64TokenByte)
	}
	if hit[kwASt] || hit[kwACDb] || hit[kwABa] || hit[kwAMC] || hit[kwAPIM] {
		addBounded(reMSAz88, isBase64BodyByte, isBase64TokenByte)
	}
	if hit[kwNuGet] {
		addBounded(reMSNuGet, isBase62Byte, isBase62Byte)
	}
	if hit[kwAccountKey] || hit[kwStorageKey] || hit[kwSharedAccessKey] {
		addGroup(reMSConnKey, plausibleSecretValue)
	}
	if hit[kwSigEq] || hit[kwDsasSecret] {
		addGroup(reMSSASSig, plausibleSecretValue)
	}
	if hit[kwSK] {
		addGroup(reAISKKey, plausibleSKKey)
	}
	if hit[kwXAI] {
		addGroup(reAIXAIKey, plausiblePrefixedKey)
	}
	if hit[kwGSK] {
		addGroup(reAIGroqKey, plausiblePrefixedKey)
	}
	if hit[kwSchemeSep] && strings.IndexByte(text, '@') >= 0 {
		addGroup(reURICreds, plausiblePasswordArg)
	}
	if hit[kwMySQL] || hit[kwMariaDB] {
		addGroup(reMySQLCLI, plausiblePasswordArg)
	}
	if hit[kwLongPass] {
		addGroup(reLongPass, plausiblePasswordArg)
	}
	if hit[kwRedisCLI] {
		addGroup(reRedisCLI, plausiblePasswordArg)
	}
	if hit[kwPasswordEq] || hit[kwPwdEq] {
		addGroup(reConnPass, func(s string) bool { return plausiblePasswordArg(s) && !looksLikeCode(s) })
	}
	if hit[kwPrivateKey] {
		spans = detectPEMPrivateKeys(text, spans)
	}
	return spans
}

// detectPEMPrivateKeys locates full "-----BEGIN ... PRIVATE KEY-----" through
// "-----END ... PRIVATE KEY-----" blocks, including encrypted blocks whose
// header lines carry commas ("Proc-Type: 4,ENCRYPTED").
func detectPEMPrivateKeys(text string, spans []scan.Span) []scan.Span {
	const (
		beginPrefix = "-----BEGIN "
		endPrefix   = "-----END "
		dashes      = "-----"
		maxBlockLen = 32768
	)
	offset := 0
	for offset < len(text) {
		rel := strings.Index(text[offset:], beginPrefix)
		if rel < 0 {
			break
		}
		start := offset + rel
		headerAfter := start + len(beginPrefix)
		headerEnd := strings.Index(text[headerAfter:], dashes)
		if headerEnd < 0 || headerEnd > 64 {
			offset = headerAfter
			continue
		}
		label := text[headerAfter : headerAfter+headerEnd]
		if !strings.Contains(strings.ToUpper(label), "PRIVATE KEY") {
			offset = headerAfter + headerEnd + len(dashes)
			continue
		}
		bodyStart := headerAfter + headerEnd + len(dashes)
		limit := min(len(text), start+maxBlockLen)
		footerMarker := endPrefix + label + dashes
		footerRel := strings.Index(text[bodyStart:limit], footerMarker)
		if footerRel < 0 {
			offset = bodyStart
			continue
		}
		inner := text[bodyStart : bodyStart+footerRel]
		if strings.Contains(inner, beginPrefix) || len(inner) < 64 || !isValidPEMBody(inner) {
			offset = bodyStart
			continue
		}
		end := bodyStart + footerRel + len(footerMarker)
		spans = append(spans, scan.Span{
			Start: start, End: end, ValueStart: start, ValueEnd: end,
			Label: "[密钥]", Source: scan.SourceRule, RuleIndex: -1,
		})
		offset = end
	}
	return spans
}

// isValidPEMBody checks that a PEM/PGP block body consists of optional RFC 1421
// header lines ("Key: Value") followed by base64 payload lines, rejecting code
// snippets that merely mention BEGIN and END marker constants on the same page.
func isValidPEMBody(inner string) bool {
	inner = strings.Trim(inner, "\r\n")
	inHeaders := true
	base64Bytes := 0
	for _, rawLine := range strings.Split(inner, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			inHeaders = false
			continue
		}
		if inHeaders && strings.Contains(line, ":") {
			// RFC 1421 / OpenPGP armor header line ("Proc-Type: 4,ENCRYPTED").
			if strings.ContainsAny(line, `"'(){};<>`) {
				return false
			}
			continue
		}
		inHeaders = false
		for i := 0; i < len(line); i++ {
			if !isBase64TokenByte(line[i]) {
				return false
			}
			base64Bytes++
		}
	}
	return base64Bytes >= 48
}

func firstMatchedGroup(m []int) (int, int) {
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 && m[2*g] < m[2*g+1] {
			return m[2*g], m[2*g+1]
		}
	}
	return -1, -1
}

func isBase62Byte(c byte) bool    { return isASCIILetter(c) || isDigit(c) }
func isBase64URLByte(c byte) bool { return isBase62Byte(c) || c == '_' || c == '-' }
func isBase64BodyByte(c byte) bool {
	return isBase62Byte(c) || c == '+' || c == '/' || c == '_' || c == '-'
}
func isBase64TokenByte(c byte) bool {
	return isBase64BodyByte(c) || c == '='
}
func isAADLeftByte(c byte) bool {
	return isBase64BodyByte(c) || c == '~' || c == '.'
}
func isAADSecretByte(c byte) bool {
	return isBase64TokenByte(c) || c == '~' || c == '.'
}

func plausiblePrefixedKey(s string) bool {
	if len(s) < 20 || isPlaceholderWord(s) || isRepeatedChar(s[4:]) {
		return false
	}
	hasLetter, hasDigit := false, false
	for i := 4; i < len(s); i++ {
		if isASCIILetter(s[i]) {
			hasLetter = true
		} else if isDigit(s[i]) {
			hasDigit = true
		}
	}
	return hasLetter && hasDigit && scan.Entropy(s[4:]) >= 2.8
}

func plausibleSecretValue(s string) bool {
	if len(s) < 8 || isPlaceholderWord(s) {
		return false
	}
	return scan.Entropy(s) >= 3.2
}

func plausiblePasswordArg(s string) bool {
	if len(s) < 3 || isPlaceholderWord(s) {
		return false
	}
	if s[0] == '$' || strings.HasPrefix(s, "{{") || strings.HasPrefix(s, "%{") ||
		(s[0] == '<' && s[len(s)-1] == '>') ||
		(s[0] == '{' && s[len(s)-1] == '}') ||
		(s[0] == '%' && s[len(s)-1] == '%') {
		return false
	}
	if strings.IndexByte(s, '{') >= 0 && strings.IndexByte(s, '}') > strings.IndexByte(s, '{') {
		return false
	}
	if rePortQuery.MatchString(s) {
		return false
	}
	lower := strings.ToLower(s)
	if dummyPasswords[lower] {
		return false
	}
	// Reject repeated mask characters such as "********" or "xxxxxxxx".
	allSame := true
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			allSame = false
			break
		}
	}
	return !allSame
}

func plausibleSKKey(s string) bool {
	if !strings.HasPrefix(s, "sk-") || isPlaceholderWord(s) {
		return false
	}
	tail := s[3:]
	for _, sub := range skKnownSubprefixes {
		if strings.HasPrefix(tail, sub) {
			tail = tail[len(sub):]
			break
		}
	}
	if len(tail) < 16 {
		return false
	}
	hasUpper, hasLower, hasDigit, hasSep := false, false, false, false
	allHex := true
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
			if c > 'F' {
				allHex = false
			}
		case c >= 'a' && c <= 'z':
			hasLower = true
			if c > 'f' {
				allHex = false
			}
		case isDigit(c):
			hasDigit = true
		case c == '-' || c == '_':
			hasSep = true
			allHex = false
		default:
			allHex = false
		}
	}
	// 32+ hex keys (DeepSeek, DashScope, OpenRouter) have lower theoretical
	// max entropy (4.0 bits/byte) than base62 keys.
	if allHex && len(tail) >= 32 && hasDigit && (hasLower || hasUpper) {
		return scan.Entropy(tail) >= 3.0
	}
	// Reject CSS / UI class names such as "sk-fading-circle-dot" or "sk-item-1".
	if !hasUpper && hasSep {
		return false
	}
	classes := 0
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	return classes >= 2 && hasDigit && scan.Entropy(tail) >= 3.4
}

func isPlaceholderWord(s string) bool {
	upper := strings.ToUpper(s)
	for _, p := range []string{"REPLACE", "YOUR_", "YOUR-", "EXAMPLE", "PLACEHOLDER", "INSERT_", "XXXX", "TODO", "FIXME"} {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

func hasAtLeastTwoColons(s string) bool {
	first := strings.IndexByte(s, ':')
	if first < 0 || first+1 >= len(s) {
		return false
	}
	return strings.IndexByte(s[first+1:], ':') >= 0
}

func isIPv6TokenByte(c byte) bool {
	return isHexByte(c) || c == ':' || c == '.'
}

// detectIPv6 finds allocated unicast IPv6 host addresses (global unicast
// 2000::/3 excluding RFC 3849 2001:db8::/32 documentation, unique-local
// fc00::/7, and link-local fe80::/10), validated with net/netip. Requiring an
// allocated scope avoids false positives on C++/Rust "::" identifiers and MAC
// addresses.
func detectIPv6(text string, spans []scan.Span) []scan.Span {
	i := 0
	for i < len(text) {
		if !isHexByte(text[i]) {
			i++
			continue
		}
		start := i
		colons := 0
		for i < len(text) && isIPv6TokenByte(text[i]) {
			if text[i] == ':' {
				colons++
			}
			i++
		}
		end := i
		// Trim a trailing sentence period or lone trailing colon ("fe80::1:").
		for end > start && (text[end-1] == '.') {
			end--
		}
		if end > start+2 && text[end-1] == ':' && text[end-2] != ':' {
			end--
			colons--
		}
		if colons < 2 || end-start < 6 {
			continue
		}
		cand := text[start:end]
		firstColon := strings.IndexByte(cand, ':')
		leftIdent := start > 0 && (isASCIILetter(text[start-1]) || isDigit(text[start-1]) || text[start-1] == '_')
		doubleColonPrefix := start >= 2 && text[start-1] == ':' && text[start-2] == ':'
		if leftIdent || firstColon != 4 {
			// Step past at most one "label:" prefix (e.g. "src:2001:...",
			// "ipv6:2001:...", "ca:2001:...") so an unspaced key name ending in
			// a hex letter does not hide the IPv6 address after the colon.
			if firstColon >= 0 && (start == 0 || text[start-1] != ':') {
				i = start + firstColon + 1
			}
			continue
		}
		if doubleColonPrefix {
			continue
		}
		if end < len(text) && (isASCIILetter(text[end]) || isDigit(text[end]) || text[end] == '_') {
			continue
		}
		addr, err := netip.ParseAddr(cand)
		if err != nil || !addr.Is6() || addr.Is4In6() || !isRedactedIPv6Scope(addr) {
			continue
		}
		spans = append(spans, scan.Span{
			Start: start, End: end, ValueStart: start, ValueEnd: end,
			Label: "[IP]", Source: scan.SourcePII, RuleIndex: -1,
		})
	}
	return spans
}

func isRedactedIPv6Scope(addr netip.Addr) bool {
	b := addr.As16()
	// Global unicast 2000::/3, excluding RFC 3849 documentation 2001:db8::/32.
	if (b[0] & 0xe0) == 0x20 {
		if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 {
			return false
		}
		return true
	}
	// Unique local fc00::/7.
	if (b[0] & 0xfe) == 0xfc {
		return true
	}
	// Link-local fe80::/10.
	if b[0] == 0xfe && (b[1]&0xc0) == 0x80 {
		return true
	}
	return false
}
