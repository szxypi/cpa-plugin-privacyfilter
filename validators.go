package main

import (
	"regexp"
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/scan"
)

var (
	reDottedIdent   = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$`)
	reScreamingEnum = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	rePureIdent     = regexp.MustCompile(`^[A-Za-z_.-]+$`)
	reFilePath      = regexp.MustCompile(`^(?:/|\.{1,2}/)[A-Za-z0-9_./-]+$`)
	reVersionLabel  = regexp.MustCompile(`(?i)\b(?:version|ver|semver|release|(?:api|client|server|sdk)[_\s.-]*(?:version|ver)|kernel)\s*[:=v"'\s]{1,6}$`)
	reURISchemeTail = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]{1,31}$`)
	reScopedPkgTail = regexp.MustCompile(`(?:^|[\s'"(/])@[A-Za-z0-9._-]+/$`)

	codeKeywords = map[string]bool{
		"null": true, "none": true, "nil": true, "true": true, "false": true,
		"undefined": true, "string": true, "bytes": true, "number": true,
		"integer": true, "boolean": true, "object": true, "optional": true,
		"required": true, "secret": true, "password": true, "token": true,
		"redacted": true, "hidden": true, "masked": true, "changeme": true,
		"default": true, "localhost": true, "example": true, "unknown": true,
	}

	// GB/T 2260 two-digit provincial prefixes for PRC resident ID cards.
	validCNProvinces = [100]bool{
		11: true, 12: true, 13: true, 14: true, 15: true,
		21: true, 22: true, 23: true,
		31: true, 32: true, 33: true, 34: true, 35: true, 36: true, 37: true,
		41: true, 42: true, 43: true, 44: true, 45: true, 46: true,
		50: true, 51: true, 52: true, 53: true, 54: true,
		61: true, 62: true, 63: true, 64: true, 65: true,
		71: true, 81: true, 82: true, 83: true,
	}

	idCardWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	idCardCheck   = "10X98765432"

	// File and systemd unit suffixes that look like domain TLDs after '@'
	// (e.g. "icon@2x.png", "cli-proxy-api@default.service") and are never
	// valid IANA email TLDs.
	nonEmailSuffixes = map[string]bool{
		"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true,
		"svg": true, "bmp": true, "ico": true, "tiff": true, "avif": true,
		"woff": true, "woff2": true, "ttf": true, "eot": true, "otf": true,
		"css": true, "scss": true, "sass": true, "less": true,
		"html": true, "htm": true, "vue": true, "svelte": true, "astro": true,
		"js": true, "mjs": true, "cjs": true, "ts": true, "tsx": true, "jsx": true,
		"json": true, "jsonl": true, "yaml": true, "yml": true, "toml": true,
		"xml": true, "sql": true, "graphql": true, "proto": true,
		"lock": true, "bak": true, "tmp": true, "swp": true, "log": true,
		"txt": true, "csv": true, "tsv": true, "pdf": true,
		"tar": true, "gz": true, "tgz": true, "bz2": true, "xz": true, "zst": true, "7z": true, "rar": true,
		"jar": true, "war": true, "class": true, "pyc": true,
		"exe": true, "dll": true, "dylib": true, "deb": true, "rpm": true, "apk": true,
		"service": true, "socket": true, "timer": true, "target": true,
		"mount": true, "automount": true, "swap": true, "path": true, "slice": true, "scope": true,
		"conf": true, "cfg": true, "ini": true, "env": true,
	}
)

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool       { return c >= '0' && c <= '9' }
func isHexByte(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// looksLikeCode rejects values from context and generic rules that are source
// code symbols, paths, CLI flags, placeholders, or keywords rather than secret literals.
func looksLikeCode(value string) bool {
	if strings.ContainsAny(value, "()[]{}<>$`\\") {
		return true
	}
	if strings.HasPrefix(value, "--") || isPlaceholderWord(value) || isRepeatedChar(value) {
		return true
	}
	if reDottedIdent.MatchString(value) || reScreamingEnum.MatchString(value) || reFilePath.MatchString(value) {
		return true
	}
	if looksLikeSnakeIdent(value) || looksLikeCamelIdent(value) {
		return true
	}
	return codeKeywords[strings.ToLower(value)]
}

func isRepeatedChar(s string) bool {
	if strings.HasPrefix(strings.ToLower(s), "sk-") && len(s) > 6 {
		s = s[3:]
	}
	if len(s) < 4 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// looksLikeCamelIdent matches multi-hump camelCase / PascalCase code symbols
// such as "DefaultApiKeyProvider" or "fetchCustomerKey" (pure ASCII letters
// with at least two lowercase-to-uppercase transitions).
func looksLikeCamelIdent(s string) bool {
	if len(s) < 8 {
		return false
	}
	humps := 0
	for i := 0; i < len(s); i++ {
		if !isASCIILetter(s[i]) {
			return false
		}
		if i > 0 && s[i-1] >= 'a' && s[i-1] <= 'z' && s[i] >= 'A' && s[i] <= 'Z' {
			humps++
		}
	}
	return humps >= 2
}

// looksLikeIdentifier reports whether value is a pure identifier without digits
// or random character mixing, such as "fetchCustomerApiKey" or "def_api_key".
func looksLikeIdentifier(value string) bool {
	return rePureIdent.MatchString(value) || looksLikeCode(value)
}

// looksLikeSnakeIdent matches lowercase snake_case identifiers such as
// "fetch_api_key_v2" while keeping structured tokens like "sk_live_4eC39HqLyjWD".
func looksLikeSnakeIdent(s string) bool {
	if strings.IndexByte(s, '_') <= 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || isDigit(c) || c == '_') {
			return false
		}
	}
	parts := strings.Split(s, "_")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 14 {
			return false
		}
	}
	return scan.Entropy(s) < 3.7
}

// isBenignIP skips dotted quads that identify no host: loopback, unspecified,
// subnet masks, cloud metadata link-local, octets with leading zeros, and
// 4-part version strings.
func isBenignIP(text string, start, end int) bool {
	ip := text[start:end]
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "0.") || strings.HasPrefix(ip, "255.") {
		return true
	}
	if ip == "169.254.169.254" {
		return true
	}
	if hasLeadingZeroOctet(ip) {
		return true
	}
	if start > 0 && isASCIILetter(text[start-1]) {
		return true
	}
	if start >= 2 {
		switch text[start-2 : start] {
		case "==", ">=", "<=", "~=", "!=":
			return true
		}
	}
	// A release or build suffix ("-microsoft", "_rc1", "+build2") marks a version.
	if end+1 < len(text) && (text[end] == '-' || text[end] == '_' || text[end] == '+') && isASCIILetter(text[end+1]) {
		return true
	}
	// Preceding version labels ("version": "1.2.3.4") mark a version unless
	// followed by a port or CIDR prefix length.
	hasPortOrCIDR := end < len(text) && (text[end] == ':' || text[end] == '/')
	if !hasPortOrCIDR {
		lo := max(0, start-28)
		if reVersionLabel.MatchString(text[lo:start]) {
			return true
		}
	}
	return false
}

func hasLeadingZeroOctet(ip string) bool {
	octStart := 0
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			if i-octStart > 1 && ip[octStart] == '0' {
				return true
			}
			octStart = i + 1
		}
	}
	return false
}

// isBenignEmail skips '@' tokens that are URI credentials, scoped package
// identifiers, retina asset filenames, or systemd template unit names.
func isBenignEmail(text string, start, end int) bool {
	// In "postgres://user:secret@host", text[start-1] is ':' inside URI userinfo.
	// Skipping the email match lets the URI credential detector replace only
	// "secret" and keep "@host" visible.
	if start > 0 && text[start-1] == ':' {
		atRel := strings.IndexByte(text[start:end], '@')
		if atRel >= 3 && !rePortQuery.MatchString(text[start:end]) {
			lo := max(0, start-96)
			prefix := text[lo : start-1]
			if idx := strings.LastIndex(prefix, "://"); idx >= 0 {
				schemeHead := prefix[:idx]
				userPart := prefix[idx+3:]
				if reURISchemeTail.MatchString(schemeHead) &&
					!strings.ContainsAny(userPart, " \t\r\n/?#:@'\",;=()[]<>") {
					return true
				}
			}
		}
	}
	if start > 0 && text[start-1] == '@' {
		return true
	}
	if start > 0 && text[start-1] == '/' {
		lo := max(0, start-64)
		if reScopedPkgTail.MatchString(text[lo:start]) {
			return true
		}
	}
	cand := text[start:end]
	dot := strings.LastIndexByte(cand, '.')
	if dot < 0 || dot+1 >= len(cand) {
		return true
	}
	ext := strings.ToLower(cand[dot+1:])
	return nonEmailSuffixes[ext]
}

// plausiblePhone validates a Chinese mobile number match using MIIT carrier
// prefixes and token boundary checks so hex hashes, decimal fractions, and
// slug IDs do not match.
func plausiblePhone(text string, start, end int) bool {
	if hasDecimalOrIdentBoundary(text, start, end) {
		return false
	}
	raw := text[start:end]
	hasCountryPrefix := strings.HasPrefix(raw, "+86") || (len(raw) > 11 && strings.HasPrefix(raw, "86"))
	if !hasCountryPrefix {
		// Reject slug/UUID segments such as "req-13800138000" or "13800138000-a1".
		if start >= 2 && text[start-1] == '-' && (isASCIILetter(text[start-2]) || isDigit(text[start-2])) {
			return false
		}
		if end+1 < len(text) && text[end] == '-' && (isASCIILetter(text[end+1]) || isDigit(text[end+1])) {
			return false
		}
	}
	digits := raw
	if len(digits) > 11 {
		digits = digits[len(digits)-11:]
	}
	if len(digits) != 11 || digits[0] != '1' {
		return false
	}
	return validCNMobilePrefix(digits[:3])
}

func validCNMobilePrefix(p3 string) bool {
	if len(p3) != 3 || p3[0] != '1' {
		return false
	}
	c1, c2 := p3[1], p3[2]
	switch c1 {
	case '3', '8':
		return isDigit(c2)
	case '4':
		return c2 == '0' || c2 == '1' || (c2 >= '4' && c2 <= '9')
	case '5':
		return isDigit(c2) && c2 != '4'
	case '6':
		return c2 == '2' || (c2 >= '5' && c2 <= '7')
	case '7':
		return c2 >= '0' && c2 <= '8'
	case '9':
		return isDigit(c2) && c2 != '4'
	}
	return false
}

// plausibleIDCard validates an 18-character PRC resident ID card number using
// GB/T 2260 province codes, calendar birth date checks, and the GB 11643-1999
// (ISO 7064:1983.MOD 11-2) check digit.
func plausibleIDCard(text string, start, end int) bool {
	if end-start != 18 || hasDecimalOrIdentBoundary(text, start, end) {
		return false
	}
	if start >= 2 && text[start-1] == '-' && isHexByte(text[start-2]) {
		return false
	}
	if end+1 < len(text) && text[end] == '-' && isHexByte(text[end+1]) {
		return false
	}
	id := text[start:end]
	prov := int(id[0]-'0')*10 + int(id[1]-'0')
	if prov < 0 || prov >= len(validCNProvinces) || !validCNProvinces[prov] {
		return false
	}
	year := parseFixedDigits(id[6:10])
	month := parseFixedDigits(id[10:12])
	day := parseFixedDigits(id[12:14])
	if year < 1900 || year > 2099 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		d := int(id[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		sum += d * idCardWeights[i]
	}
	want := idCardCheck[sum%11]
	last := id[17]
	if last == 'x' {
		last = 'X'
	}
	return last == want
}

func parseFixedDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func daysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if (year%4 == 0 && year%100 != 0) || year%400 == 0 {
			return 29
		}
		return 28
	}
	return 0
}

// plausibleCard keeps a Luhn-valid digit run only when it could be a payment
// card. Luhn alone passes about one random number in ten, so timestamps,
// decimal fractions and hex identifiers all matched.
func plausibleCard(text string, start, end int) bool {
	digits := text[start:end]
	switch digits[0] {
	case '3', '4', '5', '6':
	case '2':
		if len(digits) < 4 || digits[:4] < "2221" || digits[:4] > "2720" {
			return false
		}
	case '8':
		if digits[1] != '1' {
			return false
		}
	default:
		return false
	}
	return !hasDecimalOrIdentBoundary(text, start, end)
}

func hasDecimalOrIdentBoundary(text string, start, end int) bool {
	if start >= 2 && text[start-1] == '.' && isDigit(text[start-2]) {
		return true
	}
	if end+1 < len(text) && text[end] == '.' && isDigit(text[end+1]) {
		return true
	}
	if start > 0 && (isASCIILetter(text[start-1]) || text[start-1] == '_') {
		return true
	}
	if end < len(text) && (isASCIILetter(text[end]) || text[end] == '_') {
		return true
	}
	return false
}
