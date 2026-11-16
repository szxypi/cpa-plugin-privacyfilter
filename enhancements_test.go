package main

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/tidwall/gjson"
)

// makeValidCNID computes the GB 11643-1999 check digit at run time so the
// source file contains no literal ID card number.
func makeValidCNID(body17 string) string {
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(body17[i]-'0') * idCardWeights[i]
	}
	return body17 + string(idCardCheck[sum%11])
}

func TestGitleaksAllowlistsAndCodeIdentifiersAreNotReplaced(t *testing.T) {
	p := newTestPlugin(t)
	samples := []string{
		`def fetch_customer_api_key(): return None`,
		`api_key = DefaultApiKeyProvider`,
		`secret_key = get_secret_key_v2`,
		`API_KEY = PROD_OPENAI_API_KEY`,
		`primary_key = "user_account_01"`,
		`key_name = "id_rsa_deploy_01"`,
		`csrf_token = "form_csrf_guard_1"`,
		`import { createSecretKey } from "node:crypto"`,
		`err := s.handleStreamChunkRequest(ctx)`,
		`password_file = /run/secrets/db_password`,
		`token: --auth-token-stdin`,
	}
	for _, sample := range samples {
		a := p.analyzer.analyze(sample)
		if len(a.secrets) != 0 {
			t.Errorf("code/config identifier falsely flagged in %q: %+v", sample, a.secrets)
		}
	}

	realKey := "Z9x8C7v6" + "B5n4M3k2" + "J1h0P4q5"
	a := p.analyzer.analyze(`api_key = "` + realKey + `"`)
	if len(a.secrets) != 1 || a.secrets[0].typ != typeKey {
		t.Fatalf("expected real generic api_key to be detected, got %+v", a.secrets)
	}
}

func TestMicrosoftSecurityUtilitiesPatterns(t *testing.T) {
	p := newTestPlugin(t)

	cask := strings.Repeat("aB3d", 13) + "JQQJ99" + "xB" + strings.Repeat("9kLm", 4) + "Q" + "7pRs2tU"
	aad := "aB~" + "8Q~" + strings.Repeat("xY9_", 8)
	azFu := strings.Repeat("kL8_", 11) + "AzFu" + "9mN2p" + "Q=="
	azSe := strings.Repeat("mN7p", 10) + "aB" + "AzSe" + "B" + "8qR4t"
	az44 := strings.Repeat("pQ6r", 8) + "X" + "+ASb" + "C" + "7tU3v" + "="
	az88 := strings.Repeat("rS5t", 19) + "+ASt" + "6vW2x" + "A=="
	nuget := "oy2" + strings.Repeat("ab23cd45ef6", 3) + "ab23cd45ef"
	connKey := strings.Repeat("wX4y9K2p7LmN", 7) + "ab=="
	sasSig := strings.Repeat("zA3b8M1q5RtV", 4) + "%3D"

	cases := []struct {
		name   string
		input  string
		secret string
		keep   string
	}{
		{"Microsoft CASK (Azure OpenAI / ADO)", "AZURE_OPENAI_API_KEY=" + cask, cask, "AZURE_OPENAI_API_KEY="},
		{"Entra ID client secret", "AZURE_CLIENT_SECRET=" + aad, aad, "AZURE_CLIENT_SECRET="},
		{"Azure Function key", "x-functions-key: " + azFu, azFu, "x-functions-key: "},
		{"Azure Search key", "api-key: " + azSe, azSe, "api-key: "},
		{"Azure ServiceBus key", "SharedAccessKey=" + az44, az44, "SharedAccessKey="},
		{"Azure Storage identifiable key", "key=" + az88, az88, "key="},
		{"NuGet API key", "dotnet nuget push --api-key " + nuget, nuget, "dotnet nuget push --api-key "},
		{"Azure Storage connection string", "DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=" + connKey + ";EndpointSuffix=core.windows.net", connKey, "AccountName=prodstore;AccountKey="},
		{"Azure SAS URL signature", "https://prod.blob.core.windows.net/c/f?sv=2024-05-04&sig=" + sasSig, sasSig, "https://prod.blob.core.windows.net/c/f?sv=2024-05-04&sig="},
	}

	for _, tc := range cases {
		body := `{"messages":[{"role":"user","content":` + jsonString(tc.input) + `}]}`
		redacted, values := redactFor(t, p, tc.name, formatClaude, body)
		if strings.Contains(redacted, tc.secret) {
			t.Errorf("%s: secret survived in %s", tc.name, redacted)
		}
		if !strings.Contains(redacted, tc.keep) {
			t.Errorf("%s: non-secret context %q was swallowed in %s", tc.name, tc.keep, redacted)
		}
		ph := placeholderFor(t, values, tc.secret)
		if !strings.HasPrefix(ph, "pf-key-") {
			t.Errorf("%s: unexpected placeholder %q", tc.name, ph)
		}
	}
}

func TestModernAIGatewayKeysAndCSSFalsePositives(t *testing.T) {
	p := newTestPlugin(t)

	deepseekHex := "sk-" + "9f8e7d6c5b4a3928" + "17263544a9b8c7d6"
	openrouter := "sk-or-v1-" + strings.Repeat("a1b2c3d4e5f60718", 4)
	shortGateway := "sk-" + "9Km3pQr7" + "Xz2vBn5wL"
	xaiKey := "xai-" + strings.Repeat("Ab9xYz2K", 5)
	groqKey := "gsk_" + strings.Repeat("Mn8pQr4T", 5)

	for name, secret := range map[string]string{
		"deepseek hex key":    deepseekHex,
		"openrouter key":      openrouter,
		"gateway short key":   shortGateway,
		"xai key":             xaiKey,
		"groq key":            groqKey,
	} {
		a := p.analyzer.analyze("curl -H 'Bearer " + secret + "' https://api.example/v1")
		if len(a.secrets) != 1 || a.secrets[0].typ != typeKey {
			t.Errorf("%s (%q) not detected: %+v", name, secret, a.secrets)
		}
	}

	benign := []string{
		`<div class="sk-fading-circle-dot sk-skeleton-button-large"></div>`,
		`className="sk-three-bounce-1"`,
		`export OPENAI_API_KEY=sk-your-api-key-here`,
		`export OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxx`,
	}
	for _, text := range benign {
		if a := p.analyzer.analyze(text); len(a.secrets) != 0 {
			t.Errorf("benign sk- token %q flagged: %+v", text, a.secrets)
		}
	}
}

func TestURICredentialsCLIFlagsAndEncryptedPEMRoundTrip(t *testing.T) {
	p := newTestPlugin(t)
	dbPass := "Pg9#mK2!" + "xLq4"
	redisPass := "Rd8$nJ3@" + "vWp5"
	myPass := "My7%bH4^" + "zTn6"

	input := strings.Join([]string{
		"DATABASE_URL=postgres://app_user:" + dbPass + "@db.internal:5432/orders",
		"REDIS_URL=redis://:" + redisPass + "@cache.internal:6379/0",
		"mysql -h localhost -uroot -p" + myPass + " billing",
		"mysql -u root -p interactive_db_name",
	}, "\n")

	body := `{"messages":[{"role":"user","content":` + jsonString(input) + `}]}`
	redacted, values := redactFor(t, p, "cli1", formatClaude, body)
	for _, secret := range []string{dbPass, redisPass, myPass} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("credential %q leaked: %s", secret, redacted)
		}
	}
	for _, preserved := range []string{
		"postgres://app_user:pf-key-",
		"@db.internal:5432/orders",
		"redis://:pf-key-",
		"@cache.internal:6379/0",
		"mysql -h localhost -uroot -ppf-key-",
		"mysql -u root -p interactive_db_name",
	} {
		if !strings.Contains(redacted, preserved) {
			t.Fatalf("expected %q to survive in %s", preserved, redacted)
		}
	}
	if len(values) != 3 {
		t.Fatalf("expected exactly 3 vault values, got %d: %v", len(values), values)
	}

	// Encrypted PEM private key with commas in header must be replaced as a
	// single key span and restored byte-for-byte.
	pem := "-----BEGIN " + "RSA PRIVATE KEY-----\n" +
		"Proc-Type: 4,ENCRYPTED\n" +
		"DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n" +
		strings.Repeat("MIIEpAIBAAKCAQEA7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bN0x9\n", 3) +
		"-----END " + "RSA PRIVATE KEY-----"
	pemBody := `{"messages":[{"role":"user","content":` + jsonString("key:\n"+pem) + `}]}`
	pemRedacted, pemValues := redactFor(t, p, "pem1", formatClaude, pemBody)
	if strings.Contains(pemRedacted, "Proc-Type") || strings.Contains(pemRedacted, "MIIEpA") {
		t.Fatalf("encrypted PEM leaked: %s", pemRedacted)
	}
	pemPH := placeholderFor(t, pemValues, pem)
	resp, err := p.InterceptResponse(nil, pluginapi.ResponseInterceptRequest{
		RequestID: "pem1", SourceFormat: formatClaude,
		Body: []byte(`{"content":[{"type":"text","text":` + jsonString(pemPH) + `}]}`),
	})
	if err != nil || gjson.GetBytes(resp.Body, "content.0.text").String() != pem {
		t.Fatalf("PEM did not round-trip cleanly: err=%v body=%s", err, string(resp.Body))
	}
}

func TestPresidioChecksumsAndStructuralValidators(t *testing.T) {
	p := newTestPlugin(t)

	validID := makeValidCNID("110101" + "19900307" + "853")
	validIDWithX := ""
	for seq := 100; seq < 200; seq++ {
		cand := makeValidCNID("330106" + "19881123" + string([]byte{'0' + byte(seq/100), '0' + byte((seq/10)%10), '0' + byte(seq%10)}))
		if strings.HasSuffix(cand, "X") {
			validIDWithX = strings.ToLower(cand)
			break
		}
	}
	badChecksumID := validID[:17] + "9"
	if badChecksumID == validID {
		badChecksumID = validID[:17] + "8"
	}
	badDateID := makeValidCNID("110101" + "19990229" + "123")
	badProvID := makeValidCNID("990101" + "19900307" + "853")
	snowflake := "1857" + "29384756" + "102938"

	phoneOK := "138" + "0013" + "8000"
	phoneUnalloc := "154" + "0013" + "8000"
	ipv6Global := "2001" + ":4860:4860::8888"
	ipv6ULA := "fd00" + ":1234:5678::1"
	ipv6Link := "fe80" + "::1a2b:3c4d:5e6f:7890"
	ipv6Doc := "2001" + ":db8::1"
	ver4 := "1" + ".24" + ".3" + ".9"
	realHostPort := "10" + ".20" + ".30" + ".40:8080"

	cases := []struct {
		name, text, wantTyp string
	}{
		{"valid CN ID", "id " + validID, typeIDCard},
		{"valid CN ID lowercase x", "id " + validIDWithX, typeIDCard},
		{"bad CN ID checksum", "id " + badChecksumID, ""},
		{"invalid Feb 29 non-leap", "id " + badDateID, ""},
		{"invalid province 99", "id " + badProvID, ""},
		{"Snowflake 18-digit ID", "orderId=" + snowflake, ""},
		{"decimal fraction 18 digits", "ratio=0." + validID, ""},
		{"valid CN mobile", "tel " + phoneOK, typePhone},
		{"unallocated 154 prefix", "num " + phoneUnalloc, ""},
		{"slug-hyphen 11 digits", "trace-" + phoneOK, ""},
		{"decimal 11 digits", "score=0." + phoneOK, ""},
		{"retina asset @2x.png", "src=\"logo@2x.png\"", ""},
		{"systemd unit @.service", "systemctl status app-worker@default.service", ""},
		{"scoped package path", "node_modules/@types/node@20.11.alpha", ""},
		{"real email", "contact ops@" + "example.org", typeEmail},
		{"JSON version field", `"version": "` + ver4 + `"`, ""},
		{"leading zero octets", "code 01.02.03.04", ""},
		{"cloud metadata IP", "curl http://169" + ".254.169.254/latest/", ""},
		{"version label with port is real IP", "server = " + realHostPort, typeIP},
		{"global IPv6", "connect [" + ipv6Global + "]:443", typeIP},
		{"ULA IPv6", "peer " + ipv6ULA + "/64", typeIP},
		{"link-local IPv6", "gw " + ipv6Link + "%eth0", typeIP},
		{"RFC 3849 doc IPv6", "example " + ipv6Doc, ""},
		{"Rust module path", "use db::ca;", ""},
		{"hex words with ::", "const MAGIC = dead::beef;", ""},
	}

	for _, tc := range cases {
		a := p.analyzer.analyze(tc.text)
		got := ""
		if len(a.secrets) > 0 {
			got = a.secrets[0].typ
		}
		if got != tc.wantTyp {
			t.Errorf("%s (%q): got type %q, want %q (secrets=%+v)", tc.name, tc.text, got, tc.wantTyp, a.secrets)
		}
	}
}

func TestCaseInsensitivePlaceholderRestoreAndStreamUnknownDedup(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "ci1", formatOpenAI, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	token := placeholderFor(t, values, sampleToken)
	upperToken := strings.ToUpper(token)
	fakeUnknown := "pf-key-" + "000000000000"

	// Split an uppercased placeholder across small stream chunks, then emit a
	// chunk carrying a whole unknown placeholder, and verify restoration plus
	// single counting of the unknown reference.
	var chunks []string
	for _, piece := range chop("AUTH="+upperToken, 5) {
		chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{"content":`+jsonString(piece)+`}}]}`)
	}
	chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{"content":`+jsonString(" note="+fakeUnknown)+`}}]}`)
	chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)

	var got strings.Builder
	for _, ev := range sseData(stream(t, p, "ci1", formatOpenAI, chunks)) {
		got.WriteString(ev.Get("choices.0.delta.content").String())
	}
	want := "AUTH=" + sampleToken + " note=" + fakeUnknown
	if got.String() != want {
		t.Fatalf("got %q, want %q", got.String(), want)
	}
	st := p.states.get("ci1")
	if st == nil || st.r.unknown != 1 {
		t.Fatalf("expected unknown=1 (no double walk), got %+v", st.r)
	}
}

func TestUserConfiguredAllowlists(t *testing.T) {
	p := newTestPlugin(t, func(cfg *privacyFilterConfig) {
		cfg.AllowlistStopwords = []string{"internal-sandbox"}
		cfg.AllowlistRegexes = []string{`^10\.99\.0\.\d+$`}
	})
	ipAllowed := "10" + ".99.0.15"
	ipBlocked := "10" + ".88.0.15"
	text := "sandbox mail qa-internal-sandbox@example.com allow " + ipAllowed + " redact " + ipBlocked
	a := p.analyzer.analyze(text)
	if len(a.secrets) != 1 || text[a.secrets[0].start:a.secrets[0].end] != ipBlocked {
		t.Fatalf("unexpected secrets after user allowlist: %+v", a.secrets)
	}

	if _, err := buildPlugin([]byte("allowlist_regexes:\n  - \"(\"\n"), "."); err == nil {
		t.Fatal("invalid allowlist_regexes must fail plugin build")
	}
}

func TestSecurityReviewRegressions(t *testing.T) {
	p := newTestPlugin(t)
	dot := "."
	lanIP := "192" + dot + "168" + dot + "1" + dot + "10"
	ipv6 := "2001" + ":4860:4860::8888"

	// P1-1: "server" / "client" / "api" keys without ports are real host IPs, not versions.
	for _, sample := range []string{
		`{"server": "` + lanIP + `", "port": 22}`,
		`client=` + lanIP,
		`api: "` + lanIP + `"`,
	} {
		a := p.analyzer.analyze(sample)
		if len(a.secrets) != 1 || a.secrets[0].typ != typeIP {
			t.Errorf("P1-1 host IP missed in %q: %+v", sample, a.secrets)
		}
	}
	if a := p.analyzer.analyze(`{"server_version": "1` + dot + `24` + dot + `3` + dot + `9"}`); len(a.secrets) != 0 {
		t.Errorf("server_version should stay benign: %+v", a.secrets)
	}

	// P1-2: +driver URI schemes, ?query emails, /path emails, and .zip TLD emails.
	uriPass := "AsyncPg9#" + "kLm2"
	emailCo := "ops" + "@example.com"
	emailZip := "admin" + "@example.zip"
	uriCases := `{"messages":[{"role":"user","content":` + jsonString(strings.Join([]string{
		"DATABASE_URL=postgresql+asyncpg://app:" + uriPass + "@db.example.com:5432/orders",
		"url=http://localhost:3000?email=" + emailCo,
		"GET /api/v1/users/" + emailCo,
		"contact " + emailZip,
	}, "\n")) + `}]}`
	redacted, _ := redactFor(t, p, "p12", formatClaude, uriCases)
	for _, secret := range []string{uriPass, emailCo, emailZip} {
		if strings.Contains(redacted, secret) {
			t.Errorf("P1-2 secret %q leaked in %s", secret, redacted)
		}
	}
	for _, keep := range []string{"postgresql+asyncpg://app:pf-key-", "@db.example.com:5432/orders", "http://localhost:3000?email=pf-email-", "GET /api/v1/users/pf-email-"} {
		if !strings.Contains(redacted, keep) {
			t.Errorf("P1-2 context %q corrupted in %s", keep, redacted)
		}
	}

	// P1-3: Secrets containing "false" or starting with "true" must not hit gitleaks' ungrouped ^true|false|null$.
	falseToken := "ghp_016C7869C1AE" + "false" + "FDEE0A1CBF9C8B0EF37"
	truePass := "TruePass" + "#2026!"
	for _, sample := range []string{"GITHUB_TOKEN=" + falseToken, "password: " + truePass} {
		if a := p.analyzer.analyze(sample); len(a.secrets) != 1 {
			t.Errorf("P1-3 secret bypassed allowlist in %q: %+v", sample, a.secrets)
		}
	}

	// P1-4: Gemini stream functionCall.args containing nested parts[].text must still restore placeholders.
	_, gemVals := redactFor(t, p, "gem-fc", formatGemini, `{"contents":[{"role":"user","parts":[{"text":"key `+sampleToken+`"}]}]}`)
	gemToken := placeholderFor(t, gemVals, sampleToken)
	gemChunk := `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"post","args":{"parts":[{"text":"Bearer ` + gemToken + `"}]}}}]},"finishReason":"STOP"}]}`
	gemOut := stream(t, p, "gem-fc", formatGemini, []string{gemChunk})
	if !strings.Contains(gemOut, "Bearer "+sampleToken) {
		t.Fatalf("P1-4 Gemini functionCall.args nested parts.text not restored: %s", gemOut)
	}

	// P2-2: Code referencing PEM header/footer string constants must not be mistaken for a PEM block.
	pemCode := `if strings.HasPrefix(s, "-----BEGIN ` + `RSA PRIVATE KEY-----") && strings.HasSuffix(s, "-----END ` + `RSA PRIVATE KEY-----") { return true }`
	if a := p.analyzer.analyze(pemCode); len(a.secrets) != 0 {
		t.Errorf("P2-2 code constants flagged as PEM key: %+v", a.secrets)
	}

	// P2-3, P2-4, P2-5: Query password truncation, unspaced key:ipv6, template {var}, subshell ), and 167-char sk-svcacct-.
	qPass := "Jdbc9#mK" + "2xLq"
	svcKey := "sk-svcacct-" + strings.Repeat("Ab3dEf6hIj9kLm2nOp5q", 8)
	subBody := `{"messages":[{"role":"user","content":` + jsonString(strings.Join([]string{
		"jdbc:mysql://127.0.0.1:3306/app?user=root&password=" + qPass + "&sslmode=require",
		"out=$(mysql -N -uroot -p" + qPass + ")",
		`dsn = f"postgres://app:{db_password}@127.0.0.1:5432/prod"`,
		"src:" + ipv6 + " addr:" + ipv6 + " ipv6:" + ipv6,
		"OPENAI_API_KEY=" + svcKey,
	}, "\n")) + `}]}`
	subRedacted, subVals := redactFor(t, p, "p2345", formatClaude, subBody)
	for _, secret := range []string{qPass, ipv6, svcKey} {
		if strings.Contains(subRedacted, secret) {
			t.Errorf("P2 secret %q survived: %s", secret, subRedacted)
		}
	}
	for _, keep := range []string{"&sslmode=require", "-ppf-key-", `)\n`, "{db_password}", "src:pf-ip-", "addr:pf-ip-", "ipv6:pf-ip-"} {
		if !strings.Contains(subRedacted, keep) {
			t.Errorf("P2 expected %q preserved in %s", keep, subRedacted)
		}
	}
	for _, v := range subVals {
		if v == "{db_password}" {
			t.Fatal("P2-5 template variable entered vault")
		}
	}

	// P2-6: Reconfigured allowlist / skip_types must also suppress shared vault literal matches.
	sharedVault := newVault(p.format, []byte("0123456789abcdef0123456789abcdef"), 1000, 6)
	cfg1 := defaultConfig()
	p1, err := assemblePlugin(cfg1, ".", newStateRegistry(), func(*placeholderFormat) *vault { return sharedVault })
	if err != nil {
		t.Fatal(err)
	}
	sandboxIP := "10" + dot + "77" + dot + "0" + dot + "9"
	redactFor(t, p1, "v1", formatClaude, `{"messages":[{"role":"user","content":"host `+sandboxIP+`"}]}`)

	cfg2 := defaultConfig()
	cfg2.AllowlistRegexes = []string{`^10\.77\.0\.\d+$`}
	p2, err := assemblePlugin(cfg2, ".", newStateRegistry(), func(*placeholderFormat) *vault { return sharedVault })
	if err != nil {
		t.Fatal(err)
	}
	afterAllow, _ := redactFor(t, p2, "v2", formatClaude, `{"messages":[{"role":"user","content":"ping `+sandboxIP+`"}]}`)
	if !strings.Contains(afterAllow, sandboxIP) {
		t.Fatalf("P2-6 allowlisted value still replaced by shared vault: %s", afterAllow)
	}
}
