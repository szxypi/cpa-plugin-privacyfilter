package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/tidwall/gjson"
)

func newTestPlugin(t testing.TB, mutate ...func(*privacyFilterConfig)) *privacyFilterPlugin {
	t.Helper()
	cfg := defaultConfig()
	for _, m := range mutate {
		m(&cfg)
	}
	p, err := assemblePlugin(cfg, ".", newStateRegistry(), func(format *placeholderFormat) *vault {
		return newVault(format, []byte("0123456789abcdef0123456789abcdef"), cfg.vaultMaxEntries(), cfg.literalMinBytes())
	})
	if err != nil {
		t.Fatalf("assemblePlugin() error = %v", err)
	}
	return p
}

var rePlaceholder = regexp.MustCompile(`pf-(key|email|phone|idcard|ip|card)-[0-9a-f]{12}`)

const (
	sampleEmail = "test@example.com"
	sampleToken = "ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37"
)

// redactString runs the interceptor and returns the rewritten body as a string.
func redactString(t *testing.T, p *privacyFilterPlugin, body string) string {
	t.Helper()
	out, _, _ := p.redactRequestBody([]byte(body))
	if out == nil {
		return ""
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("rewritten body is not valid JSON: %s", string(out))
	}
	return string(out)
}

func TestClaudeStringContent(t *testing.T) {
	p := newTestPlugin(t)
	got := redactString(t, p, `{"model":"claude-sonnet-5","messages":[{"role":"user","content":"my email is `+sampleEmail+`"}]}`)
	if got == "" {
		t.Fatal("expected a rewritten body")
	}
	if strings.Contains(got, sampleEmail) {
		t.Fatalf("email survived: %s", got)
	}
	if !regexp.MustCompile(`my email is pf-email-[0-9a-f]{12}"`).MatchString(got) {
		t.Fatalf("placeholder missing: %s", got)
	}
}

func TestClaudeSystemAndBlocks(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"claude-sonnet-5",
"system":[{"type":"text","text":"the deploy key is ` + sampleToken + `"}],
"messages":[{"role":"user","content":[{"type":"text","text":"call me at 13800138000"}]}]}`
	got := redactString(t, p, body)
	if strings.Contains(got, sampleToken) || strings.Contains(got, "13800138000") {
		t.Fatalf("secret survived: %s", got)
	}
}

func TestClaudeSystemString(t *testing.T) {
	p := newTestPlugin(t)
	got := redactString(t, p, `{"model":"m","system":"contact `+sampleEmail+`","messages":[{"role":"user","content":"hi"}]}`)
	if strings.Contains(got, sampleEmail) {
		t.Fatalf("system string not redacted: %s", got)
	}
}

func TestClaudeToolResultNestedContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[
{"role":"assistant","content":[{"type":"tool_use","id":"toolu_01","name":"Read","input":{"file_path":"/etc/app.env"}}]},
{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01","content":[{"type":"text","text":"GITHUB_TOKEN=` + sampleToken + `"}]}]}]}`
	got := redactString(t, p, body)
	if got == "" {
		t.Fatal("tool_result content was not scanned at all")
	}
	if strings.Contains(got, sampleToken) {
		t.Fatalf("tool_result secret survived: %s", got)
	}
	if !strings.Contains(got, `"tool_use_id":"toolu_01"`) {
		t.Fatalf("tool_use_id must be preserved verbatim: %s", got)
	}
}

func TestClaudeToolResultStringContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"key=` + sampleToken + `"}]}]}`
	got := redactString(t, p, body)
	if strings.Contains(got, sampleToken) {
		t.Fatalf("string tool_result survived: %s", got)
	}
}

func TestClaudeThinkingBlockUntouched(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[
{"role":"assistant","content":[{"type":"thinking","thinking":"the token is ` + sampleToken + `","signature":"abc"}]},
{"role":"user","content":"ok"}]}`
	out, _, _ := p.redactRequestBody([]byte(body))
	if out != nil {
		t.Fatalf("thinking blocks must be replayed verbatim, got rewrite: %s", string(out))
	}
}

func TestClaudeImageBlockSkipped(t *testing.T) {
	p := newTestPlugin(t)
	blob := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5", 100)
	body := `{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + blob + `"}},{"type":"text","text":"see attached"}]}]}`
	out, _, _ := p.redactRequestBody([]byte(body))
	if out != nil {
		t.Fatalf("no secrets present, body should pass through: %s", string(out))
	}
}

func TestToolInputScannedAndDisabled(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"/tmp/.env","content":"GITHUB_TOKEN=` + sampleToken + `"}}]}]}`

	on := newTestPlugin(t)
	got := redactString(t, on, body)
	if strings.Contains(got, sampleToken) {
		t.Fatalf("tool_use.input secret survived with scan_tool_input on: %s", got)
	}

	disabled := false
	off := newTestPlugin(t, func(c *privacyFilterConfig) { c.ScanToolInput = &disabled })
	if out, _, _ := off.redactRequestBody([]byte(body)); out != nil {
		t.Fatalf("scan_tool_input=false must leave tool arguments alone: %s", string(out))
	}
}

func TestOpenAIChatArrayContentAndToolCalls(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-5","messages":[
{"role":"system","content":"be brief"},
{"role":"user","content":[{"type":"text","text":"mail: ` + sampleEmail + `"}]},
{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"run","arguments":"{\"cmd\":\"export TOKEN=` + sampleToken + `\"}"}}]}]}`
	got := redactString(t, p, body)
	if strings.Contains(got, sampleEmail) {
		t.Fatalf("chat array content survived: %s", got)
	}
	if strings.Contains(got, sampleToken) {
		t.Fatalf("tool_calls arguments survived: %s", got)
	}
}

func TestResponsesStringInput(t *testing.T) {
	p := newTestPlugin(t)
	got := redactString(t, p, `{"model":"gpt-5","input":"my email is `+sampleEmail+`"}`)
	if strings.Contains(got, sampleEmail) {
		t.Fatalf("responses string input survived: %s", got)
	}
}

func TestResponsesArrayInput(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-5","instructions":"reach ops at ` + sampleEmail + `","input":[
{"type":"message","role":"user","content":[{"type":"input_text","text":"deploy key ` + sampleToken + `"}]},
{"type":"function_call_output","call_id":"c1","output":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}]}`
	got := redactString(t, p, body)
	for _, secret := range []string{sampleEmail, sampleToken, "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(got, secret) {
			t.Fatalf("responses payload leaked %q: %s", secret, got)
		}
	}
}

func TestGeminiContents(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"contents":[{"role":"user","parts":[{"text":"token ` + sampleToken + `"},{"text":"and mail ` + sampleEmail + `"}]}],
"systemInstruction":{"parts":[{"text":"phone 13800138000"}]}}`
	got := redactString(t, p, body)
	for _, secret := range []string{sampleToken, sampleEmail, "13800138000"} {
		if strings.Contains(got, secret) {
			t.Fatalf("gemini payload leaked %q: %s", secret, got)
		}
	}
}

func TestGeminiFunctionResponse(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"read","response":{"content":"GITHUB_TOKEN=` + sampleToken + `"}}}]}]}`
	got := redactString(t, p, body)
	if strings.Contains(got, sampleToken) {
		t.Fatalf("gemini functionResponse survived: %s", got)
	}
}

// TestUntouchedBytesArePreserved is the reason the rewrite splices instead of
// re-marshalling: field order, escaping and whitespace of untouched fields must
// survive so prompt caching and provider signatures keep working.
func TestUntouchedBytesArePreserved(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m", "metadata":{"user_id":"uAb"}, "messages":[
  {"role":"user","content":"clean text with <html> & é"},
  {"role":"user","content":"leak ` + sampleEmail + `"}
], "temperature":0.5}`
	got := redactString(t, p, body)
	if got == "" {
		t.Fatal("expected a rewrite")
	}
	for _, fragment := range []string{
		`{"model":"m", "metadata":{"user_id":"uAb"}, "messages":[`,
		`"content":"clean text with <html> & é"`,
		`], "temperature":0.5}`,
	} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("byte-exact fragment %q lost:\n%s", fragment, got)
		}
	}
}

func TestNoHitReturnsNil(t *testing.T) {
	p := newTestPlugin(t)
	out, stats, _ := p.redactRequestBody([]byte(`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`))
	if out != nil {
		t.Fatalf("clean body must pass through untouched, got %s", string(out))
	}
	if stats.fields != 1 {
		t.Fatalf("expected one scanned field, got %d", stats.fields)
	}
}

func TestInvalidJSONPassesThrough(t *testing.T) {
	p := newTestPlugin(t)
	out, _, _ := p.redactRequestBody([]byte(`not valid json with email ` + sampleEmail))
	if out != nil {
		t.Fatalf("invalid JSON must pass through, got %s", string(out))
	}
}

func TestUnknownShapePassesThrough(t *testing.T) {
	p := newTestPlugin(t)
	out, _, _ := p.redactRequestBody([]byte(`{"unknown":{"payload":"email ` + sampleEmail + `"}}`))
	if out != nil {
		t.Fatalf("unsupported shape must pass through, got %s", string(out))
	}
}

func TestRewrittenBodyDecodesIdentically(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","max_tokens":100,"messages":[{"role":"user","content":[{"type":"text","text":"mail ` + sampleEmail + ` done"}]}]}`
	out, _, _ := p.redactRequestBody([]byte(body))
	if out == nil {
		t.Fatal("expected a rewrite")
	}
	var before, after map[string]any
	if err := json.Unmarshal([]byte(body), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &after); err != nil {
		t.Fatalf("rewritten body does not decode: %v\n%s", err, string(out))
	}
	if len(before) != len(after) {
		t.Fatalf("field count changed: %d -> %d", len(before), len(after))
	}
	text := gjson.GetBytes(out, "messages.0.content.0.text").String()
	if !regexp.MustCompile(`^mail pf-email-[0-9a-f]{12} done$`).MatchString(text) {
		t.Fatalf("unexpected redaction: %q", text)
	}
}

func TestInterceptRequest_SkippedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is ` + sampleEmail + `"}]}`
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{Model: "gpt-4", Body: []byte(body)})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("expected skipped model to pass through, got: %s", string(resp.Body))
	}
}

func TestInterceptRequest_SkippedRequestedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"upstream-model","messages":[{"role":"user","content":"my email is ` + sampleEmail + `"}]}`
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{
		Model:          "upstream-model",
		RequestedModel: "gpt-4",
		Body:           []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("expected skipped requested model to pass through, got: %s", string(resp.Body))
	}
}

func TestInterceptRequest_MaxBodyBytes(t *testing.T) {
	limit := int64(64)
	p := newTestPlugin(t, func(c *privacyFilterConfig) { c.MaxBodyBytes = &limit })
	body := `{"model":"m","messages":[{"role":"user","content":"my email is ` + sampleEmail + ` and some padding to go past the limit"}]}`
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{Model: "m", Body: []byte(body)})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatal("bodies over max_body_bytes must be skipped")
	}

	unlimited := int64(-1)
	q := newTestPlugin(t, func(c *privacyFilterConfig) { c.MaxBodyBytes = &unlimited })
	resp, err = q.interceptRequest(pluginapi.RequestInterceptRequest{Model: "m", Body: []byte(body)})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body == nil {
		t.Fatal("max_body_bytes=-1 must scan everything")
	}
}

func TestInterceptRequestBeforeAuth_Redacts(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[{"role":"user","content":"my email is ` + sampleEmail + `"}]}`
	resp, err := p.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{Model: "m", Body: []byte(body)})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth() error = %v", err)
	}
	if resp.Body == nil || strings.Contains(string(resp.Body), sampleEmail) {
		t.Fatalf("before-auth hook must redact, got %s", string(resp.Body))
	}
}

// TestInterceptRequestAfterAuth_NoOp pins the single-hook decision: the
// after-auth body is a translation of an already filtered payload, so scanning
// it again would double the cost of every request and repeat on every retry.
func TestInterceptRequestAfterAuth_NoOp(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[{"role":"user","content":"my email is ` + sampleEmail + `"}]}`
	resp, err := p.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{Model: "m", Body: []byte(body)})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatal("after-auth hook must be a no-op")
	}
}

func TestConfigShouldSkip(t *testing.T) {
	cfg := privacyFilterConfig{
		SkipModels:  []string{"gpt-4", "claude-3"},
		SkipFormats: []string{"openai"},
	}
	if !cfg.shouldSkip("gpt-4", "", "") {
		t.Fatal("should skip gpt-4")
	}
	if !cfg.shouldSkip("upstream-model", "claude-3", "") {
		t.Fatal("should skip requested claude-3")
	}
	if !cfg.shouldSkip("", "", "openai") {
		t.Fatal("should skip openai format")
	}
	if cfg.shouldSkip("gemini-pro", "", "anthropic") {
		t.Fatal("should not skip unknown model/format")
	}
}

func TestConfigParse(t *testing.T) {
	raw := `
skip_models:
  - gpt-4
skip_formats:
  - openai
disable_rules:
  - generic-api-key
max_body_bytes: 1048576
scan_tool_input: false
cache_entries: 0
workers: 2
log_stats: true
`
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if len(cfg.SkipModels) != 1 || cfg.SkipModels[0] != "gpt-4" {
		t.Fatalf("skip_models = %v, want [gpt-4]", cfg.SkipModels)
	}
	if cfg.maxBodyBytes() != 1048576 {
		t.Fatalf("max_body_bytes = %d", cfg.maxBodyBytes())
	}
	if cfg.scanToolInput() {
		t.Fatal("scan_tool_input should be false")
	}
	if cfg.cacheEntries() != 0 {
		t.Fatalf("cache_entries = %d, want 0", cfg.cacheEntries())
	}
	if cfg.workers() != 2 {
		t.Fatalf("workers = %d, want 2", cfg.workers())
	}
	if !cfg.LogStats {
		t.Fatal("log_stats should be true")
	}
	if len(cfg.DisableRules) != 1 {
		t.Fatalf("disable_rules = %v", cfg.DisableRules)
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := defaultConfig()
	if cfg.maxBodyBytes() != defaultMaxBodyBytes {
		t.Fatalf("default max_body_bytes = %d", cfg.maxBodyBytes())
	}
	if !cfg.scanToolInput() {
		t.Fatal("scan_tool_input should default to true")
	}
	if cfg.cacheEntries() != defaultCacheEntries {
		t.Fatalf("default cache_entries = %d", cfg.cacheEntries())
	}
	if cfg.workers() < 1 {
		t.Fatalf("workers must be at least 1, got %d", cfg.workers())
	}
}

func TestRegistrationCapabilityJSON(t *testing.T) {
	caps := abiCapabilities{RequestInterceptor: true, ResponseInterceptor: true, StreamChunkInterceptor: true, RequestLifecyclePlugin: true}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, field := range []string{`"request_interceptor":true`, `"response_interceptor":true`, `"response_stream_interceptor":true`, `"request_lifecycle_plugin":true`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("expected %s in JSON: %s", field, string(raw))
		}
	}
}

func TestBuildPluginMetadata(t *testing.T) {
	plugin, err := buildPlugin([]byte("enabled: true\ndata_dir: "+t.TempDir()+"\n"), ".")
	if err != nil {
		t.Fatalf("buildPlugin() error = %v", err)
	}
	if plugin.Metadata.Name != pluginName || plugin.Metadata.Version != pluginVersion {
		t.Fatalf("unexpected metadata: %+v", plugin.Metadata)
	}
	if plugin.Capabilities.RequestInterceptor == nil || plugin.Capabilities.ResponseInterceptor == nil ||
		plugin.Capabilities.StreamChunkInterceptor == nil || plugin.Capabilities.RequestLifecyclePlugin == nil {
		t.Fatal("a capability is missing")
	}
	if len(plugin.Metadata.ConfigFields) < 10 {
		t.Fatalf("expected every config field to be advertised, got %d", len(plugin.Metadata.ConfigFields))
	}
}

func TestAppendJSONString(t *testing.T) {
	cases := []string{"", "plain", "quote\"inside", "back\\slash", "tab\there\nnewline", "控制符\x01end", "<html> & 'quotes'"}
	for _, c := range cases {
		encoded := appendJSONString(nil, c)
		var decoded string
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("encoding %q produced invalid JSON %s: %v", c, string(encoded), err)
		}
		if decoded != c {
			t.Fatalf("round trip changed %q into %q", c, decoded)
		}
	}
	if got := string(appendJSONString(nil, "<a> & 'b'")); got != `"<a> & 'b'"` {
		t.Fatalf("HTML must not be escaped, got %s", got)
	}
}

// withPanicStage makes the named pipeline stage panic for the duration of fn.
// It restores the seam on exit, including after a test failure.
func withPanicStage(t *testing.T, stage string) {
	t.Helper()
	previous := panicInjector
	panicInjector = func(current string) {
		if current == stage {
			panic("injected panic at " + stage)
		}
	}
	t.Cleanup(func() { panicInjector = previous })
}

// bigMessagesBody builds a Claude body whose fields together exceed
// parallelScanThreshold, so forEachField takes the worker path.
func bigMessagesBody(fields int) string {
	var b strings.Builder
	b.WriteString(`{"model":"m","messages":[`)
	for i := 0; i < fields; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"role":"user","content":"padding `)
		b.WriteString(strings.Repeat("x", 12*1024))
		b.WriteString(` mail `)
		b.WriteString(sampleEmail)
		b.WriteString(`"}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

// TestRequestPanicSerialFailsClosed proves a scan panic on the serial path
// refuses the request instead of forwarding a half-redacted body.
func TestRequestPanicSerialFailsClosed(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[{"role":"user","content":"mail ` + sampleEmail + `"}]}`
	withPanicStage(t, stageScanField)

	resp, err := p.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{RequestID: "s1", Model: "m", Body: []byte(body)})
	if err != nil {
		t.Fatalf("a refusal must be reported as Terminate, not an error: %v", err)
	}
	if !resp.Terminate {
		t.Fatal("request panic did not terminate the request")
	}
	if resp.StatusCode != 403 {
		t.Fatalf("termination status = %d, want 403", resp.StatusCode)
	}
	if len(resp.Body) != 0 {
		t.Fatalf("a refused request must not carry a body, got %q", string(resp.Body))
	}
}

// TestRequestPanicWorkerFailsClosed proves a panic inside a scan worker
// goroutine is recovered on that goroutine, refuses the request, and does not
// take the process down. Without the per-worker recover this test crashes the
// test binary.
func TestRequestPanicWorkerFailsClosed(t *testing.T) {
	workers := 4
	p := newTestPlugin(t, func(cfg *privacyFilterConfig) { cfg.Workers = &workers })
	body := bigMessagesBody(4)
	// Pin the preconditions forEachField uses to pick the worker path, so this
	// test cannot silently degrade into a second serial-path test.
	refs := collectTexts([]byte(body), walkOptions{ScanToolInput: false})
	total := 0
	for _, ref := range refs {
		total += len(ref.value)
	}
	if len(refs) < 2 || total < parallelScanThreshold || p.cfg.workers() < 2 {
		t.Fatalf("worker path not reachable: fields=%d bytes=%d workers=%d", len(refs), total, p.cfg.workers())
	}
	withPanicStage(t, stageScanField)

	resp, err := p.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{RequestID: "w1", Model: "m", Body: []byte(body)})
	if err != nil {
		t.Fatalf("a refusal must be reported as Terminate, not an error: %v", err)
	}
	if !resp.Terminate || resp.StatusCode != 403 || len(resp.Body) != 0 {
		t.Fatalf("worker panic did not fail closed: %+v", resp)
	}
}

// TestRequestPanicRewritePhaseFailsClosed covers the second forEachField pass,
// which runs rewriteField rather than the detector.
func TestRequestPanicRewritePhaseFailsClosed(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"m","messages":[{"role":"user","content":"mail ` + sampleEmail + `"}]}`
	withPanicStage(t, stageRewriteField)

	resp, err := p.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{RequestID: "r1", Model: "m", Body: []byte(body)})
	if err != nil || !resp.Terminate || resp.StatusCode != 403 {
		t.Fatalf("rewrite panic did not fail closed: %+v %v", resp, err)
	}
}

// TestResponsePanicPassesThrough proves a response-side panic only loses the
// restore: the original body goes through, no termination is requested.
func TestResponsePanicPassesThrough(t *testing.T) {
	p := newTestPlugin(t)
	redacted, values := redactFor(t, p, "resp1", formatClaude, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	if len(values) == 0 {
		t.Fatal("expected a placeholder to restore")
	}
	body := []byte(redacted)
	withPanicStage(t, stageResponse)

	resp, err := p.InterceptResponse(nil, pluginapi.ResponseInterceptRequest{RequestID: "resp1", Model: "m", SourceFormat: formatClaude, Body: body})
	if err != nil {
		t.Fatalf("response panic must not surface an error: %v", err)
	}
	if len(resp.Body) != 0 {
		t.Fatalf("response panic must leave the body untouched, got %q", string(resp.Body))
	}
	if resp.Headers != nil || resp.ClearHeaders != nil {
		t.Fatalf("response panic must return a zero response, got %+v", resp)
	}
}

// TestStreamChunkPanicPassesThrough proves a stream-chunk panic neither drops
// the chunk nor rewrites it.
func TestStreamChunkPanicPassesThrough(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "chunk1", formatClaude, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	if len(values) == 0 {
		t.Fatal("expected a placeholder to restore")
	}
	withPanicStage(t, stageStreamChunk)

	resp, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: "chunk1", SourceFormat: formatClaude, ChunkIndex: 0,
		Body: []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\n"),
	})
	if err != nil {
		t.Fatalf("stream chunk panic must not surface an error: %v", err)
	}
	if resp.DropChunk || len(resp.Body) != 0 {
		t.Fatalf("stream chunk panic must pass the chunk through: %+v", resp)
	}
}

// TestStreamChunkPanicReleasesHeldEvent covers the withheld SSE line: the
// Responses stream holds an "event:" line until its "data:" line arrives, and
// processChunk clears held before it can panic. The recover must splice the
// held bytes back in and drop the state, or a response.completed event would
// be lost and later chunks would keep restoring from a half-updated state.
func TestStreamChunkPanicReleasesHeldEvent(t *testing.T) {
	p := newTestPlugin(t)
	_, values := redactFor(t, p, "held1", formatResponses, `{"messages":[{"role":"user","content":"key `+sampleToken+`"}]}`)
	if len(values) == 0 {
		t.Fatal("expected a placeholder to restore")
	}

	// A lone "event:" line is withheld by the previous call.
	heldLine := "event: response.completed"
	first, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: "held1", SourceFormat: formatResponses, ChunkIndex: 0,
		Body: []byte(heldLine),
	})
	if err != nil {
		t.Fatalf("stream chunk error = %v", err)
	}
	if !first.DropChunk || len(first.Body) != 0 {
		t.Fatalf("a lone event line must be withheld, got %+v", first)
	}

	// The next chunk panics after the held line has been merged and cleared.
	withPanicStage(t, stageStreamChunkMerge)
	secondBody := []byte("event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n")
	second, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: "held1", SourceFormat: formatResponses, ChunkIndex: 1,
		Body: secondBody,
	})
	if err != nil {
		t.Fatalf("stream chunk panic must not surface an error: %v", err)
	}
	if second.DropChunk {
		t.Fatal("a recovered chunk must not be dropped")
	}
	if !strings.Contains(string(second.Body), heldLine) {
		t.Fatalf("the withheld event line was lost: %q", string(second.Body))
	}
	if !strings.Contains(string(second.Body), string(secondBody)) {
		t.Fatalf("the current chunk was lost: %q", string(second.Body))
	}

	// The state is gone, so later chunks pass through untouched even though
	// their body carries a placeholder that used to be restorable.
	placeholder := placeholderFor(t, values, sampleToken)
	third, err := p.InterceptStreamChunk(nil, pluginapi.StreamChunkInterceptRequest{
		RequestID: "held1", SourceFormat: formatResponses, ChunkIndex: 2,
		Body: []byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"" + placeholder + "\"}\n\n"),
	})
	if err != nil {
		t.Fatalf("stream chunk error = %v", err)
	}
	if third.DropChunk || len(third.Body) != 0 {
		t.Fatalf("a dropped state must pass later chunks through: %+v", third)
	}
	if p.states.get("held1") != nil {
		t.Fatal("the failed request state must be removed")
	}
}

// TestABIPanicBoundaryAnswersPerCallType proves the C/Go boundary converts a
// panic into the envelope shape the host expects for each call type.
func TestABIPanicBoundaryAnswersPerCallType(t *testing.T) {
	p := newTestPlugin(t)
	privacyFilterABIState.Lock()
	privacyFilterABIState.plugin = p
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()
	withPanicStage(t, stageABI)

	requestHook := callPrivacyFilterABISafe("request.intercept_before", []byte(`{"RequestID":"a","Body":{}}`))
	var reqEnvelope struct {
		OK     bool `json:"ok"`
		Result struct {
			Terminate  bool `json:"Terminate"`
			StatusCode int  `json:"StatusCode"`
		} `json:"result"`
	}
	if err := json.Unmarshal(requestHook, &reqEnvelope); err != nil {
		t.Fatalf("request envelope is not JSON: %v (%s)", err, string(requestHook))
	}
	if !reqEnvelope.OK || !reqEnvelope.Result.Terminate || reqEnvelope.Result.StatusCode != 403 {
		t.Fatalf("request hook panic must fail closed: %s", string(requestHook))
	}

	responseHook := callPrivacyFilterABISafe("response.intercept_after", []byte(`{"RequestID":"a","Body":{}}`))
	if !strings.Contains(string(responseHook), `"ok":true`) {
		t.Fatalf("response hook panic must answer OK: %s", string(responseHook))
	}
	if strings.Contains(string(responseHook), "Terminate") {
		t.Fatalf("response hook must not terminate: %s", string(responseHook))
	}

	chunkHook := callPrivacyFilterABISafe("response.intercept_stream_chunk", []byte(`{"RequestID":"a","ChunkIndex":0}`))
	if string(chunkHook) != string(emptyStreamChunkEnvelope) {
		t.Fatalf("stream chunk panic must answer the empty chunk envelope: %s", string(chunkHook))
	}
}

// Values are assembled at run time so the source holds no literal that a
// privacy proxy in front of the editor would rewrite.
func TestVersionStringsAndNumbersAreNotAddressesOrCards(t *testing.T) {
	p := newTestPlugin(t)
	dot := "."
	kernel := "5" + dot + "15" + dot + "167" + dot + "4"
	pkg := "1" + dot + "24" + dot + "3" + dot + "9"
	host := "10" + dot + "20" + dot + "30" + dot + "40"
	fraction := "0" + dot + "0912345678901234"
	stamp := "1729" + "612345678" + "901"
	card := "4111" + "1111" + "1111" + "1111"

	cases := []struct {
		name, text string
		wantTyp    string // "" means nothing is replaced
	}{
		{"kernel release tag", "Linux " + kernel + "-microsoft-standard-WSL2", ""},
		{"pinned package", "numpy==" + pkg, ""},
		{"v prefix", "release v" + pkg, ""},
		{"real host", "connect to " + host + " now", typeIP},
		{"decimal fraction", `"costUSD":` + fraction, ""},
		{"timestamp", "startTime " + stamp, ""},
		{"real card", "card " + card + " expires", typeCard},
	}
	for _, c := range cases {
		a := p.analyzer.analyze(c.text)
		got := ""
		if len(a.secrets) > 0 {
			got = a.secrets[0].typ
		}
		if got != c.wantTyp {
			t.Errorf("%s: detected %q, want %q (%q)", c.name, got, c.wantTyp, c.text)
		}
	}
}

func TestBareNumberInToolArgumentsStaysValidJSON(t *testing.T) {
	p := newTestPlugin(t)
	phone := "138" + "0013" + "8000"
	args := `{\"phone\":` + phone + `,\"note\":\"x\"}`
	body := `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"call","arguments":"` + args + `"}}]}]}`
	got := redactString(t, p, body)
	if got == "" {
		t.Fatal("expected a rewritten body")
	}
	rewritten := gjson.Get(got, "messages.0.tool_calls.0.function.arguments").String()
	if !gjson.Valid(rewritten) {
		t.Fatalf("arguments are no longer JSON: %s", rewritten)
	}
	if strings.Contains(rewritten, phone) {
		t.Fatalf("phone survived: %s", rewritten)
	}
}
