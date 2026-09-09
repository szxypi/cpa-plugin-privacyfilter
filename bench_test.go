package main

import (
	"testing"

	"privacyfilter/filter"
)

func newLegacyPlugin(b testing.TB) *legacyPlugin {
	b.Helper()
	f, err := filter.New("rules/gitleaks.toml")
	if err != nil {
		b.Fatalf("filter.New: %v", err)
	}
	return &legacyPlugin{filter: f}
}

// BenchmarkLegacyClaudeBody200KB is the v0.2.0 baseline: upstream
// privacy-filter, a full Unmarshal/Marshal round trip, and coverage limited to
// messages[].content[].text.
func BenchmarkLegacyClaudeBody200KB(b *testing.B) {
	p := newLegacyPlugin(b)
	body := buildClaudeCorpus(200 * 1024)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.redactRequestBody(body)
	}
}

// BenchmarkColdClaudeBody200KB scans the same body with the cache disabled, so
// every field is scanned for real. It also covers far more of the body than the
// legacy path did (see TestCoverageAgainstLegacy).
func BenchmarkColdClaudeBody200KB(b *testing.B) {
	zero := 0
	p := newTestPlugin(b, func(c *privacyFilterConfig) { c.CacheEntries = &zero })
	body := buildClaudeCorpus(200 * 1024)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.redactRequestBody(body)
	}
}

// BenchmarkColdSerialClaudeBody200KB isolates the algorithmic gain from the
// parallel scan by pinning the plugin to a single worker.
func BenchmarkColdSerialClaudeBody200KB(b *testing.B) {
	zero, one := 0, 1
	p := newTestPlugin(b, func(c *privacyFilterConfig) {
		c.CacheEntries = &zero
		c.Workers = &one
	})
	body := buildClaudeCorpus(200 * 1024)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.redactRequestBody(body)
	}
}

// BenchmarkWarmClaudeBody200KB is the steady state of a real session: the turn
// before already scanned every message except the newest.
func BenchmarkWarmClaudeBody200KB(b *testing.B) {
	p := newTestPlugin(b)
	body := buildClaudeCorpus(200 * 1024)
	p.redactRequestBody(body)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.redactRequestBody(body)
	}
}

// BenchmarkCleanCodeBody200KB measures a body with no secrets at all, the
// common case.
func BenchmarkCleanCodeBody200KB(b *testing.B) {
	zero := 0
	p := newTestPlugin(b, func(c *privacyFilterConfig) { c.CacheEntries = &zero })
	body := buildCleanCorpus(200 * 1024)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.redactRequestBody(body)
	}
}

func BenchmarkLegacyCleanCodeBody200KB(b *testing.B) {
	p := newLegacyPlugin(b)
	body := buildCleanCorpus(200 * 1024)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.redactRequestBody(body)
	}
}

// BenchmarkUpstreamEngineFullCoverage200KB pairs the new walker with the
// upstream privacy-filter engine, so it measures only the engine change at
// identical coverage.
func BenchmarkUpstreamEngineFullCoverage200KB(b *testing.B) {
	f, err := filter.New("rules/gitleaks.toml")
	if err != nil {
		b.Fatal(err)
	}
	body := buildClaudeCorpus(200 * 1024)
	refs := collectTexts(body, walkOptions{ScanToolInput: true})
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range refs {
			f.Redact(refs[j].value)
		}
	}
}
