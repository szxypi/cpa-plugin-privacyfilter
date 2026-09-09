package scan

import (
	"fmt"
	"strings"
	"testing"

	upstream "privacyfilter/filter"
)

// benchText mimics the text side of a coding-agent turn: source code, a diff,
// logs, and the words ("token", "key", "api") that force gitleaks' generic
// rules to run.
func benchText(size int) string {
	var b strings.Builder
	i := 0
	for b.Len() < size {
		fmt.Fprintf(&b, "line %d: func (s *Store) Put(ctx context.Context, key string) error { return s.api.Upload(ctx, key, token) }\n", i)
		b.WriteString("2026-09-09T11:04:12.881Z INFO scheduler: lease acquired holder=worker-7 generation=41822\n")
		if i%40 == 0 {
			b.WriteString("export GITHUB_TOKEN=ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37\n")
		}
		i++
	}
	return b.String()
}

func BenchmarkScanUpstream200KB(b *testing.B) {
	f, err := upstream.New(rulesPath)
	if err != nil {
		b.Fatal(err)
	}
	text := benchText(200 * 1024)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Redact(text)
	}
}

func BenchmarkScanFast200KB(b *testing.B) {
	s := newTestScanner(b)
	text := benchText(200 * 1024)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Redact(text)
	}
}

func BenchmarkScanFastNoGeneric200KB(b *testing.B) {
	s := newTestScanner(b, "generic-api-key")
	text := benchText(200 * 1024)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Redact(text)
	}
}

func BenchmarkScanProse200KB(b *testing.B) {
	s := newTestScanner(b)
	text := strings.Repeat("The uploader retries with exponential backoff and gives up after five attempts. ", 2600)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Redact(text)
	}
}

func BenchmarkScanProseUpstream200KB(b *testing.B) {
	f, err := upstream.New(rulesPath)
	if err != nil {
		b.Fatal(err)
	}
	text := strings.Repeat("The uploader retries with exponential backoff and gives up after five attempts. ", 2600)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Redact(text)
	}
}

func BenchmarkPrescanOnly200KB(b *testing.B) {
	s := newTestScanner(b)
	text := benchText(200 * 1024)
	patHit := make([]bool, s.patterns)
	runs := make([]span, 0, 64)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clear(patHit)
		s.prescan(text, patHit, runs[:0])
	}
}
