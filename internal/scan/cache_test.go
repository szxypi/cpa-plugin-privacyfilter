package scan

import (
	"fmt"
	"strings"
	"testing"
)

func TestCacheReturnsIdenticalResults(t *testing.T) {
	s := newTestScanner(t)
	c := NewCache(64, 1<<20)
	for _, sample := range parityCorpus(t) {
		want := s.Redact(sample)
		for i := 0; i < 3; i++ {
			got := c.Redact(s, sample)
			if got.Redacted != want.Redacted || got.Hit != want.Hit || got.Count != want.Count {
				t.Fatalf("cached result differs for %q:\n want %q\n got  %q", sample, want.Redacted, got.Redacted)
			}
		}
	}
	hits, misses, _ := c.Stats()
	if hits == 0 || misses == 0 {
		t.Fatalf("expected both hits and misses, got hits=%d misses=%d", hits, misses)
	}
}

func TestCacheEvictsByEntryCount(t *testing.T) {
	s := newTestScanner(t)
	c := NewCache(8, 1<<20)
	for i := 0; i < 50; i++ {
		c.Redact(s, fmt.Sprintf("sample number %d with no secrets", i))
	}
	_, _, entries := c.Stats()
	if entries > 8 {
		t.Fatalf("cache grew past its limit: %d entries", entries)
	}
}

func TestCacheEvictsByBytes(t *testing.T) {
	s := newTestScanner(t)
	c := NewCache(1000, 4096)
	for i := 0; i < 200; i++ {
		text := fmt.Sprintf("run %d ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37 %s", i, strings.Repeat("x", 200))
		if got := c.Redact(s, text); !got.Hit {
			t.Fatalf("expected a hit for %q", text)
		}
	}
	c.mu.Lock()
	bytes := c.bytes
	c.mu.Unlock()
	if bytes > 4096 {
		t.Fatalf("cache byte budget exceeded: %d", bytes)
	}
}

func TestNilCacheStillScans(t *testing.T) {
	s := newTestScanner(t)
	var c *Cache
	got := c.Redact(s, "token: ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37")
	if !got.Hit {
		t.Fatal("nil cache must still redact")
	}
}

func BenchmarkCachedRepeatBody(b *testing.B) {
	s := newTestScanner(b)
	c := NewCache(256, 32<<20)
	text := benchText(200 * 1024)
	c.Redact(s, text)
	b.SetBytes(int64(len(text)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Redact(s, text)
	}
}
