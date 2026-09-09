package scan

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"unsafe"
)

// Cache memoises Redact results by content hash.
//
// Coding agents replay the entire conversation on every turn, so the same
// message text is re-sent dozens of times within one session. Hashing a body
// costs ~0.1ms per 200KB (SHA-NI) against tens of milliseconds of regex work,
// so the steady-state cost of a session collapses to whatever text is new.
//
// Clean texts (the overwhelming majority) are stored as a bare key: the
// redacted output is by definition the input, so nothing else is kept.
type Cache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int64
	// maxEntryBytes caps the size of a redacted string worth remembering.
	maxEntryBytes int

	entries map[[32]byte]*list.Element
	order   *list.List
	bytes   int64

	hits, misses uint64
}

type cacheEntry struct {
	key    [32]byte
	result Result
	size   int
}

// NewCache creates a cache holding at most maxEntries texts and maxBytes of
// redacted output. A non-positive maxEntries disables caching (NewCache
// returns nil, and a nil *Cache still answers Redact by scanning directly).
func NewCache(maxEntries int, maxBytes int64) *Cache {
	if maxEntries <= 0 {
		return nil
	}
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	return &Cache{
		maxEntries:    maxEntries,
		maxBytes:      maxBytes,
		maxEntryBytes: 1 << 20,
		entries:       make(map[[32]byte]*list.Element, maxEntries),
		order:         list.New(),
	}
}

// Redact returns the scanner's result for text, reusing a previous result when
// the exact same text was scanned before.
func (c *Cache) Redact(s *Scanner, text string) Result {
	if c == nil || text == "" {
		return s.Redact(text)
	}
	// sha256 neither retains nor mutates its input, so the string is hashed
	// in place instead of copying (a body field can be hundreds of KB).
	key := sha256.Sum256(unsafe.Slice(unsafe.StringData(text), len(text)))

	c.mu.Lock()
	if element, ok := c.entries[key]; ok {
		c.order.MoveToFront(element)
		entry := element.Value.(*cacheEntry)
		result := entry.result
		c.hits++
		c.mu.Unlock()
		if !result.Hit {
			// Clean texts are stored without a payload.
			result.Redacted = text
		}
		return result
	}
	c.misses++
	c.mu.Unlock()

	result := s.Redact(text)

	stored := result
	if !stored.Hit {
		stored.Redacted = ""
	} else if len(stored.Redacted) > c.maxEntryBytes {
		return result // too large to be worth remembering
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		return result // filled in concurrently
	}
	entry := &cacheEntry{key: key, result: stored, size: len(stored.Redacted)}
	c.entries[key] = c.order.PushFront(entry)
	c.bytes += int64(entry.size)
	for (len(c.entries) > c.maxEntries || c.bytes > c.maxBytes) && c.order.Len() > 0 {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		evicted := c.order.Remove(oldest).(*cacheEntry)
		delete(c.entries, evicted.key)
		c.bytes -= int64(evicted.size)
	}
	return result
}

// Stats reports cumulative hit and miss counts plus the current entry count.
func (c *Cache) Stats() (hits, misses uint64, entries int) {
	if c == nil {
		return 0, 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses, len(c.entries)
}
