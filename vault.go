package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// vault maps sensitive values to placeholders and back. It lives in process
// memory only: values are never written to disk. Placeholders are an HMAC of
// the value under a key persisted next to CPA, so the same value renders the
// same placeholder across requests and restarts, which keeps provider prompt
// caches warm.
type vault struct {
	format     *placeholderFormat
	key        []byte
	maxEntries int
	minLiteral int

	mu            sync.RWMutex
	byValue       map[string]*vaultEntry
	byPlaceholder map[string]*vaultEntry

	// Literal index: every value at least minLiteral bytes long, bucketed by
	// its first four bytes, behind a 64-bit-word bloom-style bitset.
	buckets map[uint32][]*vaultEntry
	bits    []uint64
	indexed int
}

type vaultEntry struct {
	value       string
	placeholder string
	typ         string
	lastSeen    atomic.Int64
}

const vaultBitsLog2 = 16

func newVault(format *placeholderFormat, key []byte, maxEntries, minLiteral int) *vault {
	if minLiteral < 4 {
		minLiteral = 4
	}
	return &vault{
		format:        format,
		key:           key,
		maxEntries:    maxEntries,
		minLiteral:    minLiteral,
		byValue:       make(map[string]*vaultEntry, 256),
		byPlaceholder: make(map[string]*vaultEntry, 256),
		buckets:       make(map[uint32][]*vaultEntry, 256),
		bits:          make([]uint64, 1<<(vaultBitsLog2-6)),
	}
}

// loadOrCreateKey reads the HMAC key from dir, creating it on first use. The
// key only makes placeholders stable; losing it costs one prompt-cache miss
// per conversation, never a secret.
func loadOrCreateKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "placeholder.key")
	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) < 32 {
			return nil, fmt.Errorf("placeholder key %s is truncated", path)
		}
		return raw[:32], nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return loadOrCreateKey(dir) // lost a race with another loader
	}
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(key); err != nil {
		file.Close()
		return nil, err
	}
	return key, file.Close()
}

func ephemeralKey() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
}

// put returns the placeholder for value, registering it on first sight.
func (v *vault) put(value, typ string) string {
	now := time.Now().Unix()
	v.mu.RLock()
	if e := v.byValue[value]; e != nil {
		e.lastSeen.Store(now)
		v.mu.RUnlock()
		return e.placeholder
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	if e := v.byValue[value]; e != nil {
		e.lastSeen.Store(now)
		return e.placeholder
	}
	var placeholder string
	for salt := 0; ; salt++ {
		placeholder = v.format.render(v.key, value, typ, salt)
		if v.byPlaceholder[placeholder] == nil {
			break
		}
	}
	e := &vaultEntry{value: value, placeholder: placeholder, typ: typ}
	e.lastSeen.Store(now)
	v.byValue[value] = e
	v.byPlaceholder[placeholder] = e
	if len(value) >= v.minLiteral {
		k := binary.LittleEndian.Uint32([]byte(value[:4]))
		v.buckets[k] = append(v.buckets[k], e)
		h := bitHash(k)
		v.bits[h>>6] |= 1 << (h & 63)
		v.indexed++
	}
	if v.maxEntries > 0 && len(v.byValue) > v.maxEntries {
		v.evictLocked()
	}
	return placeholder
}

// lookup resolves a placeholder to its value.
func (v *vault) lookup(placeholder string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if e := v.byPlaceholder[placeholder]; e != nil {
		e.lastSeen.Store(time.Now().Unix())
		return e.value, true
	}
	return "", false
}

func (v *vault) size() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.byValue)
}

// evictLocked drops the least recently seen tenth of the entries.
func (v *vault) evictLocked() {
	entries := make([]*vaultEntry, 0, len(v.byValue))
	for _, e := range v.byValue {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].lastSeen.Load() < entries[j].lastSeen.Load() })
	drop := len(entries) - v.maxEntries + v.maxEntries/10
	for _, e := range entries[:min(drop, len(entries))] {
		delete(v.byValue, e.value)
		delete(v.byPlaceholder, e.placeholder)
		if len(e.value) >= v.minLiteral {
			k := binary.LittleEndian.Uint32([]byte(e.value[:4]))
			bucket := v.buckets[k]
			for i := range bucket {
				if bucket[i] == e {
					bucket = append(bucket[:i], bucket[i+1:]...)
					break
				}
			}
			if len(bucket) == 0 {
				delete(v.buckets, k)
			} else {
				v.buckets[k] = bucket
			}
			v.indexed--
		}
	}
	clear(v.bits)
	for k := range v.buckets {
		h := bitHash(k)
		v.bits[h>>6] |= 1 << (h & 63)
	}
}

func bitHash(k uint32) uint32 {
	return (k * 2654435761) >> (32 - vaultBitsLog2)
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// literalMatch is one occurrence of an already known value.
type literalMatch struct {
	start, end  int
	placeholder string
}

// hasLiterals reports whether any value is long enough for the literal pass.
func (v *vault) hasLiterals() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.indexed > 0
}

// literalBoundaryMin is the key length from which a literal match no longer
// needs word boundaries: the model writes `-p<placeholder>` or `Bearer<ph>`
// just as often as it writes the value on its own.
const literalBoundaryMin = 8

// literalMatches finds known values in text that the detectors did not flag
// here, e.g. a password the model wrote into a command after it was restored.
// Without this pass such a value would go upstream in clear text. Short
// values and structured types (IPs, phones, emails) must sit on word
// boundaries; matches never overlap skip (sorted, disjoint).
func (v *vault) literalMatches(text string, skip []interval, dst []literalMatch) []literalMatch {
	if len(text) < 4 {
		return dst
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.indexed == 0 {
		return dst
	}
	now := time.Now().Unix()
	next := 0 // index into skip
	for i := 0; i+4 <= len(text); i++ {
		for next < len(skip) && skip[next].end <= i {
			next++
		}
		if next < len(skip) && skip[next].start <= i {
			i = skip[next].end - 1
			continue
		}
		midWord := i > 0 && isWordByte(text[i-1]) && isWordByte(text[i])
		k := binary.LittleEndian.Uint32([]byte(text[i : i+4]))
		h := bitHash(k)
		if v.bits[h>>6]&(1<<(h&63)) == 0 {
			continue
		}
		var best *vaultEntry
		for _, e := range v.buckets[k] {
			n := len(e.value)
			if n > len(text)-i || text[i:i+n] != e.value {
				continue
			}
			end := i + n
			strict := e.typ != typeKey || n < literalBoundaryMin
			if strict && (midWord || end < len(text) && isWordByte(text[end]) && isWordByte(text[end-1])) {
				continue
			}
			if next < len(skip) && skip[next].start < end {
				continue
			}
			if best == nil || n > len(best.value) {
				best = e
			}
		}
		if best != nil {
			best.lastSeen.Store(now)
			dst = append(dst, literalMatch{start: i, end: i + len(best.value), placeholder: best.placeholder})
			i += len(best.value) - 1
		}
	}
	return dst
}
