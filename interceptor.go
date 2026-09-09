package main

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/scan"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type privacyFilterPlugin struct {
	cfg       privacyFilterConfig
	pluginDir string
	scanner   *scan.Scanner
	cache     *scan.Cache
}

var _ pluginapi.RequestInterceptor = (*privacyFilterPlugin)(nil)

func (p *privacyFilterPlugin) Identifier() string {
	return privacyFilterProvider
}

// InterceptRequestBeforeAuth is the only hook that redacts.
//
// CPA runs request interceptors twice: once on the client's payload before a
// credential is picked, and once per execution attempt on the translated
// upstream payload. The after-auth body is derived from the before-auth body
// by format translation, so it can hold no secret the before-auth body did not
// already hold. Filtering there as well would scan every byte a second time
// (and once more per retry), for a body whose contents are already clean.
// Redacting before auth also means the redaction propagates into the
// translated payload and into opts.OriginalRequest, which is what response
// interceptors and loggers see.
func (p *privacyFilterPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(req)
}

// InterceptRequestAfterAuth deliberately does nothing; see the note on
// InterceptRequestBeforeAuth.
func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return pluginapi.RequestInterceptResponse{}, nil
}

func (p *privacyFilterPlugin) interceptRequest(req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	resp := pluginapi.RequestInterceptResponse{}
	body := req.Body
	if len(body) == 0 {
		return resp, nil
	}
	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}
	if limit := p.cfg.maxBodyBytes(); limit > 0 && int64(len(body)) > limit {
		log.Warnf("privacyfilter: skipping %d byte body over max_body_bytes=%d (model=%s)", len(body), limit, req.Model)
		return resp, nil
	}

	modified, stats := p.redactRequestBody(body)
	p.logStats(req, stats)
	if modified != nil {
		resp.Body = modified
	}
	return resp, nil
}

// redactStats describes one pass over a request body.
type redactStats struct {
	fields      int
	scanned     int
	redacted    int
	entities    int
	labels      map[string]int
	elapsed     time.Duration
	cacheHits   uint64
	cacheMisses uint64
}

// redactRequestBody scans every model-visible text field and returns a rewritten
// body, or nil when nothing changed. The rewrite splices the changed string
// literals into the original bytes, so an untouched field keeps its exact
// original encoding.
func (p *privacyFilterPlugin) redactRequestBody(body []byte) ([]byte, redactStats) {
	started := time.Now()
	stats := redactStats{}
	hitsBefore, missesBefore, _ := p.cache.Stats()

	refs := collectTexts(body, walkOptions{ScanToolInput: p.cfg.scanToolInput()})
	if len(refs) == 0 {
		stats.elapsed = time.Since(started)
		return nil, stats
	}
	stats.fields = len(refs)

	results := make([]scan.Result, len(refs))
	total := 0
	for i := range refs {
		total += len(refs[i].value)
	}
	stats.scanned = total

	p.scanFields(refs, results, total)

	edits := make([]edit, 0, 8)
	for i := range results {
		if !results[i].Hit {
			continue
		}
		stats.redacted++
		stats.entities += results[i].Count
		if stats.labels == nil {
			stats.labels = make(map[string]int, 4)
		}
		for label, count := range results[i].Labels {
			stats.labels[label] += count
		}
		edits = append(edits, edit{
			index:       refs[i].index,
			rawLen:      len(refs[i].raw),
			replacement: appendJSONString(make([]byte, 0, len(results[i].Redacted)+8), results[i].Redacted),
		})
	}
	hitsAfter, missesAfter, _ := p.cache.Stats()
	stats.cacheHits = hitsAfter - hitsBefore
	stats.cacheMisses = missesAfter - missesBefore

	if len(edits) == 0 {
		stats.elapsed = time.Since(started)
		return nil, stats
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].index < edits[j].index })
	out := spliceBody(body, edits)
	stats.elapsed = time.Since(started)
	if out == nil {
		log.Warnf("privacyfilter: refused to rewrite a body with overlapping edits (%d fields)", len(edits))
		return nil, stats
	}
	return out, stats
}

// parallelScanThreshold is the amount of text below which the goroutine
// hand-off costs more than it saves.
const parallelScanThreshold = 32 * 1024

func (p *privacyFilterPlugin) scanFields(refs []textRef, results []scan.Result, total int) {
	workers := p.cfg.workers()
	if workers <= 1 || len(refs) < 2 || total < parallelScanThreshold {
		for i := range refs {
			results[i] = p.cache.Redact(p.scanner, refs[i].value)
		}
		return
	}
	if workers > len(refs) {
		workers = len(refs)
	}
	var next int64 = -1
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&next, 1))
				if i >= len(refs) {
					return
				}
				results[i] = p.cache.Redact(p.scanner, refs[i].value)
			}
		}()
	}
	wg.Wait()
}

func (p *privacyFilterPlugin) logStats(req pluginapi.RequestInterceptRequest, stats redactStats) {
	if stats.redacted == 0 {
		// The hot path is a clean request: silent unless log_stats asked for
		// the numbers, and then only at debug level.
		if !p.cfg.LogStats {
			return
		}
		log.Debugf("privacyfilter: clean model=%s format=%s fields=%d bytes=%d cache=%d/%d took=%s",
			req.Model, req.SourceFormat, stats.fields, stats.scanned,
			stats.cacheHits, stats.cacheHits+stats.cacheMisses, stats.elapsed)
		return
	}
	log.Infof("privacyfilter: redacted %d entities in %d/%d fields model=%s format=%s bytes=%d labels=%v cache=%d/%d took=%s",
		stats.entities, stats.redacted, stats.fields, req.Model, req.SourceFormat,
		stats.scanned, stats.labels, stats.cacheHits, stats.cacheHits+stats.cacheMisses, stats.elapsed)
}
