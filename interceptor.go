package main

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type privacyFilterPlugin struct {
	cfg       privacyFilterConfig
	pluginDir string
	format    *placeholderFormat
	analyzer  *analyzer
	cache     *analysisCache
	vault     *vault
	states    *stateRegistry
	notice    string
}

var (
	_ pluginapi.RequestInterceptor     = (*privacyFilterPlugin)(nil)
	_ pluginapi.ResponseInterceptor    = (*privacyFilterPlugin)(nil)
	_ pluginapi.StreamChunkInterceptor = (*privacyFilterPlugin)(nil)
	_ pluginapi.RequestLifecyclePlugin = (*privacyFilterPlugin)(nil)
)

func (p *privacyFilterPlugin) Identifier() string {
	return privacyFilterProvider
}

// InterceptRequestBeforeAuth replaces sensitive values with placeholders.
//
// CPA runs request interceptors twice: once on the client's payload before a
// credential is picked, and once per execution attempt on the translated
// upstream payload. The after-auth body is derived from the before-auth body
// by format translation, so it can hold no value the before-auth body did not
// already hold. Replacing before auth also propagates into
// opts.OriginalRequest, which is what response hooks and loggers see.
func (p *privacyFilterPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(req)
}

// InterceptRequestAfterAuth deliberately does nothing; see
// InterceptRequestBeforeAuth.
func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return pluginapi.RequestInterceptResponse{}, nil
}

func (p *privacyFilterPlugin) interceptRequest(req pluginapi.RequestInterceptRequest) (resp pluginapi.RequestInterceptResponse, err error) {
	resp = pluginapi.RequestInterceptResponse{}
	body := req.Body
	if len(body) == 0 {
		return resp, nil
	}
	// Fail closed. The host ignores an error from a request hook and forwards
	// the original body, so a scan failure must be reported as Terminate, which
	// is the only result that stops the request. This defer covers the code
	// outside forEachField; panics inside a worker goroutine are recovered
	// there, because recover only works on the panicking goroutine.
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredPanic(hookRequestRedact, noField, string(body), recovered)
			resp, err = terminateRequest(), nil
		}
	}()
	// Every request gets a state, even an untouched one, so the response
	// hooks can tell "nothing to restore" from "never saw this request".
	st := &requestState{created: time.Now(), model: req.Model}
	defer p.states.put(req.RequestID, st)

	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}
	if limit := p.cfg.maxBodyBytes(); limit > 0 && int64(len(body)) > limit {
		log.Warnf("privacyfilter: skipping %d byte body over max_body_bytes=%d (model=%s)", len(body), limit, req.Model)
		return resp, nil
	}

	modified, stats, values := p.redactRequestBody(body)
	if stats.failed {
		// A field scan panicked. forEachField recovered it, so the body may be
		// half-processed; refuse the request instead of forwarding it.
		return terminateRequest(), nil
	}
	if len(values) > 0 && p.cfg.restoreResponses() {
		st.r = newRestorer(p.format, values)
	}
	if len(values) > 0 && p.notice != "" && p.cfg.restoreResponses() {
		base := body
		if modified != nil {
			base = modified
		}
		if withNotice := injectNotice(base, req.SourceFormat, p.notice); withNotice != nil {
			modified = withNotice
		}
	}
	p.logStats(req, stats, len(values))
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
	literals    int
	types       map[string]int
	elapsed     time.Duration
	cacheHits   uint64
	cacheMisses uint64
	// failed reports that a field scan panicked and was recovered. The caller
	// must not forward the body.
	failed bool
}

type fieldResult struct {
	text     string
	changed  bool
	entities int
	literals int
	values   map[string]string
	types    map[string]int
}

// redactRequestBody replaces sensitive values in every model-visible text
// field. It returns the rewritten body (nil when unchanged) and the
// placeholder -> value table of everything the rewritten body references.
func (p *privacyFilterPlugin) redactRequestBody(body []byte) (_ []byte, stats redactStats, _ map[string]string) {
	started := time.Now()
	hitsBefore, missesBefore := p.cache.stats()
	defer func() {
		hitsAfter, missesAfter := p.cache.stats()
		stats.cacheHits = hitsAfter - hitsBefore
		stats.cacheMisses = missesAfter - missesBefore
	}()

	values := p.existingPlaceholders(body)
	refs := collectTexts(body, walkOptions{ScanToolInput: p.cfg.scanToolInput()})
	if len(refs) == 0 && !p.vault.hasLiterals() {
		stats.elapsed = time.Since(started)
		return nil, stats, values
	}
	stats.fields = len(refs)
	for i := range refs {
		stats.scanned += len(refs[i].value)
	}

	fieldText := func(i int) string { return refs[i].value }

	// Phase 1 detects and registers every value, so phase 2's literal pass
	// catches a value detected in one field wherever it reappears in another.
	analyses := make([]textAnalysis, len(refs))
	if p.forEachField(len(refs), stats.scanned, fieldText, func(i int) {
		testPanic(stageScanField)
		analyses[i] = p.cache.get(p.analyzer, refs[i].value)
		text := refs[i].value
		for _, s := range analyses[i].secrets {
			p.vault.put(text[s.start:s.end], s.typ)
		}
	}) {
		stats.failed = true
		stats.elapsed = time.Since(started)
		return nil, stats, nil
	}

	if p.vault.hasLiterals() {
		seen := make(map[int]struct{}, len(refs))
		for i := range refs {
			seen[refs[i].index] = struct{}{}
		}
		for _, ref := range remainingStrings(body, seen, p.vault.minLiteral) {
			refs = append(refs, ref)
			analyses = append(analyses, textAnalysis{placeholders: findIntervals(p.format, ref.value)})
		}
	}
	results := make([]fieldResult, len(refs))
	if p.forEachField(len(refs), stats.scanned, fieldText, func(i int) {
		testPanic(stageRewriteField)
		results[i] = p.rewriteField(refs[i].value, analyses[i], refs[i].jsonText)
	}) {
		stats.failed = true
		stats.elapsed = time.Since(started)
		return nil, stats, nil
	}

	edits := make([]edit, 0, 8)
	for i := range results {
		result := &results[i]
		if !result.changed {
			continue
		}
		stats.redacted++
		stats.entities += result.entities
		stats.literals += result.literals
		for typ, n := range result.types {
			if stats.types == nil {
				stats.types = make(map[string]int, 4)
			}
			stats.types[typ] += n
		}
		if values == nil {
			values = make(map[string]string, len(result.values))
		}
		for placeholder, value := range result.values {
			values[placeholder] = value
		}
		edits = append(edits, edit{
			index:       refs[i].index,
			rawLen:      len(refs[i].raw),
			replacement: appendJSONString(make([]byte, 0, len(result.text)+8), result.text),
		})
	}
	stats.elapsed = time.Since(started)
	if len(edits) == 0 {
		return nil, stats, values
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].index < edits[j].index })
	out := spliceBody(body, edits)
	stats.elapsed = time.Since(started)
	if out == nil {
		log.Warnf("privacyfilter: refused to rewrite a body with overlapping edits (%d fields)", len(edits))
		return nil, stats, nil
	}
	return out, stats, values
}

// existingPlaceholders resolves placeholders a body already carries, e.g. inside
// replayed thinking blocks or when a routing plugin re-enters the pipeline.
// They join the request's restore table: a client that presents a placeholder
// is treated as its owner. The vault is not partitioned per client, so a CPA
// shared between mutually untrusted users must not rely on this for isolation.
func (p *privacyFilterPlugin) existingPlaceholders(body []byte) map[string]string {
	if !p.format.mayContainBytes(body) {
		return nil
	}
	var values map[string]string
	for _, loc := range p.format.re.FindAllIndex(body, -1) {
		placeholder := string(body[loc[0]:loc[1]])
		if value, ok := p.vault.lookup(placeholder); ok {
			if values == nil {
				values = make(map[string]string, 4)
			}
			values[placeholder] = value
		}
	}
	return values
}

func (p *privacyFilterPlugin) rewriteField(text string, analysis textAnalysis, jsonText bool) fieldResult {
	result := fieldResult{text: text}
	var reps []literalMatch
	var skip []interval
	if len(analysis.secrets) > 0 {
		reps = make([]literalMatch, 0, len(analysis.secrets)+2)
		skip = make([]interval, 0, len(analysis.secrets)+len(analysis.placeholders))
		result.types = make(map[string]int, 2)
		for _, s := range analysis.secrets {
			reps = append(reps, literalMatch{start: s.start, end: s.end, placeholder: p.vault.put(text[s.start:s.end], s.typ)})
			skip = append(skip, interval{s.start, s.end})
			result.types[s.typ]++
		}
		result.entities = len(analysis.secrets)
		skip = append(skip, analysis.placeholders...)
		sort.Slice(skip, func(i, j int) bool { return skip[i].start < skip[j].start })
	} else {
		skip = analysis.placeholders
	}
	before := len(reps)
	reps = p.vault.literalMatches(text, skip, reps)
	result.literals = len(reps) - before
	if len(reps) == 0 {
		return result
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].start < reps[j].start })

	var b strings.Builder
	b.Grow(len(text))
	result.values = make(map[string]string, len(reps))
	prev := 0
	for _, r := range reps {
		if r.start < prev {
			continue // defensive: literal matches never overlap secrets
		}
		b.WriteString(text[prev:r.start])
		if jsonText && bareJSONNumber(text, r.start, r.end) {
			// A bare number swapped for a placeholder would break the
			// arguments JSON; a string keeps it parseable.
			b.WriteByte('"')
			b.WriteString(r.placeholder)
			b.WriteByte('"')
		} else {
			b.WriteString(r.placeholder)
		}
		result.values[r.placeholder] = text[r.start:r.end]
		prev = r.end
	}
	b.WriteString(text[prev:])
	result.text = b.String()
	result.changed = true
	return result
}

// bareJSONNumber reports whether text[start:end] is a digit run that stands
// alone as a JSON value: after ':' '[' or ',' and before ',' '}' ']' or space.
func bareJSONNumber(text string, start, end int) bool {
	for i := start; i < end; i++ {
		if !isDigit(text[i]) {
			return false
		}
	}
	i := start - 1
	for i >= 0 && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
		i--
	}
	if i < 0 || (text[i] != ':' && text[i] != '[' && text[i] != ',') {
		return false
	}
	return end == len(text) || strings.IndexByte(",}] \t\r\n", text[end]) >= 0
}

// parallelScanThreshold is the amount of text below which the goroutine
// hand-off costs more than it saves.
const parallelScanThreshold = 32 * 1024

// forEachField runs fn over n fields, in this goroutine or across workers.
// A panic inside fn is recovered on the goroutine that raised it and reported
// through the return value; recover does not work across goroutines, so each
// worker carries its own recover. fieldText supplies the text of field i for
// the log line.
func (p *privacyFilterPlugin) forEachField(n, totalBytes int, fieldText func(i int) string, fn func(i int)) (failed bool) {
	run := func(i int, hook string) (ok bool) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logRecoveredPanic(hook, i, fieldText(i), recovered)
				ok = false
			}
		}()
		fn(i)
		return true
	}

	workers := p.cfg.workers()
	if workers <= 1 || n < 2 || totalBytes < parallelScanThreshold {
		for i := 0; i < n; i++ {
			if !run(i, hookRequestSerial) {
				return true
			}
		}
		return false
	}
	workers = min(workers, n)
	var next int64 = -1
	var failedFlag atomic.Bool
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				if failedFlag.Load() {
					return
				}
				i := int(atomic.AddInt64(&next, 1))
				if i >= n {
					return
				}
				if !run(i, hookRequestWorker) {
					failedFlag.Store(true)
					return
				}
			}
		}()
	}
	wg.Wait()
	return failedFlag.Load()
}

// InterceptResponse restores placeholders in a non-streaming response.
func (p *privacyFilterPlugin) InterceptResponse(ctx context.Context, req pluginapi.ResponseInterceptRequest) (resp pluginapi.ResponseInterceptResponse, err error) {
	resp = pluginapi.ResponseInterceptResponse{}
	if !p.cfg.restoreResponses() || len(req.Body) == 0 {
		return resp, nil
	}
	// A response-side failure only means "no restore". Returning the zero
	// response makes the host send the original body, so this path needs no
	// termination.
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredPanic(hookResponseAfter, noField, string(req.Body), recovered)
			resp = pluginapi.ResponseInterceptResponse{}
			err = nil
		}
	}()
	testPanic(stageResponse)
	st := p.states.take(req.RequestID)
	if st == nil {
		st = p.stateFromBody(req.OriginalRequest)
	}
	if st == nil || st.r == nil {
		return resp, nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	out, n := st.r.restoreJSON(req.Body)
	if out == nil && n == 0 && !startsWithJSON(req.Body) {
		// Some handlers answer a non-streaming call with an SSE transcript.
		out, _ = st.processChunk(req.SourceFormat, req.Body)
		n = st.restored
	}
	if n > 0 {
		log.Infof("privacyfilter: restored %d placeholders model=%s format=%s", n, req.Model, req.SourceFormat)
	}
	if out != nil {
		resp.Body = out
	}
	return resp, nil
}

func startsWithJSON(body []byte) bool {
	for _, c := range body {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// InterceptStreamChunk restores placeholders in a streamed response.
func (p *privacyFilterPlugin) InterceptStreamChunk(ctx context.Context, req pluginapi.StreamChunkInterceptRequest) (resp pluginapi.StreamChunkInterceptResponse, err error) {
	resp = pluginapi.StreamChunkInterceptResponse{}
	if !p.cfg.restoreResponses() {
		return resp, nil
	}
	// A response-side failure only means "no restore", so this chunk goes out
	// as it came in and DropChunk stays false. held is the bytes of an SSE
	// "event:" line withheld by an earlier call: processChunk consumes held
	// before it can panic, so the snapshot below is spliced back or that line
	// would be lost for good, including a response.completed event.
	//
	// Not recovered: each channel's ch.tail. It is a fragment of a JSON string
	// value, not raw chunk bytes, so it cannot be spliced back without the
	// event it belongs to. The loss is bounded by one placeholder prefix
	// length; the state is dropped below so no later chunk restores from it.
	var held []byte
	var st *requestState
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredPanic(hookResponseChunk, noField, string(req.Body), recovered)
			resp = pluginapi.StreamChunkInterceptResponse{}
			err = nil
			if st != nil {
				p.states.take(req.RequestID)
				if len(held) > 0 {
					resp.Body = joinHeld(held, req.Body)
				}
			}
		}
	}()
	testPanic(stageStreamChunk)
	st = p.states.get(req.RequestID)
	if req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
		if st == nil {
			if st = p.stateFromBody(req.OriginalRequest); st == nil {
				return resp, nil
			}
			p.states.put(req.RequestID, st)
		}
		// A bootstrap retry re-initialises the stream from scratch.
		st.mu.Lock()
		st.resetStream()
		st.mu.Unlock()
		return resp, nil
	}
	if st == nil || st.r == nil || len(req.Body) == 0 {
		return resp, nil
	}
	// Snapshot under the state lock: processChunk clears st.held as it merges.
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.held) > 0 {
		held = append([]byte(nil), st.held...)
	}
	out, drop := st.processChunk(req.SourceFormat, req.Body)
	testPanic(stageStreamChunkMerge)
	if drop {
		resp.DropChunk = true
		return resp, nil
	}
	if out != nil {
		resp.Body = out
	}
	return resp, nil
}

// joinHeld splices a withheld SSE line back in front of body, using the same
// separator processChunk uses when it merges held into the next chunk.
func joinHeld(held, body []byte) []byte {
	out := make([]byte, 0, len(held)+1+len(body))
	out = append(out, held...)
	if !bytes.HasSuffix(out, []byte("\n")) {
		out = append(out, '\n')
	}
	return append(out, body...)
}

// HandleRequestComplete forgets the request and reports what was restored.
func (p *privacyFilterPlugin) HandleRequestComplete(ctx context.Context, completion pluginapi.RequestCompletion) error {
	st := p.states.take(completion.RequestID)
	if st == nil || st.r == nil {
		return nil
	}
	st.mu.Lock()
	restored, pending, unknown := st.restored, 0, st.r.unknown
	for _, ch := range st.channels {
		if ch.tail != "" {
			pending++
		}
	}
	st.mu.Unlock()
	if restored > 0 || pending > 0 || unknown > 0 {
		log.Infof("privacyfilter: restored %d placeholders model=%s outcome=%s status=%d unflushed=%d unknown=%d",
			restored, completion.Model, completion.Outcome, completion.StatusCode, pending, unknown)
	}
	return nil
}

// stateFromBody rebuilds a request state from an already rewritten body, for
// executions whose before-auth hook this plugin instance did not see.
func (p *privacyFilterPlugin) stateFromBody(body []byte) *requestState {
	values := p.existingPlaceholders(body)
	if len(values) == 0 {
		return nil
	}
	return &requestState{created: time.Now(), r: newRestorer(p.format, values)}
}

func (p *privacyFilterPlugin) logStats(req pluginapi.RequestInterceptRequest, stats redactStats, placeholders int) {
	if stats.redacted == 0 {
		// The hot path is a clean request: silent unless log_stats asked for
		// the numbers, and then only at debug level.
		if !p.cfg.LogStats {
			return
		}
		log.Debugf("privacyfilter: clean model=%s format=%s fields=%d bytes=%d cache=%d/%d placeholders=%d took=%s",
			req.Model, req.SourceFormat, stats.fields, stats.scanned,
			stats.cacheHits, stats.cacheHits+stats.cacheMisses, placeholders, stats.elapsed)
		return
	}
	log.Infof("privacyfilter: replaced %d detected + %d known values in %d/%d fields model=%s format=%s bytes=%d types=%v placeholders=%d vault=%d cache=%d/%d took=%s",
		stats.entities, stats.literals, stats.redacted, stats.fields, req.Model, req.SourceFormat,
		stats.scanned, stats.types, placeholders, p.vault.size(),
		stats.cacheHits, stats.cacheHits+stats.cacheMisses, stats.elapsed)
}
