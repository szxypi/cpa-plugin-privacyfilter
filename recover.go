package main

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

// Hook names used in recovered-panic log lines. They mirror the ABI method
// names the host calls, so a log line maps to one entry point.
const (
	hookRequestRedact = "request.intercept_before"
	hookRequestSerial = "request.intercept_before/serial"
	hookRequestWorker = "request.intercept_before/worker"
	hookResponseAfter = "response.intercept_after"
	hookResponseChunk = "response.intercept_stream_chunk"
	hookABI           = "abi.call"
)

// panicInjector is a test seam: tests set it to panic at a named stage so the
// recovery paths can be exercised. It is nil in production, and neither the
// config, the ABI nor a request payload can reach it.
var panicInjector func(stage string)

// Stages a test can make panic.
const (
	stageScanField    = "scan_field"
	stageRewriteField = "rewrite_field"
	stageResponse     = "response"
	stageStreamChunk  = "stream_chunk"
	// stageStreamChunkMerge panics after the chunk has been merged with the
	// withheld "event:" line, which is the window the held snapshot covers.
	stageStreamChunkMerge = "stream_chunk_merge"
	stageABI              = "abi"
)

func testPanic(stage string) {
	if panicInjector != nil {
		panicInjector(stage)
	}
}

// noField marks a log line that has no field index.
const noField = -1

// logRecoveredPanic records a recovered panic without leaking body content.
// It logs the hook name, the field index when the caller has one, the text
// length and a truncated panic value. No digest of the text is logged: a
// digest of a short, low-entropy value (a phone number, an ID card number) can
// be reversed by offline enumeration, which would leak the very content this
// plugin exists to hide. debug.Stack prints argument words (pointers and
// lengths), never string contents, and is capped here.
func logRecoveredPanic(hook string, field int, text string, recovered any) {
	if field >= 0 {
		log.Errorf("privacyfilter: recovered panic hook=%s field=%d len=%d panic=%s\n%s",
			hook, field, len(text), sanitizePanic(recovered), stackHead())
		return
	}
	log.Errorf("privacyfilter: recovered panic hook=%s len=%d panic=%s\n%s",
		hook, len(text), sanitizePanic(recovered), stackHead())
}

// sanitizePanic keeps a panic value short and printable. A panic value can be
// any value, including a string that carries body content, so it is cut down
// and stripped of control bytes.
func sanitizePanic(recovered any) string {
	const maxLen = 120
	value := fmt.Sprintf("%v", recovered)
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) > maxLen {
		value = value[:maxLen] + "..."
	}
	return value
}

// stackHead returns the top of the current stack, capped so one panic cannot
// flood the log.
func stackHead() string {
	const maxLen = 900
	stack := debug.Stack()
	if len(stack) > maxLen {
		return string(stack[:maxLen]) + "...(truncated)"
	}
	return string(stack)
}

// terminationBody is the client-visible answer when a request is refused.
var terminationBody = []byte(`{"error":{"type":"privacy_filter_unavailable","message":"the privacy filter failed to scan this request; refusing to forward it unscanned"}}`)

// terminateRequest builds the fail-closed request hook result. The host only
// stops the chain when the call succeeds and Terminate is set, so this must
// be returned with a nil error. StatusCode outside [200,599] falls back to
// 403 in the host, so 403 is set explicitly.
func terminateRequest() pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusForbidden,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    terminationBody,
	}
}
