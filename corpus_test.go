package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

// TestMain keeps the plugin's own logging out of test and benchmark output.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// buildClaudeCorpus produces a Claude Messages request body that looks like a
// mid-session Claude Code turn: a large system prompt, a long tool-heavy
// history of code, diffs and logs, and a handful of real secrets sprinkled in.
// approxBytes is the target size of the serialized body.
func buildClaudeCorpus(approxBytes int) []byte {
	return buildCorpus(approxBytes, true)
}

// buildCleanCorpus is the same shape with no secrets in it: the common case.
func buildCleanCorpus(approxBytes int) []byte {
	return buildCorpus(approxBytes, false)
}

func buildCorpus(approxBytes int, withSecrets bool) []byte {
	codeChunk := strings.Join([]string{
		"func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) error {",
		"\tctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)",
		"\tdefer cancel()",
		"\tobj, err := s.store.Put(ctx, r.Body, r.ContentLength)",
		"\tif err != nil { return fmt.Errorf(\"put object: %w\", err) }",
		"\tlog.Printf(\"stored object id=%s size=%d etag=%s\", obj.ID, obj.Size, obj.ETag)",
		"\treturn json.NewEncoder(w).Encode(map[string]any{\"id\": obj.ID, \"url\": obj.URL})",
		"}",
		"",
		"diff --git a/internal/store/s3.go b/internal/store/s3.go",
		"@@ -118,7 +118,7 @@ func (c *Client) Put(ctx context.Context, r io.Reader, n int64) (*Object, error)",
		"-\tuploader := manager.NewUploader(c.api, func(u *manager.Uploader) { u.PartSize = 8 << 20 })",
		"+\tuploader := manager.NewUploader(c.api, func(u *manager.Uploader) { u.PartSize = 16 << 20 })",
		"",
		"2026-09-09T11:04:12.881Z INFO  scheduler: lease acquired holder=worker-7 generation=41822",
		"2026-09-09T11:04:12.902Z DEBUG http: GET /v1/objects/9f2c1ad4 200 in 12.4ms",
		"2026-09-09T11:04:13.114Z WARN  retry: attempt 2/5 backoff=800ms reason=connection reset by peer",
	}, "\n")

	secrets := []string{
		"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"github token: ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37",
		"my email is dev.lead@example.com, call me at 13800138000",
	}

	var messages []any
	messages = append(messages, map[string]any{
		"role": "user",
		"content": []any{
			map[string]any{"type": "text", "text": "Refactor the uploader so retries are bounded.\n" + codeChunk},
		},
	})

	size := 0
	i := 0
	for size < approxBytes {
		text := fmt.Sprintf("turn %d\n%s\n%s\n", i, codeChunk, codeChunk)
		if withSecrets && i%17 == 3 {
			text += secrets[(i/17)%len(secrets)] + "\n"
		}
		messages = append(messages, map[string]any{
			"role": "assistant",
			"content": []any{
				map[string]any{"type": "text", "text": "Looking at the uploader now."},
				map[string]any{
					"type": "tool_use",
					"id":   fmt.Sprintf("toolu_%02d", i),
					"name": "Read",
					"input": map[string]any{
						"file_path": "/home/dev/project/internal/store/s3.go",
					},
				},
			},
		})
		messages = append(messages, map[string]any{
			"role": "user",
			"content": []any{
				map[string]any{
					"type":        "tool_result",
					"tool_use_id": fmt.Sprintf("toolu_%02d", i),
					"content": []any{
						map[string]any{"type": "text", "text": text},
					},
				},
			},
		})
		size += len(text) + 200
		i++
	}

	payload := map[string]any{
		"model":      "claude-sonnet-5",
		"max_tokens": 32000,
		"stream":     true,
		"system": []any{
			map[string]any{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude.\n" + codeChunk},
		},
		"messages": messages,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return raw
}

// TestCoverageAgainstLegacy documents the coverage gap the rewrite closes: the
// v0.2.0 walker only reached messages[].content[].text, so the bulk of a
// coding-agent turn (tool results, tool arguments, the system prompt) was never
// scanned at all.
func TestCoverageAgainstLegacy(t *testing.T) {
	body := buildClaudeCorpus(200 * 1024)

	legacy := newLegacyPlugin(t)
	_, legacyScanned := legacy.redactRequestBody(body)

	p := newTestPlugin(t)
	out, stats, _ := p.redactRequestBody(body)

	t.Logf("body=%d bytes, legacy scanned=%d bytes, current scanned=%d bytes in %d fields",
		len(body), legacyScanned, stats.scanned, stats.fields)
	if stats.scanned < legacyScanned*4 {
		t.Fatalf("expected the rewrite to cover far more text: legacy=%d current=%d", legacyScanned, stats.scanned)
	}
	if out == nil {
		t.Fatal("expected the corpus secrets to be redacted")
	}
	if bytes.Contains(out, []byte("ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37")) {
		t.Fatal("a github token inside a tool_result survived")
	}
	if bytes.Contains(out, []byte("dev.lead@example.com")) {
		t.Fatal("an email inside a tool_result survived")
	}
}
