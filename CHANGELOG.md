# Changelog

## 0.4.0

Reversible replacement. Sensitive values are replaced by placeholders on the way upstream and restored on the way
back, so coding agents can keep using keys, passwords and addresses without the provider ever seeing them.

### Changed

- Placeholders are `pf-<type>-<12 hex>` (or a v8 UUID with `placeholder_style: uuid`), derived by HMAC-SHA256 from the
  value under a key stored in `data_dir/placeholder.key`. Same value, same placeholder, across requests and restarts.
- The placeholder -> value table (vault) is process memory only, bounded by `vault_max_entries`.
- Detections are narrowed to the value: rule matches without a `secretGroup` use their first capture group (with the
  rule's entropy re-checked on it), and `NAME=value` token runs drop the name. Context-sentence matches that look like
  code (`os.getenv(`, `config.auth.token`, `null`) and loopback / netmask IPs are no longer replaced.
- Known values are replaced again wherever they appear on a word boundary (`literal_min_bytes`), so a value restored
  into a command does not go upstream in clear text on the next turn.
- The detection cache stores offsets instead of redacted text.
- New config: `placeholder_style`, `placeholder_prefix`, `restore_responses`, `notice`, `skip_types`, `data_dir`,
  `vault_max_entries`, `literal_min_bytes`. Config field descriptions are in Chinese.

### Added

- `ResponseInterceptor`: restores non-streaming responses, skipping thinking / reasoning content and signatures.
- `StreamChunkInterceptor`: per-protocol delta restoration for Claude, OpenAI chat, OpenAI Responses and Gemini
  streams, with hold-back of placeholder prefixes split across deltas and JSON escaping inside tool arguments.
  Requests without placeholders are answered in the ABI layer without decoding the chunk.
- `RequestLifecyclePlugin`: drops per-request state when the request completes.
- A system-prompt notice (`notice`) when a request carries placeholders.
- `roundtrip_test.go` covers determinism, the literal pass, byte-stable history replay, every stream protocol and
  notice injection; `integration_abi_test.py` exercises the new ABI methods.

## 0.3.0

This release is a fork-local rework aimed at coding-agent traffic (Claude Code,
Codex, opencode, antigravity): bodies of tens of KB to several MB where the
whole conversation is replayed on every turn.

### Fixed

- **Most of a request was never scanned.** The walker only reached
  `messages[].content` and `messages[].content[].text`, so Claude
  `tool_result` bodies, `tool_use` arguments, the `system` prompt, OpenAI
  Responses `input` items, `instructions`, tool-call arguments and every Gemini
  field went to the provider unfiltered. On a 229KB Claude Code turn the old
  walker scanned 3.6KB (1.6%); the new one scans 197KB (86%, the remainder
  being JSON structure, ids and numbers). Coverage now includes Claude
  Messages, OpenAI chat completions, OpenAI Responses and Gemini
  generateContent.
- **Every request was filtered twice.** The plugin implemented both the
  before-auth and after-auth interceptor hooks with the same body-rewriting
  logic. The after-auth payload is a format translation of the before-auth
  payload, so the second pass could never find anything new, and it repeated on
  every retry / credential switch. Only the before-auth hook redacts now; the
  after-auth ABI entry point returns immediately without even decoding the
  request envelope.
- **Rewriting the body reordered and re-escaped every field.** The old path ran
  `json.Unmarshal` into `map[string]any` and re-marshalled, which reorders keys,
  re-escapes strings and drops the original formatting. That changes bytes the
  provider may hash (prompt caching) even for untouched messages. The rewrite
  now splices only the changed string literals into the original bytes.
- Extended-thinking blocks (`thinking`, `redacted_thinking`, `reasoning`) are
  no longer candidates for redaction: they carry a provider signature and must
  be replayed verbatim.
- Base64 blobs (inline images, audio, files) are skipped instead of being run
  through 200 regexes.
- The embedded rule set no longer goes through a temporary file on disk on
  every load; it is parsed straight from memory.

### Changed

- Detection moved to `internal/scan`, a port of
  [packyme/privacy-filter](https://github.com/packyme/privacy-filter) with
  identical matching semantics. `internal/scan/parity_test.go` diffs it against
  the upstream library over ~440 samples (upstream's own regression fixtures,
  hand-written cases for every detector, and pseudo-random noise) on every test
  run, with both the gitleaks and the built-in rule sets.
  - one Aho-Corasick pass over the text replaces ~290 `strings.Contains`
    keyword probes (10.8ms -> 0.55ms per 200KB) and allocates no lower-cased
    copy of the body;
  - the same pass derives byte-class signals that skip whole regex passes when
    they provably cannot match: `@` for email, digit-run length for
    phone/ID-card/bank-card, a digit-dot-digit-dot chain for IPv4, and an
    assignment separator for the context-password rule;
  - the high-entropy fallback regex is gone: the prescan already produces the
    exact `[A-Za-z0-9+/=_-]{20,}` runs it would have found
    (`TestPrescanTokenRunsMatchRegex` pins the equivalence).
- Scan results are memoised by SHA-256 of the text (`cache_entries`,
  `cache_bytes`). Agents resend the whole history every turn, so in steady
  state only the new content is actually scanned. Clean texts are stored as a
  bare key, so the cache costs nothing for the common case.
- A request's fields are scanned in parallel (`workers`, default 4, capped at
  `NumCPU`) once there is more than 32KB to look at.
- Upgraded the CPA SDK from v7.1.70 to v7.2.155. The `request_interceptor` ABI
  is unchanged; `RequestInterceptRequest` gained `RequestID`/`TraceID` and
  `RequestInterceptResponse` gained the termination fields, both additive.
  Reported `schema_version` moves 1 -> 6, which only affects capabilities this
  plugin does not implement.

### Added

- `disable_rules`: drop gitleaks rules by id. `generic-api-key` alone is 60% of
  scan time and the biggest source of false positives.
- `max_body_bytes` (default 4MiB): bodies above this are forwarded unscanned.
- `scan_tool_input` (default true): include tool-call arguments and tool
  results.
- `cache_entries` / `cache_bytes` / `workers` / `log_stats`.
- `make dist` builds `dist/privacyfilter-v<version>.so` plus its `.sha256`.
- `ops/deploy` installs that artifact into a local CPA and restarts it.
- `integration_abi_test.py` drives the compiled library through the real C ABI.

### Benchmarks

`go test -run XXX -bench . -benchtime 20x ./...` on a Ryzen 9 5900X (24
threads), Go 1.26.0, gitleaks rule set (221 rules), against a synthetic 229KB
Claude Code turn (`buildClaudeCorpus`) holding code, diffs, logs, tool calls
and a few real secrets.

| Path | Time | Text actually scanned |
| --- | --- | --- |
| v0.2.0 pipeline | 3.0ms | 3.6KB (1.6% of the body) |
| v0.2.0 engine, v0.3.0 coverage, serial | 117.0ms | 197KB |
| v0.3.0, serial (`workers: 1`) | 75.0ms | 197KB |
| v0.3.0, default (`workers: 4`) | 21.5ms | 197KB |
| v0.3.0, warm cache (steady state of a session) | 2.1ms | 197KB |

Per 200KB of text, one field, single core:

| Case | v0.2.0 engine | v0.3.0 engine |
| --- | --- | --- |
| Source code and logs | 138.6ms | 83.1ms |
| Source code and logs, `disable_rules: [generic-api-key]` | - | 34.4ms |
| Prose | 89.4ms | 5.0ms |
| Keyword prescan alone | 10.8ms | 0.55ms |
| Text already scanned once (cache hit) | - | 0.11ms |

## 0.2.0

- Embed the gitleaks rules into the shared library.

## 0.1.0

- Initial privacy filter CPA plugin.
