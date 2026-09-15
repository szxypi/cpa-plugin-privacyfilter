# CPA Plugin Privacy Filter

English | [简体中文](README.zh-CN.md)

A native privacy filter plugin for CLIProxyAPI. Before a request is forwarded upstream it replaces keys, tokens,
passwords, emails, IP addresses and other sensitive values with placeholders, and it swaps the placeholders back to the
real values in the response. The values stay in the local CPA process; the model can still put them into commands,
code and configuration.

AI learners and builders can join the Linux.do community: [linux.do](https://linux.do/).

This project uses [packyme/privacy-filter](https://github.com/packyme/privacy-filter) for the core filtering logic and
adapts it to the CPA plugin ABI from [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).

## What It Does

When CLIProxyAPI receives a request, this plugin scans supported text fields before the request leaves the local
process and replaces every detected value with a deterministic placeholder such as `pf-key-3a7f9c21d0b4`. When the
model's reply (streamed text and tool-call arguments included) passes back through the plugin, placeholders are
restored to the real values.

Typical use cases:

- Prevent accidental leakage of API keys and tokens
- Remove personal contact information before sending prompts to models
- Apply Gitleaks-style secret detection to LLM traffic
- Keep filtering local to the CLIProxyAPI plugin pipeline

## v0.4.0: reversible replacement

Up to v0.3.0 values were replaced by fixed labels (`[密钥]`, `[邮箱]`). The model never had the value and wrote the
label into commands and config files, so coding-agent workflows kept failing. v0.4.0 makes the replacement reversible:

| Stage | Behaviour |
| --- | --- |
| Placeholder | `<prefix>-<type>-<12 hex>`, an HMAC of the value under a local key: the same value always renders the same placeholder, so replayed history keeps prompt caches warm. Types: `key`, `email`, `phone`, `idcard`, `ip`, `card`. A `uuid` style is available. |
| Mapping | Held in CPA process memory only (the vault), never written to disk. The only file is `data_dir/placeholder.key` (0600), which keeps placeholders stable across restarts. |
| Request | Detections are narrowed to the value itself (`GITHUB_TOKEN=ghp_...` replaces only `ghp_...`, the key name stays visible). A value that was detected once is replaced in any string of later bodies, including fields the detectors do not read and tool arguments with `scan_tool_input: false`; keys of 8+ bytes match without word boundaries, so `-p<password>` is covered. |
| Response | Non-streaming bodies are restored as JSON. Streams are handled per protocol, including the Responses WebSocket downstream Codex uses; a placeholder split across deltas is held back and flushed before the block ends. Values inside tool-call arguments (JSON text) are JSON-escaped. Only placeholders present in the request's upstream body are restored, so a provider cannot pull another conversation's value in by emitting its placeholder. |
| Not restored | `thinking`, `redacted_thinking`, `reasoning` and signatures are replayed verbatim by clients and signed by providers, so they keep their placeholders. |
| Notice | When a request carries placeholders and restoration is on, a short matter-of-fact note is appended to the system prompt telling the model to use references verbatim. Framing them as protected secrets made models refuse to use them. |

Why not UUIDs by default: a UUID costs about 24 tokens and models copy them noticeably less reliably than short ids
([boundaryml](https://boundaryml.com/blog/uuid-swap)); LLM Guard, llmasking-go and Kong's AI Sanitizer all use a type plus
a short id. The fixed prefix also lets the response side skip text without a placeholder at no cost.

Verified end to end: Claude Messages, OpenAI chat, OpenAI Responses and Gemini clients, against Claude and OpenAI
upstreams, streaming and not; the upstream never saw a clear value and clients got real values in text and tool
arguments. Real models (MiniMax-M3, DeepSeek) completed config-writing tasks through placeholders.

Known limits:

- The vault lives in memory and is empty after a CPA restart. Values are re-learned from the history of the next
  request, but a value whose recognisable context is gone (compacted away) may not be caught in a new context.
- The vault is not partitioned per client: a client that presents a known placeholder is treated as its owner. Do
  not rely on it for isolation between mutually untrusted users of one CPA.
- CPA 7.3.3's gemini->claude translator drops `systemInstruction`, so that combination gets no notice (replacement
  and restoration still work).

## Changes in This Fork (v0.3.0)

This fork (v0.3.0) is tuned for coding-agent traffic: Claude Code, Codex, opencode and antigravity send bodies of tens
of KB to several MB and replay the entire conversation on every turn. [CHANGELOG.md](CHANGELOG.md) has the full list
and the benchmark numbers; the short version:

- **Coverage.** Upstream only walked `messages[].content[].text`. On a 229KB Claude Code turn that reached 3.6KB, 1.6%
  of the body: `tool_result` output, `tool_use` arguments, the `system` prompt, Responses `input` items and every
  Gemini field were forwarded unfiltered. This fork covers Claude Messages, OpenAI chat completions, OpenAI Responses
  and Gemini `generateContent`, and scans 197KB of the same body.
- **One hook, not two.** Upstream ran the same redaction in both the before-auth and after-auth interceptor hooks. The
  after-auth payload is a format translation of the before-auth payload, so the second pass can find nothing new — it
  just doubled the cost, and repeated on every retry. Only the before-auth hook filters now.
- **Byte-exact rewrites.** Upstream re-marshalled the whole body, which reorders keys and re-escapes strings even in
  untouched messages. This fork splices only the changed string literals into the original bytes, so prompt caching and
  provider signatures are not disturbed. Extended-thinking blocks are never edited.
- **A faster engine.** Detection moved to `internal/scan`: one Aho-Corasick pass replaces ~290 `strings.Contains`
  keyword probes, byte-class signals skip regex passes that provably cannot match, and the high-entropy fallback regex
  is computed by the prescan itself. Same matching semantics — `internal/scan/parity_test.go` diffs every result
  against the upstream library.
- **A content cache.** Scan results are memoised by SHA-256, so a session's replayed history is scanned once, not once
  per turn. Fields are scanned in parallel.
- New knobs: `disable_rules`, `max_body_bytes`, `scan_tool_input`, `cache_entries`, `cache_bytes`, `workers`,
  `log_stats`. Defaults keep the previous detection behaviour.

Measured on a Ryzen 9 5900X against a 229KB Claude Code turn: 117.0ms for the old engine at this coverage, 75.0ms
single-threaded with the new one, 21.5ms with the default four workers, and 2.1ms in the steady state of a session
where the cache already holds the replayed history.

## Features

- Request interceptor for the CLIProxyAPI plugin runtime
- Redacts emails, phone numbers, ID numbers, bank cards, IPs, secrets, connection strings, certificates and similar
- Uses built-in Gitleaks rules from `rules/gitleaks.toml`, embedded into the shared library
- Supports custom Gitleaks rule files and per-rule opt-out
- Handles Claude Messages, OpenAI chat completions, OpenAI Responses and Gemini request bodies
- Can skip filtering by model name, source format or body size
- Builds as a native shared library for Linux, macOS, and Windows

## Requirements

- Go 1.26+
- CGO enabled
- `make`

## Build

Clone and build the plugin:

```bash
git clone https://github.com/rheodev/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter

make build
```

The default build writes the shared library to the repository root:

- Linux: `privacyfilter.so`
- macOS: `privacyfilter.dylib`
- Windows: `privacyfilter.dll`

`make dist` writes the deployable artifact instead, named the way CPA derives plugin ids from file names, together with
its checksum:

```bash
make dist
# dist/privacyfilter-v0.4.0.so
# dist/privacyfilter-v0.4.0.so.sha256
```

Build for a specific platform:

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
GOOS=windows GOARCH=amd64 make build
```

Use `BUILD_DIR` to place `make build` output elsewhere:

```bash
BUILD_DIR=dist make build
```

## Use with CLIProxyAPI

Place the shared library in your CLIProxyAPI plugin directory. The gitleaks
rules are embedded in the binary, so no extra files are required:

```text
privacyfilter/
└── privacyfilter.so        # or privacyfilter.dylib / privacyfilter.dll
```

Then enable the `privacyfilter` plugin in CLIProxyAPI.

Plugin metadata:

- Name: `privacyfilter`
- Capabilities: `RequestInterceptor` (before-auth hook only), `ResponseInterceptor`, `StreamChunkInterceptor`, `RequestLifecyclePlugin`
- Author: `rheodev, szxypi`

### Local install (systemd deployment)

`ops/deploy` installs the artifact into a CPA instance that runs as the `cliproxy` service user, removes older
versions of the library, restarts the service and waits for the registration line in the journal:

```bash
make dist
sudo ops/deploy            # or: sudo ops/deploy 0.4.0
```

It expects the layout used by a native systemd install:

- library directory `/var/lib/cli-proxy-api/plugins/linux/amd64/`
- config `/var/lib/cli-proxy-api/config.yaml`
- unit `cli-proxy-api.service`

CPA derives the plugin id from the file name (`privacyfilter-v0.4.0.so` -> `privacyfilter`) and ignores any library
with no matching `plugins.configs` entry, so the config entry must exist before the restart. `ops/deploy` refuses to
run without one. Edit `config.yaml` in place; replacing it by rename detaches CPA's config watcher from the file.

## Configuration

The plugin is configured inside CLIProxyAPI's main config file (`config.yaml`).
Under `plugins.configs.<id>`, the host-owned fields (`enabled`, `priority`) are
consumed by CLIProxyAPI, and the remaining YAML subtree is passed to the plugin
verbatim.

Recommended starting point:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      priority: 10
      # Bodies above this are forwarded unscanned; -1 disables the limit.
      max_body_bytes: 4194304
      # Scan tool-call arguments and tool results, not just message text.
      scan_tool_input: true
      # Remember scanned text between turns; agents replay the whole history.
      cache_entries: 4096
      cache_bytes: 67108864
      workers: 4
      # Uncomment to trade the noisiest, slowest gitleaks rule for ~60% of the
      # scan time. Everything else in the rule set stays active.
      # disable_rules:
      #   - generic-api-key
      # log_stats: true
```

Plugin fields:

| Field             | Type    | Default    | Description                                                                                   |
|-------------------|---------|------------|-----------------------------------------------------------------------------------------------|
| `gitleaks_toml`   | string  | `""`       | Custom gitleaks rule file path. Relative paths are resolved from the plugin directory.        |
| `skip_models`     | array   | `[]`       | Models that should skip redaction (matched against both the routed and the requested model).  |
| `skip_formats`    | array   | `[]`       | Source formats that should skip redaction.                                                    |
| `disable_rules`   | array   | `[]`       | Gitleaks rule ids to drop. `generic-api-key` is ~60% of scan time and most false positives.   |
| `max_body_bytes`  | integer | `4194304`  | Skip bodies larger than this. `-1` means no limit.                                            |
| `scan_tool_input` | boolean | `true`     | Include tool-call arguments and tool results.                                                 |
| `cache_entries`   | integer | `4096`     | Texts remembered between requests. `0` disables the cache.                                    |
| `cache_bytes`     | integer | `67108864` | Byte budget for cached redacted text.                                                         |
| `workers`         | integer | `4`        | Goroutines used to scan one request's fields, capped at `NumCPU`.                             |
| `log_stats`       | boolean | `false`    | Also log a debug line for clean requests. Redactions are always logged at info.               |

When `gitleaks_toml` is empty and no `rules/gitleaks.toml` sidecar file exists,
the plugin uses the rules embedded in the binary at build time.

## How It Works

The plugin runs on the before-auth request interception hook and rewrites the body in place:

1. Checks `skip_models`, `skip_formats` and `max_body_bytes`.
2. Validates the body as JSON and walks it with a format-aware collector.
3. Scans each collected text field, in parallel and through the content cache.
4. Splices the redacted string literals back into the original bytes; every other byte is copied verbatim.
5. Leaves the request untouched if the body is not JSON, holds no known field, or nothing matched.

The after-auth hook is a deliberate no-op: that payload is a format translation of the body already filtered before
auth, so scanning it again costs a full pass per attempt and can find nothing new.

Fields that are scanned:

| Format | Fields |
| --- | --- |
| Claude Messages | `system` (string or blocks), `messages[].content` (string or blocks), `text` blocks, `tool_result.content` (string, blocks or nested text), `tool_use.input` strings |
| OpenAI chat | `messages[].content` (string or parts), `tool_calls[].function.arguments`, `function_call.arguments` |
| OpenAI Responses | `instructions`, `input` (string or items), `input_text` / `output_text` parts, `function_call_output.output` |
| Gemini | `contents[].parts[].text`, `systemInstruction` / `system_instruction`, `functionCall.args`, `functionResponse.response` |

Fields that are deliberately skipped: `thinking`, `redacted_thinking` and `reasoning` blocks (they carry a provider
signature and must be replayed verbatim), inline base64 (images, audio, files), and structural identifiers such as
`tool_use_id`, ids, roles and model names.

Supported request shapes include:

```json
{
  "model": "claude-sonnet-5",
  "system": [{"type": "text", "text": "You are Claude Code."}],
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "tool_result", "tool_use_id": "toolu_01", "content": [{"type": "text", "text": "GITHUB_TOKEN=ghp_xxx"}]}
      ]
    }
  ]
}
```

```json
{
  "model": "gpt-5",
  "input": "My GitHub token is ghp_xxx"
}
```

## Rules

Built-in rules are embedded into the shared library at build time from:

```text
rules/gitleaks.toml
```

At runtime the plugin resolves rules in this order:

1. `gitleaks_toml` config value, if set
2. `rules/gitleaks.toml` sidecar next to the shared library
3. The rules embedded at build time (default)

Update embedded rules and rebuild:

```bash
make update-rules
make build
```

You can also set `gitleaks_toml` to use your own rule file:

```yaml
gitleaks_toml: custom/gitleaks.toml
```

Relative paths are resolved from the plugin directory.

## Development

Common commands:

```bash
make test                                   # go vet ./... && go test ./...
make bench                                  # every benchmark, 10 iterations
make dist                                   # dist/privacyfilter-v<version>.so + .sha256
python3 integration_abi_test.py dist/privacyfilter-v0.4.0.so
```

`integration_abi_test.py` loads the compiled library through the real C ABI (`cliproxy_plugin_init`, `plugin.register`,
`request.intercept_before`, `request.intercept_after`, `plugin.reconfigure`) and asserts the redaction, the byte-exact
rewrite and the after-auth no-op.

Main files:

```text
main.go                       Plugin metadata and build entry
abi.go                        CLIProxyAPI plugin ABI adapter
interceptor.go                Hook wiring, parallel scan, stats
payload.go                    Format-aware JSON walk and byte-exact splice
config.go                     YAML configuration and rule loading
internal/scan/scan.go         Scanner, prescan, redaction
internal/scan/ac.go           Aho-Corasick keyword automaton
internal/scan/detect.go       Detection logic ported from packyme/privacy-filter
internal/scan/rules.go        Gitleaks rule loading
internal/scan/cache.go        Content cache
rules/gitleaks.toml           Built-in detection rules
ops/deploy                    Local systemd install
```

Dependency note:

```text
privacyfilter => github.com/packyme/privacy-filter   # parity oracle in tests
```

## Credits

- Core filtering logic: [packyme/privacy-filter](https://github.com/packyme/privacy-filter)
- Plugin runtime: [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
