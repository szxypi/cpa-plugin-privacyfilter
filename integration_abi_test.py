#!/usr/bin/env python3
"""Exercise the compiled privacy filter plugin through CPA's public C ABI."""

import base64
import ctypes
import json
import pathlib
import sys
import tempfile


class Buffer(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]


PluginCall = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(Buffer),
)
PluginFree = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
PluginShutdown = ctypes.CFUNCTYPE(None)


class HostAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("host_ctx", ctypes.c_void_p),
        ("call", ctypes.c_void_p),
        ("free_buffer", ctypes.c_void_p),
    ]


class PluginAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("call", PluginCall),
        ("free_buffer", PluginFree),
        ("shutdown", PluginShutdown),
    ]


def invoke(plugin: PluginAPI, method: str, request: dict) -> dict:
    encoded = json.dumps(request, separators=(",", ":")).encode()
    request_buffer = (ctypes.c_uint8 * max(1, len(encoded))).from_buffer_copy(
        encoded or b"\0"
    )
    response = Buffer()
    rc = plugin.call(
        method.encode(), request_buffer, len(encoded), ctypes.byref(response)
    )
    try:
        raw = ctypes.string_at(response.ptr, response.len) if response.ptr else b""
    finally:
        if response.ptr:
            plugin.free_buffer(response.ptr, response.len)
    decoded = json.loads(raw)
    if rc != 0 or not decoded.get("ok"):
        raise RuntimeError(f"{method} failed: rc={rc}, response={decoded}")
    return decoded["result"]


SECRET_TOKEN = "ghp_016C7869C1AE4A4EBFDEE0A1CBF9C8B0EF37"
SECRET_EMAIL = "dev.lead@example.com"

CLAUDE_BODY = json.dumps(
    {
        "model": "claude-sonnet-5",
        "max_tokens": 4096,
        "system": [{"type": "text", "text": "You are Claude Code."}],
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_01ABCDEF",
                        "name": "Read",
                        "input": {"file_path": "/srv/app/.env"},
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01ABCDEF",
                        "content": [
                            {
                                "type": "text",
                                "text": f"GITHUB_TOKEN={SECRET_TOKEN}\nOWNER={SECRET_EMAIL}\n",
                            }
                        ],
                    }
                ],
            },
        ],
    },
    separators=(",", ":"),
).encode()

GEMINI_BODY = json.dumps(
    {
        "contents": [
            {"role": "user", "parts": [{"text": f"push with {SECRET_TOKEN}"}]}
        ]
    },
    separators=(",", ":"),
).encode()


def intercept(plugin: PluginAPI, method: str, body: bytes, model: str = "claude-sonnet-5") -> bytes | None:
    result = invoke(
        plugin,
        method,
        {
            "RequestID": "req-1",
            "TraceID": "trace-1",
            "SourceFormat": "claude",
            "ToFormat": "claude",
            "Model": model,
            "RequestedModel": model,
            "Stream": True,
            "Headers": {},
            "Body": base64.b64encode(body).decode(),
            "Metadata": {},
            "host_callback_id": "",
        },
    )
    encoded = result.get("Body")
    if not encoded:
        return None
    return base64.b64decode(encoded)


def main() -> None:
    library_path = pathlib.Path(sys.argv[1]).resolve()
    library = ctypes.CDLL(str(library_path))
    init = library.cliproxy_plugin_init
    init.argtypes = [ctypes.POINTER(HostAPI), ctypes.POINTER(PluginAPI)]
    init.restype = ctypes.c_int

    host = HostAPI(abi_version=1)
    plugin = PluginAPI()
    if init(ctypes.byref(host), ctypes.byref(plugin)) != 0:
        raise RuntimeError("cliproxy_plugin_init failed")

    # An empty plugin dir forces the embedded gitleaks rules, which is how the
    # library is actually deployed.
    plugin_dir = tempfile.mkdtemp(prefix="privacyfilter-abi-")
    config = (
        "enabled: true\n"
        "priority: 1\n"
        "log_stats: true\n"
        "cache_entries: 64\n"
        "workers: 2\n"
    ).encode()

    try:
        registration = invoke(
            plugin,
            "plugin.register",
            {
                "config_yaml": base64.b64encode(config).decode(),
                "plugin_dir": plugin_dir,
            },
        )
        capabilities = registration["capabilities"]
        if not capabilities.get("request_interceptor"):
            raise AssertionError(f"unexpected capabilities: {capabilities}")
        metadata = registration["metadata"]
        for field in ("Name", "Version", "Author", "GitHubRepository"):
            if not metadata.get(field):
                raise AssertionError(f"required metadata field missing: {field}")
        if metadata["Name"] != "privacyfilter":
            raise AssertionError(f"unexpected plugin name: {metadata['Name']}")
        advertised = {field["Name"] for field in metadata["ConfigFields"]}
        expected = {
            "gitleaks_toml", "skip_models", "skip_formats", "disable_rules",
            "max_body_bytes", "scan_tool_input", "cache_entries", "cache_bytes",
            "workers", "log_stats",
        }
        if advertised != expected:
            raise AssertionError(f"config fields drifted: {sorted(advertised)}")

        # Before auth: the tool_result secrets must be gone and the structural
        # identifiers must survive byte for byte.
        redacted = intercept(plugin, "request.intercept_before", CLAUDE_BODY)
        if redacted is None:
            raise AssertionError("before-auth hook did not rewrite a body with secrets")
        text = redacted.decode()
        if SECRET_TOKEN in text or SECRET_EMAIL in text:
            raise AssertionError(f"secret survived redaction: {text}")
        if "[密钥]" not in text or "[邮箱]" not in text:
            raise AssertionError(f"placeholders missing: {text}")
        if '"tool_use_id":"toolu_01ABCDEF"' not in text:
            raise AssertionError("tool_use_id was not preserved")
        if '"model":"claude-sonnet-5","max_tokens":4096' not in text:
            raise AssertionError("untouched bytes were rewritten")
        parsed = json.loads(redacted)
        if parsed["messages"][0]["content"][0]["input"]["file_path"] != "/srv/app/.env":
            raise AssertionError("tool arguments were mangled")

        # After auth is a deliberate no-op: the payload there is a translation
        # of an already filtered body.
        if intercept(plugin, "request.intercept_after", CLAUDE_BODY) is not None:
            raise AssertionError("after-auth hook must not rewrite the body")

        # A clean body must pass through untouched (nil body on the wire).
        clean = json.dumps(
            {"model": "m", "messages": [{"role": "user", "content": "hello world"}]},
            separators=(",", ":"),
        ).encode()
        if intercept(plugin, "request.intercept_before", clean) is not None:
            raise AssertionError("a clean body must pass through unchanged")

        # Gemini shape.
        gemini = intercept(plugin, "request.intercept_before", GEMINI_BODY)
        if gemini is None or SECRET_TOKEN in gemini.decode():
            raise AssertionError("gemini contents were not filtered")

        # Reconfiguration must take effect: skip this model entirely.
        skip_config = (
            "enabled: true\n"
            "skip_models:\n"
            "  - claude-sonnet-5\n"
        ).encode()
        invoke(
            plugin,
            "plugin.reconfigure",
            {
                "config_yaml": base64.b64encode(skip_config).decode(),
                "plugin_dir": plugin_dir,
            },
        )
        if intercept(plugin, "request.intercept_before", CLAUDE_BODY) is not None:
            raise AssertionError("skip_models was not honoured after reconfigure")

        print(
            "ABI integration passed: "
            f"schema={registration['schema_version']}, plugin={metadata['Name']} "
            f"v{metadata['Version']}, body={len(CLAUDE_BODY)}->{len(redacted)} bytes"
        )
    finally:
        plugin.shutdown()


if __name__ == "__main__":
    main()
