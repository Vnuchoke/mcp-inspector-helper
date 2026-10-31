#!/usr/bin/env python3
"""Export MCP servers from an OpenCode V2 JSON/JSONC config to MCP Inspector."""

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

REFERENCES = re.compile(r"\{(file|env):([^{}]+)\}")
SENSITIVE_ENV = re.compile(
    r"(?:TOKEN|PASSWORD|PASSWD|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY|"
    r"DATABASE_URI|DATABASE_URL|DSN|CREDENTIAL|AUTH)",
    re.IGNORECASE,
)


def load_jsonc(path: Path) -> dict:
    """Read JSON with // comments, /* */ comments and trailing commas."""
    raw = path.read_text(encoding="utf-8-sig")
    stripped = []
    i = 0
    quoted = False
    while i < len(raw):
        ch = raw[i]
        if quoted:
            stripped.append(ch)
            if ch == "\\" and i + 1 < len(raw):
                i += 1
                stripped.append(raw[i])
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            stripped.append(ch)
        elif raw.startswith("//", i):
            i += 2
            while i < len(raw) and raw[i] not in "\r\n":
                i += 1
            continue
        elif raw.startswith("/*", i):
            end = raw.find("*/", i + 2)
            if end < 0:
                raise ValueError("Unclosed /* comment */ in JSONC")
            stripped.append("\n" * raw[i:end + 2].count("\n"))
            i = end + 2
            continue
        else:
            stripped.append(ch)
        i += 1

    text = "".join(stripped)
    without_trailing = []
    quoted = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quoted:
            without_trailing.append(ch)
            if ch == "\\" and i + 1 < len(text):
                i += 1
                without_trailing.append(text[i])
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            without_trailing.append(ch)
        elif ch == ",":
            j = i + 1
            while j < len(text) and text[j].isspace():
                j += 1
            if j < len(text) and text[j] in "]}":
                i += 1
                continue
            without_trailing.append(ch)
        else:
            without_trailing.append(ch)
        i += 1

    result = json.loads("".join(without_trailing))
    if not isinstance(result, dict):
        raise ValueError("The OpenCode config root must be a JSON object")
    return result


def value_with_references(value: str, with_secrets: bool) -> str:
    if not with_secrets:
        return "" if REFERENCES.search(value) else value

    def replace(match: re.Match) -> str:
        kind, name = match.group(1), match.group(2)
        if kind == "env":
            if name not in os.environ:
                raise ValueError(f"Environment variable not set: {name}")
            return os.environ[name]
        file = Path(name).expanduser()
        return file.read_text(encoding="utf-8").rstrip("\r\n")

    return REFERENCES.sub(replace, value)


def convert_server(name: str, source: dict, with_secrets: bool) -> dict:
    kind = source.get("type")
    if kind == "local":
        command = source.get("command")
        if not isinstance(command, list) or not command or not all(
            isinstance(part, str) for part in command
        ):
            raise ValueError(f"{name}: 'command' must be a nonempty array of strings")
        dest = {"type": "stdio", "command": command[0], "args": command[1:]}
        if "cwd" in source:
            dest["cwd"] = source["cwd"]
        environment = source.get("environment", {})
        if not isinstance(environment, dict):
            raise ValueError(f"{name}: 'environment' must be an object")
        if environment:
            dest["env"] = {}
            for key, value in environment.items():
                if not isinstance(value, str):
                    raise ValueError(f"{name}: environment variable {key} must be a string")
                dest["env"][key] = (
                    value_with_references(value, True)
                    if with_secrets
                    else ("" if SENSITIVE_ENV.search(key) else value_with_references(value, False))
                )
    elif kind == "remote":
        url = source.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError(f"{name}: 'url' must be a nonempty string")
        dest = {"type": "http", "url": value_with_references(url, with_secrets)}
        headers = source.get("headers", {})
        if not isinstance(headers, dict):
            raise ValueError(f"{name}: 'headers' must be an object")
        if headers:
            if not all(isinstance(v, str) for v in headers.values()):
                raise ValueError(f"{name}: header values must be strings")
            # Header values can contain credentials under arbitrary names.
            dest["headers"] = {
                key: value_with_references(value, True) if with_secrets else ""
                for key, value in headers.items()
            }
    else:
        raise ValueError(f"{name}: unsupported server type {kind!r}")

    protocol = source.get("protocol", "legacy")
    if protocol not in ("legacy", "auto", "2026-07-28"):
        raise ValueError(f"{name}: unsupported protocol {protocol!r}")
    if protocol != "legacy":
        dest["protocolEra"] = "auto" if protocol == "auto" else "modern"

    timeout = source.get("timeout", {})
    if timeout:
        if not isinstance(timeout, dict):
            raise ValueError(f"{name}: timeout must be an object")
        for field, target in (("startup", "connectionTimeout"), ("execution", "requestTimeout")):
            if field in timeout:
                dest[target] = timeout[field]
        if "catalog" in timeout:
            print(f"Warning: {name}: catalog timeout has no exact Inspector equivalent", file=sys.stderr)

    oauth = source.get("oauth")
    if isinstance(oauth, dict):
        auth = {}
        for source_key, target_key in (("client_id", "clientId"), ("client_secret", "clientSecret"), ("scope", "scopes")):
            if source_key in oauth:
                field = oauth[source_key]
                if not isinstance(field, str):
                    raise ValueError(f"{name}: oauth.{source_key} must be a string")
                auth[target_key] = (
                    value_with_references(field, True)
                    if with_secrets or source_key != "client_secret" and not REFERENCES.search(field)
                    else ""
                )
        if auth:
            dest["oauth"] = auth
        unknown = set(oauth) - {"client_id", "client_secret", "scope"}
        if unknown:
            print(f"Warning: {name}: OAuth options not migrated: {', '.join(sorted(unknown))}", file=sys.stderr)
    elif oauth is False:
        print(f"Warning: {name}: oauth=false has no exact Inspector equivalent", file=sys.stderr)

    known = {"type", "command", "environment", "cwd", "url", "headers", "protocol", "timeout", "oauth", "disabled", "enabled", "codemode"}
    unknown = set(source) - known
    if unknown:
        print(f"Warning: {name}: unsupported options ignored: {', '.join(sorted(unknown))}", file=sys.stderr)
    return dest


def save_private_json(path: Path, document: dict, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Output already exists: {path}. Pass --force to replace it.")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(document, output, ensure_ascii=False, indent=2)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Path to opencode.json or opencode.jsonc")
    parser.add_argument("--output", type=Path, default=Path("~/.mcp-inspector/opencode-mcp.json"))
    parser.add_argument("--with-secrets", action="store_true", help="Resolve {file:...}/{env:...} and retain credentials")
    parser.add_argument("--include-disabled", action="store_true", help="Include disabled OpenCode servers (selectable in Inspector)")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file")
    args = parser.parse_args()

    if args.input is None:
        candidates = [Path("~/.config/opencode/opencode.jsonc"), Path("~/.config/opencode/opencode.json")]
        source_path = next((p.expanduser() for p in candidates if p.expanduser().is_file()), None)
        if source_path is None:
            parser.error("OpenCode config not found; pass --input /path/to/opencode.jsonc")
    else:
        source_path = args.input.expanduser()

    config = load_jsonc(source_path)
    mcp = config.get("mcp")
    if not isinstance(mcp, dict) or not isinstance(mcp.get("servers"), dict):
        raise ValueError("Expected MCP servers at 'mcp.servers' (OpenCode V2)")

    exported = {}
    disabled_names = []
    for name, server in mcp["servers"].items():
        if not isinstance(server, dict):
            raise ValueError(f"{name}: server config must be an object")
        if server.get("disabled") is True or server.get("enabled") is False:
            disabled_names.append(name)
            if not args.include_disabled:
                continue
        exported[name] = convert_server(name, server, args.with_secrets)

    output_path = args.output.expanduser()
    save_private_json(output_path, {"mcpServers": exported}, args.force)
    print(f"Exported {len(exported)} MCP servers to {output_path}")
    print(f"Disabled in OpenCode: {len(disabled_names)}; {'included' if args.include_disabled else 'skipped'}")
    print(f"Secrets: {'included (file is PRIVATE)' if args.with_secrets else 'redacted; use --with-secrets to connect authenticated servers'}")
    print("File permissions: 0600")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
