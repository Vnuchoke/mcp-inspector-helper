#!/bin/sh
# Collect tools/list and prompts/list from each server in a MCP Inspector config.
# Each method is attempted up to MAX_ATTEMPTS times.
set -eu

CONFIG="${CONFIG:-$HOME/.mcp-inspector/opencode-mcp.json}"
OUTPUT="${OUTPUT:-$HOME/.mcp-inspector/results}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-120}"
RETRY_DELAY_SECONDS="${RETRY_DELAY_SECONDS:-3}"

# File-backed encrypted OAuth token storage (same settings as the interactive Inspector).
MCP_INSPECTOR_SECRET_STORE="${MCP_INSPECTOR_SECRET_STORE:-file}"
MCP_INSPECTOR_SECRET_KEY_FILE="${MCP_INSPECTOR_SECRET_KEY_FILE:-$HOME/.config/mcp-inspector/secret.key}"
export MCP_INSPECTOR_SECRET_STORE MCP_INSPECTOR_SECRET_KEY_FILE

umask 077

for executable in jq timeout mcp-inspector; do
  if ! command -v "$executable" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$executable" >&2
    exit 1
  fi
done

if [ ! -r "$CONFIG" ]; then
  printf 'Config not found or unreadable: %s\n' "$CONFIG" >&2
  exit 1
fi

if ! jq -e '.mcpServers | type == "object"' "$CONFIG" >/dev/null; then
  printf 'Config has no mcpServers object: %s\n' "$CONFIG" >&2
  exit 1
fi

mkdir -p "$OUTPUT"
server_list="$(mktemp "$OUTPUT/.servers.XXXXXX")"
trap 'rm -f "$server_list"' 0

jq -r '.mcpServers | keys[]' "$CONFIG" > "$server_list"

passed=0
failed=0
while IFS= read -r server; do
  server_dir="$OUTPUT/$server"
  mkdir -p "$server_dir"

  for method in tools/list prompts/list; do
    name="${method%%/*}"
    result="$server_dir/$name.json"
    error="$server_dir/$name.error.log"
    temporary="$server_dir/$name.json.tmp"
    attempt=1
    success=0

    # Do not allow a previous run's result to masquerade as a fresh success.
    rm -f "$result" "$temporary" "$error"

    while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
      printf '%-35s %-15s attempt %s/%s: ' \
        "$server" "$method" "$attempt" "$MAX_ATTEMPTS"

      if timeout "${TIMEOUT_SECONDS}s" mcp-inspector --cli \
        --config "$CONFIG" \
        --server "$server" \
        --method "$method" \
        --format json \
        > "$temporary" 2> "$error"; then
        # A zero exit code is not enough: ensure we got the requested list.
        if jq -e --arg method "$method" '
          (.result | type) == "object" and
          (if $method == "tools/list" then
             (.result.tools | type) == "array"
           else
             (.result.prompts | type) == "array"
           end)
        ' "$temporary" >/dev/null 2>&1; then
          mv -f "$temporary" "$result"
          [ -s "$error" ] || rm -f "$error"
          printf 'OK\n'
          success=1
          passed=$((passed + 1))
          break
        fi
        printf 'Invalid JSON or unexpected response shape\n' >> "$error"
        printf 'FAILED (invalid response)\n'
      else
        status=$?
        printf 'FAILED (exit code %s)\n' "$status"
        printf 'mcp-inspector/timeout exit code: %s\n' "$status" >> "$error"
      fi

      rm -f "$temporary"
      if [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then
        sleep "$RETRY_DELAY_SECONDS"
      fi
      attempt=$((attempt + 1))
    done

    if [ "$success" -eq 0 ]; then
      failed=$((failed + 1))
      printf '  Final failure. See: %s\n' "$error"
    fi
  done
done < "$server_list"

printf '\nComplete: OK=%s, FAILED=%s. Results: %s\n' \
  "$passed" "$failed" "$OUTPUT"

[ "$failed" -eq 0 ]
