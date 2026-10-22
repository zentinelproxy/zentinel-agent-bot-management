#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# Without the data/ files (the built-in bot lists, as `zentinel bundle
# install` runs it), over the Unix socket and over gRPC:
#   1. no config file: a request with a browser's headers is forwarded (200);
#      a DuckDuckBot User-Agent from an address outside DuckDuckBot's ranges
#      (a fake crawler) gets 403 and never reaches the upstream;
#   2. block_threshold 70: known scanners (sqlmap, nikto, masscan) get 403,
#      the browser request is still forwarded. With the default threshold of
#      80 a scanner scores about 74 and gets a challenge decision, which
#      Zentinel treats as allow, so the defaults alone do not block them.
# Each run also checks that with the agent stopped the request is refused.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

# Run from an empty directory so data/*.json from the checkout is not used.
abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
AGENT_BIN=$(abs "$AGENT_BIN"); ZENTINEL_BIN=$(abs "$ZENTINEL_BIN"); AGENT_SMOKE=$(abs "$AGENT_SMOKE")
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"

BROWSER='"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"'

bad() { printf '{"name": "%s User-Agent", "path": "/smoke", "headers": {"User-Agent": "%s"}, "expect": 403}' "$1" "$2"; }

printf 'thresholds:\n  block_threshold: 70\n' > strict.yaml

fake() { printf '{"name": "fake %s from 127.0.0.1", "path": "/smoke", "headers": {%s, "User-Agent": "%s"}, "expect": 403}' "$1" "$BROWSER_HEADERS" "$2"; }
BROWSER_HEADERS='"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br"'

for transport in uds grpc; do
    echo "=== bot-management agent over $transport, defaults: fake crawler"
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name bot-management \
        --transport "$transport" \
        --clean "{\"name\": \"browser request\", \"path\": \"/smoke\", \"headers\": {$BROWSER}}" \
        --case "$(fake DuckDuckBot 'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)')"

    echo "=== bot-management agent over $transport, block_threshold 70: scanners"
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name bot-management \
        --transport "$transport" --agent-arg=--config="$dir/strict.yaml" \
        --clean "{\"name\": \"browser request\", \"path\": \"/smoke\", \"headers\": {$BROWSER}}" \
        --case "$(bad sqlmap 'sqlmap/1.7.2#stable (https://sqlmap.org)')" \
        --case "$(bad nikto 'Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)')" \
        --case "$(bad masscan 'masscan/1.3 (https://github.com/robertdavidgraham/masscan)')"
done
