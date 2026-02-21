# Zentinel Bot Management Agent

A bot detection and management agent for [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Built in **pure Rust**, it combines four detection engines -- header analysis, User-Agent validation, a known bot database with reverse DNS verification, and behavioral analysis -- to produce a composite bot score (0-100) and issue ALLOW, BLOCK, or CHALLENGE decisions per request.

## Features

### Detection Engines

- **Header Analysis** - Checks for missing browser headers (`Accept`, `Accept-Language`, `Accept-Encoding`), automation tool markers (`X-Selenium`, `X-Puppeteer`, `X-Playwright`), suspicious header value patterns, `sec-ch-ua` consistency for modern Chrome, and generic `Accept: */*` detection
- **User-Agent Validation** - Matches against known bot keywords (curl, wget, python-requests, scrapy), security scanner signatures (sqlmap, nikto, nessus, nuclei, gobuster), headless browser indicators (HeadlessChrome, PhantomJS, Puppeteer, Playwright), outdated browser versions, impossible OS combinations (Android + Windows, iPhone + Android), and empty/missing User-Agent strings
- **Known Bot Database** - Identifies good bots (Googlebot, Bingbot, DuckDuckBot, Facebookbot, Twitterbot, LinkedInBot, Slackbot, UptimeRobot, Pingdom, StatusCake, Datadog) by User-Agent pattern and IP range, with optional reverse DNS verification using forward-confirmed reverse DNS (FCrDNS). Detects fake bots that claim to be crawlers but fail IP/DNS verification. Also matches against a bad patterns database for security scanners (sqlmap, nikto, nessus, masscan, zgrab, nuclei, gobuster, dirbuster, wfuzz, hydra) and scrapers (scrapy, httrack)
- **Behavioral Analysis** - Tracks per-IP sessions over time: requests per minute with configurable thresholds, timing regularity via coefficient of variation (low CV = bot-like regular intervals), path diversity analysis (high ratio of unique paths = systematic crawling), and sustained high request rates

### Scoring System

Each detection engine produces an independent signal score (0-100). These are combined using configurable weights (default: header 0.20, User-Agent 0.25, known bot 0.35, behavioral 0.20) into a final weighted score. Confidence is calculated from the proportion of signals available.

### Three-Way Decision Model

| Score Range | Decision | Action |
|-------------|----------|--------|
| 0 -- allow_threshold (default 30) | **Allow** | Request passes through with bot score headers |
| allow_threshold -- block_threshold | **Challenge** | JavaScript challenge, CAPTCHA, or proof-of-work |
| block_threshold (default 80) -- 100 | **Block** | 403 response with `{"error": "access_denied", "reason": "bot_detected"}` |

Verified good bots (score 0, confidence 1.0) are always allowed. Verified fake bots (score 100, confidence 1.0) are always blocked. Decisions are suppressed when confidence is below `min_confidence` (default 0.5).

### Challenge System

- **JavaScript challenge** - Redirects to a configurable JS challenge URL, sets an HMAC-SHA256 signed token cookie on success
- **CAPTCHA challenge** - Redirects to a CAPTCHA page
- **Proof-of-work challenge** - Requires client to solve a computational puzzle (configurable difficulty)

Challenge tokens are signed with HMAC-SHA256, include a timestamp and nonce, and are verified with constant-time comparison to prevent timing attacks. Valid tokens bypass detection on subsequent requests.

### Bot Categories

Detected bots are classified into categories:

| Category | Examples |
|----------|----------|
| `human` | Real browser traffic |
| `search_engine` | Googlebot, Bingbot, DuckDuckBot |
| `social_media` | Facebookbot, Twitterbot, LinkedInBot, Slackbot |
| `monitoring` | UptimeRobot, Pingdom, StatusCake, Datadog |
| `seo_tool` | Ahrefs, Semrush |
| `security_scanner` | sqlmap, nikto, nessus, nuclei |
| `malicious` | Fake crawlers, brute forcers |
| `automation` | curl, wget, python-requests |
| `headless_browser` | Puppeteer, Selenium, Playwright, PhantomJS |
| `unknown` | Unclassified |

### Response Headers

Every response includes bot metadata headers:

```
X-Bot-Score: 75
X-Bot-Category: automation
X-Bot-Confidence: 0.85
X-Bot-Verified: Googlebot          # only for verified bots
X-Bot-Challenge: passed            # only after challenge success
X-Bot-Signals: {"header_score":...}  # only with debug_headers enabled
```

### Metrics

The agent exports counter and gauge metrics via the v2 agent protocol:

| Metric | Type | Description |
|--------|------|-------------|
| `bot_management_requests_total` | counter | Total requests processed |
| `bot_management_requests_allowed` | counter | Requests allowed |
| `bot_management_requests_blocked` | counter | Requests blocked |
| `bot_management_requests_challenged` | counter | Requests sent to challenge |
| `bot_management_verified_good_bots` | counter | Verified legitimate crawlers |
| `bot_management_verified_bad_bots` | counter | Detected fake crawlers |
| `bot_management_block_threshold` | gauge | Current block threshold |
| `bot_management_allow_threshold` | gauge | Current allow threshold |

## Installation

### From Source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-bot-management
cd zentinel-agent-bot-management
cargo build --release
```

### Binary

```bash
./target/release/zentinel-bot-management-agent --socket /var/run/zentinel/bot-management.sock
```

### Docker

```bash
docker run --rm \
  -v /var/run/zentinel:/var/run/zentinel \
  ghcr.io/zentinelproxy/zentinel-agent-bot-management:latest
```

## Quick Start

```bash
# Basic usage with Unix socket (default)
zentinel-bot-management-agent --socket /var/run/zentinel/bot-management.sock

# With gRPC transport
zentinel-bot-management-agent --grpc-address 127.0.0.1:50052

# With custom config file
zentinel-bot-management-agent --socket /tmp/bot.sock --config bot-config.yaml

# With custom bot databases
zentinel-bot-management-agent \
  --socket /tmp/bot.sock \
  --good-bots data/good_bots.json \
  --bad-patterns data/bad_patterns.json

# With JSON structured logging
zentinel-bot-management-agent --socket /tmp/bot.sock --json-logs --log-level debug
```

## Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--socket` / `-s` | `/tmp/zentinel-bot-management.sock` | Unix socket path for UDS transport |
| `--grpc-address` | - | gRPC address (e.g., `127.0.0.1:50052`); overrides UDS |
| `--config` / `-c` | - | Path to YAML or JSON configuration file |
| `--good-bots` | `data/good_bots.json` | Path to known good bots database |
| `--bad-patterns` | `data/bad_patterns.json` | Path to bad User-Agent patterns database |
| `--json-logs` | `false` | Enable JSON structured logging |
| `--log-level` | `info` | Log level: trace, debug, info, warn, error |

## Configuration

Configuration is loaded from a YAML or JSON file passed with `--config`. All fields are optional and fall back to defaults.

### Full YAML Example

```yaml
# Score thresholds for decisions
thresholds:
  allow_threshold: 30       # Score at or below this = allow (0-100)
  block_threshold: 80       # Score at or above this = block (0-100)
  min_confidence: 0.5       # Minimum confidence to act on a score (0.0-1.0)

# Detection engine toggles and weights
detection:
  header_analysis: true
  user_agent_validation: true
  known_bot_lookup: true
  behavioral_analysis: true
  weights:
    header: 0.20
    user_agent: 0.25
    known_bot: 0.35          # Known bot database has highest weight
    behavioral: 0.20

# Allow list for known good bots
allow_list:
  search_engines: true       # Google, Bing, DuckDuckGo
  social_media: true         # Facebook, Twitter, LinkedIn, Slack
  monitoring: true           # UptimeRobot, Pingdom, StatusCake, Datadog
  seo_tools: false           # Ahrefs, Semrush (off by default)
  verify_identity: true      # Reverse DNS verification for crawlers
  custom_patterns:           # Additional User-Agent patterns to allow
    - "my-internal-bot/*"
  custom_ip_ranges:          # Additional IP ranges to allow (CIDR)
    - "10.0.0.0/8"

# Challenge settings
challenge:
  default_type: java_script  # java_script, captcha, or proof_of_work
  js_challenge_url: "/_zentinel/challenge.js"
  challenge_url: null        # URL for CAPTCHA challenges
  token_validity_seconds: 300
  token_secret: "change-me-in-production"  # HMAC-SHA256 signing key
  cookie_name: "_zentinel_bot_check"

# Behavioral analysis tuning
behavioral:
  max_sessions: 100000       # Maximum concurrent IP sessions to track
  session_timeout_seconds: 3600
  rpm_threshold: 60          # Requests per minute before flagging
  min_requests_for_scoring: 5  # Wait for N requests before scoring
  max_request_history: 100   # Request timestamps to retain per session

# Cache settings
cache:
  verification_cache_size: 10000
  verification_cache_ttl_seconds: 3600
  dns_cache_size: 10000
  dns_cache_ttl_seconds: 3600

# Performance
performance:
  max_detection_time_ms: 50
  adaptive_throttling: true

# Add X-Bot-Signals debug header to responses
debug_headers: false
```

### Minimal Configuration

For most deployments, a minimal config is sufficient since defaults are sensible:

```yaml
thresholds:
  block_threshold: 85

challenge:
  token_secret: "your-secret-key-here"
```

## Known Bot Databases

### Good Bots (`data/good_bots.json`)

A JSON array of bot definitions. Each entry includes a name, category, User-Agent patterns, optional IP ranges in CIDR notation, and an optional reverse DNS suffix for verification:

```json
[
  {
    "name": "Googlebot",
    "category": "search_engine",
    "ua_patterns": ["Googlebot", "Googlebot-Image", "Googlebot-Video"],
    "ip_ranges": ["66.249.64.0/19", "64.233.160.0/19"],
    "verify_dns": ".googlebot.com",
    "is_good": true
  }
]
```

When `verify_identity` is enabled, the agent performs a two-step verification for bots with a `verify_dns` suffix:
1. Reverse DNS lookup on the client IP to get the hostname
2. Forward DNS lookup on the hostname to confirm it resolves back to the client IP

If the bot claims to be Googlebot but the IP does not reverse-resolve to `*.googlebot.com`, it is flagged as a fake bot with score 100.

### Bad Patterns (`data/bad_patterns.json`)

A JSON array of regex patterns that match malicious User-Agent strings:

```json
[
  {
    "pattern": "(?i)sqlmap",
    "reason": "security_scanner_sqlmap",
    "score": 95
  },
  {
    "pattern": "(?i)hydra",
    "reason": "brute_forcer_hydra",
    "score": 95
  }
]
```

## Zentinel Proxy Integration

Register the bot management agent in your Zentinel proxy configuration:

```kdl
agents {
    agent "bot-management" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/zentinel/bot-management.sock"
        }
        events ["request_headers"]
        timeout-ms 50
        failure-mode "open"
    }
}

routes {
    route "web" {
        matches { path-prefix "/" }
        upstream "backend"
        agents ["bot-management"]
    }
}
```

For gRPC transport:

```kdl
agents {
    agent "bot-management" {
        type "custom"
        transport "grpc" {
            address "127.0.0.1:50052"
        }
        events ["request_headers"]
        timeout-ms 50
        failure-mode "open"
    }
}
```

The agent communicates using the Zentinel Agent Protocol v2. It supports:
- **Config push** - Receive configuration updates from the proxy at runtime
- **Metrics export** - Report counter and gauge metrics to the proxy
- **Health reporting** - Report health status for load balancing and circuit breaking
- **Cancellation** - Cancel in-flight detection if the client disconnects
- **Concurrent requests** - Handle up to 100 concurrent request inspections

## Example Detection Scenarios

### Scenario 1: Verified Googlebot

A request arrives with `User-Agent: Googlebot/2.1` from IP `66.249.66.10`.

1. **Header analysis**: Missing browser headers -> score 45
2. **User-Agent validation**: Contains "bot" keyword -> score 40
3. **Known bot database**: Matches Googlebot UA pattern, IP is in `66.249.64.0/19` -> **verified good bot**
4. **Result**: Score 0, confidence 1.0, category `search_engine`, decision **ALLOW**

The known bot database short-circuits when a bot is verified. The request passes with `X-Bot-Score: 0` and `X-Bot-Verified: Googlebot`.

### Scenario 2: Fake Googlebot

A request arrives with `User-Agent: Googlebot/2.1` from IP `185.220.101.55` (not a Google IP).

1. **Known bot database**: Matches Googlebot UA pattern, but IP is not in any Google CIDR range. Reverse DNS does not resolve to `*.googlebot.com`. -> **fake bot detected**
2. **Result**: Score 100, confidence 1.0, category `malicious`, decision **BLOCK** (403)

### Scenario 3: Headless Browser Scraper

A request arrives with `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0` and headers missing `Accept-Language`, `Accept-Encoding`, and `sec-ch-ua`.

1. **Header analysis**: Missing accept-language (+15), missing accept-encoding (+15), claims Chrome 120 but no sec-ch-ua (+20) -> score 50
2. **User-Agent validation**: Contains "headless" keyword -> score 60
3. **Known bot database**: No match -> score 50 (neutral)
4. **Behavioral analysis**: First few requests -> score 50 (insufficient data)
5. **Weighted score**: (50*0.20 + 60*0.25 + 50*0.35 + 50*0.20) / 1.0 = 52.5 -> **53**
6. **Result**: Score 53, confidence 1.0, category `headless_browser`, decision **CHALLENGE**

The client receives a JavaScript challenge. If it solves the challenge and returns with a valid `_zentinel_bot_check` cookie, subsequent requests are allowed.

### Scenario 4: Aggressive Scraping Bot

A request arrives from `10.0.1.50` with `User-Agent: python-requests/2.28.0`. Over the past minute, this IP has made 120 requests to 110 unique paths.

1. **Header analysis**: Missing accept, accept-language, accept-encoding -> score 45
2. **User-Agent validation**: Contains "python-requests" keyword -> score 45
3. **Known bot database**: No match -> score 50
4. **Behavioral analysis**: RPM 120 (threshold 60, score +40), high path diversity 0.92 (score +20) -> score 60
5. **Weighted score**: (45*0.20 + 45*0.25 + 50*0.35 + 60*0.20) / 1.0 = 49.75 -> **50**
6. **Result**: Score 50, category `automation`, decision **CHALLENGE**

If the scraper continues without solving the challenge, the behavioral score continues to rise and will eventually push the overall score above the block threshold.

### Scenario 5: Normal Browser User

A request arrives with a full Chrome User-Agent, all standard browser headers present including `sec-ch-ua`, `Accept-Language: en-US,en;q=0.9`, and `Accept-Encoding: gzip, deflate, br`.

1. **Header analysis**: All expected headers present -> score 0
2. **User-Agent validation**: Valid modern Chrome UA -> score 0
3. **Known bot database**: No match -> score 50 (neutral)
4. **Behavioral analysis**: Normal browsing pattern, low RPM, irregular timing (high CV) -> score 0
5. **Weighted score**: (0*0.20 + 0*0.25 + 50*0.35 + 0*0.20) / 1.0 = 17.5 -> **18**
6. **Result**: Score 18, confidence 1.0, category `human`, decision **ALLOW**

## Testing

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --test integration

# All tests
cargo test
```

## Development

```bash
# Debug build with logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock

# Release build
cargo build --release

# Check formatting
cargo fmt --check

# Lint
cargo clippy
```

## Architecture

```
+-------------------------------------------------------------+
|                    Zentinel Proxy                            |
+--------------------------+----------------------------------+
                           | Unix Socket / gRPC
                           v
+-------------------------------------------------------------+
|                 Bot Management Agent                        |
|  +---------------+  +----------------+  +-----------------+ |
|  |   Header      |  |  User-Agent    |  |   Known Bot     | |
|  |   Analyzer    |  |  Analyzer      |  |   Database      | |
|  +-------+-------+  +-------+--------+  +--------+--------+ |
|          |                  |                     |          |
|  +-------+------------------+--------+            |          |
|  |          Score Calculator         |<-----------+          |
|  +---------------+------------------+                        |
|                  |                                           |
|  +---------------v------------------+                        |
|  |      Behavioral Analyzer         |                        |
|  +---------------+------------------+                        |
|                  |                                           |
|  +---------------v------------------+                        |
|  |     Decision Engine              |                        |
|  |  (Allow / Challenge / Block)     |                        |
|  +---------------+------------------+                        |
|                  |                                           |
|  +---------------v------------------+                        |
|  |     Challenge Manager            |                        |
|  |  (JS / CAPTCHA / Proof-of-Work)  |                        |
|  +----------------------------------+                        |
+-------------------------------------------------------------+
```

## License

Apache-2.0

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Report security vulnerabilities to security@raskell.io.
