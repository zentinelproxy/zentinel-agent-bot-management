<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Bot management agent</h3>

<p align="center">Scores each request for bot likelihood from its headers, User-Agent, known-crawler identity and per-IP behavior, at the request-headers phase.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-bot-management/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-bot-management/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/bot-management/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For sites that want to keep scanners, scrapers and automation clients out
while letting real browsers and verified crawlers through. Four detectors each
produce a score from 0 to 100; a weighted sum gives the request's bot score,
which is compared to two thresholds: at or below `allow_threshold` the request
passes, at or above `block_threshold` it gets a `403`, and in between the agent
returns a challenge decision (which Zentinel 0.6.50 does not act on yet, see
[How it works](#how-it-works)). A Googlebot or Bingbot User-Agent from an
address that fails IP-range and reverse-DNS checks is blocked outright. If the
agent is unreachable, the filter's `failure-mode` decides; the quick start
uses `closed`.

## Quick start

```bash
zentinel bundle install bot-management
zentinel-bot-management-agent --socket /tmp/zentinel-bot-management.sock
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

agents {
    agent "bot-management" type="custom" {
        unix-socket "/tmp/zentinel-bot-management.sock"
        events "request_headers"
        timeout-ms 100
    }
}

filters {
    filter "bot-management" {
        type "agent"
        agent "bot-management"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches { path-prefix "/" }
        upstream "backend"
        filters "bot-management"
    }
}
```

`curl -i -A 'Googlebot/2.1' http://localhost:8080/` is answered with `403`: the
User-Agent claims Googlebot, but `127.0.0.1` is outside Google's ranges and
does not reverse-resolve to `.googlebot.com`. Other responses carry
`X-Bot-Score`, `X-Bot-Category` and `X-Bot-Confidence`.

## Install

### Bundle (recommended)

```bash
zentinel bundle install bot-management
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-bot-management-agent`.

### Release binaries

Tarballs for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are attached to each [release](https://github.com/zentinelproxy/zentinel-agent-bot-management/releases).
They contain only the binary; without the `data/` files the agent uses its
built-in bot lists (see [Bot databases](#bot-databases)).

### From source

`cargo install --git` does not work for this crate: it depends on a sibling
checkout of [`zentinel`](https://github.com/zentinelproxy/zentinel) by path
(`../zentinel/crates/agent-protocol`). Clone both side by side; the build needs
`protoc`.

```bash
git clone https://github.com/zentinelproxy/zentinel
git clone https://github.com/zentinelproxy/zentinel-agent-bot-management
cd zentinel-agent-bot-management
cargo build --release
# target/release/zentinel-bot-management-agent
```

### Container image (build locally)

No image is published. The `Dockerfile` packages a prebuilt Linux binary placed
in the repository root. The image's `SOCKET_PATH` variable is not read by the
agent, so pass the socket path as an argument:

```bash
docker build -t zentinel-agent-bot-management --target prebuilt .
docker run --rm -v /var/run/zentinel:/var/run/zentinel \
  zentinel-agent-bot-management --socket /var/run/zentinel/bot-management.sock
```

The image runs as `nonroot`, so the mounted directory must be writable by it.

## Configuration

The agent is configured with command-line flags and an optional YAML or JSON
file (`--config`; `.yaml`/`.yml` is read as YAML, anything else as JSON). It
also accepts configuration over the protocol (`on_configure`), but only
validates it and does not apply it, and Zentinel 0.6.50 does not forward an
`agent { config { ... } }` block, so set it here.

| Option | Default | Meaning |
|---|---|---|
| `--socket`, `-s` | `/tmp/zentinel-bot-management.sock` | Unix socket to listen on. |
| `--grpc-address` | none | Listen on gRPC at this address (e.g. `127.0.0.1:50052`) instead of the socket. |
| `--config`, `-c` | none | Configuration file (YAML or JSON). Without it, all defaults apply. |
| `--good-bots` | `data/good_bots.json` | Known good bots database, relative to the working directory. Built-in list if the file does not exist. |
| `--bad-patterns` | `data/bad_patterns.json` | Bad User-Agent patterns database. Built-in list if the file does not exist. |
| `--json-logs` | off | Log as JSON. |
| `--log-level` | `info` | `trace`, `debug`, `info`, `warn` or `error`. `RUST_LOG` is also honored. |

A minimal file:

```yaml
thresholds:
  block_threshold: 85
challenge:
  token_secret: "replace-with-a-long-random-secret"
```

Every key is optional. Keys that are read:

| Option | Default | Meaning |
|---|---|---|
| `thresholds.allow_threshold` | `30` | Score at or below which the request is allowed. |
| `thresholds.block_threshold` | `80` | Score at or above which the request is blocked with `403`. |
| `thresholds.min_confidence` | `0.5` | Below this confidence an unverified request is allowed whatever its score. |
| `detection.header_analysis` | `true` | Run the header detector. |
| `detection.user_agent_validation` | `true` | Run the User-Agent detector. |
| `detection.known_bot_lookup` | `true` | Run the known-bot database. |
| `detection.behavioral_analysis` | `true` | Run the per-IP behavioral detector. |
| `detection.weights.header` / `.user_agent` / `.known_bot` / `.behavioral` | `0.20` / `0.25` / `0.35` / `0.20` | Weight of each detector in the final score. |
| `allow_list.verify_identity` | `true` | Check a crawler's IP range or forward-confirmed reverse DNS before trusting its User-Agent. When `false`, the User-Agent alone verifies it. |
| `challenge.default_type` | `java_script` | Challenge decision type: `java_script`, `captcha` or `proof_of_work`. |
| `challenge.js_challenge_url` | `/_zentinel/challenge.js` | URL passed in a JavaScript challenge decision. |
| `challenge.challenge_url` | none | URL passed in a CAPTCHA challenge decision. |
| `challenge.token_secret` | `change-me-in-production` | HMAC-SHA256 key for challenge tokens. Set it if you use tokens. |
| `challenge.token_validity_seconds` | `300` | Token lifetime. |
| `challenge.cookie_name` | `_zentinel_bot_check` | Cookie that carries a token. |
| `behavioral.max_sessions` | `100000` | Per-IP sessions kept in memory. |
| `behavioral.session_timeout_seconds` | `3600` | Idle time after which a session is dropped. |
| `behavioral.rpm_threshold` | `60` | Requests per minute above which an IP is scored as high rate. |
| `behavioral.min_requests_for_scoring` | `5` | Requests from an IP before behavior is scored. |
| `behavioral.max_request_history` | `100` | Request timestamps kept per session. |
| `cache.verification_cache_size` | `10000` | Cached crawler verification results. |
| `cache.verification_cache_ttl_seconds` | `3600` | Lifetime of a cached verification. |
| `debug_headers` | `false` | Add `X-Bot-Signals` (per-detector scores as JSON) to responses. |
| `trusted_proxies` | empty | IPs or CIDRs of proxies whose `X-Forwarded-For` / `X-Real-IP` are believed for the client IP. An invalid entry stops the agent from starting. |

The file format also has `allow_list.search_engines`, `social_media`,
`monitoring`, `seo_tools`, `custom_patterns`, `custom_ip_ranges`,
`cache.dns_cache_size`, `cache.dns_cache_ttl_seconds` and `performance.*`.
They are parsed but not read by any code, so setting them changes nothing.

### Bot databases

`--good-bots` is a JSON array of crawlers:

```json
[
  {
    "name": "Googlebot",
    "category": "search_engine",
    "ua_patterns": ["Googlebot"],
    "ip_ranges": ["66.249.64.0/19"],
    "verify_dns": ".googlebot.com",
    "is_good": true
  }
]
```

`--bad-patterns` is a JSON array of `{ "pattern": "(?i)sqlmap", "reason": "security_scanner_sqlmap", "score": 95 }`
entries (regular expressions matched against the User-Agent). The files in
[`data/`](data/) match the built-in lists: Googlebot, Bingbot, DuckDuckBot,
Facebookbot, Twitterbot, LinkedInBot, Slackbot, UptimeRobot, Pingdom,
StatusCake and Datadog as good bots, and twelve scanner and scraper patterns.

Full reference: <https://registry.zentinelproxy.io/bot-management/>

## How it works

The agent subscribes to `request_headers` only.

- **Header detector**: missing `Accept`, `Accept-Language` or `Accept-Encoding`;
  automation headers (`X-Selenium`, `X-Puppeteer`, `X-Playwright`,
  `X-Automation`, `X-Headless`, `X-Requested-With`); header values starting with
  selenium/puppeteer/playwright or containing "headless"; a bare `Accept: */*`;
  a modern Chrome User-Agent without `sec-ch-ua`.
- **User-Agent detector**: keywords for tools and libraries (curl, wget,
  python-requests, go-http-client, ...), scanners (sqlmap, nikto, nmap, nuclei,
  ...), headless browsers, SEO crawlers; Chrome or Firefox below version 80;
  impossible platform combinations (Android with Windows or iPhone); a User-Agent
  shorter than 20 characters; an empty or missing User-Agent.
- **Known-bot database**: a bad-pattern match scores the pattern's value; a
  good-bot User-Agent is checked against the bot's IP ranges, then by
  forward-confirmed reverse DNS when the entry has `verify_dns`. Verified means
  score 0 and allow; a failed check means score 100 and block. Googlebot and
  Bingbot are checked by range and DNS, DuckDuckBot by range only (outside its
  ranges it is a fake); entries with neither (Facebook, Twitter, LinkedIn,
  Slack) are verified by User-Agent alone. A request without a usable client IP
  cannot pass a range or DNS check.
- **Client IP** is the connection address Zentinel reports in the request
  metadata; `X-Forwarded-For` / `X-Real-IP` sent by the client are ignored.
  Only when that address is in `trusted_proxies` are they read, right to left,
  taking the first hop that is not a trusted proxy (needed only with Zentinel
  older than 0.6.48, which does not resolve the client behind its listener's
  `trusted-proxies` itself). Requests without a usable address share one
  behavioral session.
- **Behavioral detector**: per client IP, in process memory: requests per
  minute, timing regularity (coefficient of variation of intervals), share of
  distinct paths, and sustained high rate.

The final score is the weighted mean of the detectors that ran. A client not
in either database gets a neutral 50 from the known-bot detector, and the
behavioral detector also returns 50 until an IP has sent
`min_requests_for_scoring` requests, so with the default weights and
thresholds a plain `curl` request scores about 53 and lands in the challenge
band rather than being blocked; lower `block_threshold` or adjust the weights
if you want such clients blocked.

Responses carry `X-Bot-Score`, `X-Bot-Category`, `X-Bot-Confidence`, and
`X-Bot-Verified` for a verified crawler. The category for a verified crawler
is always reported as `search_engine`, whatever its database entry says. A
block returns `403` with `{"error": "access_denied", "reason": "bot_detected"}`.

**Challenges are partial.** Between the thresholds the agent returns a
challenge decision with a signed token in its parameters, and on later
requests it allows any request whose cookie carries a valid token (adding
`X-Bot-Challenge: passed`). Nothing serves a challenge page or sets the cookie,
and Zentinel 0.6.50 treats a challenge decision as allow, so those requests
reach the upstream unchanged.

The agent reports counters `bot_management_requests_total`,
`_requests_allowed`, `_requests_blocked`, `_requests_challenged`,
`_verified_good_bots`, `_verified_bad_bots` and gauges
`bot_management_block_threshold`, `_allow_threshold` through the protocol's
metrics export.

## Development

```bash
git clone https://github.com/zentinelproxy/zentinel ../zentinel   # path dependency
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Needs `protoc` (CI installs `protobuf-compiler`) and stable Rust (CI uses
`dtolnay/rust-toolchain@stable`).

## Related

- [Registry page](https://registry.zentinelproxy.io/bot-management/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
