# relgate

A release gate you run in CI. Point it at a service you own, and it does two things
before you ship:

- **Passive security checks** — missing security headers, insecure cookies, wide-open
  CORS, obsolete TLS, version leaks in `Server` headers.
- **A bounded load test** — throughput and p50/p95/p99 latency, with pass/fail thresholds.

It prints a report, writes a Markdown summary for a PR comment, and exits non-zero when
the gate fails, so a red result blocks the merge. Written in Go, no runtime dependencies.

## It only tests what you own

This is a tool for checking your own stack, not other people's. That's built in, not just
asked of you:

- It reads targets from a config file you commit. There is no built-in target list.
- Every host it may contact must be in `allowed_hosts`. A redirect to any other host is
  blocked mid-flight, so it can't be steered off your infrastructure.
- It won't run until you set `i_am_authorized: true`, affirming you own or are allowed to
  test those hosts.
- Concurrency, request rate and duration are capped (200 / 2000 rps / 300 s). The load
  test is sized to catch regressions, not to knock a service over.

"Passive" security means it reads what the server returns and inspects headers and error
responses. It sends no exploit payloads and changes no data.

## Quick start

```bash
go build -o relgate ./cmd/relgate
cp relgate.example.yaml relgate.yaml   # edit target + allowed_hosts
./relgate -config relgate.yaml
```

Write a Markdown report for a PR comment:

```bash
./relgate -config relgate.yaml -md report.md
```

Exit codes: `0` pass, `1` ran but the gate failed, `2` couldn't run (bad config, etc).

## Example output

Run against a local FastAPI service:

```
Load
----
  requests   1493 (errors 0, 0.00%)
  throughput 299 req/s
  latency    p50 2ms  p95 4ms  p99 6ms  max 20ms

RESULT: PASS
```

A full Markdown report is in [`testdata/example-report.md`](testdata/example-report.md).

## Configuration

See [`relgate.example.yaml`](relgate.example.yaml). The fields:

| field | meaning |
|---|---|
| `target` | base URL to test |
| `allowed_hosts` | hosts relgate may contact; the target must be here |
| `i_am_authorized` | must be `true` |
| `security.paths` | paths to probe for headers/misconfig |
| `security.fail_on` | lowest severity that fails the run |
| `load.path` | endpoint to load-test |
| `load.duration_seconds` | how long (≤ 300) |
| `load.concurrency` | parallel clients (≤ 200) |
| `load.max_rps` | request rate cap (≤ 2000) |
| `load.thresholds.p95_ms` | fail if p95 exceeds this |
| `load.thresholds.max_error_rate` | fail if the error rate exceeds this |

## Use it in GitHub Actions

Start your service, then run relgate against it. Example workflow in
[`.github/workflows/gate.yml`](.github/workflows/gate.yml). The idea:

```yaml
- run: docker compose up -d && ./scripts/wait-for-health.sh
- run: relgate -config relgate.ci.yaml -md report.md
- if: always()
  uses: actions/github-script@v7   # post report.md as a PR comment
```

## What each security check looks for

| check | severity | why |
|---|---|---|
| Content-Security-Policy | medium | limits where scripts load from (XSS) |
| Strict-Transport-Security | medium | HTTPS-only (on https targets) |
| insecure cookie (no Secure/HttpOnly) | medium | session theft over HTTP / via JS |
| CORS `*` with credentials | high | exposes authenticated responses to any site |
| obsolete TLS (< 1.2) | high | weak transport |
| X-Frame-Options / X-Content-Type-Options / Referrer-Policy | low | clickjacking, MIME sniffing, referrer leakage |
| version leak in `Server` / `X-Powered-By` | low | easier CVE targeting |

## Layout

```
cmd/relgate/       CLI entry point
internal/config/   config loading, validation, the allowlist safeguard
internal/security/ passive header/TLS/cookie/CORS checks
internal/load/     bounded load runner + rate limiter
internal/report/   result types, console + Markdown rendering
internal/run/      wiring + the allowlist-enforcing HTTP transport
```

## What I'd add next

- Auth support (a bearer token) so protected endpoints can be load-tested
- A JSON output mode for dashboards
- More checks: open redirects, missing rate limiting on auth endpoints
- Compare against a saved baseline and flag regressions
