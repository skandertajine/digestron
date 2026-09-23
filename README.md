# digestron

Drowning in logs and metrics? Copy-pasting them into a chatbot to figure out
what happened tonight? That's digestron's job.

digestron **pulls** whatever matters from your existing stack — security
events, logs, metrics, any signal Elasticsearch or Prometheus can count —
aggregates it deterministically, has your **LLM** (local Ollama or any
OpenAI-compatible API) write a short plain-language summary, and **delivers**
it to your notification channels (Home Assistant, email, any webhook), on
schedule. Security digest, nightly ops report, error-budget recap: if you can
query it, digestron can digest it. One static binary, YAML configuration,
Prometheus metrics, a built-in web UI showing every run and its token cost.

What it is **not**: a SIEM, a SOC platform, a chat agent. It reads, it never
remediates. Severities are computed in code from thresholds you set — the LLM
only writes prose.

## Quick start

```sh
docker run --rm \
  -v $(pwd)/config.yaml:/etc/digestron/config.yaml:ro \
  -e ES_PASSWORD -e HA_TOKEN \
  ghcr.io/skandertajine/digestron:latest run -config /etc/digestron/config.yaml
```

Copy [config.example.yaml](config.example.yaml) and adapt it. Three blocks:
`sources` (where to pull from), `llm` (who summarizes), `sinks` (where to
deliver). Then:

```sh
digestron check -config config.yaml   # probe every configured module
digestron run -config config.yaml     # one digest, then exit (cron/CronJob)
digestron serve -config config.yaml   # internal scheduler + metrics + web UI
```

`serve` exposes on `:9090`: the web UI at `/` (run history: findings received
per source, text sent per sink, LLM token usage), Prometheus metrics at
`/metrics`, and `/healthz`. Kubernetes manifests for both modes live in
[deploy/](deploy/). Every response carries a strict `Content-Security-Policy`
(the page is one file, inline styles and scripts only, no external resource of
any kind) plus `X-Frame-Options: DENY`.

The header strip shows the build, the last success and its age (flagged once
past 2h), the next scheduled run, the current run's phase (`collecting`,
`summarizing`, `delivering`) and the log ring's size. **Check all**
(`POST /api/check`, optionally `{"module":"name"}` for one) probes every
source, sink and the LLM with its own 10s timeout and shows ok/failed/no-probe
per module — it reaches every configured backend, so it sits behind the same
cross-origin guard as the button. **Stop** (`DELETE /api/run`) cancels the run
in flight: it stops between stages (never mid-request), is still recorded in
the history titled `(cancelled)`, and is never counted as a success — a
cancelled hourly digest does not refresh `last_success_timestamp`, on purpose.

The UI has one button, **Run now** (`POST /api/run`, `GET /api/run` for its
progress). With *dry run* ticked, the default, the run queries every source
and the LLM but skips the sinks, so a test never reaches a phone; it lands in
the history titled `(manual, dry)` and stays out of the metrics. Untick it
and the run is a real digest, delivered and recorded, titled `(manual)`.
Scheduled and manual runs never overlap: a second press answers `409`. A
scheduler tick that lands during a full manual run is skipped and logged,
because that run delivers the same window; one that lands during a dry run is
replayed as soon as the dry run ends, because a dry run delivers nothing.

From a shell, the API defaults to dry as well:

```
curl -X POST 'http://digestron-dev.home/api/run'          # dry: sources + LLM, no sinks
curl -X POST 'http://digestron-dev.home/api/run?dry=0'    # delivered, recorded
```

### Process log in the UI

The page ends with the process log: every line digestron writes, debug
included, kept in a bounded in-memory ring (4000 lines or 2 MiB, oldest
evicted first). Filter by level, text or run; the *logs* link on a run card
shows only that run's lines, and every line of a run carries its ID, known
before the run starts. `kubectl logs` prints exactly what it always did: the
*stderr* selector changes what stderr prints until the next restart, and never
what the page can see.

```
GET /api/logs?since=<seq>&level=<debug|info|warn|error>&run=<id>&q=<text>&limit=<n>
PUT /api/logs/level   {"level": "debug"}
```

Configured secrets are replaced by `<redacted>` wherever text leaves the
process: these lines, `kubectl logs`, and the error texts stored in a run's
report (`history.json`, `/api/runs/{id}` and the digest the sinks receive),
because an upstream that rejects a request often quotes it back inside its
error. That covers any `password`, `token` or `api_key` setting, every header
value (a `Bearer x` value also hides `x` alone), a password or query token in a
URL, the whole URL of a webhook sink (it is the credential), the `user:password`
pair a Basic header carries, and the JSON-escaped, URL-encoded and base64 forms
an upstream echoes. Values under 8 bytes are not hidden. Prompts, query bodies
and replies are never logged, only their sizes.

The ring is per process. When the process restarts the page notices, says so,
and shows the new process's log from its first line.

Every run is stored in `history.json` with a `kind`: `schedule` (the cron tick),
`manual` (the button, delivered) or `test` (a dry run). Test runs keep their
own budget, a quarter of `history.keep` and at most 50, so an afternoon of
dry runs cannot push the hourly digests out of the history.

The page has no login, like `/metrics`. Browsers cannot press the button on
behalf of another site (cross-origin `POST`s are refused with `403`); anything
that is not a browser, curl included, is not affected by that guard, so keep
the ingress internal.

## Sources

| Type | What it does |
|---|---|
| `elasticsearch` | Runs `_search` queries over your log indices. Ships with presets; fully custom bodies supported. |
| `prometheus` | Instant or range queries against any Prometheus-compatible API. |

Each query yields one finding: a count, a severity scored against your
`severity: {warning: N, critical: M}` thresholds, and a breakdown (by
convention, a single terms aggregation named `breakdown`). A query that
fails does not take its neighbours with it: the source returns what it did
collect and the digest names the casualties — a source that lost some
queries on a `Partial sources:` line, one that returned nothing at all on a
`Failed sources:` line, because those are different things to go and fix.
Counts you can trust, minus the ones you cannot.

A count is only reported when the cluster says it is complete. Elasticsearch
answers `200` with partial results when a shard fails or the search times
out, and stops counting at 10000 unless the body sets `track_total_hits`
(every preset does); Prometheus answers `200` with a `warnings` array when it
served the query from incomplete data. In each case the query is reported as
failed instead of contributing a number that reads like a measurement.

Embedded Elasticsearch presets (tuned for a Filebeat-style index). Exact
matches and aggregations go through the `.keyword` subfield: under default
dynamic mapping a string lands as `text`, where a `term` clause matches
analysed tokens (`BLOCK` never matches, `pi-nginx` splits in two) and a
`terms` aggregation is refused outright. The fields that are *not* matched
exactly keep their bare name — `message` through `match_phrase` on the
analysed text, `http.response.status_code` through a numeric `range`:

| Preset | Measures | Needs fields |
|---|---|---|
| `fail2ban` | fail2ban bans | `source`, `fail2ban.action`, `client.ip` |
| `ssh_auth` | SSH auth failures (rejected credentials and unknown users) | `log.syslog.appname`, `event.outcome`, `message`, `client.ip` |
| `app_login_failures` | Failed logins across common apps (Home Assistant, ArgoCD, Grafana, Immich, Vaultwarden) | `kubernetes.namespace`, `message` |
| `ufw_blocks` | Directed firewall blocks (multicast noise excluded) | `ufw.action`, `destination.ip`, `client.ip` |
| `nginx_public` | HTTP errors on the public edge | `source`, `http.response.status_code`, `client.ip` |

## LLM providers

| Type | Notes |
|---|---|
| `ollama` | Native `/api/chat`: explicit `num_ctx` (the server default silently truncates long prompts), `think: false` by default (a reasoning model otherwise spends the whole budget on its trace and returns nothing), `keep_alive` to skip cold starts. |
| `openai-compatible` | Any `/v1/chat/completions`: OpenAI, a [LiteLLM](https://github.com/BerriAI/litellm) proxy (→ 100+ providers), vLLM, LM Studio, Groq, Mistral. The max-tokens field name is configurable because implementations disagree. |
| `noop` | No LLM. The digest is the raw counters. Also available as `run -no-llm`. |

When the LLM is down, the digest still goes out — raw counters beat silence.

## Sinks

| Type | Notes |
|---|---|
| `homeassistant` | `notify.<service>` call; the message is the LLM summary, falling back to the raw digest. Either way it carries the sources that did not fully answer, and the title is marked `PARTIAL` when there are any — the verdict is the max over the findings that *survived*, so an incomplete run is otherwise indistinguishable from a quiet one on a locked screen. |
| `email` | SMTP with STARTTLS; subject templated on the report. |
| `webhook` | Generic escape hatch: method, headers, `text/template` body over the report (`rendertext`, `sourceproblems`, `tojson` helpers). |

## Metrics

All prefixed `digestron_`: `last_success_timestamp_seconds` (alert on its
age), `runs_total{status}`, `run_duration_seconds`,
`module_runs_total{module,status}` — `success`, `error`, or `partial` for a
source that lost some queries and delivered the rest —
`module_duration_seconds{module}`, `findings_total{module,severity}`,
`notifications_total{sink,status}`, `llm_tokens_total{model,kind}`,
`llm_duration_seconds`, `build_info`.

In `run` mode a failed run exits non-zero, so a Kubernetes CronJob plus
kube-state-metrics (`kube_job_status_failed`) covers alerting with no extra
infrastructure. A *partial* run is not a failed run: the digest went out with
the counts that survived, and failing the Job would only have Kubernetes
retry it and push the same window to your phone twice. Alert on
`module_runs_total{status="partial"}` instead.

## Security posture

Log content is attacker-influenced by definition, so digestron treats its own
input as hostile:

- The findings JSON is wrapped in **fence markers derived from a fresh random
  token on every run** before reaching the LLM — log lines cannot escape their
  data role (prompt injection).
- **Severities and the verdict are computed in Go**, from your thresholds. The
  model cannot downgrade an incident.
- Secrets are a dedicated type that renders `<redacted>` through fmt, JSON and
  slog; sink tokens travel in headers, never in URLs; prompts are never logged.
- Config secrets come from environment references, expanded at load; an unset
  variable fails the start, not the 3am run.

## Configuration

Everything lives in one YAML file — see
[config.example.yaml](config.example.yaml), which is loaded and instantiated
in CI so it can never drift from the code. Any scalar can be overridden with
`DIGESTRON_`-prefixed env vars (`__` separates nesting levels:
`DIGESTRON_LLM__TIMEOUT=180s`).

## Extending

A provider is one file implementing a one-method interface (`Collect`, `Send`
or `Complete`), registered in its `init()`, plus its test. Grep any provider
under `internal/source`, `internal/sink` or `internal/llm` for a template —
none exceeds ~150 lines. PRs welcome.

## License

Apache-2.0
