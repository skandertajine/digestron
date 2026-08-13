# digestron

Drowning in logs and metrics? Copy-pasting them into a chatbot to figure out
what happened tonight? That's digestron's job.

digestron **pulls** security data from your existing stack (Elasticsearch,
Prometheus), aggregates it deterministically, has your **LLM** — local Ollama
or any OpenAI-compatible API — write a short plain-language summary, and
**delivers** it to your notification channels (Home Assistant, email, any
webhook), on schedule. One static binary, YAML configuration, Prometheus
metrics, a built-in web UI showing every run and its token cost.

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
[deploy/](deploy/).

## Sources

| Type | What it does |
|---|---|
| `elasticsearch` | Runs `_search` queries over your log indices. Ships with presets; fully custom bodies supported. |
| `prometheus` | Instant or range queries against any Prometheus-compatible API. |

Each query yields one finding: a count, a severity scored against your
`severity: {warning: N, critical: M}` thresholds, and a breakdown (by
convention, a single terms aggregation named `breakdown`).

Embedded Elasticsearch presets (tuned for a Filebeat-style index):

| Preset | Measures | Needs fields |
|---|---|---|
| `fail2ban` | fail2ban bans | `source_text`, `fail2ban.action`, `client.ip` |
| `ssh_auth` | SSH auth failures | `ssh.auth_method`, `event.outcome`, `client.ip` |
| `app_login_failures` | Failed logins across common apps (Home Assistant, ArgoCD, Grafana, Immich, Vaultwarden) | `kubernetes.namespace`, `message` |
| `ufw_blocks` | Directed firewall blocks (multicast noise excluded) | `ufw.action`, `destination.ip`, `client.ip` |
| `nginx_public` | HTTP errors on the public edge | `source_text`, `http.response.status_code`, `client.ip` |

## LLM providers

| Type | Notes |
|---|---|
| `ollama` | Native `/api/chat`: explicit `num_ctx` (the server default silently truncates long prompts), `think` disabled, `keep_alive` to skip cold starts. |
| `openai-compatible` | Any `/v1/chat/completions`: OpenAI, a [LiteLLM](https://github.com/BerriAI/litellm) proxy (→ 100+ providers), vLLM, LM Studio, Groq, Mistral. The max-tokens field name is configurable because implementations disagree. |
| `noop` | No LLM. The digest is the raw counters. Also available as `run -no-llm`. |

When the LLM is down, the digest still goes out — raw counters beat silence.

## Sinks

| Type | Notes |
|---|---|
| `homeassistant` | `notify.<service>` call; the message is the LLM summary, falling back to the raw digest. |
| `email` | SMTP with STARTTLS; subject templated on the report. |
| `webhook` | Generic escape hatch: method, headers, `text/template` body over the report (`rendertext`, `tojson` helpers). |

## Metrics

All prefixed `digestron_`: `last_success_timestamp_seconds` (alert on its
age), `runs_total{status}`, `run_duration_seconds`,
`module_runs_total{module,status}`, `module_duration_seconds{module}`,
`findings_total{module,severity}`, `notifications_total{sink,status}`,
`llm_tokens_total{model,kind}`, `llm_duration_seconds`, `build_info`.

In `run` mode a failed run exits non-zero, so a Kubernetes CronJob plus
kube-state-metrics (`kube_job_status_failed`) covers alerting with no extra
infrastructure.

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
