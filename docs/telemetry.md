# Telemetry

Fleet's pool manager (`oyzu-pool-manager`) and executor (`oyzu-executor`) can
export traces and metrics to an OpenTelemetry Collector. It is for operating
managed execution: whether managers log in, claim and renew, whether executors
heartbeat and drain logs, and how a revocation or a cancel shows up. It is off
unless you turn it on, it carries no credential and no build content, and it
cannot change what a job does.

The platform's [telemetry reference](https://github.com/oyzuai/platform/blob/main/docs/reference/telemetry.md)
owns the runs-side instruments (`oyzu.fleet.operations` and friends). This page
is the Fleet side. The two correlate by server-assigned numbers (job, attempt,
manager), never by a credential.

## Turning it on

Set these in the manager's environment. There are no flags and no stored
settings.

| Variable | Meaning |
| --- | --- |
| `OYZU_OTEL_ENABLED` | `true` turns telemetry on; anything else leaves it off |
| `OYZU_OTEL_ENDPOINT` | The Collector's OTLP/HTTP base URL (`http://collector:4318`). An `http` or `https` URL with no user info, query or fragment; anything else leaves telemetry off and logs why |
| `OYZU_OTEL_ENVIRONMENT`, `OYZU_OTEL_VERSION`, `OYZU_OTEL_INSTANCE` | Resource attributes, short lowercase tokens |

There is no header setting. Fleet sends no `Authorization` and reads no
`OTEL_EXPORTER_OTLP_HEADERS`: the Collector must accept the manager's network
position (a loopback or private-network Collector, or a gateway that adds
credentials on the way out). Put exporter credentials in that gateway, never in
the manager's or a job's environment.

The settings are **consumed at start**: Fleet reads them and removes every
`OYZU_OTEL_*`, `OTEL_*`, `TRACEPARENT` and `TRACESTATE` variable from the process
environment before any job starts, so no build, kind, Docker CLI or other child
process inherits an endpoint or a trace parent. The process driver hands the
executor its own settings and a trace parent through its start-up environment
(`Process.Telemetry`) and nowhere else; `--pass-env` cannot forward a telemetry
variable. The container and Kubernetes drivers do not pass telemetry into the
executor, so an executor there exports nothing and has no trace parent: the
manager's own spans and runs' spans still correlate by job and attempt.

## What is sent

Spans (service `oyzu-pool-manager` or `oyzu-executor`):

| Span | Where | Attributes |
| --- | --- | --- |
| `fleet.manager.enroll`, `.login`, `.rotate`, `.claim` | manager | `oyzu.fleet.manager`, `oyzu.fleet.key`, and for a claim `oyzu.fleet.job`, `oyzu.fleet.attempt` |
| `fleet.manager.job` | manager, one per assigned job | job, attempt, manager, pool |
| `fleet.executor.job` | executor, child of the manager's job span when a trace parent was handed down | job, attempt, kind, operation, heartbeat interval, final state, exit code |
| `fleet.client.<route>` | both, one per runner API call, client kind | route, HTTP status |

Metrics:

| Instrument | Type | Dimensions |
| --- | --- | --- |
| `oyzu.fleet.client.requests` | counter | `oyzu.fleet.route`, `oyzu.outcome`, `oyzu.reason` |
| `oyzu.fleet.client.duration` | histogram, seconds | route, outcome |
| `oyzu.fleet.lease.headroom` | histogram, seconds | none |
| `oyzu.fleet.log_drain.operations` | counter | route (`upload`, `finish`), phase (`live`, `post_finish`), outcome, reason |
| `oyzu.fleet.executions` | counter | `oyzu.fleet.state` (the outcome the executor reported) |

A route is one of the closed set of runner API paths (anything else is
`other`). Outcomes are `success`, `challenge` (the 401), `denied`, `invalid`,
`cancelled`, `unavailable` and `fault`; reasons are a short fixed list such as
`refused`, `conflict`, `timeout` and `network`. Fleet reports a credential
refusal as `challenge/refused` and never says which credential or why: the
uniform 401 is the protocol's, and runs' audit holds the classified reason.

## What never is

* Attribute keys are an allowlist; every identifier is a number the server or
  manager assigned. String values must be short lowercase tokens; a value shaped
  like an Oyzu credential, a bearer, a JWT or a private key is dropped whatever
  its key.
* No URL, header, token, assertion, key, startup value, repository, branch,
  commit, file path, log line, environment variable or error text is recorded.
  Errors are classified into the reasons above.
* The traceparent a client sends to runs is optional correlation. Runs makes it a
  span link, never a parent, and no authentication field is ever trace context.

## Failure behavior

Recording never blocks. The span queue is bounded (2048) and drops the oldest
data when full; export runs on its own goroutines with short timeouts. An
unreachable or slow Collector costs a counter and one log line a minute, and
never delays a heartbeat, a renewal, a finish or a log upload.

## Verification

`telemetry`'s tests cover the allowlist, credential-shaped values, the bounded
queue, the environment being consumed and the child environments being scrubbed.
`manager` and `executor` tests cover the handoff. The connected proof, in the
platform repository (`oyzu run iam-fleet-proof`), shows spans and metrics from a
real manager and executor in Tempo and Prometheus next to runs' and scans every
signal for the run's credentials. See
[authentication](authentication.md#implementation-status).
