# Standalone pool server

Status: slice 1 implemented, 2026-10-25; deployment and isolated build proof
remain separate acceptance steps. The client side and the public contract edits
are in oyzu's
[standalone remote pool proposal](https://github.com/oyzuai/oyzu/blob/main/docs/proposals/OEP-draft-standalone-remote-pool/README.md),
which owns the problem, scope, slices and first proof. This page owns the
server.

`pool-server` is a single-tenant server that lets one machine run remote
builds without the platform. It serves two existing public contracts:

- the [runs API](https://github.com/oyzuai/oyzu/blob/main/docs/contracts/runs-v1alpha1/openapi.yaml)
  to callers (`oyzu build --remote`, `oyzu run --remote`);
- the [runner protocol](https://github.com/oyzuai/oyzu/blob/main/docs/contracts/runner-v1/openapi.yaml)
  to the Fleet manager and executor, which run unchanged.

It replaces nothing in the platform. The platform's runs service stays the
governed implementation of the same APIs.

## Shape

- New command `cmd/pool-server`, package `poolserver`. Go standard library
  only, like the rest of Fleet.
- One process with one plain-HTTP listener on loopback (default
  `127.0.0.1:8480`). TLS and tailnet identity come from `tailscale serve`
  in front of it. The runner API is under `/runner/v1/` and the runs API under
  `/api/v1alpha1/`, the paths `runnerclient.New` and oyzu's `src/remote/api.rs`
  already use.
- One account (its configured name, so `/accounts/{account}/...` paths stay
  valid), one pool, and one project per allowed repository (project id = the
  repository name, lowercased to an identifier).
- State in one directory (default `/var/lib/oyzu-pool`): a JSON file per run
  and per job, append-only NDJSON logs per attempt, used-assertion `jti`s, the
  managers and their keys. Writes go through a temp file and rename. No
  database. A restart keeps queued and finished runs; running jobs whose lease
  lapses become `timed_out` with `LEASE_EXPIRED`.

## Configuration

`/etc/oyzu-pool/server.json`, owned by root, mode 0600 (JSON because Fleet has
no TOML parser and takes no dependencies):

```json
{
  "account": "oyzu",
  "listen": "127.0.0.1:8480",
  "public_url": "https://pool.taild79a0f.ts.net",
  "state_dir": "/var/lib/oyzu-pool",
  "repositories": ["oyzuai/oyzu", "oyzuai/platform", "oyzuai/fleet"],
  "enrollment_token_sha256": "<hex of the single-use manager enrollment token>",
  "callers": {
    "tailnet_users": ["micah@example.com"],
    "github": [
      { "repository": "oyzuai/oyzu", "refs": ["refs/heads/main", "refs/pull/*"] }
    ]
  },
  "github_app": {
    "app_id": 5467712,
    "private_key_file": "/etc/oyzu-pool/github-app.pem"
  },
  "egress_allow": [
    { "host": "github.com", "port": 443 },
    { "host": "*.githubusercontent.com", "port": 443 }
  ]
}
```

The installation id is looked up per repository
(`GET /repos/{owner}/{repo}/installation` with the app JWT) and cached.

Build `./cmd/pool-server` and start `pool-server --config
/etc/oyzu-pool/server.json`. The configured listener must be a numeric loopback
address and `public_url` an HTTPS origin. `GET /healthz` answers 204 while
state storage is available and discloses no pool metadata. An absent or invalid
App key fails startup; the process never runs jobs or falls back to the host.
The App ID is fixed to 5467712. Repository names that normalize to the same
project identifier are rejected at startup.

Run exactly one process per state directory. State files are private (0600),
and directories 0700. A durable `transaction.json` is replayed after interrupted
cross-file writes before requests are accepted; an I/O failure makes subsequent
mutations fail closed until restart. Log bytes are synced before their metadata
is committed; recovery trims any uncommitted suffix. Keep the state directory
on a local filesystem supporting atomic rename and file/directory fsync.

## Runner API subset

What the shipped manager and executor call, from `runnerclient`. Request and
response shapes are the ones in `runnerclient`; the server must match them
exactly.

| Route | Behavior |
| --- | --- |
| `enroll` | Accepts the configured single-use enrollment token (compare SHA-256, then forget it), registers the manager's Ed25519 public key, answers `Enrolled`. |
| `token` | `private_key_jwt` login. Verify with `assertion.Parse` and `Verify(key, assertion.TypeLogin, audience, now)`; audience default `oyzu-runs`. Each `jti` once. Issues a random 10-minute manager bearer (store its SHA-256). |
| `keys` | Rotation signed by the current key (`assertion.TypeRotation`, `new_key` claim). At most two active keys; a third is 409. |
| `readiness/session` | Answers `{"session": "", "enabled": false}`. The manager then skips readiness. Other `readiness/*` routes answer 404. |
| `report` | Stores facts and slots; used only for the status page. |
| `demand` | Counts queued jobs. |
| `claim` | Takes the oldest queued job, creates attempt n+1, answers `Claim` with a single-use 5-minute startup bearer and `egress.allow` from configuration plus the server itself. 204 when nothing is queued. No `execution_trust_decision`. |
| `release` | Requeues a claimed job whose executor never started, without using an attempt. |
| `job/start` | Spends the startup bearer once; answers `Started` with a job bearer (lease 2 minutes, `heartbeat_seconds` 30) and the `Job`. |
| `job/heartbeat` | Renews the lease; answers `cancel: true` once the run's cancel was requested. |
| `job/source` | Mints a GitHub App installation token for `job.repository` only, with `permissions: {"contents": "read"}`, and answers `Source`. Slice 2 adds the snapshot answer. |
| `job/logs`, `job/logs/finish` | Stores chunks (base64 gzip NDJSON, hash-checked, gapless `seq`) as `runnerclient.LogChunk` and `LogFinish` describe. The finishing bearer keeps log authority for 15 minutes after `job/finish`. |
| `job/finish` | Records the `Outcome`; sets the run's state, exit code, reason and outputs. |
| `job/id-token` | Slice 3: an Ed25519-signed JWT (`iss` = `public_url`, `aud` from the request, `sub` = `repo:<repository>:ref:<ref>`, plus `repository`, `sha`, `ref`, `run_id`, `source_kind`), 10 minutes. JWKS at `/.well-known/jwks.json`. Before slice 3 it answers 404. |
| `job/egress` | 404 (no grants). |
| `job/secrets`, `job/write-token`, `job/kind/*` | 404. Jobs from this server never name secrets and are never renovate, lock or kind jobs. |

The new key's first successful login retires its predecessor; access bearers
already issued by the predecessor retain their bounded lifetime. Expired startup
assignments requeue without consuming an attempt. A one-second lease reaper runs
alongside the HTTP server. Logs accept up to 1 MiB compressed and decompressed
per chunk, 1,000 entries per chunk, and 512 MiB per attempt. Duplicate chunks
with the same hash and duplicate identical log finishes are safe to retry.

The `Job` the server builds:

- `kind` `build`, `operation` `build` or `run`, `repository`, `head_sha`,
  `head_branch` from the run's `ref`, `targets`, `task`, `affected_base`.
- `command` is chosen by the server, never by the caller:
  `["oyzu", "build", "--isolated", "--full", ...targets]`, with
  `"--affected", <base>` in place of targets when given, or
  `["oyzu", "run", "--isolated", <task>]`. Every pool build runs isolated;
  there is no field that turns it off.

## Runs API

Implements `createRun`, `getRun` (ETag and `wait` long poll), `cancelRun`,
`getRunLogs` (cursor = base64 of the last sequence, `wait` up to 30 seconds,
`complete` once finished and drained), `getRunResult` and `getRunOutput`.
`listRuns` answers the caller's own runs, newest first. Errors are RFC 9457
problems with the `code` values the contract lists; `src/remote/api.rs`
branches on `code`.

`createRun` checks, in order: the caller (below), the repository is in
`repositories`, the commit exists (`GET /repos/{owner}/{repo}/commits/{sha}`
with an installation token; 404 → `COMMIT_NOT_FOUND`), then queues the run and
its job. `Idempotency-Key` behaves as the contract says (same key and body →
200 with the first run).

`getRunOutput` answers 404 `OUTPUT_NOT_FOUND` for now. The executor reports
output metadata only, so `--download` is a named follow-up (see the proposal).

## Callers

| Caller | Proves it with | May |
| --- | --- | --- |
| A person | `Tailscale-User-Login`, set by `tailscale serve`. Trusted only when the TCP peer is loopback. Must be in `callers.tailnet_users`. | Create runs for any listed repository; read and cancel their own runs. |
| A GitHub Actions job | `Authorization: Bearer <GitHub OIDC ID token>`. Verify RS256 against `https://token.actions.githubusercontent.com/.well-known/jwks` (cache keys, refetch on unknown `kid`), `iss`, `aud` = `public_url`, `exp`/`nbf`. Reuse the verifier in platform `deploy/ovh-farm/cache-gate/oidc.go`. | Create a run only when `repository` and `sha` equal the token's claims and `ref` matches a listed pattern for that repository; read and cancel only runs it created. |

Anything else is 401 `UNAUTHENTICATED`. A known caller asking for an unlisted
repository is 403 `PERMISSION_DENIED`.

An explicit bearer always has to authenticate itself, even when a tailnet login
header is also present. Actions ownership is bound to the signed repository,
run ID, run attempt and subject; a refreshed token for the same job can read
its runs. Creation also requires the submitted ref to equal the signed ref.
Ref allow patterns support `*` (including `/`), such as `refs/pull/*`.
Idempotency is scoped to caller and account and retained with the run, including
across restarts. Lists expose only the caller's runs.

The server uses the public contract's `PERMISSION_DENIED` for a disallowed
source and `OUTPUT_NOT_FOUND` for unavailable output bytes. Output metadata
remains available in the result resource; downloading bytes is a follow-up.

## Credentials and where they live

| Credential | Lives | Reaches |
| --- | --- | --- |
| GitHub App private key | `/etc/oyzu-pool/github-app.pem`, root 0600, read by the server at start | Nothing else. Never logged. |
| Installation tokens | Minted per `job/source` call, one repository, `contents: read`, ≤ 1 hour | The executor's checkout only. The executor masks it and keeps it out of the `oyzu` process environment. |
| Manager key | The manager's state directory | Login and rotation assertions. |
| Startup and job bearers | Server stores SHA-256 only | One executor, one attempt. |
| Pool signing key (slice 3) | `state_dir/issuer.key`, 0600 | Signs job ID tokens; public half at the JWKS URL. |

## Slice 3: cache writes

The cache-gate on build01 already verifies GitHub OIDC tokens to authorize
writes. Add the pool's issuer and JWKS URL as a second trusted issuer. The gate
allows writes when the pool token's `ref` is `refs/heads/main`, its
`source_kind` is `commit`, and its `repository` is listed. PR and snapshot jobs
keep read-only access. The image sets machine-scope `cache.remote` to the gate.

## Slice 4: per-stage checks

On `job/finish`, and while the job runs as entries arrive, the server reads the
build's structured `finished` log events and the reports the outcome lists. It
posts one check run per target and stage (`oyzu / <target> / <stage>`) on the
run's commit with the App's Checks permission, `in_progress` when the scope
starts and `completed` with its conclusion at the end. Test failures from JUnit
reports become annotations (GitHub limits 50 per request; batch). Snapshot runs
post no checks.

## Deployment on build01

Configured in platform `deploy/ovh-farm` (Ansible), not in this repository:

- `oyzu-pool-server.service` (systemd, its own user, `ReadWritePaths` the state
  directory, reads the config and key).
- `tailscale serve --service=svc:pool --https=443 http://127.0.0.1:8480`, so
  callers reach `https://pool.taild79a0f.ts.net` with tailnet identity headers.
  The tailnet policy grants `tag:ci` and the listed users access to the service.
- One Fleet manager (`--driver container`, rootless Podman socket as the
  engine, `--egress enforce`, `--concurrency 2`, `--image` pinned by digest),
  enrolled against the public HTTPS origin with the enrollment token.
- The executor image: `ghcr.io/oyzuai/oyzu-execution/base:1` plus the released
  `oyzu` CLI and `oyzu-executor`. Isolated builds inside a rootless Podman
  container on build01 are unproven; prove that first and report what it
  needs (user namespaces, `/dev/fuse`, seccomp) before building more.
- The GitHub Actions runners on build01 stay as they are; the pool's two slots
  are in addition.

Podman4.9's compatibility API needs an engine-side file for Fleet's fixed
seccomp policy and native mask/unmask options. The adapter qualifies only a
directly-bound, same-UID Linux Podman process sharing the manager's mount/user/PID
namespaces and root filesystem. Remote, forwarded and ambiguous socket-activated
endpoints fail closed. `XDG_RUNTIME_DIR` must be private 0700; the fixed
content-addressed profile remains in its `oyzu-fleet-sandbox` child through the
runtime-directory lifetime so concurrent containers keep their policy file.
Do not delete it while managers or their containers may still use it.

Docker retains inline policy requests. Podman readiness inspects its real OCI
configuration and compares the resolved fixed syscall policy, nonroot user,
empty capabilities, NNP, private namespaces, exact masks and read-only `/sys`
including every submount. An echoed HostConfig is insufficient. The first
qualification is bounded to Linux amd64 and Podman4.9; unsupported engines or
control drift do not receive readiness authority.

Keep the original config and App key root-owned 0600. For the service user,
systemd can expose them using `LoadCredential=server.json:/etc/oyzu-pool/server.json`
and `LoadCredential=github-app.pem:/etc/oyzu-pool/github-app.pem`. Start with the
credential-mounted config and set its `private_key_file` to the key's runtime
credential path. The loader accepts regular 0400 or 0600 files owned by root
or the service's effective user. On Ubuntu's systemd255, a named service-user
read ACL makes credential mode appear 0440: that is accepted only within the
exact `CREDENTIALS_DIRECTORY=/run/credentials/oyzu-pool-server.service`, a
protected read-only tmpfs mount, with the exact root-owner/service-user ACL and
no owning-group, other-user or other-group access. Generic group-readable files
and symlinks are rejected. It never logs key contents. Enroll the manager
against the public HTTPS origin so its container executors can reach the runner
API; container loopback does not reach the host listener.

## Verification

Focused Go tests for each route, run through the real `runnerclient` and the
real manager against an `httptest` server, plus the OIDC verifier with a local
key. Tests inject only generated App signing keys and local GitHub responses;
they need no live App credential. Run `oyzu exec -- go test -race ./poolserver
./cmd/pool-server` and `oyzu exec -- go vet ./poolserver ./cmd/pool-server`.
The real proof is the one the proposal names, run on build01.
