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

- New command `cmd/pool-server`, package `poolserver`. Source uploads use the
  Go `github.com/klauspost/compress/zstd` decoder; no external decoder is needed.
- One process with one plain-HTTP listener on loopback (default
  `127.0.0.1:8480`). TLS comes from a reverse proxy such as Caddy or nginx, or from
  `tailscale serve` (which can also supply tailnet identity). The runner API is under `/runner/v1/` and the runs API under
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
no TOML parser):

```json
{
  "account": "oyzu",
  "listen": "127.0.0.1:8480",
  "public_url": "https://pool.taild79a0f.ts.net",
  "state_dir": "/var/lib/oyzu-pool",
  "source_retention": "7d",
  "source_quota": 21474836480,
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

A minimal no-App configuration for a public repository is:

```json
{
  "account": "personal",
  "public_url": "https://pool.example.com",
  "repositories": ["owner/public-repo"],
  "enrollment_token_sha256": "<64 lowercase hex characters>",
  "callers": { "tokens": [] },
  "egress_allow": [
    { "host": "github.com", "port": 443 },
    { "host": "*.githubusercontent.com", "port": 443 }
  ]
}
```

Save the config as a private 0600 file, then create a caller before starting:

```sh
pool-server token create --config /etc/oyzu-pool/server.json --name alice
pool-server token list --config /etc/oyzu-pool/server.json
pool-server token revoke --config /etc/oyzu-pool/server.json --name alice
```

Create prints a cryptographically random `oyzp_` token once; save it securely.
Only its SHA-256 hash is stored in `callers.tokens`, as
`{"name":"alice","sha256":"<64 lowercase hex characters>"}`. Names must be
unique and match `[a-z0-9-]{1,64}`. List prints names only. Administrative edits
must be serialized. Create and revoke atomically replace the configuration,
preserving owner and mode. Restart the server after a change; there is no hot
reload. Startup refuses configurations with no callers and names the create
command in its error.

On the laptop, configure the origin, account and environment authentication:

```sh
oyzu config set --global platform.url https://pool.example.com
oyzu config set --global platform.account personal
oyzu config set --global platform.authentication.provider environment
```

Set `OYZU_PLATFORM_TOKEN` to the caller token in the laptop's environment. `oyzu build --remote` builds a pushed
commit; `oyzu build --remote --worktree` uploads a snapshot. Enroll a Fleet
manager and isolated executors as described below; the server itself does not
execute builds. A generic reverse proxy must terminate HTTPS and forward to the
loopback listener. Leave `tailnet_users` empty when using tokens alone: the
server ignores `Tailscale-User-Login` in that configuration.

Without an App, commit runs support public GitHub repositories only. The server
first looks up the repository anonymously; a private response or 404 returns
403 `PERMISSION_DENIED` with detail
"commit runs of private repositories need a GitHub App (see docs/pool-server.md)".
Commit existence and repository IDs use the same anonymous API; the executor
fetches over HTTPS with no source token. Anonymous GitHub API access is limited
to 60 requests/hour per IP. Repository lookups (including private/404 results)
are cached for ten minutes; commit lookups are not cached. Snapshot source
uploads and checkout need no GitHub access and work with or
without an App. At run creation, repository facts are looked up on a best-effort
basis for job-token cache authorization; an unavailable lookup does not block
a snapshot run.

The preceding App configuration remains supported, including App ID 5467712.
Use your own App ID and private key to enable private sources and per-stage
checks; install it on each listed repository with contents read and checks write
permissions.

The installation id is looked up per repository
(`GET /repos/{owner}/{repo}/installation` with the app JWT) and cached.

Build `./cmd/pool-server` and start `pool-server --config
/etc/oyzu-pool/server.json`. The configured listener must be a numeric loopback
address and `public_url` an HTTPS origin. `GET /healthz` answers 204 while
state storage is available and discloses no pool metadata. When `github_app` is configured, an absent or invalid
App key fails startup; the process never runs jobs or falls back to the host.
The App ID may be any positive integer; omit `github_app` entirely to run
without an App. Repository names that normalize to the same
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
| `job/source` | Without an App, answers an anonymous source with no token. With an App, mints an installation token for `job.repository` only, with `permissions: {"contents": "read"}`, and answers `Source`. Snapshot runs receive a download grant. |
| `job/logs`, `job/logs/finish` | Stores chunks (base64 gzip NDJSON, hash-checked, gapless `seq`) as `runnerclient.LogChunk` and `LogFinish` describe. The finishing bearer keeps log authority for 15 minutes after `job/finish`. |
| `job/finish` | Records the `Outcome`; sets the run's state, exit code, reason and outputs. |
| `job/id-token` | Requires a live job bearer; answers an Ed25519-signed JWT (`iss` = `public_url`, `aud` from the request, `sub` = `repo:<repository>:ref:<ref>`, plus `repository`, `sha`, `ref`, `run_id`, `source_kind`), valid for 10 minutes. JWKS at `/.well-known/jwks.json`. |
| `job/egress` | 404 (no grants). |
| `job/secrets`, `job/write-token`, `job/kind/*` | 404. Jobs from this server never name secrets and are never renovate, lock or kind jobs. |

The new key's first successful login retires its predecessor; access bearers
already issued by the predecessor retain their bounded lifetime. Expired startup
assignments requeue without consuming an attempt. A one-second lease reaper runs
alongside the HTTP server. Logs accept up to 1 MiB compressed and decompressed
per chunk, 1,000 entries per chunk, and 512 MiB per attempt. Duplicate chunks
with the same hash and duplicate identical log finishes are safe to retry.

An executor's honest failure or timeout after cancellation stays a failure or
timeout with `cancel_requested_at` and diagnostics retained. Only confirmed
cancellation becomes `cancelled`; success cannot override a pending cancel.
Isolated task cancellation uses the same fresh finalized native manifest and
normal process-wait checks as builds. Missing, stale or incomplete records and
forced termination remain failures; delivery of a signal alone proves no cleanup.
An absent task reported as `skipped` by the executor becomes
`failed`/`TASK_NOT_DEFINED` for a manual run. Verbose outcomes accept the
executor's bounded tail while retaining a short display summary; full output
stays in the log resource. Public output metadata includes only the five fields
in the runs contract.

The `Job` the server builds:

- `kind` `build`, `operation` `build` or `run`, `repository`, `head_sha`,
  `head_branch` from the run's `ref`, `targets`, `task`, `affected_base`.
- `command` is chosen by the server, never by the caller:
  `["oyzu", "build", "--isolated", "--full", ...targets]`, with
  `"--affected", <base>` in place of targets when given, or
  `["oyzu", "run", "--isolated", <task>]`. Every pool build runs isolated;
  there is no field that turns it off.

## Runs API

### Working-tree snapshots

Authenticated callers first send `POST /api/v1alpha1/accounts/{account}/sources/missing`
with `{"blobs":["sha256:…",…]}` (at most 10,000 digests per request). The response
is `{"missing":[…]}`. They PUT absent files to `…/blobs/{digest}` with
`application/octet-stream`, optionally using `Content-Encoding: zstd`. The server
verifies SHA-256 over the decoded bytes and caps each blob at 512 MiB. Blob bytes
live in `state_dir/blobs/<hex>`; publication is temp-then-link and immutable.

`PUT …/sources/{digest}` accepts `application/vnd.oyzu.source.v1alpha1+json`.
The digest covers the original canonical JSON bytes, whose root is
`{"entries":[…]}`. Entries are sorted by unique portable relative paths. Files
carry `path`, `kind: "file"`, integer Unix `mode`, `mtime` in Unix nanoseconds,
`size` and `digest`; directories carry `path`, `kind: "directory"`, `mode` and
`mtime`; symlinks carry `path`, `kind: "symlink"` and `target`. Unknown, duplicate
or missing fields, `.git`, absolute/traversing paths, escaping links and
non-directory ancestors are refused. Limits are 200,000 entries, 512 MiB of
logical file content (including repeated blobs), and 512 MiB of manifest bytes.
The complete manifest is stored at `state_dir/sources/<hex>` only when every
listed blob is present with the declared size. Otherwise 422
`SOURCE_BLOBS_MISSING` includes a top-level `missing` digest list for reupload.
Both PUT routes answer 201 for new content and 200 for existing content after
verification. Other failures include 413 `SOURCE_TOO_LARGE`, 422
`SOURCE_DIGEST_MISMATCH`, `SOURCE_INVALID` or `SOURCE_KIND_UNSUPPORTED`, and
400 `REQUEST_INVALID` for unreadable or malformed compressed bodies.

Upload authorization is persisted by account and caller separately from the
deduplicated bytes. A caller can reference a digest only after submitting its
complete verified manifest, including when the bytes already exist. Knowing
another caller's digest grants no run or download access.

File blobs are shared within the configured account: permitted callers may learn
whether a blob already exists, while run access remains tied to ownership of
the complete source manifest.

`RunCreate` requires exactly one of `commit` and
`source: {kind: snapshot, digest, base_commit?}`. The uploaded digest must exist;
the optional base commit need not be pushed. The run echoes `source` and exposes
its base commit as `commit` when present. Results also identify snapshot source.
Actions workload callers remain bound to their signed commit and cannot create
snapshot runs.

For a snapshot, `job/source` returns `{kind: snapshot, url, digest}` instead of
a GitHub token. The download grant lasts at most five minutes, names one source
manifest and its listed blobs for one live job attempt, and sends no job bearer
to the download endpoint. Blob URLs replace `/sources/{manifest-digest}` with
`/blobs/{blob-digest}` and reuse the grant query. The
executor uses its configured HTTP transport (including gateway proxy and trust),
verifies the manifest digest and contract, then downloads and verifies files
with at most eight requests in parallel. Optional zstd blob responses decode in
Go. No tar stream, decoder subprocess or sibling staging directory is used.
The destination must be empty. Relative symlinks are created last and must
resolve inside the source. File and directory permission modes and nanosecond
modification times are restored; links have no timestamp field in this contract.

The server records each manifest's `last_used` on upload and run creation. At
startup and hourly it removes manifests unused for `source_retention` (default
`7d`), then evicts the least recently used unreferenced manifests as needed for
`source_quota` (default 20 GiB, configured in bytes). Retention accepts a positive
day count with `d` or a Go duration such as `168h`; quota must be positive.
Queued and running runs protect their source regardless of retention or quota,
so protected content can keep usage over quota. Unreferenced blobs are deleted
only after a one-hour grace from their upload. Shared blobs remain while any
retained manifest references them. Metadata and owner removal occur under the
server lock; filesystem deletion occurs outside it, serialized with uploads.
Each sweep emits one `source sweep manifests=… blobs=… bytes_freed=… error=…`
log line. Rerunning a cleaned source uploads missing files again through the same
lookup/upload path. This cleanup covers source storage only, not the action cache.

Commands remain chosen by the server with isolation and full build checks.
The executor sets `OYZU_REMOTE_SOURCE_DIGEST` for the branch CLI: this disables
remote-cache writes and publication even when project settings request them.
The CLI records snapshot source in its build manifest and refuses to publish
that manifest later. Deploy the snapshot-capable CLI with the executor; updating
only the caller or server is insufficient. Snapshot runs retain read access to
configured shared caches. Git-source jobs keep their existing checkout path.

### Run lifecycle

Implements `createRun`, `getRun` (ETag and `wait` long poll), `cancelRun`,
`getRunLogs` (cursor = base64 of the last sequence, `wait` up to 30 seconds,
`complete` once finished and drained), `getRunResult` and `getRunOutput`.
`listRuns` answers the caller's own runs, newest first. Errors are RFC 9457
problems with the `code` values the contract lists; `src/remote/api.rs`
branches on `code`.

`createRun` checks, in order: the caller (below), the repository is in
`repositories`, the commit exists (`GET /repos/{owner}/{repo}/commits/{sha}`
with an installation token when an App is configured, anonymously otherwise;
404 → `COMMIT_NOT_FOUND`), then queues the run and
its job. `Idempotency-Key` behaves as the contract says (same key and body →
200 with the first run).

`getRunOutput` answers 404 `OUTPUT_NOT_FOUND` for now. The executor reports
output metadata only, so `--download` is a named follow-up (see the proposal).

## Callers

| Caller | Proves it with | May |
| --- | --- | --- |
| A person | `Tailscale-User-Login`, set by `tailscale serve`. Honored only when `callers.tailnet_users` is non-empty and the TCP peer is loopback. Must be in `callers.tailnet_users`. | Create runs for any listed repository; read and cancel their own runs. |
| A person with a caller token | `Authorization: Bearer <token>` matching a SHA-256 hash in `callers.tokens`; identity is `token:<name>`. | Create runs for any listed repository; read and cancel their own runs. |
| A GitHub Actions job | `Authorization: Bearer <GitHub OIDC ID token>`. Verify RS256 against `https://token.actions.githubusercontent.com/.well-known/jwks` (cache keys, refetch on unknown `kid`), `iss`, `aud` = `public_url`, `exp`/`nbf`. Reuse the verifier in platform `deploy/ovh-farm/cache-gate/oidc.go`. | Create a run only when `repository` and `sha` equal the token's claims and `ref` matches a listed pattern for that repository; read and cancel only runs it created. |

While `callers.tailnet_users` is empty, the server ignores
`Tailscale-User-Login` entirely. If you later add tailnet users behind a generic
reverse proxy, that proxy must strip incoming `Tailscale-User-Login` headers;
only a trusted identity proxy may set them. The loopback peer check alone does
not authenticate a header forwarded by a generic proxy.

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
| Check-write installation tokens | Minted separately for one repository, `checks: write`, ≤ 1 hour; cached in server memory until five minutes before expiry | The pool server only; never sent to an executor. |
| Manager key | The manager's state directory | Login and rotation assertions. |
| Startup and job bearers | Server stores SHA-256 only | One executor, one attempt. |
| Pool signing key | `state_dir/issuer.key`, 0600 | Signs job ID tokens; public half at the JWKS URL. |

On first startup the server generates an Ed25519 signing key and persists its
seed in `state_dir/issuer.key` as private JSON. Restarts reuse the same key and
`kid`; an unreadable, corrupt or incorrectly protected existing key fails
startup instead of silently replacing the issuer identity. Keep it with the
state backup. Key rotation remains a follow-up. `GET /.well-known/jwks.json`
needs no caller credential and exposes only the public OKP/Ed25519 signing key.

The executor's existing loopback broker requests a token with the build's
chosen audience; it passes no authorization claims. `job/id-token` accepts
`{"audience":"https://cache.example.test"}` and answers `token` and
`expires_at`, as the runner protocol specifies. Empty or oversized audiences
and audiences containing NUL or newline controls are refused. Manager,
startup, expired and finished-job bearers cannot mint tokens. Tokens already
issued retain their ten-minute lifetime.

Actions-created runs persist the verified creator's `repository`,
`repository_id`, `repository_owner_id`, `ref`, `ref_type`, `event_name` and
`job_workflow_ref` when present, and copy those values into job tokens without
deriving missing claims. This authority survives server restarts and creator
token expiry. At creation, person-created commit and snapshot runs look up
`repository_id` and `repository_owner_id` through the GitHub API (anonymously
without an App), and persist them separately as repository source facts. Without an App, private or missing repositories
yield no facts for snapshots and do not produce a lookup error log.
Person-created job tokens include those IDs when available,
but never gain `event_name`, `ref_type` or `job_workflow_ref`; they remain
read-only. Other lookup failures are logged without failing the run, and its tokens
omit the IDs. Tokens reuse persisted facts without another lookup. Older
terminal runs without these facts still omit the IDs and Actions-only claims.
Every token separately identifies the pool run with
`run_id`, its commit (or snapshot base commit, when supplied) with `sha`, and
its source with `source_kind: commit` or `snapshot`.

## Slice 3: cache writes

The server supplies job identity for slice 3. The separately deployed
cache-gate on build01 must trust the configured pool issuer and JWKS URL
alongside its GitHub OIDC issuer before pool tokens authorize cache access.
Only an Actions-created main push commit run may write: the token must preserve
the creator's verified repository IDs, branch type, event and workflow ref,
alongside `source_kind: commit`. Tailnet callers have no Actions event or
workflow claims. PR, tailnet and snapshot jobs keep read-only access. The
executor image's machine-scope `cache.remote` must point at the gate, and the
pool's egress allow list must permit that origin. These deployment settings
and gate authorization are owned by platform `deploy/ovh-farm`; issuing a
token alone does not demonstrate a cache write or cache hit.

## Slice 4: per-stage checks

Without a GitHub App, per-stage checks are skipped; the server logs this once
at startup. Adding your own App enables private commit sources and checks.

For commit runs, the first log entry with a `<target>:<stage>` scope queues a
GitHub check named `oyzu / <target> / <stage>` on the run's commit, initially
`in_progress`. A structured `finished` event completes it: `success` becomes
`success`, `failed` becomes `failure`, `skipped` and `cancelled` retain those
conclusions, and other statuses become `neutral`. At `job/finish`, remaining
open checks become `cancelled` for a cancelled run; otherwise they fail with
"stage did not report a result". Finished events delivered during the log drain
can supply the stage's actual result. An expired executor lease also closes
open checks as failures.

The executor sends JUnit failures in the outcome's optional `test_failures`
array, with at most 200 failures and at most 1 KiB of UTF-8 message text per
failure. The server attaches failure annotations to the matching scope's check,
using checkout-relative paths and the reported line (line 1 when absent).
Annotations are sent in batches of at most 50. Failures without a path appear
in the check summary; long summaries are truncated to fit GitHub's limit.

Log and outcome acceptance queues check updates without waiting for GitHub.
A single background publisher runs with the lease reaper's lifecycle and
coalesces queued updates per run, so a stage may already be complete when its
check first appears. Stopping the reaper cancels and waits for the publisher.

The existing App issuer mints a separate, single-repository `checks: write`
token; this token stays in server memory and is reused until five minutes
before expiry. A check request rejected with 401 refreshes its token and retries
once. Snapshot runs and repositories without
an App installation post no checks. GitHub failures are logged without
credentials and do not change the build result. Check IDs and pending results
are persisted per run and scope. Retried chunks reuse those IDs; the lease
reaper queues pending delivery every 30 seconds, including after a restart,
without waiting for GitHub. A stable external ID also
lets the server recover a check when GitHub accepted its creation but the
response was lost. Annotation batches are append operations: a lost response
can cause the affected batch to appear again on retry.

Checks currently have no run-page link or re-run button. Coverage and lint
annotations, checks for snapshot runs, and Windows/macOS pools are later work.

A repository maintainer can mark an individual stage check as required in
branch protection. The pool never changes branch protection settings.

## Git providers

The pool server supports GitHub only today. That is a limitation of this
version, not a design choice: the pool must not become a product that only works
with GitHub. Teams host code on GitLab, Bitbucket, Azure DevOps, Gitea or
Forgejo, often self-managed, and the server should serve them the same way.

GitHub is assumed in five places:

| Concern | Today | Where |
| --- | --- | --- |
| Repository identity | A run must name provider `github` and an `owner/name` repository. | `poolserver/runs.go`, `types.go` |
| CI callers | Only GitHub Actions OIDC tokens are verified. | `poolserver/oidc.go` |
| Repository facts | `repository_id` and `repository_owner_id` come from the GitHub API. | `poolserver/github.go`, `anonymous.go` |
| Clone credential | A GitHub App installation token, or anonymous HTTPS for public repositories. | `poolserver/github.go`, `executor/` |
| Stage results | GitHub check runs. | `poolserver/checks_github.go` |

Working-tree snapshot runs only need a git provider for facts and checks,
because the source bytes come from the caller.

Planned shape (not implemented): one narrow provider interface in
`poolserver` with four operations: verify a CI caller's ID token, look up
repository facts, issue a short-lived read-only clone credential, and report a
stage status on a commit. Each provider gets its own implementation and config
block, beside `github_app`. GitHub is the first implementation and GitLab the
second (GitLab and self-managed GitLab: `id_tokens` OIDC, project or group
access tokens, commit statuses). After those come Bitbucket Cloud and Data Center,
Azure DevOps, and Gitea/Forgejo. A provider without OIDC for CI callers uses caller
tokens. A provider without a status API skips stage results and says so once,
as the server already does when no App is configured.

The wire side is owned by the public runs contract. Its `Repository.provider`
enum and `name` pattern (`owner/name`, which excludes GitLab subgroups and Azure
DevOps `org/project/repo`) are edited in place when the second provider lands. See the
[standalone remote pool proposal](https://github.com/oyzuai/oyzu/blob/main/docs/proposals/OEP-draft-standalone-remote-pool/README.md#git-providers).

## Deployment on build01

### Released artifacts

Releases provide `oyzu-pool-server_<version>_linux_<arch>.tar.gz`,
`oyzu-pool-manager_<version>_linux_<arch>.tar.gz` and
`oyzu-executor_<version>_linux_<arch>.tar.gz` for `amd64` and `arm64`, with
license notices, CycloneDX SBOMs, signed `SHA256SUMS` and build attestations.
The public `ghcr.io/oyzuai/oyzu-pool-executor:<version>` image contains the
executor, released oyzu CLI and crun; pass the release notes' digest reference
to the manager's `--image` flag. The image currently supports linux/amd64
(the pinned public oyzu release has no Linux arm64 CLI). See
[the image build instructions](../deploy/README.md) for pins and verification.


Configured in platform `deploy/ovh-farm` (Ansible), not in this repository:

- `oyzu-pool-server.service` (systemd, its own user, `ReadWritePaths` the state
  directory, reads the config and key).
- `tailscale serve --service=svc:pool --https=443 http://127.0.0.1:8480`, so
  callers reach `https://pool.taild79a0f.ts.net` with tailnet identity headers.
  Access follows the canonical [platform tailnet policy](https://github.com/oyzuai/platform/blob/main/deploy/tailnet/policy.hujson),
  including its service and node-tag rules; do not add an independent pool ACL.
- One Fleet manager (`--driver container`, rootless Podman socket as the
  engine, `--egress enforce`, `--concurrency 2`, `--image` pinned by digest),
  enrolled against the public HTTPS origin with the enrollment token.
- The executor image uses the execution base plus a released or source-bootstrapped
  `oyzu` CLI and `oyzu-executor`, pinned together by image digest. The current
  candidate's full isolated Go build and terminal/Actions acceptance remain
  pending. Earlier sandbox or Node prerequisites do not establish that result.
- The GitHub Actions runners on build01 stay as they are; the pool's two slots
  are in addition.

Podman4.9's compatibility API needs an engine-side file for Fleet's fixed
seccomp policy and native mask/unmask options. The adapter qualifies only a
directly-bound Linux Podman process with the manager's host UID, a verified
rootless UID mapping, host PID namespace and root filesystem. Different mount
or user namespaces require a kernel-backed check that the daemon sees the same
private profile directory/file inodes and fixed bytes. The trusted executable
and process start time are checked as well. Remote, forwarded and ambiguous socket-activated
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

Qualified Podman4.9 also needs a managed namespace anchor: its rootless network
cleanup can destroy the shared bridge namespace when a gateway detaches its
last job network as the sole remaining bridge container. Fleet starts one
nonroot `/bin/sleep infinity` anchor from the same pinned image before the
gateway, with a read-only root, fixed sandbox, no mounts, ports or credentials,
32 MiB memory, 0.1 CPU and 16 processes. Actual bridge allocation, OCI controls,
process and network-namespace identity are inspected and included in the opaque
runtime readiness fingerprint. Podman's native default endpoint name `podman`
and compatibility alias `bridge` are resolved to the inspected bridge definition
ID, with matching container/IP membership required. Missing, stopped, replaced or
unobservable anchors revoke local authority and block admission and network disconnects;
Fleet does not silently replace them under an accepted proof. Restart the
drained manager to establish a new pair and repeat qualification.

After job/probe drain, bounded shutdown removes job networks, confirms gateway
removal, then removes the anchor. An uncertain gateway removal retains the
anchor and reports failure. Reaping preserves the current pair and removes
only owned stale pairs in that order. Docker uses its ordinary gateway path.

Each outer job container retains Fleet's private writable copy-on-write root
and its own writable `/work` volume; these are removed with that job. The
isolated inner Oyzu operation keeps its read-only root/protected tool mounts.
The runtime fingerprint and allocation inspection measure the outer policy
explicitly, including its actual OCI root setting on Podman. Anchors, gateways
and probes retain read-only roots. Podman may report `Config.Image` as a local tag even when
created by digest: qualification checks the native manifest digest, the image's
exact RepoDigest and matching actual image configuration ID instead of trusting
that tag. Anchor environment and labels include only the pinned image defaults,
Fleet's ownership labels and the fixed engine-generated container/hostname values.

The pool admits claims only after the enrolled manager reports
`oyzu.io/isolation=container`, `oyzu.io/egress=enforced` and
`oyzu.io/untrusted=accepted`. Reports are refreshed every ten seconds; missing,
negative or thirty-second-old qualification yields zero demand and no claim,
even if slots are ready for trusted work. A failed local egress self-test cannot
authorize these jobs. The server timestamps qualification on receipt.

Affected builds fetch the exact requested head and baseline commits with depth
one and complete trees/blobs, so the isolated CLI can compare the baseline
without source credentials or silently falling back because its objects are
absent. An unavailable requested baseline fails checkout.

Task names are resolved by the checked-out Oyzu CLI, including qualified and
native tasks, through the fixed `oyzu run --isolated <task>` command. Resolver
or isolation errors finish as failed with the CLI diagnostics; the executor
does not infer task availability from the root TOML or fall back to host execution.

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
key. Job token tests cover Actions push/PR claims, absent Actions facts,
tailnet and snapshot sources, issuer persistence across restart and a JWKS
signature round trip. Tests inject only generated App signing keys and local
GitHub responses; they need no live App credential. Run
`oyzu exec -- go test -race ./poolserver ./cmd/pool-server` and
`oyzu exec -- go vet ./poolserver ./cmd/pool-server` on Linux.
The real proof is the one the proposal names, run on build01.

For the dedicated UID1002 Podman4.9 prerequisite, a compiled
`manager/container` test binary runs `-test.run=^TestPodmanEffectiveSandbox$
-test.v` with `XDG_RUNTIME_DIR=/run/user/1002`,
`FLEET_PODMAN_PROOF_SOCKET` naming that user's direct service and
`FLEET_PODMAN_PROOF_IMAGE` naming the fully qualified immutable base-image
RepoDigest. It creates and removes only its named proof containers, checks the
actual OCI and effective kernel controls, and rejects an added proc mask.
This qualifies the sandbox adapter; it does not prove an isolated Oyzu build.
