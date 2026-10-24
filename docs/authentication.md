# Manager and executor authentication

This guide describes Fleet's current client lifecycle at revision `06951a0`.
The public
[runner protocol](https://github.com/oyzuai/oyzu/blob/main/docs/contracts/runner-v1/openapi.yaml)
owns endpoint/payload definitions. This documentation review ran no new live
server, cloud or isolation qualification. Examples and credentials in that
contract are synthetic.

## Separate authorities

The manager's infrastructure identity provisions and removes compute. Its Oyzu
credential authenticates participation in an enrolled pool. An executor's
credential is limited to an assigned job attempt. Build code receives only the
capabilities deliberately supplied for that job, such as a dependency session or
an outbound job assertion; it must not inherit the manager's cloud credentials,
private key or the executor's runner bearer.

Only Oyzu issues the manager, startup and job credentials. The manager's Ed25519
key signs login/rotation assertions, not executor credentials. Authentication
attributes a manager and its executors; it is not independent proof of runtime
integrity or permission to submit arbitrary jobs.

## Enrollment, login and assignment

1. An operator supplies a single-use enrollment credential for the intended pool.
   The manager generates and keeps its private key locally and registers its
   public half using `enroll`. The enrollment credential is bootstrap, not the
   ongoing login credential.
2. The manager uses `token` with a signed `private_key_jwt` assertion and a fresh
   identifier. The server accepts each assertion once and issues a ten-minute
   manager bearer. Keep server/audience configuration aligned; a key or client
   assertion is not a token that can be presented as a job credential.
3. The manager reports capacity and claims eligible work. A claim returns one
   assignment/attempt and a single-use five-minute startup bearer.
4. The selected driver starts an executor with only its startup material. The
   executor spends that bearer at `job/start`, receiving the assigned job and its
   job credential. A second exchange or late startup must fail.
5. The executor fetches the assigned source, performs supported job operations,
   heartbeats, uploads masked logs and reports the outcome. It does not select
   another account, job or attempt by changing a payload.

See [running the manager](../README.md#running-the-manager) and
[driver support](../README.md#executor-images) before provisioning a host. The
shipped binary selects container, Kubernetes or process; cloud VM adapters remain
library code requiring integration. A configured infrastructure role does not
replace Oyzu enrollment.

## Execution decision reference

The draft [runner-v1 startup contract](https://github.com/oyzuai/oyzu/pull/981)
adds the server-issued opaque `execution_trust_decision` reference. A
trust-governed build claim supplies a canonical lowercase, nonzero UUID. Fleet
carries it through the driver to the executor and echoes it without constructing
decision facts. Its typed startup request carries readiness alongside the
reference. Shape validation happens before spending startup material; a server
refusal has no fallback that drops the reference. Other assignments may omit it
only when the server does not require the binding.

The reference grants no execution, resource-use or credential authority. Current
one-use startup, assignment and readiness checks remain mandatory. The server
must reject missing, unknown, substituted, stale or wrong-attempt required
references before issuing a job credential.

Bounded local tests exercise the actual HTTP client and a real process-driver
child running the actual executor command. The controlled HTTP server refuses
before issuing work. Container, Kubernetes and VM handoff tests use their
existing fake infrastructure. These qualify transport only; connected server
binding, native Secret consumption, host integrity and deployment remain
unqualified. GitHub Actions remains intentionally disabled/unrun.

## Renewal and rotation

Executors heartbeat every 30 seconds. The running lease is two minutes, and the
job bearer expires fifteen minutes after its last successful renewal. Heartbeat
extends the existing opaque bearer on the server; the executor does not locally
edit an expiry or mint an offline replacement. Loss of live attempt authority
means it must stop making ordinary job calls.

The manager registers its next key using a rotation assertion signed by its
current key, normally every 30 days. At most two active keys overlap. First login
with the new key retires the previous key; ordinary retirement does not imply
that already-issued credentials are revoked. Rotation preserves manager identity.
After a compromise, an operator must use the server's revocation/rekey procedure;
merely rotating a local file or deleting a consumed enrollment token is not
manager-level revocation.

## Completion, revocation and uncertain outcomes

The server enforces current manager/key and job attempt/lease authority. Credential
failure is the contract's 401, without distinguishing unknown, expired, consumed
and revoked secrets. Manager credentials can be renewed by a fresh login while
the manager remains enrolled and its key remains active; an executor cannot
authenticate a lost attempt again by borrowing the manager's bearer.

After `job/finish`, ordinary job authority ends. Only the token that finished the
attempt retains a bounded exception for `job/logs` and `job/logs/finish`, for up
to fifteen minutes. Manager/key revocation still rejects this log-only authority.
It cannot fetch source, obtain new credentials or report another job outcome.

An issuance/finish request can succeed while its response is lost. Follow the
operation's specified retry/idempotency behavior and preserve the assignment
identity; do not infer failed execution or launch a replacement from a network
error alone. A 503 follows bounded backoff, not offline credential creation.

Revoking runner authority stops fresh server access; it does not establish that
a process stopped or retract completed effects. An already-issued outbound
assertion may remain valid at its relying party, and credentials exchanged there
have their own lease/revocation mechanism. Do not promise immediate cloud
revocation from the lifetime of the runner credential.

## Isolation and custody limits

The process driver runs build code as the manager's OS user, which can read its
private key and state. Use it only for trusted code. Containers/pods have separate
credential delivery and network boundaries, but a successful login is not proof
that the host, daemon, metadata path or cluster policy is safe. Preserve the
existing [egress controls and self-test](../README.md#egress-control) and do not
infer untrusted-work support for another driver.

Do not put manager, startup or job bearers in command-line diagnostics or logs.
Use the driver's intended isolated startup channel. Preserve state-directory
permissions, TLS verification and the existing token masks; masking is not an
isolation boundary. Upstream signing or publication credentials require their
separately authorized protected runtime, not an ordinary authenticated build.

## Implementation and verification handoff

The existing protocol/lifetimes above are the baseline. Implementation starts
with finite client regressions and integration coverage, not replacing enrollment
with general user login or teaching the manager to mint runner credentials.
The runner OpenAPI remains authoritative; any optional correlation extension
updates that existing contract and all producers/consumers together, without a
successor version. Existing authentication fields do not double as trace context.

| Planned acceptance ID | Required observable result |
| --- | --- |
| FLEET-AUTH-01 | A real enrollment/login/claim/start sequence reaches one assigned execution; wrong audience, replayed assertion and consumed/expired startup material grant no access |
| FLEET-AUTH-02 | Heartbeat extends the same current job bearer while the attempt is live; lost/revoked manager/key/attempt authority prevents fresh ordinary operations and renewal |
| FLEET-AUTH-03 | Key rotation preserves manager attribution and distinguishes retirement from compromise revocation; lost login/finish responses do not create a new assignment or business effect by assumption |
| FLEET-AUTH-04 | Finish removes ordinary authority; only the finishing bearer has bounded log drain, and current manager/key revocation still denies that path |
| FLEET-AUTH-05 | Manager/executor spans and safe outcome metrics preserve job/attempt causation where supported; credentials/build content never enter administrative telemetry, and exporter outage does not block renewal |

Own local assertion/client/manager/executor behavior in this repository. Run
`oyzu build --full` for changed client code and keep focused checks with
`assertion`, `runnerclient`, `manager` and `executor`. Real server-side replay,
revocation and database behavior require a connected protocol integration in the
server owner; a scripted local response cannot qualify those guarantees. Record
actual commands, Fleet/server/fixture revisions, driver, clock/lease settings and
redacted outcomes in the implementation evidence. These are planned criteria,
not tests executed by this documentation review.

First connected proof uses an enrolled container manager and one pinned,
nonproduction build fixture, with no VM driver or external cloud prerequisite.
Observe enrollment through ordinary completion, then revoke live authority in a
second attempt and exercise post-finish log limits independently. Broader Windows,
cloud VM, untrusted-host and isolation qualification stay explicit follow-ups;
process mode retains its trusted-code restriction. Do not forward platform
exporter credentials or manager/job bearers into the customer's build process.

## Implementation status

Added October 20, 2026 with the platform's IAM-6 managed-execution package. The
wire protocol and every lifetime above are unchanged. This repository now has
optional, credential-free [telemetry](telemetry.md) for the manager and executor:
spans and metrics over OTLP/HTTP with an attribute allowlist, a bounded
non-blocking queue, environment settings that are consumed at start, scrubbed
child environments (a build, a kind and the Docker CLI never see an endpoint or
trace parent), and a trace parent handed to a process-driver executor so its
spans join the manager's. The client sends a `traceparent` to runs only as
optional correlation; runs links to it and never adopts it, and no
authentication field is trace context.

The platform's `iam-fleet-proof` task built this tree's manager and executor and
ran them in process mode against a runs service built from the platform tree,
with real Keycloak, Postgres and the OpenTelemetry stack, and a trusted build
fixture. It ran once, directly (not through `oyzu run`), and passed all 77 of its
checks. What that run covered, by acceptance ID, and what it did not:

| ID | Covered by the connected run | Not covered |
| --- | --- | --- |
| FLEET-AUTH-01 | Real enrollment, login, claim and start reaching one assigned execution; a replayed enrollment token and a consumed startup token granted nothing | Wrong audience and a replayed login assertion at the connected level; an expired startup token |
| FLEET-AUTH-02 | Heartbeat extended the same job bearer; manager revocation, key revocation, lease loss with requeue and run cancellation each denied every fresh ordinary route with the uniform 401 | Behavior under a slow or partitioned server |
| FLEET-AUTH-03 | A manager rotated its key and kept its attribution; `rekey --revoke-now` revoked everything issued under the old keys while a key enrolled with the rekey token had fresh authority | Lost login or finish responses |
| FLEET-AUTH-04 | After finish only the finishing bearer's `job/logs` and `job/logs/finish` worked, and manager and key revocation denied them | The full fifteen-minute expiry |
| FLEET-AUTH-05 | Spans and metrics from the manager and executor in Tempo and Prometheus next to runs'; no credential in any signal, process output or the build's output (the scan covered 58 issued values); unit tests show a Collector outage never blocks renewal | An outage during the connected run; the container and Kubernetes drivers, which export no executor telemetry |

The process driver ran only the trusted fixture. The proof did not exercise the
container, Kubernetes or VM drivers, Windows, untrusted code or the secrets
route, and it found no defect in this repository's client. The one pair of
variables a build sees that look like credentials, `OYZU_ID_TOKEN_URL` and
`OYZU_ID_TOKEN_REQUEST_TOKEN`, belongs to the executor's existing loopback
ID-token broker: random per job, good only against that loopback port, never the
job bearer. The acceptance IDs above remain planned criteria, not qualified.
