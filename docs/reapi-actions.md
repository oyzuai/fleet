# Isolated action workloads

Fleet's action-workload extension supports platform's standard remote execution
service. The platform admits a source-free command and input graph, then assigns
one job and attempt to an eligible executor. The executor supplies the files to
an isolated action runtime and returns outputs through the same live assignment.

The typed action client and Linux container runtime implement the first bounded
profile for [#60](https://github.com/oyzuai/fleet/issues/60), under
[platform's approved design](https://github.com/oyzuai/platform/pull/716).
Runtime isolation and client interoperability require the real execution proof
described below; unit fixtures do not establish either claim.

## Responsibilities

Platform owns protocol parsing, scoped authorization, action admission, verified
content and durable operation completion. Fleet owns allocation, typed workload
dispatch, the worker lease and runtime termination. Native source-based jobs keep
their existing source and Oyzu-command contract.

An action assignment is distinct from a native job. A missing runtime, unsupported
workload or incomplete authority refuses the action; it never dispatches the
action as a native build or host command. An executor's action capability must
match a real configured isolation runtime.

`runnerclient.Job.Kind == "action"` selects `ActionAssignment`; it never uses
repository, source, native plan, secret or Oyzu-command preparation. Assignments
carry the server-selected instance/operation binding, immutable image, explicit
argv/environment, working directory, typed output declarations, timeout and positive
CPU/memory/process and workspace bounds. Input files carry bytes, SHA-256 identity, size and
executable mode. Empty directories and contained relative symlinks are preserved. Input paths are relative to
the private input root; output paths are relative to the command's working
directory, and completion preserves those logical output paths.

The live job token calls `POST runner/v1/job/action/inputs` and
`POST runner/v1/job/action/finish`. Platform must revalidate the current
job/attempt, lease and server-owned input closure on both routes. Assignment
instance/operation fields do not grant authority. A completion separates process
exit code, stdout/stderr and output bytes from canonical service error codes.
A nonzero process exit is a process result. It is not an infrastructure error.

## Runtime boundary

The first runtime is a trusted host-side executor controlling an isolated Linux
container through the existing engine contracts. Action code receives only its
private input/work files, admitted image/argv/environment and declared output
locations. It receives no worker token, Docker socket, host home, control files,
broader tenant data or host-network fallback. The initial egress profile is no
network. Requested image and execution requirements are server-selected and
immutable before dispatch.

The ordinary executor has no action driver. A trusted embedding injects an
`executor.ActionDriver` into `Config` or `CommandWithActionDriver`. The standalone
process manager enables this explicitly with `--driver process --action-engine
<endpoint>`, using a dedicated pool eligible for those actions. It probes the
Linux engine's required seccomp support before reporting
`oyzu.io/action-runtime=linux-container` and all four `oyzu.io/action-feature-*`
facts from `runnerclient.ActionFeatures`. Every action requires every feature,
since its output kinds are unknown before execution. The executor separately
checks the engine and installed static Linux/amd64 helper before advertising
`action_runtime` and `action_features` at startup. Runs refuses missing or unknown
features before issuing a job credential, inputs or runnable assignment.
Other process, container and Kubernetes executors do not gain this capability.
Process pools retain their existing trusted-host restrictions for native jobs.

The manager passes its explicit endpoint to the standalone executor through
`FLEET_ACTION_ENGINE`; the executor removes that variable before dispatch. A
container gets a fresh named tmpfs work volume with image-volume copying disabled,
UID/GID 1000, network `none`, read-only root, no capabilities and the shared
Fleet syscall/no-new-privileges policy. The runtime overrides image ENTRYPOINT
and CMD with the admitted argv, verifies the actual allocation before start,
and refuses extra mounts or missing controls. Images must already be provisioned
by the operator under the admitted SHA-256 reference. Actions do not pull images.
This action profile requires Docker's Linux named-tmpfs mechanism; the existing
Podman adapter does not advertise it. Windows-hosted workers remain unqualified.

The workspace defaults and ceilings are 64 MiB and 32768 inodes, enforced by
the volume's `size` and `nr_inodes` options, including intermediate and undeclared
writes. There is no unbounded local-volume fallback. A stopped preparation
container receives only the installed static executor in a private bootstrap
volume through the engine API. Preparation never starts. A credential-free
`hold-workspace` entry point keeps the tmpfs mounted through input copy, user
start, confirmed termination and whole-workspace collection. It runs before
configuration, environment, logging, engine and credential loading. The holder
gets read-only root/bootstrap/workspace, UID/GID 1000, no network, image lifecycle
hooks or logs, 64 MiB memory with equal swap, 32 PIDs and 50000000 NanoCPUs.
The user receives only the writable workspace and its original admitted argv.

The nominal reservation is action memory plus workspace bytes, 64 MiB holder
memory and 64 MiB inode allowance. Host admission adds 320 MiB for bounded
bootstrap and in-memory transfer/lifecycle space, plus holder CPU and PIDs.
All sums use checked signed-int64 arithmetic. Runs compares the whole host
reservation to each manager slot's share of reported engine memory and CPU.
These use distinct `oyzu.io/action-memory-bytes` and `oyzu.io/action-cpu` facts;
the native process facts retain the executor host's values.
Core's action-memory maximum retains its meaning; no tenant aggregate budget
is introduced. Missing capacity or an unrepresentable reservation refuses work.

This first profile bounds file bytes to 16 MiB per direction, combined
stdout/stderr to 1 MiB, JSON transfer to 32 MiB and directory entries to 10,000.
The input archive also counts implicit working/output parent directories and
its root against the entry limit, and bounds actual tar bytes to 32 MiB before
allocating engine resources. The private work output archive is also bounded.
Timeout is at most one hour. Physical paths must be canonical and have real
directory parents. Relative link targets retain raw `.`/`..` components and
repeated separators, with 4096 bytes each, 1 MiB total and 40 dereferences per
lookup. Component resolution expands targets before later parents and refuses
root escapes, cycles and traversal through files. Dangling modern links remain
links; legacy file/directory links require the declared referent kind. Working
directories and output parents may be contained directory aliases. Missing
working directories and dangling output parents refuse execution.

The complete stopped archive is bounded and parsed in memory before selection;
it is never extracted on the executor host. Hardlinks, special files, duplicate
entries and physical link/file ancestors refuse the snapshot. Unselected image
links remain inert private metadata. Selected outputs preserve logical paths,
empty directories, executable bits and links. Metadata-only `workspace_nodes`
lets Runs verify undeclared link referents without transferring their file bytes.

Cancellation or lease loss stops the action runtime. Completion must distinguish
a process exit from service failure and must not report confirmed termination
until the container is observed stopped. Late attempts cannot publish results.
The worker keeps lease watching active through transfer and suppresses completion
when the lease is lost. Platform's atomic live-attempt check remains required
against races during completion. Cancellation, timeout and ambiguous start/wait
failures stop the container and inspect its state before acknowledging
termination. Cleanup removes the container and its private work volume;
unrecoverable engine failures are reported as service failures.

The trusted process manager creates a private owner anchor in the existing job
directory before launching an executor. The runtime receives that manager,
job, attempt and directory identity separately from the action assignment and
syncs a resource journal before its first engine allocation. Container and
volume labels bind the same identity and a private random resource name. This
also recovers an allocation whose engine response was lost.

Normal cleanup, `Process.Teardown` and restart `Process.Reap` use that exact
journal and full ownership labels. The journal plans exact user, preparation,
holder, workspace and bootstrap roles before allocation. Cleanup stops and
removes user/preparation, then holder, then both volumes and the journal. A failed cleanup
retains recovery state and holds capacity; an adopted executor's exit follows
the same rule. A configured action process pool releases a failed job only
after successful teardown. Completion cannot confirm termination while cleanup
is incomplete. Resources belonging to other owners are preserved. Recovery
requires the trusted manager and its configured engine connection to return;
there is no immediate-stop guarantee while both manager and executor are down.
Holder loss or an ambiguous engine observation stops the user and discards all
outputs. The holder is never recreated to continue an attempt. Recovery removes
interrupted ephemeral storage; it never resumes its bytes.

## Verification

Focused executor/runtime checks cover dispatch, lease binding, missing-driver
refusal, bounded files and process termination. The real Bazel execution and
Oyzu cache acceptance proof is owned by
[platform #718](https://github.com/oyzuai/platform/issues/718). Unit fixtures
alone do not establish runtime isolation or REAPI conformance.

The [crash recovery reproducer](../testdata/action-crash-proof/main.go) takes a
locally cached immutable Linux image as its argument. On a trusted controller
with engine access, it observes a live action, kills only its own executor
helper, reconstructs `Process` and invokes `Reap`. It checks that the recorded
action and volume are removed, a separate task-owned foreign sentinel survives,
and capacity becomes reusable. The reproducer removes its sentinel and scratch
directory on exit. Its controller engine connection must never be mounted into
the action child.
