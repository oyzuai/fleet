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
argv/environment, working directory, declared output paths, timeout and positive
CPU/memory/process bounds. Input files carry bytes, SHA-256 identity, size and
executable mode. Empty directories are preserved. Input paths are relative to
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
`oyzu.io/action-runtime=linux-container`. The executor separately probes its
injected runtime before advertising `action_runtime=linux-container` at startup.
Other process, container and Kubernetes executors do not gain this capability.
Process pools retain their existing trusted-host restrictions for native jobs.

The manager passes its explicit endpoint to the standalone executor through
`FLEET_ACTION_ENGINE`; the executor removes that variable before dispatch. A
container gets a fresh named work volume with image-volume copying disabled,
UID/GID 1000, network `none`, read-only root, no capabilities and the shared
Fleet syscall/no-new-privileges policy. The runtime overrides image ENTRYPOINT
and CMD with the admitted argv, verifies the actual allocation before start,
and refuses extra mounts or missing controls. Images must already be provisioned
by the operator under the admitted SHA-256 reference. Actions do not pull images.
Docker and the existing qualified Podman adapter use the same engine contract;
an engine unable to expose the required allocation before execution is refused.

This first profile bounds file bytes to 16 MiB per direction, combined
stdout/stderr to 1 MiB, JSON transfer to 32 MiB and directory entries to 10,000.
The private work archive is also bounded. Timeout is at most one hour. Paths
must be canonical relative portable paths. Links and special files are refused,
including in output archives; archives are parsed in memory and never extracted
onto the executor host. Larger transfer profiles and symlink interoperability
remain outside this first profile.

Cancellation or lease loss stops the action runtime. Completion must distinguish
a process exit from service failure and must not report confirmed termination
until the container is observed stopped. Late attempts cannot publish results.
The worker keeps lease watching active through transfer and suppresses completion
when the lease is lost. Platform's atomic live-attempt check remains required
against races during completion. Cancellation, timeout and ambiguous start/wait
failures stop the container and inspect its state before acknowledging
termination. Cleanup removes the container and its private work volume;
unrecoverable engine failures are reported as service failures.

## Verification

Focused executor/runtime checks cover dispatch, lease binding, missing-driver
refusal, bounded files and process termination. The real Bazel execution and
Oyzu cache acceptance proof is owned by
[platform #718](https://github.com/oyzuai/platform/issues/718). Unit fixtures
alone do not establish runtime isolation or REAPI conformance.
