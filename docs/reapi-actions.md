# Isolated action workloads

Fleet's action-workload extension supports platform's standard remote execution
service. The platform admits a source-free command and input graph, then assigns
one job and attempt to an eligible executor. The executor supplies the files to
an isolated action runtime and returns outputs through the same live assignment.

Status: implementation starting in [#60](https://github.com/oyzuai/fleet/issues/60)
under [platform's approved design](https://github.com/oyzuai/platform/pull/716).
No action runtime or client interoperability is claimed by this initial record.

## Responsibilities

Platform owns protocol parsing, scoped authorization, action admission, verified
content and durable operation completion. Fleet owns allocation, typed workload
dispatch, the worker lease and runtime termination. Native source-based jobs keep
their existing source and Oyzu-command contract.

An action assignment is distinct from a native job. A missing runtime, unsupported
workload or incomplete authority refuses the action; it never dispatches the
action as a native build or host command. An executor's action capability must
match a real configured isolation runtime.

## Runtime boundary

The first runtime is a trusted host-side executor controlling an isolated Linux
container through the existing engine contracts. Action code receives only its
private input/work files, admitted image/argv/environment and declared output
locations. It receives no worker token, Docker socket, host home, control files,
broader tenant data or host-network fallback. The initial egress profile is no
network. Requested image and execution requirements are server-selected and
immutable before dispatch.

Cancellation or lease loss stops the action runtime. Completion must distinguish
a process exit from service failure and must not report confirmed termination
until the container is observed stopped. Late attempts cannot publish results.

## Verification

Focused executor/runtime checks cover dispatch, lease binding, missing-driver
refusal, bounded files and process termination. The real Bazel execution and
Oyzu cache acceptance proof is owned by
[platform #718](https://github.com/oyzuai/platform/issues/718). Unit fixtures
alone do not establish runtime isolation or REAPI conformance.
