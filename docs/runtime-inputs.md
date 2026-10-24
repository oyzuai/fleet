# Private inputs for isolated native actions

The executor transports an admitted build's private file mappings to its native
actions through the existing bounded stdin request. The self-contained
[client contract](https://github.com/oyzuai/oyzu/blob/feat/runtime-credential-bindings-20261024/docs/contracts/runner-v1/runtime-inputs.md)
owns the descriptor. This implementation is in progress; the connected native
proof remains pending.

Only the authenticated executor creates that descriptor, after the ordinary
job Secret request and exact mapped-variable check. It binds the actual job and
attempt to the private directory and file-variable names. File contents never
enter the admitted plan or request JSON. Isolated native inputs currently accept
file mappings only; an environment-value mapping refuses that execution mode.

For a slice with an enforced egress gateway, Fleet also serves its existing job
proxy on a private mode-0600 `egress.sock` in that directory. A socket-aware
client inside a network-denied action can use ordinary HTTP proxy traffic over
this socket. Fleet supplies the loopback proxy authentication internally, and
the same job proxy and gateway still check every destination. This does not
enable direct action networking, arbitrary socket mounts or a new policy engine.

The engine validates the private descriptor and mounts it read-only at a fixed
path. Unsupported engines reject the new required fields; there is no weaker
delivery retry. The new paired consumer is tracked in
[Oyzu #945](https://github.com/oyzuai/oyzu/issues/945) and
[draft #946](https://github.com/oyzuai/oyzu/pull/946).

The executor closes its proxy socket and removes task-owned files when the job
finishes. This is lifecycle cleanup, not secure erasure: the host or arbitrary
authorized workload may retain a copy of bytes it already received. Existing
server authorization, lease, release, egress and artifact-admission checks remain
independently required.
