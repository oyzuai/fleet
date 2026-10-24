# Private inputs for isolated native actions

The executor transports an admitted build's private file mappings to its native
actions through the existing bounded stdin request. The self-contained
[client contract](https://github.com/oyzuai/oyzu/blob/feat/runtime-credential-bindings-20261024/docs/contracts/runner-v1/runtime-inputs.md)
owns the descriptor. The first paired Linux amd64 Docker native proof passed;
broader runtime and platform qualification remains incomplete.

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

## Measured consumer proof

`oyzu run runtime-inputs-proof` requires `FLEET_NATIVE_CLI` to identify a compiled
candidate. With optional `FLEET_RUNTIME_PROOF_RECEIPT` set to an absolute path,
it retains only the nonsecret admitted plan, finalized manifest and outcomes.
Routine unit tests skip this selected integration proof when no candidate is
provided; the registered task refuses to skip it.

Fleet harness `aa5b5000220643a26136e4d69a970ae26ba05f69` passed against compiled
Oyzu `2c48a31fbd19f2a743cc6f23a584db714e5e5371`, binary SHA-256
`3da3ebf4777ff22b97cce6ba7b5f1ae8cf36f5a06670484bb0fdbd596d1e8ef6`.
The 370.56-second native check obtained one authenticated HTTP receipt through
the actual proxy/gateway, native JUnit with one pass and no skips, and a
manifest-matching executable that ran with `runtime file proof` output. An
actual subsequent execute without the required input failed its native test;
a mismatched attempt was refused before action execution. The affected target
used no action-result reuse or storage.

The separate actual gateway check allowed its configured destination, refused a
different destination and forwarded no proxy-authentication credential. Provider
and DNS mapping were controlled local fixtures. This does not qualify hosted
providers, HTTPS destinations, arbitrary TCP clients, other hosts or the complete
platform Secret-authorization flow. See the
[attributed consumer evidence](https://github.com/oyzuai/oyzu/blob/feat/runtime-credential-bindings-20261024/docs/qualification/runtime-inputs.md)
for input, plan, image, artifact and report identities and the earlier failures.
