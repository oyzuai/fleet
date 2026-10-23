# Container syscall policy input

`docker-default.json` is an unmodified snapshot of
[moby/profiles seccomp/default.json](https://github.com/moby/profiles/blob/6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef/seccomp/default.json),
revision `6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef`, SHA-256
`6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6`.
Its Apache-2.0 license is retained in `LICENSE`. This data is separate from
Fleet's implementation license and is not Wardyn code.

Fleet's `sandbox.go` derives the fixed daemonless OCI profile from this input.
It retains default-deny behavior and adds the bounded namespace setup rules
listed there. The profile's applied options and filesystem controls are part of
the readiness runtime fingerprint and are inspected before startup handoff.
