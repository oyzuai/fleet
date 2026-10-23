# Container build sandbox

The Linux container driver uses one fixed `daemonless-oci-v1` syscall/proc
profile for jobs and their network diagnostics. It supports the rootless OCI
runtime used by Oyzu's admitted worker. The outer container runs as the configured
non-root UID, drops every capability, uses `no-new-privileges`, receives no engine
socket or host mount, and retains its CPU, memory, process and gateway controls.
The outer PID, IPC, UTS and cgroup namespaces remain private; the driver refuses
host/shared namespace modes and user-namespace overrides during inspection.
AppArmor keeps the engine's configuration; an incompatible host policy remains
a failed runtime prerequisite rather than being disabled.

## Syscalls and proc mounts

The profile derives from a pinned Moby default-deny syscall policy. It adds
`clone`, `unshare`, `mount`, `umount2`, `pivot_root` and `sethostname` for rootless
namespace setup. Their kernel namespace/capability checks still apply: an outer
job cannot enter or change a parent namespace. Only `KEYCTL_JOIN_SESSION_KEYRING`
is added for crun's session setup; keyring reads and other operations remain
denied. `setns`, `chroot`, BPF and module-management calls gain no unconditional
permission. The ordinary OCI worker applies its own process restrictions inside
the outer boundary.

Docker's masked/read-only proc submounts prevent a descendant user namespace
from mounting its own private proc. The fixed profile therefore supplies its
own outer path policy: `/sys` is read-only and firmware/powercap remain masked;
proc access is governed by the non-root kernel/DAC checks. The OCI worker mounts
and restricts its own private proc in its separate PID/mount namespace. This
explicitly replaces the former engine-default seccomp/proc-mask assumption;
it is not a promise that those defaults support nested OCI execution.

## Measurement and startup

The syscall policy, capability restrictions, proc/sys path policy and observed
engine security configuration enter the readiness runtime fingerprint. A policy
change needs a fresh measurement. Before startup handoff, the driver checks the
actual allocation's user, dropped/added capabilities, `no-new-privileges`, exact
syscall policy, private namespace modes and path controls in addition to image,
network, DNS and mounts.
The same inspection continues while running. Missing, altered or unconfined
settings fail the binding; an image label cannot assert them into existence.

There is no user-supplied syscall document, profile switch or extra capability
flag. The existing authenticated claim/start lifecycle still owns execution
authority. Readiness does not grant access to source or other job resources.

## Qualification and provenance

On Linux amd64, Docker 28.4.0 and the pinned crun 1.24, the real native OCI test
passes with empty outer/inner capability sets, no privilege escalation, a private
PID/network namespace and a produced output. Keyring read and changing the outer
network namespace are refused. Actual engine configurations with the default
syscall policy or a changed proc mask are recognized as different allocations.
The existing seven-check egress suite also passes under this exact profile,
including deliberately ineffective TCP/DNS controls and replacement fencing.
Other host policies and architectures need their own runtime result; these
checks do not qualify a complete remote contribution or independent host trust.

```sh
OYZU_CRUN=/path/to/the/runtime/provisioned/by/oyzu/install \
  oyzu run container-runtime-proof
oyzu run readiness-container-proof
```

The unmodified policy snapshot, upstream revision, hash and Apache-2.0 license
are in [profiles](../manager/container/profiles/README.md). Apache-2.0 permits
adaptation and commercial distribution with its notices retained; this data
keeps its own license alongside Fleet's FSL implementation. No Wardyn code or
dependency is used. crun remains an existing Oyzu-managed runtime; the disposable
test uses the normally installed binary.
