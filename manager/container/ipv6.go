package container

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/oyzuai/fleet/egressgate"
)

// ipv6ProbeTimeout bounds one probe container, start to logs.
const ipv6ProbeTimeout = 30 * time.Second

// ipv6Sysctls returns the sysctls a job or readiness container is created
// with. They turn IPv6 off in its network namespace, link-local included.
//
// A kernel booted with ipv6.disable=1 has no IPv6 for any container and no
// such sysctls, so asking for them only stops every container from starting.
// They are left out when, and only when, the executor image's probe reads
// the engine's own kernel's ipv6.disable setting as 1; the manager's kernel,
// configuration and environment play no part. Since a host can reboot under
// a long-lived manager, that answer is checked again for every container.
// Any other answer, including a probe that fails, keeps the sysctls until
// the manager restarts.
func (d *Driver) ipv6Sysctls(ctx context.Context, labels map[string]string) (map[string]string, error) {
	disabled, err := d.kernelIPv6Disabled(ctx, labels)
	if err != nil || disabled {
		return nil, err
	}
	return map[string]string{"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}, nil
}

// kernelIPv6Disabled runs `gateway probe-ipv6` in a network-less container
// on the engine. Only its printing egressgate.IPv6Disabled and exiting 0 is
// true. An error means the caller's context ended or the engine could not
// create or start the probe.
func (d *Driver) kernelIPv6Disabled(ctx context.Context, labels map[string]string) (bool, error) {
	if d.ipv6Kept.Load() {
		return false, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, ipv6ProbeTimeout)
	defer cancel()
	id, err := d.Engine.CreateContainer(probeCtx, "", Spec{Image: d.Image, Cmd: []string{d.Command[0], "gateway", "probe-ipv6"}, User: d.user(), Network: "none", Labels: labels, ReadOnly: true, PidsLimit: 8})
	if err != nil {
		return false, fmt.Errorf("probe the engine's kernel for IPv6: %w", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer stop()
		_ = d.Engine.RemoveContainer(cleanup, id)
	}()
	if err := d.Engine.StartContainer(probeCtx, id); err != nil {
		return false, fmt.Errorf("probe the engine's kernel for IPv6: %w", err)
	}
	code, err := d.Engine.WaitContainer(probeCtx, id)
	var logs []byte
	if err == nil && code == 0 {
		logs, err = d.Engine.ContainerLogs(probeCtx, id, 4)
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err == nil && code == 0 && string(bytes.TrimSpace(logs)) == egressgate.IPv6Disabled {
		return true, nil
	}
	if d.Log != nil {
		d.Log.Info("keeping the IPv6-disabling sysctls", "probe_exit", code, "probe_error", err, "probe_output", string(bytes.TrimSpace(logs)))
	}
	d.ipv6Kept.Store(true)
	return false, nil
}
