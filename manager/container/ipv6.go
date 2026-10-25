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
// a long-lived manager, that answer is checked again for every container. A
// clear answer that the kernel has IPv6 is kept until the manager restarts;
// a probe that fails keeps the sysctls for that container only.
func (d *Driver) ipv6Sysctls(ctx context.Context, labels map[string]string) (map[string]string, error) {
	disabled, err := d.kernelIPv6Disabled(ctx, labels)
	if err != nil || disabled {
		return nil, err
	}
	return map[string]string{"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}, nil
}

// kernelIPv6Disabled runs `gateway probe-ipv6` in a network-less container
// on the engine. Only its exiting 0 with exactly egressgate.IPv6Disabled as
// its output is true. An error means the caller's context ended or the
// engine could not create or start the probe.
func (d *Driver) kernelIPv6Disabled(ctx context.Context, labels map[string]string) (bool, error) {
	if d.ipv6Available.Load() {
		return false, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, ipv6ProbeTimeout)
	defer cancel()
	// Named so that Reap leaves it alone while it runs.
	name := fmt.Sprintf("oyzu-%s-ipv6-probe-%d", d.managerLabel(), d.ipv6Seq.Add(1))
	d.mu.Lock()
	if d.ipv6Probing == nil {
		d.ipv6Probing = map[string]bool{}
	}
	d.ipv6Probing[name] = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.ipv6Probing, name)
		d.mu.Unlock()
	}()
	id, err := d.Engine.CreateContainer(probeCtx, name, Spec{Image: d.Image, Cmd: []string{d.Command[0], "gateway", "probe-ipv6"}, User: d.user(), Network: "none", Labels: labels, ReadOnly: true, PidsLimit: 8})
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
		logs, err = d.Engine.ContainerLogs(probeCtx, id, 16)
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	answer := ""
	if err == nil && code == 0 {
		answer = string(logs)
	}
	switch answer {
	case egressgate.IPv6Disabled + "\n":
		return true, nil
	case egressgate.IPv6Available + "\n":
		d.ipv6Available.Store(true)
		return false, nil
	}
	d.log().Warn("the IPv6 probe gave no clear answer; keeping the IPv6-disabling sysctls", "exit", code, "error", err, "output", string(bytes.TrimSpace(logs)))
	return false, nil
}
