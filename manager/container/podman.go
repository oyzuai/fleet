package container

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

// Podman4's Docker compatibility API treats seccomp as a filename and ignores
// MaskedPaths/ReadonlyPaths. These fixed native security options remove the
// default proc restrictions and restore only Fleet's two fixed sysfs masks.
// /sys must remain a read-only OCI mount; inspection verifies the effective
// controls instead of accepting the echoed HostConfig fields.
func podmanSecurityOptions(path string) []string {
	options := []string{"no-new-privileges:true", "seccomp=" + path, "mask=/sys/firmware:/sys/devices/virtual/powercap"}
	// ALL also changes Podman's cgroup mount to writable. Remove only its
	// measured default masks/readonly proc paths; preserve read-only cgroups.
	for _, p := range []string{"/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi", "/sys/firmware", "/sys/fs/selinux", "/sys/dev/block", "/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"} {
		options = append(options, "unmask="+p)
	}
	return options
}
func podmanEchoedOptions(options []string, path string) bool {
	return sameStrings(options, []string{"no-new-privileges", "seccomp=" + path}) || sameStrings(options, []string{"no-new-privileges:true", "seccomp=" + path})
}
func (d *Docker) podmanOCIPath(ctx context.Context, id string) (string, error) {
	// Compat inspect omits OCIConfigPath and native mask/unmask options. Obtain
	// the actual engine-generated runtime spec from native inspect instead.
	native := Docker{client: d.client, base: strings.TrimSuffix(d.base, apiVersion) + "v4.9.0/libpod", callTimeout: d.callTimeout}
	var out struct{ OCIConfigPath string }
	if err := native.do(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out); err != nil {
		return "", err
	}
	return out.OCIConfigPath, nil
}
func (d *Docker) prepareSandbox(ctx context.Context) error {
	d.adapterMu.Lock()
	defer d.adapterMu.Unlock()
	if d.engineDetected {
		return nil
	}
	var version struct {
		Components []struct{ Name string }
		Version    string
	}
	err := d.do(ctx, "GET", "/version", nil, nil, &version)
	if err != nil && !isStatus(err, 404) {
		return err
	}
	for _, c := range version.Components {
		if c.Name == "Podman Engine" {
			d.podman = true
		}
	}
	if d.podman {
		if d.unixPath == "" {
			return errors.New("Podman sandbox requires a qualified same-host Unix service")
		}
		if !strings.HasPrefix(version.Version, "4.9.") {
			return errors.New("Podman sandbox adapter is qualified for Podman4.9 only")
		}
		p, err := newPodmanProfile(ctx, d.unixPath)
		if err != nil {
			return err
		}
		d.profile = p
	}
	d.engineDetected = true
	return nil
}
