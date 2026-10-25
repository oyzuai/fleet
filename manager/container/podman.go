package container

import (
	"context"
	"errors"
	"strings"
)

// Podman4's Docker compatibility API treats seccomp as a filename and ignores
// MaskedPaths/ReadonlyPaths. These fixed native security options remove the
// default proc restrictions and restore only Fleet's two fixed sysfs masks.
// /sys must remain a read-only OCI mount; inspection verifies the effective
// controls instead of accepting the echoed HostConfig fields.
func podmanSecurityOptions(path string) []string {
	return []string{"no-new-privileges:true", "seccomp=" + path, "unmask=ALL", "mask=/sys/firmware:/sys/devices/virtual/powercap"}
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
