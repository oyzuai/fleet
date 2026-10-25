package container

import (
	"context"
	"errors"
	"net"
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
	out, err := d.podmanContainer(ctx, id)
	return out.OCIConfigPath, err
}

type podmanContainerObservation struct{ OCIConfigPath, ImageDigest string }

func (d *Docker) podmanContainer(ctx context.Context, id string) (podmanContainerObservation, error) {
	// Compat inspect omits OCIConfigPath and native mask/unmask options. Obtain
	// the actual engine-generated runtime spec from native inspect instead.
	native := Docker{client: d.client, base: strings.TrimSuffix(d.base, apiVersion) + "v4.9.0/libpod", callTimeout: d.callTimeout}
	var out podmanContainerObservation
	if err := native.do(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out); err != nil {
		return out, err
	}
	return out, nil
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

type podmanNetworkObservation struct {
	ID,Name,Driver string
	Internal bool
	Containers map[string]struct {IPv4Address string}
}
// Podman4.9 inspect reports network names in the compatibility NetworkID
// field. Resolve them through the same engine and verify the actual container
// endpoint before using the network-definition ID in a measurement.
func (d *Docker) inspectPodmanNetwork(ctx context.Context,id,name,address string) (podmanNetworkObservation,error) {
	var n podmanNetworkObservation
	if name==""||address=="" {return n,errors.New("missing Podman network endpoint")}
	if err:=d.do(ctx,"GET","/networks/"+url.PathEscape(name),nil,nil,&n);err!=nil {return n,err}
	endpoint,ok:=n.Containers[id]
	ip,_,err:=net.ParseCIDR(endpoint.IPv4Address)
	if n.ID==""||n.Name!=name||n.Driver!="bridge"||!ok||err!=nil||!ip.Equal(net.ParseIP(address)) {return n,errors.New("Podman actual network identity or endpoint differs")}
	return n,nil
}
