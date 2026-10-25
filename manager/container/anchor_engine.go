package container

import (
	"context"
	"errors"
	"maps"
	"net/url"
	"slices"
	"strings"
)

func (d *Docker) NamespaceAnchorRequired(ctx context.Context) (bool, error) {
	if err := d.prepareSandbox(ctx); err != nil { return false, err }
	if d.podman { if err := d.profile.validate(); err != nil { return false, err } }
	return d.podman, nil
}

func (d *Docker) InspectNamespaceAnchor(ctx context.Context, id string, spec Spec) (anchorIdentity, error) {
	var identity anchorIdentity
	required, err := d.NamespaceAnchorRequired(ctx)
	if err != nil { return identity, err }
	if !required { return identity, errors.New("namespace anchor requires qualified Podman4.9") }
	var out struct {
		ID, Name, Image string
		Config struct { Image, User, WorkingDir string; Cmd, Entrypoint, Env []string; Labels map[string]string }
		State struct { Running bool; Pid int; Restarting, Paused, Dead bool }
		HostConfig hostConfig
		Mounts []struct { Destination string }
		NetworkSettings struct { Networks map[string]struct { NetworkID, IPAddress string } }
	}
	if err := d.do(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out); err != nil { return identity, err }
	var image struct { ID string `json:"Id"`; Config struct { Env, Entrypoint []string } }
	if err := d.do(ctx, "GET", "/images/"+url.PathEscape(spec.Image)+"/json", nil, nil, &image); err != nil { return identity, err }
	// Compare image defaults too: the anchor receives no manager/source/control
	// credentials. Do not print either environment in a diagnostic.
	expectedEnv := append(slices.Clone(image.Config.Env), "HOME=/")
	// Docker merges HOME by key rather than retaining a duplicate image value.
	for i := 0; i < len(expectedEnv)-1; i++ { if len(expectedEnv[i]) >= 5 && expectedEnv[i][:5] == "HOME=" { expectedEnv = slices.Delete(expectedEnv, i, i+1); i-- } }
	h := out.HostConfig
	if out.ID != id || strings.TrimPrefix(out.Name,"/") != "oyzu-"+spec.Labels[LabelManager]+"-namespace-anchor" || !out.State.Running || out.State.Pid <= 0 || out.State.Restarting || out.State.Paused || out.State.Dead ||
		out.Config.Image != spec.Image || image.ID == "" || out.Image != image.ID || out.Config.User != spec.User || out.Config.WorkingDir != spec.WorkDir ||
		!slices.Equal(out.Config.Cmd, spec.Cmd) || len(out.Config.Entrypoint) != 0 || len(image.Config.Entrypoint) != 0 || !sameStrings(out.Config.Env, expectedEnv) || !maps.Equal(out.Config.Labels, spec.Labels) ||
		!h.ReadonlyRootfs || h.Privileged || h.NetworkMode != defaultNetwork || h.Memory != spec.MemoryBytes || h.MemorySwap != spec.MemoryBytes || h.PidsLimit != spec.PidsLimit ||
		len(out.Mounts) != 0 || len(h.Mounts) != 0 || len(h.PortBindings) != 0 || len(h.Dns) != 0 || len(h.Sysctls) != 0 || len(out.NetworkSettings.Networks) != 1 ||
		!podmanEchoedOptions(h.SecurityOpt, d.profile.path) || len(h.CapAdd) != 0 || !sameStrings(h.CapDrop, []string{"ALL"}) {
		return identity, errors.New("namespace anchor allocation differs from its fixed template")
	}
	var networkID string
	for _, n := range out.NetworkSettings.Networks { if n.NetworkID != "" && n.IPAddress != "" { networkID = n.NetworkID } }
	var bridge struct { ID, Driver string; Internal bool }
	if err := d.do(ctx, "GET", "/networks/bridge", nil, nil, &bridge); err != nil { return identity, err }
	if networkID == "" || networkID != bridge.ID || bridge.Driver != "bridge" || bridge.Internal { return identity, errors.New("namespace anchor has no actual default bridge allocation") }
	ociPath, err := d.podmanOCIPath(ctx, id)
	if err != nil { return identity, err }
	namespace, process, err := d.profile.inspectAnchor(ociPath, id, spec, out.State.Pid)
	if err != nil { return identity, err }
	identity = anchorIdentity{Container: id, Image: out.Image, Network: networkID, Namespace: namespace, Process: process, Configuration: configurationDigest(spec)}
	return identity, nil
}
