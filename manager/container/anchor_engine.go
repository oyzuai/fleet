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
	if err := d.prepareSandbox(ctx); err != nil {
		return false, err
	}
	if d.podman {
		if err := d.profile.validate(); err != nil {
			return false, err
		}
	}
	return d.podman, nil
}

func (d *Docker) InspectNamespaceAnchor(ctx context.Context, id string, spec Spec) (anchorIdentity, error) {
	var identity anchorIdentity
	required, err := d.NamespaceAnchorRequired(ctx)
	if err != nil {
		return identity, err
	}
	if !required {
		return identity, errors.New("namespace anchor requires qualified Podman4.9")
	}
	var out struct {
		ID, Name, Image string
		Config          struct {
			Image, User, WorkingDir, Hostname string
			Cmd, Entrypoint, Env              []string
			Labels                            map[string]string
		}
		State struct {
			Running                  bool
			Pid                      int
			Restarting, Paused, Dead bool
		}
		HostConfig      hostConfig
		Mounts          []struct{ Destination string }
		NetworkSettings struct {
			IPAddress string
			Networks map[string]podmanEndpoint
		}
	}
	if err := d.do(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out); err != nil {
		return identity, err
	}
	var image struct {
		ID          string `json:"Id"`
		RepoDigests []string
		Config      struct {
			Env, Entrypoint []string
			Labels          map[string]string
		}
	}
	if err := d.do(ctx, "GET", "/images/"+url.PathEscape(spec.Image)+"/json", nil, nil, &image); err != nil {
		return identity, err
	}
	native, err := d.podmanContainer(ctx, id)
	if err != nil {
		return identity, err
	}
	_, requestedDigest, _ := strings.Cut(spec.Image, "@")
	// Compare image defaults too: the anchor receives no manager/source/control
	// credentials. Do not print either environment in a diagnostic.
	expectedEnv := anchorEnvironment(image.Config.Env, id)
	expectedLabels := maps.Clone(image.Config.Labels)
	if expectedLabels == nil {
		expectedLabels = map[string]string{}
	}
	maps.Copy(expectedLabels, spec.Labels)
	h := out.HostConfig
	checks := []struct {
		name  string
		valid bool
	}{
		{"identity", out.ID == id && strings.TrimPrefix(out.Name, "/") == "oyzu-"+spec.Labels[LabelManager]+"-namespace-anchor"},
		{"liveness", out.State.Running && out.State.Pid > 0 && !out.State.Restarting && !out.State.Paused && !out.State.Dead},
		// Podman rewrites Config.Image to a local tag. Bind the actual native
		// manifest digest AND resolved config ID to the exact requested pin.
		{"image-reference", native.ImageDigest == requestedDigest && slices.Contains(image.RepoDigests, spec.Image)},
		{"image-identity", image.ID != "" && out.Image == image.ID},
		{"user", out.Config.User == spec.User}, {"directory", out.Config.WorkingDir == spec.WorkDir},
		{"command", slices.Equal(out.Config.Cmd, spec.Cmd) && len(out.Config.Entrypoint) == 0 && len(image.Config.Entrypoint) == 0},
		{"environment", sameEnvironment(out.Config.Env, expectedEnv) && len(id) >= 12 && out.Config.Hostname == id[:12]}, {"labels", maps.Equal(out.Config.Labels, expectedLabels)},
		{"readonly", h.ReadonlyRootfs && !h.Privileged}, {"bridge", h.NetworkMode == defaultNetwork},
		{"memory", h.Memory == spec.MemoryBytes}, {"swap", h.MemorySwap == spec.MemoryBytes}, {"pids", h.PidsLimit == spec.PidsLimit},
		{"mounts", len(out.Mounts) == 0 && len(h.Mounts) == 0}, {"ports", len(h.PortBindings) == 0},
		{"dns", len(h.Dns) == 0}, {"sysctls", len(h.Sysctls) == 0}, {"networks", len(out.NetworkSettings.Networks) == 1},
		{"security-options", podmanEchoedOptions(h.SecurityOpt, d.profile.path)},
		// Podman expands CapDrop into its default cap names. Authority comes
		// from the actual OCI empty capability sets, checked below.
		{"capabilities", len(h.CapAdd) == 0},
	}
	var failed []string
	for _, check := range checks {
		if !check.valid {
			failed = append(failed, check.name)
		}
	}
	if len(failed) > 0 {
		return identity, errors.New("namespace anchor allocation differs from its fixed template: " + strings.Join(failed, ","))
	}
	networkIP,err:=podmanDefaultBridgeAddress(out.NetworkSettings.IPAddress,out.NetworkSettings.Networks)
	if err!=nil {return identity,err}
	networkName:=defaultNetwork
	bridge, err := d.inspectPodmanNetwork(ctx, id, networkName, networkIP)
	if err != nil {
		return identity, err
	}
	if bridge.Internal {
		return identity, errors.New("namespace anchor default bridge is internal")
	}
	namespace, process, err := d.profile.inspectAnchor(native.OCIConfigPath, id, spec, out.State.Pid)
	if err != nil {
		return identity, err
	}
	identity = anchorIdentity{Container: id, Image: out.Image, Network: bridge.ID, Namespace: namespace, Process: process, Configuration: configurationDigest(spec)}
	return identity, nil
}

type podmanEndpoint struct {NetworkID,IPAddress string}
func podmanDefaultBridgeAddress(topLevel string,networks map[string]podmanEndpoint) (string,error) {
	n,ok:=networks[defaultNetwork]
	if len(networks)!=1 || !ok || n.NetworkID!=defaultNetwork {return "",errors.New("namespace anchor has no actual default bridge allocation")}
	address:=n.IPAddress
	// Podman4.9's default-network branch keeps its address at the top level;
	// custom network endpoints must never use this fallback.
	if address=="" {address=topLevel}
	if address=="" {return "",errors.New("namespace anchor default bridge has no address")}
	return address,nil
}

func anchorEnvironment(image []string, id string) map[string]string {
	env := map[string]string{}
	for _, entry := range image {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	env["HOME"] = "/"
	env["container"] = "podman"
	if len(id) >= 12 {
		env["HOSTNAME"] = id[:12]
	}
	return env
}
func sameEnvironment(actual []string, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, entry := range actual {
		key, value, ok := strings.Cut(entry, "=")
		want, exists := expected[key]
		if !ok || !exists || seen[key] || value != want {
			return false
		}
		seen[key] = true
	}
	return true
}
