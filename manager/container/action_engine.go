package container

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/oyzuai/fleet/runnerclient"
)

// ActionEngine extends Engine only for source-free actions. Existing pool
// engines do not gain an action capability by implementing the ordinary Engine.
type ActionEngine interface {
	Engine
	ActionReady(context.Context) error
	CreateActionVolume(context.Context, string, map[string]string, int64, int64) error
	VerifyActionVolume(context.Context, string, map[string]string, map[string]string) error
	VerifyActionContainer(context.Context, string, Spec) error
	ReadContainerArchive(context.Context, string, string) ([]byte, error)
	ContainerOutput(context.Context, string) ([]byte, []byte, error)
}

func (d *Docker) ActionReady(ctx context.Context) error {
	info, err := d.Info(ctx)
	if err != nil {
		return err
	}
	if info.OSType != "linux" || (info.Architecture != "amd64" && info.Architecture != "x86_64") || d.podman {
		return errors.New("actions require a Linux container engine")
	}
	if !info.MemoryLimit || !info.CpuCfsQuota || !info.CpuCfsPeriod || !info.PidsLimit {
		return errors.New("action engine cannot enforce required resource bounds")
	}
	if err := d.prepareSandbox(ctx); err != nil {
		return err
	}
	for _, opt := range info.SecurityOptions {
		if strings.Contains(opt, "seccomp") {
			return nil
		}
	}
	return errors.New("action engine does not report required seccomp isolation")
}

// VerifyActionContainer observes the fixed allocation before admitted code can
// start. Unknown controls or extra image-declared volumes refuse execution.
func (d *Docker) VerifyActionContainer(ctx context.Context, id string, spec Spec) error {
	var actual struct {
		Config struct {
			Image, User, WorkingDir string
			Cmd, Entrypoint         []string
			NetworkDisabled         bool
			Labels                  map[string]string
			Healthcheck             *struct{ Test []string }
		}
		HostConfig hostConfig
		Mounts     []struct {
			Type, Name, Destination string
			RW                      bool
		}
	}
	if err := d.do(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, nil, &actual); err != nil {
		return err
	}
	h := actual.HostConfig
	if actual.Config.Image != spec.Image || actual.Config.User != spec.User || actual.Config.WorkingDir != spec.WorkDir || !actionLabelsMatch(actual.Config.Labels, spec.Labels) ||
		!slices.Equal(actual.Config.Entrypoint, spec.Entrypoint) || !slices.Equal(actual.Config.Cmd, spec.Cmd) ||
		!actual.Config.NetworkDisabled || h.NetworkMode != "none" || h.Privileged || !h.ReadonlyRootfs ||
		h.NanoCpus != spec.NanoCPUs || h.Memory != spec.MemoryBytes || h.MemorySwap != spec.MemoryBytes || h.PidsLimit != spec.PidsLimit ||
		h.PidMode != "" || h.UTSMode != "" || len(actual.Mounts) != len(createBody(spec).HostConfig.Mounts) {
		return errors.New("action allocation differs from required isolation")
	}
	for _, expected := range createBody(spec).HostConfig.Mounts {
		found := false
		for _, m := range actual.Mounts {
			if m.Type == expected.Type && m.Name == expected.Source && m.Destination == expected.Target && m.RW == !expected.ReadOnly {
				found = true
			}
		}
		if !found {
			return errors.New("action mount differs from planned allocation")
		}
	}
	if spec.ActionControl && (h.Init == nil || *h.Init || h.RestartPolicy.Name != "no" || h.LogConfig.Type != "none" || actual.Config.Healthcheck == nil || !slices.Equal(actual.Config.Healthcheck.Test, []string{"NONE"})) {
		return errors.New("image lifecycle controls not disabled")
	}
	if !d.podman {
		if !h.sandbox().applied() {
			return errors.New("action sandbox policy was not applied")
		}
		return nil
	}
	// The existing Podman adapter verifies the actual OCI policy. If the
	// engine cannot expose it before start, actions on that engine are refused.
	if !podmanEchoedOptions(h.SecurityOpt, d.profile.path) {
		return errors.New("action Podman security options differ")
	}
	native, err := d.podmanContainer(ctx, id)
	if err != nil {
		return err
	}
	readOnly, err := d.profile.inspectAllocationOCI(native.OCIConfigPath, id, spec.User)
	if err != nil {
		return err
	}
	if !readOnly {
		return errors.New("action OCI root is writable")
	}
	return nil
}

func (d *Docker) actionBytes(ctx context.Context, endpoint string, query url.Values, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, d.callTimeout)
	defer cancel()
	u := d.base + endpoint + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, &apiError{Status: resp.StatusCode, Message: "action data unavailable"}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("action engine data exceeds byte limit")
	}
	return b, nil
}

func (d *Docker) ReadContainerArchive(ctx context.Context, id, p string) ([]byte, error) {
	return d.actionBytes(ctx, "/containers/"+url.PathEscape(id)+"/archive", url.Values{"path": {p}}, runnerclient.MaxActionWire)
}

func (d *Docker) ContainerOutput(ctx context.Context, id string) ([]byte, []byte, error) {
	b, err := d.actionBytes(ctx, "/containers/"+url.PathEscape(id)+"/logs", url.Values{"stdout": {"1"}, "stderr": {"1"}}, runnerclient.MaxActionLogs+8*runnerclient.MaxActionLogs)
	if err != nil {
		return nil, nil, err
	}
	var stdout, stderr []byte
	for len(b) > 0 {
		if len(b) < 8 || (b[0] != 1 && b[0] != 2) || b[1] != 0 || b[2] != 0 || b[3] != 0 {
			return nil, nil, errors.New("invalid action log stream")
		}
		n := int64(binary.BigEndian.Uint32(b[4:8]))
		stream := b[0]
		b = b[8:]
		if n > int64(len(b)) || int64(len(stdout)+len(stderr))+n > runnerclient.MaxActionLogs {
			return nil, nil, fmt.Errorf("action logs truncated or over limit")
		}
		if stream == 1 {
			stdout = append(stdout, b[:n]...)
		} else {
			stderr = append(stderr, b[:n]...)
		}
		b = b[n:]
	}
	return stdout, stderr, nil
}
