package container

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

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
	// AttachActionOutput subscribes before start. Closing it must unblock reads.
	AttachActionOutput(context.Context, string) (io.ReadCloser, error)
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
	if spec.ActionControl == spec.ActionUser {
		return errors.New("action container must have exactly one action role")
	}
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
	expectedLogs := createBody(spec).HostConfig.LogConfig
	if h.Init == nil || *h.Init || h.RestartPolicy.Name != "no" || h.LogConfig.Type != expectedLogs.Type || !maps.Equal(h.LogConfig.Config, expectedLogs.Config) || actual.Config.Healthcheck == nil || !slices.Equal(actual.Config.Healthcheck.Test, []string{"NONE"}) {
		return errors.New("action lifecycle or log policy differs from required allocation")
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

type actionOutputStream struct {
	io.ReadCloser
	cancel context.CancelFunc
	stop   func() bool
}

func (s *actionOutputStream) Close() error {
	s.stop()
	s.cancel()
	return s.ReadCloser.Close()
}

func (d *Docker) AttachActionOutput(ctx context.Context, id string) (io.ReadCloser, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	// Bound the handshake separately; the admitted action deadline bounds reads.
	timer := time.AfterFunc(d.callTimeout, cancel)
	u := d.base + "/containers/" + url.PathEscape(id) + "/attach?stream=1&stdout=1&stderr=1&logs=0"
	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, u, nil)
	if err != nil {
		timer.Stop()
		cancel()
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	resp, err := d.client.Do(req)
	timer.Stop()
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "tcp") || streamCtx.Err() != nil {
		resp.Body.Close()
		cancel()
		return nil, errors.New("action output attachment unavailable")
	}
	// An upgraded HTTP body outlives the request; explicitly close it on cancel.
	stop := context.AfterFunc(streamCtx, func() { resp.Body.Close() })
	return &actionOutputStream{ReadCloser: resp.Body, cancel: cancel, stop: stop}, nil
}

func readActionOutput(r io.Reader) ([]byte, []byte, error) {
	var stdout, stderr []byte
	var wireBytes int64
	for {
		var header [8]byte
		nread, err := io.ReadFull(r, header[:])
		if err == io.EOF && nread == 0 {
			return stdout, stderr, nil
		}
		if err != nil || (header[0] != 1 && header[0] != 2) || header[1] != 0 || header[2] != 0 || header[3] != 0 {
			return nil, nil, errors.New("invalid action log stream")
		}
		n := int64(binary.BigEndian.Uint32(header[4:]))
		wireBytes += 8 + n
		if int64(len(stdout)+len(stderr))+n > runnerclient.MaxActionLogs || wireBytes > 9*runnerclient.MaxActionLogs {
			return nil, nil, fmt.Errorf("action logs truncated or over limit")
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, errors.New("truncated action log frame")
		}
		if header[0] == 1 {
			stdout = append(stdout, payload...)
		} else {
			stderr = append(stderr, payload...)
		}
	}
}
