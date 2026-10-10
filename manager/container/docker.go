package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// apiVersion is the Docker Engine API version the client speaks. Docker 20.10
// and later and Podman 3 and later serve it.
const apiVersion = "v1.41"

// Docker is an Engine over the Docker Engine API, served by Docker or by
// Podman's compatible service.
type Docker struct {
	client *http.Client
	base   string
}

var _ Engine = (*Docker)(nil)

// NewDocker connects to the engine at host: unix:///path/to.sock or
// tcp://host:port, as in DOCKER_HOST; the local Docker socket when empty.
// Windows named pipes are not supported; point it at a TCP or Unix socket.
func NewDocker(host string) (*Docker, error) {
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("container engine %q: %w", host, err)
	}
	switch u.Scheme {
	case "unix":
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}
		return &Docker{client: &http.Client{Transport: t}, base: "http://engine/" + apiVersion}, nil
	case "tcp", "http":
		return &Docker{client: &http.Client{}, base: "http://" + u.Host + "/" + apiVersion}, nil
	case "npipe":
		return nil, errors.New("container engine: Windows named pipes are not supported; expose the engine on tcp:// or a unix socket")
	}
	return nil, fmt.Errorf("container engine %q: scheme must be unix or tcp", host)
}

// apiError is an engine error response.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("engine: %d %s", e.Status, e.Message) }

func isStatus(err error, codes ...int) bool {
	var ae *apiError
	if !errors.As(err, &ae) {
		return false
	}
	for _, c := range codes {
		if ae.Status == c {
			return true
		}
	}
	return false
}

// do sends a request; body is JSON-encoded unless it is already a []byte,
// which is sent as a tar. out, when not nil, receives the JSON response.
func (d *Docker) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	var r io.Reader
	contentType := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		r, contentType = bytes.NewReader(b), "application/x-tar"
	default:
		buf, err := json.Marshal(b)
		if err != nil {
			return err
		}
		r, contentType = bytes.NewReader(buf), "application/json"
	}
	u := d.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct{ Message string }
		if json.Unmarshal(msg, &e) == nil && e.Message != "" {
			return &apiError{Status: resp.StatusCode, Message: e.Message}
		}
		return &apiError{Status: resp.StatusCode, Message: strings.TrimSpace(string(msg))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func labelFilter(labels map[string]string) url.Values {
	var l []string
	for k, v := range labels {
		l = append(l, k+"="+v)
	}
	f, _ := json.Marshal(map[string][]string{"label": l})
	return url.Values{"filters": {string(f)}}
}

// Info implements Engine.
func (d *Docker) Info(ctx context.Context) (Info, error) {
	var i struct {
		OSType       string
		Architecture string
		NCPU         int
		MemTotal     int64
	}
	if err := d.do(ctx, http.MethodGet, "/info", nil, nil, &i); err != nil {
		return Info{}, err
	}
	return Info{OSType: i.OSType, Architecture: i.Architecture, NCPU: i.NCPU, MemTotal: i.MemTotal}, nil
}

// ImagePresent implements Engine.
func (d *Docker) ImagePresent(ctx context.Context, ref string) (bool, error) {
	err := d.do(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return false, nil
	}
	return err == nil, err
}

// PullImage implements Engine. The engine streams progress as JSON lines and
// reports a failed pull in the stream, after a 200.
func (d *Docker) PullImage(ctx context.Context, ref string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.base+"/images/create?"+url.Values{"fromImage": {ref}}.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return &apiError{Status: resp.StatusCode, Message: strings.TrimSpace(string(msg))}
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var m struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&m); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if m.Error != "" {
			return errors.New(m.Error)
		}
	}
}

// CreateVolume implements Engine.
func (d *Docker) CreateVolume(ctx context.Context, name string, labels map[string]string) error {
	return d.do(ctx, http.MethodPost, "/volumes/create", nil,
		map[string]any{"Name": name, "Driver": "local", "Labels": labels}, nil)
}

// RemoveVolume implements Engine.
func (d *Docker) RemoveVolume(ctx context.Context, name string) error {
	err := d.do(ctx, http.MethodDelete, "/volumes/"+url.PathEscape(name), url.Values{"force": {"1"}}, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// ListVolumes implements Engine.
func (d *Docker) ListVolumes(ctx context.Context, labels map[string]string) ([]Volume, error) {
	var out struct{ Volumes []Volume }
	if err := d.do(ctx, http.MethodGet, "/volumes", labelFilter(labels), nil, &out); err != nil {
		return nil, err
	}
	return out.Volumes, nil
}

// hostConfig is the part of a container's configuration that decides its
// isolation. Everything not set here is the engine's default, which keeps
// the default seccomp and AppArmor profiles and a private PID, IPC and UTS
// namespace.
type hostConfig struct {
	Privileged     bool
	CapDrop        []string
	SecurityOpt    []string
	Mounts         []mount
	NetworkMode    string
	NanoCpus       int64 `json:",omitempty"`
	Memory         int64 `json:",omitempty"`
	MemorySwap     int64 `json:",omitempty"`
	PidsLimit      int64 `json:",omitempty"`
	ReadonlyRootfs bool
}

type mount struct {
	Type   string
	Source string
	Target string
}

// containerConfig is the body of a create request.
type containerConfig struct {
	Image           string
	Cmd             []string
	User            string
	WorkingDir      string
	Labels          map[string]string
	Env             []string
	NetworkDisabled bool
	HostConfig      hostConfig
}

// createBody is what CreateContainer sends for spec; it is separate so the
// isolation it asks for can be tested without an engine.
func createBody(spec Spec) containerConfig {
	hc := hostConfig{
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Mounts:      []mount{{Type: "volume", Source: spec.Volume, Target: spec.WorkDir}},
		NetworkMode: spec.Network,
		NanoCpus:    spec.NanoCPUs,
		Memory:      spec.MemoryBytes,
		PidsLimit:   spec.PidsLimit,
	}
	if spec.MemoryBytes > 0 {
		// No swap beyond the memory cap.
		hc.MemorySwap = spec.MemoryBytes
	}
	return containerConfig{
		Image: spec.Image, Cmd: spec.Cmd, User: spec.User, WorkingDir: spec.WorkDir,
		Labels: spec.Labels, Env: []string{"HOME=" + spec.WorkDir}, NetworkDisabled: spec.Network == "none",
		HostConfig: hc,
	}
}

// CreateContainer implements Engine.
func (d *Docker) CreateContainer(ctx context.Context, name string, spec Spec) (string, error) {
	var out struct{ Id string }
	if err := d.do(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, createBody(spec), &out); err != nil {
		return "", err
	}
	return out.Id, nil
}

// CopyFiles implements Engine.
func (d *Docker) CopyFiles(ctx context.Context, id, path string, tar []byte) error {
	return d.do(ctx, http.MethodPut, "/containers/"+url.PathEscape(id)+"/archive", url.Values{"path": {path}}, tar, nil)
}

// StartContainer implements Engine.
func (d *Docker) StartContainer(ctx context.Context, id string) error {
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

// WaitContainer implements Engine.
func (d *Docker) WaitContainer(ctx context.Context, id string) (int, error) {
	var out struct {
		StatusCode int
		Error      *struct{ Message string }
	}
	if err := d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait",
		url.Values{"condition": {"not-running"}}, nil, &out); err != nil {
		return 0, err
	}
	if out.Error != nil && out.Error.Message != "" {
		return out.StatusCode, errors.New(out.Error.Message)
	}
	return out.StatusCode, nil
}

// InspectContainer implements Engine.
func (d *Docker) InspectContainer(ctx context.Context, id string) (State, error) {
	var out struct{ State State }
	if err := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out); err != nil {
		return State{}, err
	}
	return out.State, nil
}

// StopContainer implements Engine.
func (d *Docker) StopContainer(ctx context.Context, id string, grace time.Duration) error {
	err := d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop",
		url.Values{"t": {strconv.Itoa(int(grace / time.Second))}}, nil, nil)
	if isStatus(err, http.StatusNotModified, http.StatusNotFound) {
		return nil
	}
	return err
}

// RemoveContainer implements Engine.
func (d *Docker) RemoveContainer(ctx context.Context, id string) error {
	err := d.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id), url.Values{"force": {"1"}, "v": {"1"}}, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// ListContainers implements Engine.
func (d *Docker) ListContainers(ctx context.Context, labels map[string]string) ([]Summary, error) {
	var out []struct {
		Id     string
		Names  []string
		Labels map[string]string
		State  string
	}
	q := labelFilter(labels)
	q.Set("all", "1")
	if err := d.do(ctx, http.MethodGet, "/containers/json", q, nil, &out); err != nil {
		return nil, err
	}
	s := make([]Summary, 0, len(out))
	for _, c := range out {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		s = append(s, Summary{ID: c.Id, Name: name, Labels: c.Labels, State: c.State})
	}
	return s, nil
}
