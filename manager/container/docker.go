package container

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	// callTimeout bounds every call but waiting for a container and
	// pulling an image.
	callTimeout    time.Duration
	unixPath       string
	adapterMu      sync.Mutex
	engineDetected bool
	podman         bool
	profile        *podmanProfile
}

var _ Engine = (*Docker)(nil)

// defaultCallTimeout bounds one engine call, so a stalled engine fails the
// call instead of holding a job's start or teardown.
const defaultCallTimeout = 2 * time.Minute

// DockerOptions are how the manager reaches a remote engine.
type DockerOptions struct {
	// CertPath is a directory holding ca.pem, cert.pem and key.pem, as in
	// DOCKER_CERT_PATH. When set, or when TLSVerify is, a tcp:// engine is
	// reached over TLS with that client certificate, and its server
	// certificate is verified against ca.pem (the system roots when there is
	// none). Verification is never turned off.
	CertPath string
	// TLSVerify asks for TLS as DOCKER_TLS_VERIFY does; with no CertPath the
	// certificates come from ~/.docker.
	TLSVerify bool
	// AllowPlaintext permits a plain-HTTP tcp:// engine on a host other than
	// this one. Anyone on the path could read the startup tokens copied into
	// containers and change what is created, so it is refused by default.
	AllowPlaintext bool
	// CallTimeout bounds each call; 2 minutes when 0.
	CallTimeout time.Duration
}

// NewDocker connects to the engine at host, as in DOCKER_HOST:
// unix:///path/to.sock, npipe:////./pipe/name on Windows, or tcp://host:port.
// When host is empty it is the local engine: the Docker socket, or Docker
// Desktop's named pipe on Windows. A tcp:// engine on another host must use
// TLS unless opts.AllowPlaintext says otherwise.
func NewDocker(host string, opts DockerOptions) (*Docker, error) {
	if host == "" {
		host = defaultHost
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("container engine %q: %w", host, err)
	}
	callTimeout := opts.CallTimeout
	if callTimeout <= 0 {
		callTimeout = defaultCallTimeout
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	switch u.Scheme {
	case "unix":
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", path)
		}}
		return &Docker{client: &http.Client{Transport: t}, base: "http://engine/" + apiVersion, callTimeout: callTimeout, unixPath: path}, nil
	case "npipe":
		path := pipePath(u)
		t := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialPipe(ctx, path)
		}}
		return &Docker{client: &http.Client{Transport: t}, base: "http://engine/" + apiVersion, callTimeout: callTimeout}, nil
	case "tcp", "http", "https":
		if u.Host == "" {
			return nil, fmt.Errorf("container engine %q: no host", host)
		}
		t := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 30 * time.Second}
		useTLS := u.Scheme == "https" || opts.CertPath != "" || opts.TLSVerify
		if !useTLS {
			if !opts.AllowPlaintext && !loopback(u.Hostname()) {
				return nil, fmt.Errorf("container engine %q is plain HTTP on another host, where anyone on the path "+
					"could read job startup tokens; use TLS (--engine-cert-path or DOCKER_CERT_PATH and DOCKER_TLS_VERIFY), "+
					"or pass --engine-allow-plaintext if the network is trusted", host)
			}
			return &Docker{client: &http.Client{Transport: t}, base: "http://" + u.Host + "/" + apiVersion, callTimeout: callTimeout}, nil
		}
		cfg, err := clientTLS(opts.CertPath)
		if err != nil {
			return nil, fmt.Errorf("container engine %q: %w", host, err)
		}
		t.TLSClientConfig = cfg
		return &Docker{client: &http.Client{Transport: t}, base: "https://" + u.Host + "/" + apiVersion, callTimeout: callTimeout}, nil
	}
	return nil, fmt.Errorf("container engine %q: scheme must be unix, npipe or tcp", host)
}

// pipePath turns npipe:////./pipe/docker_engine into \\.\pipe\docker_engine.
func pipePath(u *url.URL) string {
	p := u.Path
	if u.Host != "" {
		p = "//" + u.Host + p
	}
	return strings.ReplaceAll(p, "/", `\`)
}

// loopback reports whether host names this machine.
func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// clientTLS loads a client certificate from dir, as the Docker CLI does:
// ca.pem, cert.pem and key.pem. dir defaults to ~/.docker.
func clientTLS(dir string) (*tls.Config, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("no certificate directory: %w", err)
		}
		dir = filepath.Join(home, ".docker")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	switch {
	case err == nil:
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("no certificates in %s", filepath.Join(dir, "ca.pem"))
		}
		cfg.RootCAs = roots
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := os.Stat(certFile); err == nil {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return cfg, nil
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

// do sends a request under the call timeout; body is JSON-encoded unless it
// is already a []byte, which is sent as a tar. out, when not nil, receives
// the JSON response.
func (d *Docker) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	return d.doFor(ctx, d.callTimeout, method, path, query, body, out)
}

// doFor is do with its own timeout; 0 leaves the call bounded only by ctx.
func (d *Docker) doFor(ctx context.Context, timeout time.Duration, method, path string, query url.Values, body any, out any) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
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
	if err := d.prepareSandbox(ctx); err != nil {
		return Info{}, err
	}
	var i struct {
		ID            string
		ServerVersion string
		OSType        string
		Architecture  string
		NCPU          int
		MemTotal      int64
	}
	if err := d.do(ctx, http.MethodGet, "/info", nil, nil, &i); err != nil {
		return Info{}, err
	}
	if d.podman {
		// Podman4.9's compatibility /info generates a fresh UUID per call.
		// Bind the opaque host identity to the qualified local daemon instead.
		var err error
		i.ID, err = d.profile.hostIdentity()
		if err != nil {
			return Info{}, err
		}
	}
	return Info{ID: i.ID, ServerVersion: i.ServerVersion, OSType: i.OSType, Architecture: i.Architecture, NCPU: i.NCPU, MemTotal: i.MemTotal}, nil
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
// isolation. The fixed daemonless syscall/proc policy is explicit; AppArmor and
// private PID, IPC and UTS namespaces retain the engine's normal configuration.
type hostConfig struct {
	Privileged                                          bool
	CapDrop                                             []string
	CapAdd                                              []string `json:",omitempty"`
	SecurityOpt                                         []string
	MaskedPaths                                         []string
	ReadonlyPaths                                       []string
	PidMode, IpcMode, UTSMode, CgroupnsMode, UsernsMode string `json:",omitempty"`
	Mounts                                              []mount
	NetworkMode                                         string
	NanoCpus                                            int64 `json:",omitempty"`
	Memory                                              int64 `json:",omitempty"`
	MemorySwap                                          int64 `json:",omitempty"`
	PidsLimit                                           int64 `json:",omitempty"`
	ReadonlyRootfs                                      bool
	Dns                                                 []string                 `json:",omitempty"`
	Sysctls                                             map[string]string        `json:",omitempty"`
	PortBindings                                        map[string][]portBinding `json:",omitempty"`
}

type portBinding struct {
	HostIp   string
	HostPort string
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
	ExposedPorts    map[string]struct{} `json:",omitempty"`
	NetworkDisabled bool
	HostConfig      hostConfig
}

// createBody is what CreateContainer sends for spec; it is separate so the
// isolation it asks for can be tested without an engine.
func createBody(spec Spec) containerConfig {
	policy := containerSandboxPolicy()
	hc := hostConfig{
		CapDrop:       policy.CapDrop,
		SecurityOpt:   policy.SecurityOpt,
		MaskedPaths:   policy.MaskedPaths,
		ReadonlyPaths: policy.ReadonlyPaths,
		IpcMode:       policy.IpcMode, CgroupnsMode: policy.CgroupnsMode,
		NetworkMode: spec.Network,
		Dns:         spec.DNS,
		Sysctls:     spec.Sysctls,
		NanoCpus:    spec.NanoCPUs,
		Memory:      spec.MemoryBytes,
		PidsLimit:   spec.PidsLimit,
	}
	if spec.Volume != "" {
		hc.Mounts = []mount{{Type: "volume", Source: spec.Volume, Target: spec.WorkDir}}
	}
	hc.ReadonlyRootfs = spec.ReadOnly
	if spec.MemoryBytes > 0 {
		// No swap beyond the memory cap.
		hc.MemorySwap = spec.MemoryBytes
	}
	var exposed map[string]struct{}
	for _, p := range spec.Publish {
		if exposed == nil {
			exposed, hc.PortBindings = map[string]struct{}{}, map[string][]portBinding{}
		}
		key := strconv.Itoa(p) + "/tcp"
		exposed[key] = struct{}{}
		hc.PortBindings[key] = []portBinding{{HostIp: "127.0.0.1"}}
	}
	return containerConfig{
		Image: spec.Image, Cmd: spec.Cmd, User: spec.User, WorkingDir: spec.WorkDir,
		Labels: spec.Labels, Env: append([]string{"HOME=" + spec.WorkDir}, spec.Env...), ExposedPorts: exposed,
		NetworkDisabled: spec.Network == "none", HostConfig: hc,
	}
}

// CreateContainer implements Engine.
func (d *Docker) CreateContainer(ctx context.Context, name string, spec Spec) (string, error) {
	if err := d.prepareSandbox(ctx); err != nil {
		return "", err
	}
	body := createBody(spec)
	if d.podman {
		if err := d.profile.validate(); err != nil {
			return "", err
		}
		body.HostConfig.SecurityOpt = podmanSecurityOptions(d.profile.path)
	}
	var out struct{ Id string }
	if err := d.do(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, &out); err != nil {
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
	if err := d.prepareSandbox(ctx); err != nil {
		return err
	}
	if d.podman {
		if err := d.profile.validate(); err != nil {
			return err
		}
	}
	return d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

// WaitContainer implements Engine.
func (d *Docker) WaitContainer(ctx context.Context, id string) (int, error) {
	var out struct {
		StatusCode int
		Error      *struct{ Message string }
	}
	// Waiting lasts as long as the job, so only ctx bounds it.
	if err := d.doFor(ctx, 0, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait",
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

// maxLogs bounds what ContainerLogs reads, whatever the engine sends.
const maxLogs = 1 << 20

// ContainerLogs implements Engine. A container without a TTY, which is
// every job's, gets its output as a multiplexed stream: an 8-byte header
// (stream, three zeros, big-endian length) before each frame.
func (d *Docker) ContainerLogs(ctx context.Context, id string, lines int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, d.callTimeout)
	defer cancel()
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {strconv.Itoa(lines)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/containers/"+url.PathEscape(id)+"/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxLogs))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &apiError{Status: resp.StatusCode, Message: strings.TrimSpace(string(b))}
	}
	return demux(b), nil
}

// demux joins the frames of a multiplexed log stream; anything that is not
// one is returned as it is.
func demux(b []byte) []byte {
	var out []byte
	for rest := b; len(rest) > 0; {
		if len(rest) < 8 || rest[0] > 2 || rest[1] != 0 || rest[2] != 0 || rest[3] != 0 {
			return b
		}
		n := int(rest[4])<<24 | int(rest[5])<<16 | int(rest[6])<<8 | int(rest[7])
		rest = rest[8:]
		n = min(n, len(rest))
		out = append(out, rest[:n]...)
		rest = rest[n:]
	}
	return out
}

// StopContainer implements Engine.
func (d *Docker) StopContainer(ctx context.Context, id string, grace time.Duration) error {
	err := d.doFor(ctx, d.callTimeout+grace, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop",
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

// CreateNetwork implements Engine. A bridge network gets its subnet from the
// engine; the response to create does not carry it, so the network is read
// back.
func (d *Docker) CreateNetwork(ctx context.Context, name string, spec NetworkSpec) (Network, error) {
	var created struct{ Id string }
	err := d.do(ctx, http.MethodPost, "/networks/create", nil, map[string]any{
		"Name": name, "Driver": "bridge", "Internal": spec.Internal, "Labels": spec.Labels, "CheckDuplicate": true,
	}, &created)
	if err != nil {
		return Network{}, err
	}
	var out networkJSON
	if err := d.do(ctx, http.MethodGet, "/networks/"+url.PathEscape(created.Id), nil, nil, &out); err != nil {
		_ = d.RemoveNetwork(ctx, created.Id)
		return Network{}, err
	}
	return out.network(), nil
}

type networkJSON struct {
	Internal   bool
	EnableIPv6 bool
	Driver     string
	Id         string
	Name       string
	Labels     map[string]string
	IPAM       struct{ Config []struct{ Subnet string } }
}

func (n networkJSON) network() Network {
	out := Network{ID: n.Id, Name: n.Name, Labels: n.Labels, Internal: n.Internal, IPv6: n.EnableIPv6, Driver: n.Driver}
	for _, c := range n.IPAM.Config {
		// The first IPv4 range is the one jobs connect from.
		if c.Subnet != "" && !strings.Contains(c.Subnet, ":") {
			out.Subnet = c.Subnet
			break
		}
	}
	return out
}

// RemoveNetwork implements Engine.
func (d *Docker) RemoveNetwork(ctx context.Context, name string) error {
	err := d.do(ctx, http.MethodDelete, "/networks/"+url.PathEscape(name), nil, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// ListNetworks implements Engine.
func (d *Docker) ListNetworks(ctx context.Context, labels map[string]string) ([]Network, error) {
	var out []networkJSON
	if err := d.do(ctx, http.MethodGet, "/networks", labelFilter(labels), nil, &out); err != nil {
		return nil, err
	}
	nets := make([]Network, 0, len(out))
	for _, n := range out {
		nets = append(nets, n.network())
	}
	return nets, nil
}

// ConnectNetwork implements Engine.
func (d *Docker) ConnectNetwork(ctx context.Context, network, container string) (string, error) {
	if err := d.do(ctx, http.MethodPost, "/networks/"+url.PathEscape(network)+"/connect", nil,
		map[string]any{"Container": container}, nil); err != nil {
		return "", err
	}
	var out struct {
		NetworkSettings struct {
			Networks map[string]struct{ IPAddress string }
		}
	}
	if err := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(container)+"/json", nil, nil, &out); err != nil {
		return "", err
	}
	ip := out.NetworkSettings.Networks[network].IPAddress
	if ip == "" {
		return "", fmt.Errorf("the engine gave the container no address on network %s", network)
	}
	return ip, nil
}

// DisconnectNetwork implements Engine.
func (d *Docker) DisconnectNetwork(ctx context.Context, network, container string) error {
	err := d.do(ctx, http.MethodPost, "/networks/"+url.PathEscape(network)+"/disconnect", nil,
		map[string]any{"Container": container, "Force": true}, nil)
	var ae *apiError
	if errors.As(err, &ae) && (ae.Status == http.StatusNotFound || strings.Contains(ae.Message, "is not connected")) {
		return nil
	}
	return err
}

// PublishedPort implements Engine.
func (d *Docker) PublishedPort(ctx context.Context, id string, port int) (int, error) {
	var out struct {
		NetworkSettings struct {
			Ports map[string][]struct{ HostPort string }
		}
	}
	if err := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out); err != nil {
		return 0, err
	}
	for _, b := range out.NetworkSettings.Ports[strconv.Itoa(port)+"/tcp"] {
		if n, err := strconv.Atoi(b.HostPort); err == nil && n > 0 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("the engine published no host port for %d", port)
}

func (d *Docker) InspectReadinessAllocation(ctx context.Context, id string) (allocation, error) {
	if err := d.prepareSandbox(ctx); err != nil {
		return allocation{}, err
	}
	var out struct {
		Image           string
		Config          struct{ Image, User string }
		HostConfig      hostConfig
		NetworkSettings struct {
			Networks map[string]struct {
				GlobalIPv6Address string
				NetworkID         string
			}
		}
		Mounts        []struct{ Destination string }
		OCIConfigPath string
	}
	if err := d.do(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, nil, &out); err != nil {
		return allocation{}, err
	}
	var image struct {
		ID          string `json:"Id"`
		RepoDigests []string
	}
	imageLookup := out.Config.Image
	if d.podman {
		imageLookup = out.Image
	}
	if err := d.do(ctx, "GET", "/images/"+url.PathEscape(imageLookup)+"/json", nil, nil, &image); err != nil {
		return allocation{}, err
	}
	a := allocation{ImageReference: out.Config.Image, ExpectedImage: image.ID, DNS: out.HostConfig.Dns, Image: out.Image, Networks: len(out.NetworkSettings.Networks), Privileged: out.HostConfig.Privileged, HostNetwork: out.HostConfig.NetworkMode == "host", User: out.Config.User,
		SandboxApplied: out.HostConfig.sandbox().applied(), ReadOnly: out.HostConfig.ReadonlyRootfs}
	if d.podman {
		a.SandboxApplied = false
		if err := d.profile.validate(); err != nil {
			return a, err
		}
		if !podmanEchoedOptions(out.HostConfig.SecurityOpt, d.profile.path) {
			return a, errors.New("Podman sandbox options changed")
		}
		native, err := d.podmanContainer(ctx, id)
		if err != nil {
			return a, err
		}
		if err := d.profile.inspectOCI(native.OCIConfigPath, id, out.Config.User); err != nil {
			return a, err
		}
		for _, ref := range image.RepoDigests {
			_, digest, ok := strings.Cut(ref, "@")
			if ok && digest == native.ImageDigest {
				a.PinnedImages = append(a.PinnedImages, ref)
			}
		}
		a.SandboxApplied = true
	}
	for _, n := range out.NetworkSettings.Networks {
		a.IPv6 = a.IPv6 || n.GlobalIPv6Address != ""
		a.NetworkIDs = append(a.NetworkIDs, n.NetworkID)
	}
	for _, m := range out.Mounts {
		if m.Destination != WorkDir {
			a.ExtraMount = true
		}
	}
	return a, nil
}

func (h hostConfig) sandbox() sandboxPolicy {
	return sandboxPolicy{CapDrop: h.CapDrop, CapAdd: h.CapAdd, SecurityOpt: h.SecurityOpt, MaskedPaths: h.MaskedPaths, ReadonlyPaths: h.ReadonlyPaths,
		PidMode: h.PidMode, IpcMode: h.IpcMode, UTSMode: h.UTSMode, CgroupnsMode: h.CgroupnsMode, UsernsMode: h.UsernsMode}
}
