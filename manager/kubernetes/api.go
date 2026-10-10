package kubernetes

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
	"strings"
	"time"
)

// API is the part of the Kubernetes API the driver uses, all within one
// namespace.
type API interface {
	CreateSecret(ctx context.Context, s Secret) error
	// SetSecretOwner makes the pod the secret's owner, so the cluster
	// deletes the secret with it.
	SetSecretOwner(ctx context.Context, secret string, owner OwnerReference) error
	// DeleteSecret deletes a secret; one that is already gone succeeds.
	DeleteSecret(ctx context.Context, name string) error
	ListSecrets(ctx context.Context, selector string) ([]ObjectMeta, error)
	// CreatePod creates a pod and returns its UID.
	CreatePod(ctx context.Context, p Pod) (string, error)
	// GetPod returns the pod's status, or ErrNotFound.
	GetPod(ctx context.Context, name string) (PodStatus, error)
	// DeletePod deletes a pod, giving it grace to stop; one that is already
	// gone succeeds.
	DeletePod(ctx context.Context, name string, grace time.Duration) error
	ListPods(ctx context.Context, selector string) ([]ObjectMeta, error)
}

// ErrNotFound is returned for an object that does not exist.
var ErrNotFound = errors.New("kubernetes: not found")

// The object shapes below are the subset of core/v1 the driver writes and
// reads, with Kubernetes' own JSON names.

type ObjectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	UID             string            `json:"uid,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	OwnerReferences []OwnerReference  `json:"ownerReferences,omitempty"`
}

type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

type Secret struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ObjectMeta        `json:"metadata"`
	Type       string            `json:"type"`
	Data       map[string][]byte `json:"data"`
	Immutable  bool              `json:"immutable"`
}

type Pod struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       PodSpec    `json:"spec"`
}

type PodSpec struct {
	RestartPolicy                 string              `json:"restartPolicy"`
	AutomountServiceAccountToken  *bool               `json:"automountServiceAccountToken"`
	EnableServiceLinks            *bool               `json:"enableServiceLinks"`
	ServiceAccountName            string              `json:"serviceAccountName,omitempty"`
	RuntimeClassName              string              `json:"runtimeClassName,omitempty"`
	PriorityClassName             string              `json:"priorityClassName,omitempty"`
	NodeSelector                  map[string]string   `json:"nodeSelector,omitempty"`
	Tolerations                   []Toleration        `json:"tolerations,omitempty"`
	TerminationGracePeriodSeconds *int64              `json:"terminationGracePeriodSeconds,omitempty"`
	SecurityContext               *PodSecurityContext `json:"securityContext"`
	Containers                    []Container         `json:"containers"`
	Volumes                       []Volume            `json:"volumes,omitempty"`
}

type Toleration struct {
	Key      string `json:"key,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

type PodSecurityContext struct {
	RunAsNonRoot   *bool           `json:"runAsNonRoot"`
	RunAsUser      *int64          `json:"runAsUser"`
	RunAsGroup     *int64          `json:"runAsGroup"`
	FSGroup        *int64          `json:"fsGroup"`
	SeccompProfile *SeccompProfile `json:"seccompProfile"`
}

type SeccompProfile struct {
	Type string `json:"type"`
}

type Container struct {
	Name            string                    `json:"name"`
	Image           string                    `json:"image"`
	ImagePullPolicy string                    `json:"imagePullPolicy"`
	Command         []string                  `json:"command,omitempty"`
	Args            []string                  `json:"args,omitempty"`
	WorkingDir      string                    `json:"workingDir,omitempty"`
	Env             []EnvVar                  `json:"env,omitempty"`
	Resources       ResourceRequirements      `json:"resources"`
	SecurityContext *ContainerSecurityContext `json:"securityContext"`
	VolumeMounts    []VolumeMount             `json:"volumeMounts,omitempty"`
}

type EnvVar struct {
	Name      string        `json:"name"`
	Value     string        `json:"value,omitempty"`
	ValueFrom *EnvVarSource `json:"valueFrom,omitempty"`
}

type EnvVarSource struct {
	SecretKeyRef *SecretKeySelector `json:"secretKeyRef,omitempty"`
}

type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type ResourceRequirements struct {
	Limits   map[string]string `json:"limits,omitempty"`
	Requests map[string]string `json:"requests,omitempty"`
}

type ContainerSecurityContext struct {
	Privileged               *bool         `json:"privileged"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation"`
	Capabilities             *Capabilities `json:"capabilities"`
}

type Capabilities struct {
	Drop []string `json:"drop"`
}

type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
}

type Volume struct {
	Name     string          `json:"name"`
	EmptyDir *EmptyDirVolume `json:"emptyDir,omitempty"`
}

type EmptyDirVolume struct {
	SizeLimit string `json:"sizeLimit,omitempty"`
}

type PodStatus struct {
	Phase             string            `json:"phase"`
	Reason            string            `json:"reason,omitempty"`
	Message           string            `json:"message,omitempty"`
	Conditions        []PodCondition    `json:"conditions,omitempty"`
	ContainerStatuses []ContainerStatus `json:"containerStatuses,omitempty"`
}

type PodCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type ContainerStatus struct {
	Name  string         `json:"name"`
	State ContainerState `json:"state"`
}

type ContainerState struct {
	Waiting    *ContainerStateWaiting    `json:"waiting,omitempty"`
	Running    *struct{}                 `json:"running,omitempty"`
	Terminated *ContainerStateTerminated `json:"terminated,omitempty"`
}

type ContainerStateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type ContainerStateTerminated struct {
	ExitCode int    `json:"exitCode"`
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Client is an API over the cluster's REST endpoint, scoped to one
// namespace. Its bearer token is re-read from TokenFile on every request,
// because projected service account tokens rotate.
type Client struct {
	Server    string
	Namespace string
	TokenFile string
	HTTP      *http.Client
}

var _ API = (*Client)(nil)

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// InCluster is a Client for the pod's own service account. namespace
// defaults to the pod's namespace.
func InCluster(namespace string) (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kubernetes: not running in a cluster (KUBERNETES_SERVICE_HOST is unset); pass --kube-server")
	}
	if namespace == "" {
		b, err := os.ReadFile(serviceAccountDir + "/namespace")
		if err != nil {
			return nil, fmt.Errorf("kubernetes: the pod's namespace: %w", err)
		}
		namespace = strings.TrimSpace(string(b))
	}
	return NewClient("https://"+net.JoinHostPort(host, port), serviceAccountDir+"/ca.crt",
		serviceAccountDir+"/token", namespace)
}

// NewClient is a Client for server, trusting the CA in caFile (the system
// roots when empty) and sending the token in tokenFile.
func NewClient(server, caFile, tokenFile, namespace string) (*Client, error) {
	if namespace == "" {
		return nil, errors.New("kubernetes: a namespace is required")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kubernetes: no certificates in %s", caFile)
		}
		t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &Client{Server: strings.TrimSuffix(server, "/"), Namespace: namespace, TokenFile: tokenFile,
		HTTP: &http.Client{Transport: t, Timeout: time.Minute}}, nil
}

type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("kubernetes: %d %s", e.Status, e.Message) }

func (e *apiError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

func (c *Client) do(ctx context.Context, method, path, contentType string, query url.Values, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	u := c.Server + "/api/v1/namespaces/" + url.PathEscape(c.Namespace) + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	if c.TokenFile != "" {
		tok, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return fmt.Errorf("kubernetes: read the token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var st struct{ Message string }
		if json.Unmarshal(b, &st) == nil && st.Message != "" {
			return &apiError{Status: resp.StatusCode, Message: st.Message}
		}
		return &apiError{Status: resp.StatusCode, Message: strings.TrimSpace(string(b))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func ignoreNotFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// CreateSecret implements API.
func (c *Client) CreateSecret(ctx context.Context, s Secret) error {
	s.APIVersion, s.Kind = "v1", "Secret"
	return c.do(ctx, http.MethodPost, "/secrets", "", nil, s, nil)
}

// SetSecretOwner implements API.
func (c *Client) SetSecretOwner(ctx context.Context, secret string, owner OwnerReference) error {
	patch := map[string]any{"metadata": map[string]any{"ownerReferences": []OwnerReference{owner}}}
	return c.do(ctx, http.MethodPatch, "/secrets/"+url.PathEscape(secret), "application/merge-patch+json", nil, patch, nil)
}

// DeleteSecret implements API.
func (c *Client) DeleteSecret(ctx context.Context, name string) error {
	return ignoreNotFound(c.do(ctx, http.MethodDelete, "/secrets/"+url.PathEscape(name), "", nil, nil, nil))
}

// ListSecrets implements API.
func (c *Client) ListSecrets(ctx context.Context, selector string) ([]ObjectMeta, error) {
	return c.list(ctx, "/secrets", selector)
}

func (c *Client) list(ctx context.Context, path, selector string) ([]ObjectMeta, error) {
	var out struct {
		Items []struct {
			Metadata ObjectMeta `json:"metadata"`
		} `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, path, "", url.Values{"labelSelector": {selector}}, nil, &out); err != nil {
		return nil, err
	}
	m := make([]ObjectMeta, 0, len(out.Items))
	for _, i := range out.Items {
		m = append(m, i.Metadata)
	}
	return m, nil
}

// CreatePod implements API.
func (c *Client) CreatePod(ctx context.Context, p Pod) (string, error) {
	p.APIVersion, p.Kind = "v1", "Pod"
	var out struct {
		Metadata ObjectMeta `json:"metadata"`
	}
	if err := c.do(ctx, http.MethodPost, "/pods", "", nil, p, &out); err != nil {
		return "", err
	}
	return out.Metadata.UID, nil
}

// GetPod implements API.
func (c *Client) GetPod(ctx context.Context, name string) (PodStatus, error) {
	var out struct {
		Status PodStatus `json:"status"`
	}
	err := c.do(ctx, http.MethodGet, "/pods/"+url.PathEscape(name), "", nil, nil, &out)
	return out.Status, err
}

// DeletePod implements API.
func (c *Client) DeletePod(ctx context.Context, name string, grace time.Duration) error {
	body := map[string]any{"gracePeriodSeconds": int64(grace / time.Second), "propagationPolicy": "Background"}
	return ignoreNotFound(c.do(ctx, http.MethodDelete, "/pods/"+url.PathEscape(name), "", nil, body, nil))
}

// ListPods implements API.
func (c *Client) ListPods(ctx context.Context, selector string) ([]ObjectMeta, error) {
	return c.list(ctx, "/pods", selector)
}
