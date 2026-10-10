// Package gcp is the Google Compute Engine adapter for VM pools. It maps a
// pool's spec onto Compute Engine instances, labels them for reaping, and
// verifies the Google-signed instance identity tokens instances present to
// the manager.
//
// It talks to Compute Engine through API, the small subset of calls it
// needs, shaped so the production binding to the Google Cloud client library
// is a thin wrapper. Until Oyzu has a Google Cloud project it is exercised
// only against fakes; everything here that depends on real Compute Engine
// behaviour is marked as such.
package gcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/vm"
	"github.com/oyzuai/fleet/manager/vm/idtoken"
)

// GoogleKeys is where Google publishes the keys that sign instance identity
// tokens.
const GoogleKeys = "https://www.googleapis.com/oauth2/v3/certs"

// googleIssuers are the iss values Google uses on identity tokens.
var googleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

// API is the subset of Compute Engine the adapter uses. Instances are
// addressed by name within the pool's zone.
type API interface {
	InsertInstance(ctx context.Context, in InsertInput) error
	GetInstance(ctx context.Context, name string) (Instance, error)
	// ListInstances returns the zone's instances matching a Compute Engine
	// filter expression.
	ListInstances(ctx context.Context, filter string) ([]Instance, error)
	SetLabels(ctx context.Context, name string, labels map[string]string) error
	DeleteInstance(ctx context.Context, name string) error
	GetMachineType(ctx context.Context, name string) (MachineType, error)
}

// ErrNotFound is what API returns for an instance that does not exist.
var ErrNotFound = errors.New("gcp: no such instance")

// InsertInput creates one instance.
type InsertInput struct {
	Name        string
	MachineType string
	// SourceImage is the boot disk's image, such as
	// projects/oyzu-images/global/images/oyzu-executor-20261010.
	SourceImage string
	DiskGiB     int
	// Subnetwork is the subnetwork the one network interface joins. No
	// external address is attached; instances reach out through Cloud NAT.
	Subnetwork string
	// NetworkTags select the firewall rules that apply.
	NetworkTags []string
	// ServiceAccount is the instance's own service account email.
	ServiceAccount string
	// Spot asks for the SPOT provisioning model with the STOP termination
	// action, so a reclaimed instance stays visible as preempted until
	// teardown deletes it.
	Spot   bool
	Labels map[string]string
	// Metadata is the instance's metadata. It never holds a startup script
	// or any secret.
	Metadata map[string]string
	// ShieldedSecureBoot turns on Shielded VM secure boot, vTPM and
	// integrity monitoring.
	ShieldedSecureBoot bool
}

// Instance is Compute Engine's view of one instance.
type Instance struct {
	Name string
	// ID is the numeric instance id the identity token carries.
	ID string
	// Status is PROVISIONING, STAGING, RUNNING, STOPPING, SUSPENDING,
	// SUSPENDED, REPAIRING or TERMINATED.
	Status        string
	StatusMessage string
	NetworkIP     string
	// SourceImage is the boot disk's image as a URL or a relative name.
	SourceImage       string
	CreationTimestamp time.Time
	Labels            map[string]string
	Spot              bool
}

// MachineType is a machine shape from Compute Engine's catalogue.
type MachineType struct {
	GuestCPUs int
	MemoryMB  int
	// Architecture is X86_64 or ARM64.
	Architecture string
}

// Config configures the adapter for one pool.
type Config struct {
	API API
	// Project and Zone are where the pool's instances live; identity tokens
	// from anywhere else are refused.
	Project string
	Zone    string
	// Audience is the aud instances request their identity token for, such
	// as the manager's handover URL.
	Audience string
	// NetworkTags select the firewall rules that allow only the runs
	// service, the source provider, registries, the cache and the
	// manager's handover port.
	NetworkTags []string
	// Keys verifies identity tokens; a JWKS on GoogleKeys when nil.
	Keys idtoken.Keys
	// Now is time.Now when nil.
	Now func() time.Time
}

// Cloud implements vm.Cloud on Compute Engine.
type Cloud struct {
	cfg Config
}

var _ vm.Cloud = (*Cloud)(nil)

// New checks cfg.
func New(cfg Config) (*Cloud, error) {
	if cfg.API == nil || cfg.Project == "" || cfg.Zone == "" || cfg.Audience == "" {
		return nil, errors.New("gcp: API, Project, Zone and Audience are required")
	}
	if cfg.Keys == nil {
		cfg.Keys = &idtoken.JWKS{URL: GoogleKeys}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cloud{cfg: cfg}, nil
}

// Create implements vm.Cloud. The instance gets the spec's own service
// account (never the manager's), no external address, Shielded VM, project
// SSH keys blocked and no startup script: its job arrives only through the
// handover. The service account is required because an instance proves
// itself with that account's identity token.
func (c *Cloud) Create(ctx context.Context, spec vm.Spec, tags map[string]string) (string, error) {
	if spec.Identity == "" {
		return "", errors.New("gcp: the pool needs a service account for its instances to prove their identity")
	}
	name := instanceName(tags[vm.TagPool])
	err := c.cfg.API.InsertInstance(ctx, InsertInput{
		Name:               name,
		MachineType:        spec.Shape,
		SourceImage:        spec.Image,
		DiskGiB:            spec.DiskGiB,
		Subnetwork:         spec.Network,
		NetworkTags:        c.cfg.NetworkTags,
		ServiceAccount:     spec.Identity,
		Spot:               spec.Spot,
		Labels:             labels(tags),
		Metadata:           map[string]string{"block-project-ssh-keys": "true", "serial-port-enable": "false"},
		ShieldedSecureBoot: true,
	})
	if err != nil {
		return "", err
	}
	return name, nil
}

// instanceName is a fresh, valid instance name: lowercase, starting with a
// letter, at most 63 characters, never reused.
func instanceName(pool string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	prefix := invalidName.ReplaceAllString(strings.ToLower("oyzu-"+pool), "-")
	if len(prefix) > 48 {
		prefix = prefix[:48]
	}
	return strings.TrimRight(prefix, "-") + "-" + hex.EncodeToString(b)
}

var invalidName = regexp.MustCompile(`[^a-z0-9-]`)

// Describe implements vm.Cloud.
func (c *Cloud) Describe(ctx context.Context, ids []string) (map[string]vm.Instance, error) {
	out := map[string]vm.Instance{}
	for _, id := range ids {
		i, err := c.cfg.API.GetInstance(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[id] = convert(i)
	}
	return out, nil
}

// List implements vm.Cloud.
func (c *Cloud) List(ctx context.Context, manager string) ([]vm.Instance, error) {
	found, err := c.cfg.API.ListInstances(ctx, fmt.Sprintf("labels.%s = %q", knownLabel(vm.TagManager), labelValue(manager)))
	if err != nil {
		return nil, err
	}
	out := make([]vm.Instance, 0, len(found))
	for _, i := range found {
		out = append(out, convert(i))
	}
	return out, nil
}

// Tag implements vm.Cloud. Compute Engine replaces an instance's labels as a
// whole, so the current ones are read and merged first.
func (c *Cloud) Tag(ctx context.Context, id string, tags map[string]string) error {
	i, err := c.cfg.API.GetInstance(ctx, id)
	if err != nil {
		return err
	}
	merged := map[string]string{}
	for k, v := range i.Labels {
		merged[k] = v
	}
	for k, v := range labels(tags) {
		merged[k] = v
	}
	return c.cfg.API.SetLabels(ctx, id, merged)
}

// Destroy implements vm.Cloud. The boot disk is created with auto-delete,
// so deleting the instance deletes it too.
func (c *Cloud) Destroy(ctx context.Context, id string) error {
	err := c.cfg.API.DeleteInstance(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func convert(i Instance) vm.Instance {
	state := vm.StatePending
	switch i.Status {
	case "RUNNING":
		state = vm.StateRunning
	case "STOPPING", "SUSPENDING", "SUSPENDED", "TERMINATED":
		state = vm.StateStopping
	}
	return vm.Instance{
		ID: i.Name, State: state, Address: i.NetworkIP, Launched: i.CreationTimestamp, Tags: tags(i.Labels),
		// The manager never stops an instance, only deletes it, so a spot
		// instance stopping or stopped was reclaimed. To be confirmed
		// against real Compute Engine.
		Preempted: i.Spot && state == vm.StateStopping,
		Detail:    strings.TrimSpace(i.Status + " " + i.StatusMessage),
	}
}

// Label keys and values allow only lowercase letters, digits, '-' and '_',
// at most 63 characters, so the oyzu.io/ tags are spelled oyzu-pool,
// oyzu-manager and oyzu-job.
var invalidLabel = regexp.MustCompile(`[^a-z0-9_-]`)

// knownLabel is the label key for one of the oyzu.io/ tags.
func knownLabel(tag string) string {
	return "oyzu-" + labelValue(strings.TrimPrefix(tag, "oyzu.io/"))
}

func labelValue(v string) string {
	v = invalidLabel.ReplaceAllString(strings.ToLower(v), "-")
	if len(v) > 63 {
		v = v[:63]
	}
	return v
}

var knownTags = []string{vm.TagPool, vm.TagManager, vm.TagJob}

func labels(tags map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		key := labelValue(k)
		for _, t := range knownTags {
			if k == t {
				key = knownLabel(t)
			}
		}
		out[key] = labelValue(v)
	}
	return out
}

func tags(labels map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range labels {
		out[k] = v
	}
	for _, t := range knownTags {
		if v, ok := labels[knownLabel(t)]; ok {
			out[t] = v
		}
	}
	return out
}

// tokenClaims are the identity token's claims the adapter checks; the
// token must be requested with format=full.
type tokenClaims struct {
	Google struct {
		ComputeEngine struct {
			ProjectID         string `json:"project_id"`
			Zone              string `json:"zone"`
			InstanceID        string `json:"instance_id"`
			InstanceName      string `json:"instance_name"`
			InstanceCreatedAt int64  `json:"instance_creation_timestamp"`
		} `json:"compute_engine"`
	} `json:"google"`
}

// VerifyIdentity implements vm.Cloud. The proof's document is the instance
// identity token the metadata server issues for the configured audience
// with format=full; the signature is unused because the token carries its
// own. The token names the instance but not its image, so the instance is
// read back to confirm its numeric id and creation time match the token,
// which rules out a deleted instance's name being reused, and to report
// the boot disk's image.
func (c *Cloud) VerifyIdentity(ctx context.Context, p vm.Proof) (vm.Identity, error) {
	var claims tokenClaims
	policy := idtoken.Policy{Issuers: googleIssuers, Audience: c.cfg.Audience}
	if err := idtoken.Verify(ctx, c.cfg.Keys, policy, string(p.Document), c.cfg.Now(), &claims); err != nil {
		return vm.Identity{}, fmt.Errorf("gcp: %w", err)
	}
	ce := claims.Google.ComputeEngine
	switch {
	case ce.ProjectID != c.cfg.Project:
		return vm.Identity{}, fmt.Errorf("gcp: the instance belongs to project %q, not the pool's", ce.ProjectID)
	case ce.Zone != c.cfg.Zone:
		return vm.Identity{}, fmt.Errorf("gcp: the instance is in zone %q, not the pool's", ce.Zone)
	case ce.InstanceName == "" || ce.InstanceID == "":
		return vm.Identity{}, errors.New("gcp: the token names no instance; request it with format=full")
	}
	i, err := c.cfg.API.GetInstance(ctx, ce.InstanceName)
	if err != nil {
		return vm.Identity{}, fmt.Errorf("gcp: read instance %s: %w", ce.InstanceName, err)
	}
	if i.ID != ce.InstanceID || (ce.InstanceCreatedAt != 0 && i.CreationTimestamp.Unix() != ce.InstanceCreatedAt) {
		return vm.Identity{}, fmt.Errorf("gcp: instance %s is not the one the token was issued to", ce.InstanceName)
	}
	return vm.Identity{InstanceID: i.Name, Image: imageName(i.SourceImage)}, nil
}

// imageName turns a boot disk's source image URL into the relative name a
// pool spec uses. A spec must name an exact image, not an image family,
// because the disk records the image the family resolved to.
func imageName(s string) string {
	for _, p := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		s = strings.TrimPrefix(s, p)
	}
	return s
}

// Facts implements vm.Cloud from Compute Engine's machine type catalogue.
// Pools run Linux executors first.
func (c *Cloud) Facts(ctx context.Context, spec vm.Spec) (manager.Facts, error) {
	t, err := c.cfg.API.GetMachineType(ctx, spec.Shape)
	if err != nil {
		return nil, err
	}
	f := manager.Facts{
		manager.FactOS:     "linux",
		manager.FactCPU:    strconv.Itoa(t.GuestCPUs),
		manager.FactMemory: strconv.Itoa(t.MemoryMB) + "Mi",
	}
	switch t.Architecture {
	case "X86_64", "":
		// Machine types without an architecture are x86.
		f[manager.FactArch] = "amd64"
	case "ARM64":
		f[manager.FactArch] = "arm64"
	}
	return f, nil
}
