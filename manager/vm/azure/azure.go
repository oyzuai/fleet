// Package azure is the Azure Virtual Machines adapter for VM pools. It maps
// a pool's spec onto Azure VMs, tags them for reaping, and verifies the
// managed identity tokens instances present to the manager.
//
// It talks to Azure through API, the small subset of calls it needs, shaped
// so the production binding to the Azure SDK for Go is a thin wrapper. Until
// Oyzu has an Azure subscription it is exercised only against fakes;
// everything here that depends on real Azure behaviour is marked as such.
package azure

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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

// API is the subset of Azure Resource Manager the adapter uses. VMs are
// addressed by name within the pool's resource group.
type API interface {
	// CreateVM creates the VM and the one network interface it needs.
	CreateVM(ctx context.Context, in CreateInput) error
	GetVM(ctx context.Context, name string) (VM, error)
	// ListVMs returns every VM in the resource group, with instance views.
	ListVMs(ctx context.Context) ([]VM, error)
	// MergeTags adds tags to a VM, keeping the ones it has.
	MergeTags(ctx context.Context, name string, tags map[string]string) error
	DeleteVM(ctx context.Context, name string) error
	GetVMSize(ctx context.Context, name string) (VMSize, error)
}

// ErrNotFound is what API returns for a VM that does not exist.
var ErrNotFound = errors.New("azure: no such VM")

// CreateInput creates one VM.
type CreateInput struct {
	Name string
	Size string
	// ImageID is an Azure Compute Gallery image version resource id.
	ImageID string
	DiskGiB int
	// SubnetID is the subnet the network interface joins. No public
	// address is attached; the subnet's network security group allows only
	// the runs service, the source provider, registries, the cache and the
	// manager's handover port.
	SubnetID string
	// SystemAssignedIdentity gives the VM the managed identity it proves
	// itself with. UserAssignedIdentity is the pool's own narrow identity
	// for the build, never the manager's; empty means none.
	SystemAssignedIdentity bool
	UserAssignedIdentity   string
	// AdminUsername and SSHPublicKey satisfy Azure's requirement for a
	// Linux login. The key is generated per VM and its private half
	// discarded, and password login is off, so nobody can log in.
	AdminUsername string
	SSHPublicKey  string
	// Spot asks for Spot priority with the Deallocate eviction policy, so
	// an evicted VM stays visible as preempted until teardown deletes it.
	Spot bool
	// DeleteWithVM sets the OS disk's and network interface's delete option
	// so deleting the VM deletes them too.
	DeleteWithVM bool
	// SecureBoot turns on Trusted Launch with secure boot and vTPM.
	SecureBoot bool
	Tags       map[string]string
	// CustomData is always empty: no script or secret reaches the VM.
	CustomData string
}

// VM is Azure's view of one VM.
type VM struct {
	Name string
	// VMID is Azure's unique id for this incarnation of the VM.
	VMID string
	// PrincipalID is the object id of the VM's system-assigned identity.
	PrincipalID string
	// ImageID is the image reference the VM was created from.
	ImageID string
	// ProvisioningState is Creating, Updating, Succeeded, Failed or
	// Deleting; PowerState is the instance view's PowerState/ code, such as
	// running or deallocated.
	ProvisioningState string
	PowerState        string
	PrivateIP         string
	Created           time.Time
	Tags              map[string]string
	Spot              bool
}

// VMSize is a machine shape from Azure's resource SKU catalogue.
type VMSize struct {
	VCPUs     int
	MemoryMiB int
	// Architecture is the CpuArchitectureType capability: x64 or Arm64.
	Architecture string
}

// Config configures the adapter for one pool.
type Config struct {
	API API
	// Tenant, Subscription and ResourceGroup are where the pool's VMs live;
	// identity tokens from anywhere else are refused.
	Tenant        string
	Subscription  string
	ResourceGroup string
	// Audience is the application ID URI instances request their managed
	// identity token for.
	Audience string
	// Keys verifies identity tokens; a JWKS on the tenant's signing keys
	// when nil.
	Keys idtoken.Keys
	// Now is time.Now when nil.
	Now func() time.Time
}

// Cloud implements vm.Cloud on Azure Virtual Machines.
type Cloud struct {
	cfg Config
}

var _ vm.Cloud = (*Cloud)(nil)

// New checks cfg.
func New(cfg Config) (*Cloud, error) {
	if cfg.API == nil || cfg.Tenant == "" || cfg.Subscription == "" || cfg.ResourceGroup == "" || cfg.Audience == "" {
		return nil, errors.New("azure: API, Tenant, Subscription, ResourceGroup and Audience are required")
	}
	if cfg.Keys == nil {
		cfg.Keys = &idtoken.JWKS{URL: "https://login.microsoftonline.com/" + cfg.Tenant + "/discovery/v2.0/keys"}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Cloud{cfg: cfg}, nil
}

// tagImage records the image a VM was created from as the pool spelled it,
// because Azure may return the resource id in another case.
const tagImage = "oyzu-image"

// Create implements vm.Cloud. The VM gets a system-assigned identity to
// prove itself with, the spec's own user-assigned identity (never the
// manager's), Trusted Launch, no public address, no custom data and a login
// key nobody holds: its job arrives only through the handover.
func (c *Cloud) Create(ctx context.Context, spec vm.Spec, tags map[string]string) (string, error) {
	key, err := unusableSSHKey()
	if err != nil {
		return "", err
	}
	name := vmName(tags[vm.TagPool])
	t := azureTags(tags)
	t[tagImage] = spec.Image
	err = c.cfg.API.CreateVM(ctx, CreateInput{
		Name:                   name,
		Size:                   spec.Shape,
		ImageID:                spec.Image,
		DiskGiB:                spec.DiskGiB,
		SubnetID:               spec.Network,
		SystemAssignedIdentity: true,
		UserAssignedIdentity:   spec.Identity,
		AdminUsername:          "oyzu",
		SSHPublicKey:           key,
		Spot:                   spec.Spot,
		DeleteWithVM:           true,
		SecureBoot:             true,
		Tags:                   t,
	})
	if err != nil {
		return "", err
	}
	return name, nil
}

// unusableSSHKey returns an OpenSSH ed25519 public key whose private half
// is thrown away. Azure's ed25519 support for Linux VMs is to be confirmed
// against a real subscription.
func unusableSSHKey() (string, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	var b []byte
	for _, part := range [][]byte{[]byte("ssh-ed25519"), pub} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b) + " oyzu-unusable", nil
}

var invalidName = regexp.MustCompile(`[^a-z0-9-]`)

// vmName is a fresh, valid Linux VM name of at most 64 characters, never
// reused.
func vmName(pool string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	prefix := invalidName.ReplaceAllString(strings.ToLower("oyzu-"+pool), "-")
	if len(prefix) > 48 {
		prefix = prefix[:48]
	}
	return strings.TrimRight(prefix, "-") + "-" + hex.EncodeToString(b)
}

// Describe implements vm.Cloud.
func (c *Cloud) Describe(ctx context.Context, ids []string) (map[string]vm.Instance, error) {
	out := map[string]vm.Instance{}
	for _, id := range ids {
		v, err := c.cfg.API.GetVM(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[id] = convert(v)
	}
	return out, nil
}

// List implements vm.Cloud. Resource Manager cannot filter VMs by tag in
// one call, so the resource group's VMs are filtered here.
func (c *Cloud) List(ctx context.Context, manager string) ([]vm.Instance, error) {
	all, err := c.cfg.API.ListVMs(ctx)
	if err != nil {
		return nil, err
	}
	var out []vm.Instance
	for _, v := range all {
		i := convert(v)
		if i.Tags[vm.TagManager] == manager && i.State != vm.StateGone {
			out = append(out, i)
		}
	}
	return out, nil
}

// Tag implements vm.Cloud.
func (c *Cloud) Tag(ctx context.Context, id string, tags map[string]string) error {
	return c.cfg.API.MergeTags(ctx, id, azureTags(tags))
}

// Destroy implements vm.Cloud. The OS disk and network interface are
// created to be deleted with the VM.
func (c *Cloud) Destroy(ctx context.Context, id string) error {
	err := c.cfg.API.DeleteVM(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func convert(v VM) vm.Instance {
	state := vm.StatePending
	switch {
	case v.ProvisioningState == "Deleting":
		state = vm.StateGone
	case v.ProvisioningState == "Failed":
		state = vm.StateStopping
	case v.PowerState == "running":
		state = vm.StateRunning
	case v.PowerState == "stopping", v.PowerState == "stopped", v.PowerState == "deallocating", v.PowerState == "deallocated":
		state = vm.StateStopping
	}
	return vm.Instance{
		ID: v.Name, State: state, Address: v.PrivateIP, Launched: v.Created, Tags: oyzuTags(v.Tags),
		// The manager never deallocates a VM, only deletes it, so a Spot VM
		// deallocating or deallocated was evicted. To be confirmed against
		// real Azure.
		Preempted: v.Spot && (v.PowerState == "deallocating" || v.PowerState == "deallocated"),
		Detail:    strings.TrimSpace(v.ProvisioningState + " " + v.PowerState),
	}
}

// Azure tag names may not contain '/', so the oyzu.io/ tags are spelled
// oyzu-pool, oyzu-manager and oyzu-job.
var knownTags = []string{vm.TagPool, vm.TagManager, vm.TagJob}

func azureTag(tag string) string { return "oyzu-" + strings.TrimPrefix(tag, "oyzu.io/") }

func azureTags(tags map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		out[strings.ReplaceAll(k, "/", "-")] = v
	}
	for _, t := range knownTags {
		if v, ok := tags[t]; ok {
			delete(out, strings.ReplaceAll(t, "/", "-"))
			out[azureTag(t)] = v
		}
	}
	return out
}

func oyzuTags(tags map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		out[k] = v
	}
	for _, t := range knownTags {
		if v, ok := tags[azureTag(t)]; ok {
			out[t] = v
		}
	}
	return out
}

// tokenClaims are the managed identity token's claims the adapter checks.
type tokenClaims struct {
	TenantID string `json:"tid"`
	ObjectID string `json:"oid"`
	// ResourceID is the resource the managed identity belongs to: for a
	// system-assigned identity, the VM itself.
	ResourceID string `json:"xms_mirid"`
}

// resourceID parses a VM's Resource Manager id; segment names are matched
// without regard to case, as Azure does.
var resourceID = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)/resourcegroups/([^/]+)/providers/microsoft\.compute/virtualmachines/([^/]+)$`)

// VerifyIdentity implements vm.Cloud. The proof's document is the access
// token the VM's system-assigned managed identity gets from the instance
// metadata service for the configured audience; the signature is unused
// because the token carries its own. The token names the VM by resource id
// but not its image, so the VM is read back to confirm its system-assigned
// identity is the one the token was issued to, which rules out a deleted
// VM's name being reused, and to report its image.
func (c *Cloud) VerifyIdentity(ctx context.Context, p vm.Proof) (vm.Identity, error) {
	var claims tokenClaims
	policy := idtoken.Policy{
		Issuers: []string{
			"https://sts.windows.net/" + c.cfg.Tenant + "/",
			"https://login.microsoftonline.com/" + c.cfg.Tenant + "/v2.0",
		},
		Audience: c.cfg.Audience,
	}
	if err := idtoken.Verify(ctx, c.cfg.Keys, policy, string(p.Document), c.cfg.Now(), &claims); err != nil {
		return vm.Identity{}, fmt.Errorf("azure: %w", err)
	}
	if claims.TenantID != c.cfg.Tenant {
		return vm.Identity{}, fmt.Errorf("azure: the token is from tenant %q, not the pool's", claims.TenantID)
	}
	m := resourceID.FindStringSubmatch(claims.ResourceID)
	switch {
	case m == nil:
		return vm.Identity{}, errors.New("azure: the token is not a VM's system-assigned identity")
	case !strings.EqualFold(m[1], c.cfg.Subscription):
		return vm.Identity{}, fmt.Errorf("azure: the VM belongs to subscription %q, not the pool's", m[1])
	case !strings.EqualFold(m[2], c.cfg.ResourceGroup):
		return vm.Identity{}, fmt.Errorf("azure: the VM is in resource group %q, not the pool's", m[2])
	}
	v, err := c.cfg.API.GetVM(ctx, m[3])
	if err != nil {
		return vm.Identity{}, fmt.Errorf("azure: read VM %s: %w", m[3], err)
	}
	if claims.ObjectID == "" || !strings.EqualFold(v.PrincipalID, claims.ObjectID) {
		return vm.Identity{}, fmt.Errorf("azure: VM %s is not the one the token was issued to", m[3])
	}
	image := v.ImageID
	if spelled := v.Tags[tagImage]; strings.EqualFold(spelled, image) {
		image = spelled
	}
	return vm.Identity{InstanceID: v.Name, Image: image}, nil
}

// Facts implements vm.Cloud from Azure's resource SKU catalogue. Pools run
// Linux executors first.
func (c *Cloud) Facts(ctx context.Context, spec vm.Spec) (manager.Facts, error) {
	s, err := c.cfg.API.GetVMSize(ctx, spec.Shape)
	if err != nil {
		return nil, err
	}
	f := manager.Facts{
		manager.FactOS:     "linux",
		manager.FactCPU:    strconv.Itoa(s.VCPUs),
		manager.FactMemory: strconv.Itoa(s.MemoryMiB) + "Mi",
	}
	switch strings.ToLower(s.Architecture) {
	case "x64", "":
		f[manager.FactArch] = "amd64"
	case "arm64":
		f[manager.FactArch] = "arm64"
	}
	return f, nil
}
