// Package aws is the Amazon EC2 adapter for VM pools. It maps a pool's spec
// onto EC2 instances, tags them for reaping, insists on IMDSv2 and verifies
// the signed instance identity documents instances present to the manager.
//
// It talks to EC2 through API, the small subset of calls it needs, shaped so
// the production binding to the AWS SDK is a thin wrapper. Until Oyzu has an
// AWS account it is exercised only against fakes; everything here that
// depends on real EC2 behaviour is marked as such.
package aws

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/vm"
)

// API is the subset of EC2 the adapter uses.
type API interface {
	RunInstance(ctx context.Context, in RunInput) (string, error)
	DescribeInstances(ctx context.Context, in DescribeInput) ([]Instance, error)
	TerminateInstances(ctx context.Context, ids []string) error
	CreateTags(ctx context.Context, ids []string, tags map[string]string) error
	DescribeInstanceType(ctx context.Context, name string) (InstanceType, error)
}

// RunInput launches one instance.
type RunInput struct {
	ImageID          string
	InstanceType     string
	SubnetID         string
	SecurityGroupIDs []string
	// InstanceProfile is the instance's own role; empty means none.
	InstanceProfile string
	Spot            bool
	RootVolumeGiB   int
	Tags            map[string]string
	// MetadataTokensRequired turns IMDSv1 off, and MetadataHopLimit 1 keeps
	// the metadata service unreachable from containers on the instance.
	MetadataTokensRequired bool
	MetadataHopLimit       int
}

// DescribeInput selects instances by id, or by filters such as
// "tag:oyzu.io/manager" and "instance-state-name".
type DescribeInput struct {
	IDs     []string
	Filters map[string][]string
}

// Instance is EC2's view of one instance.
type Instance struct {
	ID         string
	State      string // pending, running, shutting-down, terminated, stopping, stopped
	PrivateIP  string
	ImageID    string
	LaunchTime time.Time
	Tags       map[string]string
	// StateReasonCode is EC2's state reason, such as
	// Server.SpotInstanceTermination.
	StateReasonCode    string
	StateReasonMessage string
}

// InstanceType is a machine shape from EC2's catalogue.
type InstanceType struct {
	VCPUs         int
	MemoryMiB     int
	Architectures []string // x86_64, arm64
}

// Config configures the adapter for one pool.
type Config struct {
	API API
	// Region and Account are where the pool's instances live; identity
	// documents from anywhere else are refused.
	Region  string
	Account string
	// SecurityGroupIDs allow only the runs service, the source provider,
	// registries, the cache and the manager's handover port.
	SecurityGroupIDs []string
	// Certificate is AWS's published PEM certificate for verifying the
	// region's base64 instance identity signatures.
	Certificate []byte
}

// Cloud implements vm.Cloud on EC2.
type Cloud struct {
	cfg  Config
	cert *x509.Certificate
}

var _ vm.Cloud = (*Cloud)(nil)

// New checks cfg and parses the region's certificate.
func New(cfg Config) (*Cloud, error) {
	if cfg.API == nil || cfg.Region == "" || cfg.Account == "" {
		return nil, errors.New("aws: API, Region and Account are required")
	}
	block, _ := pem.Decode(cfg.Certificate)
	if block == nil {
		return nil, errors.New("aws: Certificate is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("aws: parse Certificate: %w", err)
	}
	return &Cloud{cfg: cfg, cert: cert}, nil
}

// Create implements vm.Cloud. Instances accept only IMDSv2 with a hop limit
// of 1, get the spec's own instance profile (never the manager's), and
// carry no user data: an instance's job arrives only through the handover.
func (c *Cloud) Create(ctx context.Context, spec vm.Spec, tags map[string]string) (string, error) {
	return c.cfg.API.RunInstance(ctx, RunInput{
		ImageID:                spec.Image,
		InstanceType:           spec.Shape,
		SubnetID:               spec.Network,
		SecurityGroupIDs:       c.cfg.SecurityGroupIDs,
		InstanceProfile:        spec.Identity,
		Spot:                   spec.Spot,
		RootVolumeGiB:          spec.DiskGiB,
		Tags:                   tags,
		MetadataTokensRequired: true,
		MetadataHopLimit:       1,
	})
}

// Describe implements vm.Cloud.
func (c *Cloud) Describe(ctx context.Context, ids []string) (map[string]vm.Instance, error) {
	found, err := c.cfg.API.DescribeInstances(ctx, DescribeInput{IDs: ids})
	if err != nil {
		return nil, err
	}
	out := map[string]vm.Instance{}
	for _, i := range found {
		out[i.ID] = convert(i)
	}
	return out, nil
}

// List implements vm.Cloud.
func (c *Cloud) List(ctx context.Context, manager string) ([]vm.Instance, error) {
	found, err := c.cfg.API.DescribeInstances(ctx, DescribeInput{Filters: map[string][]string{
		"tag:" + vm.TagManager: {manager},
		"instance-state-name":  {"pending", "running", "shutting-down", "stopping", "stopped"},
	}})
	if err != nil {
		return nil, err
	}
	out := make([]vm.Instance, 0, len(found))
	for _, i := range found {
		out = append(out, convert(i))
	}
	return out, nil
}

// Tag implements vm.Cloud.
func (c *Cloud) Tag(ctx context.Context, id string, tags map[string]string) error {
	return c.cfg.API.CreateTags(ctx, []string{id}, tags)
}

// Destroy implements vm.Cloud. Terminating deletes the root volume, which
// EC2 does by default for volumes created at launch.
func (c *Cloud) Destroy(ctx context.Context, id string) error {
	return c.cfg.API.TerminateInstances(ctx, []string{id})
}

// spotReasons are the state reason codes EC2 gives when it reclaims spot
// capacity. To be confirmed against real EC2.
var spotReasons = map[string]bool{
	"Server.SpotInstanceTermination": true,
	"Server.SpotInstanceShutdown":    true,
}

func convert(i Instance) vm.Instance {
	state := vm.StatePending
	switch i.State {
	case "running":
		state = vm.StateRunning
	case "shutting-down", "stopping", "stopped":
		state = vm.StateStopping
	case "terminated":
		state = vm.StateGone
	}
	detail := i.StateReasonMessage
	if detail == "" {
		detail = i.StateReasonCode
	}
	return vm.Instance{ID: i.ID, State: state, Address: i.PrivateIP, Launched: i.LaunchTime,
		Tags: i.Tags, Preempted: spotReasons[i.StateReasonCode], Detail: detail}
}

// document is the instance identity document's fields the adapter checks.
type document struct {
	AccountID  string `json:"accountId"`
	Region     string `json:"region"`
	InstanceID string `json:"instanceId"`
	ImageID    string `json:"imageId"`
	PrivateIP  string `json:"privateIp"`
}

// VerifyIdentity implements vm.Cloud. The proof is the instance identity
// document and the base64 signature the instance metadata service returns
// for it, verified as SHA256 with RSA against the region's AWS certificate.
// The signature algorithm is AWS's documented one, to be confirmed against
// real instance metadata once an account exists.
func (c *Cloud) VerifyIdentity(_ context.Context, p vm.Proof) (vm.Identity, error) {
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(p.Signature)))
	if err != nil {
		return vm.Identity{}, fmt.Errorf("aws: the identity signature is not base64: %w", err)
	}
	if err := c.cert.CheckSignature(x509.SHA256WithRSA, p.Document, sig); err != nil {
		return vm.Identity{}, fmt.Errorf("aws: the identity document's signature does not verify: %w", err)
	}
	var doc document
	if err := json.Unmarshal(p.Document, &doc); err != nil {
		return vm.Identity{}, fmt.Errorf("aws: the identity document is not JSON: %w", err)
	}
	switch {
	case doc.AccountID != c.cfg.Account:
		return vm.Identity{}, fmt.Errorf("aws: the instance belongs to account %q, not the pool's", doc.AccountID)
	case doc.Region != c.cfg.Region:
		return vm.Identity{}, fmt.Errorf("aws: the instance is in region %q, not the pool's", doc.Region)
	case doc.InstanceID == "":
		return vm.Identity{}, errors.New("aws: the identity document names no instance")
	}
	return vm.Identity{InstanceID: doc.InstanceID, Image: doc.ImageID}, nil
}

// Facts implements vm.Cloud from EC2's instance type catalogue. Pools run
// Linux executors first.
func (c *Cloud) Facts(ctx context.Context, spec vm.Spec) (manager.Facts, error) {
	t, err := c.cfg.API.DescribeInstanceType(ctx, spec.Shape)
	if err != nil {
		return nil, err
	}
	f := manager.Facts{
		manager.FactOS:     "linux",
		manager.FactCPU:    strconv.Itoa(t.VCPUs),
		manager.FactMemory: strconv.Itoa(t.MemoryMiB) + "Mi",
	}
	for _, a := range t.Architectures {
		switch a {
		case "x86_64":
			f[manager.FactArch] = "amd64"
		case "arm64":
			f[manager.FactArch] = "arm64"
		}
	}
	return f, nil
}
