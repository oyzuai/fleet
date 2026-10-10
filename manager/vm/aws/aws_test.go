package aws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/manager/vm"
)

type fakeEC2 struct {
	run       []RunInput
	describe  []DescribeInput
	instances []Instance
}

func (f *fakeEC2) RunInstance(_ context.Context, in RunInput) (string, error) {
	f.run = append(f.run, in)
	return "i-0abc", nil
}

func (f *fakeEC2) DescribeInstances(_ context.Context, in DescribeInput) ([]Instance, error) {
	f.describe = append(f.describe, in)
	return f.instances, nil
}

func (f *fakeEC2) TerminateInstances(context.Context, []string) error { return nil }

func (f *fakeEC2) CreateTags(context.Context, []string, map[string]string) error { return nil }

func (f *fakeEC2) DescribeInstanceType(_ context.Context, name string) (InstanceType, error) {
	return InstanceType{VCPUs: 8, MemoryMiB: 16384, Architectures: []string{"x86_64"}}, nil
}

// signer stands in for AWS's regional signing key and its certificate.
type signer struct {
	key  *rsa.PrivateKey
	cert []byte
}

func newSigner(t *testing.T) signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test region"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key, cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (s signer) proof(t *testing.T, doc string) vm.Proof {
	t.Helper()
	sum := sha256.Sum256([]byte(doc))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return vm.Proof{Document: []byte(doc), Signature: []byte(base64.StdEncoding.EncodeToString(sig) + "\n")}
}

func newCloud(t *testing.T, api API, s signer) *Cloud {
	t.Helper()
	c, err := New(Config{API: api, Region: "us-east-1", Account: "111122223333",
		SecurityGroupIDs: []string{"sg-builds"}, Certificate: s.cert})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const doc = `{"accountId":"111122223333","region":"us-east-1","instanceId":"i-0abc","imageId":"ami-executor","privateIp":"10.0.0.5"}`

func TestCreateRequiresIMDSv2AndCarriesNoUserData(t *testing.T) {
	api := &fakeEC2{}
	c := newCloud(t, api, newSigner(t))
	id, err := c.Create(context.Background(), vm.Spec{Image: "ami-executor", Shape: "c7i.2xlarge",
		Network: "subnet-builds", Identity: "oyzu-executor", Spot: true},
		map[string]string{vm.TagManager: "7"})
	if err != nil || id != "i-0abc" {
		t.Fatalf("create: %q, %v", id, err)
	}
	in := api.run[0]
	if !in.MetadataTokensRequired || in.MetadataHopLimit != 1 {
		t.Fatalf("metadata options: %+v", in)
	}
	if in.InstanceProfile != "oyzu-executor" || in.SubnetID != "subnet-builds" || !in.Spot || in.Tags[vm.TagManager] != "7" {
		t.Fatalf("run input: %+v", in)
	}
}

func TestListFiltersByManagerAndLiveStates(t *testing.T) {
	api := &fakeEC2{}
	c := newCloud(t, api, newSigner(t))
	if _, err := c.List(context.Background(), "7"); err != nil {
		t.Fatal(err)
	}
	f := api.describe[0].Filters
	if got := f["tag:"+vm.TagManager]; len(got) != 1 || got[0] != "7" {
		t.Fatalf("manager filter: %v", f)
	}
	for _, s := range f["instance-state-name"] {
		if s == "terminated" {
			t.Fatal("terminated instances are listed")
		}
	}
}

func TestSpotTerminationIsPreempted(t *testing.T) {
	api := &fakeEC2{instances: []Instance{{ID: "i-1", State: "terminated", StateReasonCode: "Server.SpotInstanceTermination"},
		{ID: "i-2", State: "shutting-down", StateReasonCode: "Client.UserInitiatedShutdown"}}}
	c := newCloud(t, api, newSigner(t))
	got, err := c.Describe(context.Background(), []string{"i-1", "i-2"})
	if err != nil {
		t.Fatal(err)
	}
	if got["i-1"].State != vm.StateGone || !got["i-1"].Preempted {
		t.Fatalf("spot instance: %+v", got["i-1"])
	}
	if got["i-2"].State != vm.StateStopping || got["i-2"].Preempted {
		t.Fatalf("stopping instance: %+v", got["i-2"])
	}
}

func TestVerifyIdentity(t *testing.T) {
	s := newSigner(t)
	c := newCloud(t, &fakeEC2{}, s)
	ctx := context.Background()
	id, err := c.VerifyIdentity(ctx, s.proof(t, doc))
	if err != nil || id.InstanceID != "i-0abc" || id.Image != "ami-executor" {
		t.Fatalf("verify: %+v, %v", id, err)
	}
	tampered := s.proof(t, doc)
	tampered.Document = []byte(`{"accountId":"111122223333","region":"us-east-1","instanceId":"i-other","imageId":"ami-executor"}`)
	if _, err := c.VerifyIdentity(ctx, tampered); err == nil {
		t.Fatal("a tampered document verified")
	}
	other := `{"accountId":"999999999999","region":"us-east-1","instanceId":"i-0abc","imageId":"ami-executor"}`
	if _, err := c.VerifyIdentity(ctx, s.proof(t, other)); err == nil {
		t.Fatal("another account's instance verified")
	}
	if _, err := c.VerifyIdentity(ctx, newSigner(t).proof(t, doc)); err == nil {
		t.Fatal("a document signed by another key verified")
	}
}

func TestFactsFromTheCatalogue(t *testing.T) {
	c := newCloud(t, &fakeEC2{}, newSigner(t))
	f, err := c.Facts(context.Background(), vm.Spec{Shape: "c7i.2xlarge"})
	if err != nil {
		t.Fatal(err)
	}
	if f[manager.FactArch] != "amd64" || f[manager.FactCPU] != "8" || f[manager.FactMemory] != "16384Mi" {
		t.Fatalf("facts: %v", f)
	}
}
