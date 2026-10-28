package kindrunner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/executionconfig"
	"github.com/oyzuai/fleet/kindprotocol"
	"github.com/oyzuai/fleet/runnerclient"
)

func kindTrust(t *testing.T) *runnerclient.ExecutionConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	canonical, digest, err := executionconfig.CanonicalBundle(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	if err != nil {
		t.Fatal(err)
	}
	roots := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(roots, []byte(canonical), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", roots)
	return &runnerclient.ExecutionConfig{Version: 1, Revision: "kind-revision", Bundles: []runnerclient.ExecutionCABundle{{PEM: canonical, Digest: digest, Required: true}}, Proxy: &runnerclient.ExecutionProxy{HTTPS: "http://corporate.example:3128"}}
}

func TestKindExecutionEvidenceAndCleanup(t *testing.T) {
	f, cfg, job, _ := setup(t, "trust", kindprotocol.OpObserve, 30, 0, nil)
	cfg.WorkDir = t.TempDir()
	job.ExecutionConfig = kindTrust(t)
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	if len(f.finish["result"]) == 0 {
		t.Fatalf("kind did not receive trust: %s", f.finish["no_result"])
	}
	var evidence runnerclient.ExecutionEvidence
	if err := json.Unmarshal(f.finish["execution"], &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Revision != "kind-revision" || len(evidence.BundleDigests) != 1 || evidence.ProxyHosts[0] != "corporate.example" {
		t.Fatalf("evidence: %+v", evidence)
	}
	if strings.Contains(string(f.finish["execution"]), "CERTIFICATE") || strings.Contains(string(f.finish["execution"]), "http://") {
		t.Fatal("launch inputs in evidence")
	}
	files, err := os.ReadDir(cfg.WorkDir)
	if err != nil || len(files) != 0 {
		t.Fatal("kind trust files survived completion", err)
	}
}

func TestImageKindMountsTrustReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the existing Docker CLI fake is a POSIX shell script")
	}
	_, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	job.ExecutionConfig = kindTrust(t)
	job.KindOperation.Image = "cache.example/scanner@sha256:" + strings.Repeat("a", 64)
	cfg.WorkDir = t.TempDir()
	args := filepath.Join(t.TempDir(), "args")
	docker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(docker, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$OYZU_TRUST_ARGS\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OYZU_TRUST_ARGS", args)
	cfg.Docker = docker
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{":" + ContainerTrustDir + ":ro", "SSL_CERT_FILE=" + ContainerTrustDir + "/ca.pem", "NODE_EXTRA_CA_CERTS=" + ContainerTrustDir + "/additional-ca.pem", "HTTPS_PROXY=http://corporate.example:3128"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("Docker launch lacks %s", want)
		}
	}
}

func TestKindCannotStartWithoutRequiredTrust(t *testing.T) {
	f, cfg, job, _ := setup(t, "ok", kindprotocol.OpObserve, 30, 0, nil)
	job.ExecutionConfig = &runnerclient.ExecutionConfig{Version: 1, Revision: "kind-revision", Bundles: []runnerclient.ExecutionCABundle{{Required: true}}}
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	var none runnerclient.KindNoResult
	if err := json.Unmarshal(f.finish["no_result"], &none); err != nil {
		t.Fatal(err)
	}
	if none.Code != executionconfig.Unavailable || none.Started {
		t.Fatalf("no result: %+v", none)
	}
}
