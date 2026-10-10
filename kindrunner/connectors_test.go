package kindrunner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/oyzuai/fleet/kindprotocol"
	"github.com/oyzuai/fleet/runnerclient"
)

// reportConnectors is the fake kind's connectors mode: one log event per
// file under connectors/, with its contents, and one per AWS variable.
func reportConnectors(ev func(kindprotocol.EventBody, int64)) {
	dir := os.Getenv("OYZU_SECRETS_DIR")
	var lines []string
	filepath.WalkDir(filepath.Join(dir, ConnectorsDir), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		b, _ := os.ReadFile(path)
		if filepath.Base(path) == ConnectorFile {
			var desc ConnectorDescription
			json.Unmarshal(b, &desc)
			b = []byte(desc.Identifier + " " + desc.Kind + " " + desc.Target + " " + strings.Join(desc.SecretFiles, ",") + " " + desc.IDTokenFile)
		}
		lines = append(lines, "file "+filepath.ToSlash(rel)+"="+string(b))
		return nil
	})
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "AWS_") {
			lines = append(lines, "env "+strings.Replace(kv, dir, "$DIR", 1))
		}
	}
	sort.Strings(lines)
	for i, l := range lines {
		ev(kindprotocol.EventBody{Type: "log", Level: "info", Message: l}, int64(i+1))
	}
}

func connectorLines(f *fakeRuns) map[string]bool {
	out := map[string]bool{}
	for _, e := range f.events {
		if strings.HasPrefix(e.Message, "file ") || strings.HasPrefix(e.Message, "env ") {
			out[e.Message] = true
		}
	}
	return out
}

func testConnectors() runnerclient.KindConnectors {
	exp := time.Now().Add(5 * time.Minute)
	return runnerclient.KindConnectors{Target: "web-prod", Grant: "web-on-prod", Connectors: []runnerclient.KindConnector{
		{Role: "apply", Identifier: "aws-prod", Kind: "aws", Mechanism: "aws-workload-identity",
			Settings:   map[string]any{"account_id": "123456789012"},
			Parameters: map[string]any{"role_arn": "arn:aws:iam::123456789012:role/deploy"},
			Secrets:    []runnerclient.KindConnectorSecret{}, IDToken: "apply.jwt", IDTokenExpires: &exp},
		{Role: "observe", Identifier: "argo", Kind: "argo-cd", Mechanism: "api-token",
			Settings: map[string]any{"server": "https://argo.example.test"}, Parameters: map[string]any{},
			Secrets: []runnerclient.KindConnectorSecret{{Field: "token", Value: []byte("argocd_abc")}}},
	}}
}

func TestConnectorsAreFiles(t *testing.T) {
	// Credentials the pool itself has must not reach a kind that uses a
	// connector.
	t.Setenv("AWS_ACCESS_KEY_ID", "pool-key")
	t.Setenv("AWS_PROFILE", "pool")
	f, cfg, job, _ := setup(t, "connectors", kindprotocol.OpPlan, 30, 0, nil)
	f.connectors = testConnectors()
	job.KindOperation.Connectors = []string{"apply", "observe"}
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	got := connectorLines(f)
	for _, want := range []string{
		"file connectors/apply/connector.json=aws-prod aws web-prod  id_token",
		"file connectors/apply/id_token=apply.jwt",
		"file connectors/observe/connector.json=argo argo-cd web-prod token ",
		"file connectors/observe/token=argocd_abc",
		"env AWS_ROLE_ARN=arn:aws:iam::123456789012:role/deploy",
		"env AWS_WEB_IDENTITY_TOKEN_FILE=$DIR/connectors/apply/id_token",
		"env AWS_ROLE_SESSION_NAME=oyzu-7-1-apply",
	} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	for line := range got {
		if strings.HasPrefix(line, "env AWS_ACCESS_KEY_ID") || strings.HasPrefix(line, "env AWS_PROFILE") {
			t.Errorf("the pool's credentials reached the kind: %s", line)
		}
	}
	// Nothing about the values reaches runs, and nothing is left behind.
	if left, _ := filepath.Glob(filepath.Join(cfg.SecretsDir, "*")); len(left) != 0 {
		t.Fatalf("connector files left behind: %v", left)
	}
}

// A named binding is written under connectors/named/<alias>/, beside the
// apply and observe connectors, and never points the AWS SDKs anywhere.
func TestNamedConnectorsAreFiles(t *testing.T) {
	f, cfg, job, _ := setup(t, "connectors", kindprotocol.OpPlan, 30, 0, nil)
	f.connectors = testConnectors()
	f.connectors.Connectors = append(f.connectors.Connectors, runnerclient.KindConnector{
		Role: "apply", Alias: "cloudflare", Identifier: "cf-dns", Kind: "credentials", Mechanism: "secrets",
		Settings:   map[string]any{"variables": map[string]any{"api_token": "CLOUDFLARE_API_TOKEN"}},
		Parameters: map[string]any{}, Secrets: []runnerclient.KindConnectorSecret{{Field: "api_token", Value: []byte("cf_abc")}}},
		runnerclient.KindConnector{Role: "apply", Alias: "aws-dns", Identifier: "aws-dns", Kind: "aws", Mechanism: "aws-workload-identity",
			Parameters: map[string]any{"role_arn": "arn:aws:iam::210987654321:role/dns"}, Secrets: []runnerclient.KindConnectorSecret{},
			IDToken: "dns.jwt"})
	job.KindOperation.Connectors = []string{"apply", "observe", "named/cloudflare", "named/aws-dns"}
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	got := connectorLines(f)
	for _, want := range []string{
		"file connectors/named/cloudflare/connector.json=cf-dns credentials web-prod api_token ",
		"file connectors/named/cloudflare/api_token=cf_abc",
		"file connectors/named/aws-dns/id_token=dns.jwt",
		"env AWS_ROLE_ARN=arn:aws:iam::123456789012:role/deploy",
	} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if got["env AWS_ROLE_ARN=arn:aws:iam::210987654321:role/dns"] {
		t.Error("a named aws connector took over the AWS SDKs' default chain")
	}

	// An alias that is not a directory name is refused.
	f, cfg, job, _ = setup(t, "connectors", kindprotocol.OpPlan, 30, 0, nil)
	f.connectors = testConnectors()
	f.connectors.Connectors = append(f.connectors.Connectors, runnerclient.KindConnector{Role: "apply", Alias: "../x",
		Identifier: "x", Kind: "credentials", Mechanism: "secrets", Secrets: []runnerclient.KindConnectorSecret{}})
	job.KindOperation.Connectors = []string{"apply", "named/../x"}
	_ = Run(context.Background(), cfg, job)
	if got := connectorLines(f); len(got) != 0 {
		t.Fatalf("the kind ran with a bad alias: %v", got)
	}
}

func TestReadOnlyOperationActsThroughObserve(t *testing.T) {
	f, cfg, job, _ := setup(t, "connectors", kindprotocol.OpObserve, 30, 0, nil)
	f.connectors = testConnectors()
	// runs sends only the observe connector to a read-only operation; give
	// it an aws observe connector to check the variables follow the role.
	f.connectors.Connectors = []runnerclient.KindConnector{f.connectors.Connectors[0]}
	f.connectors.Connectors[0].Role = "observe"
	job.KindOperation.Connectors = []string{"observe"}
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	got := connectorLines(f)
	if !got["env AWS_WEB_IDENTITY_TOKEN_FILE=$DIR/connectors/observe/id_token"] || !got["env AWS_ROLE_SESSION_NAME=oyzu-7-1-observe"] {
		t.Fatalf("observe connector: %v", got)
	}
}

func TestBadConnectorNeverStartsTheKind(t *testing.T) {
	f, cfg, job, _ := setup(t, "connectors", kindprotocol.OpPlan, 30, 0, nil)
	f.connectors = testConnectors()
	f.connectors.Connectors[1].Secrets[0].Field = "../escape"
	job.KindOperation.Connectors = []string{"apply", "observe"}
	if err := Run(context.Background(), cfg, job); err != nil {
		t.Fatal(err)
	}
	var none runnerclient.KindNoResult
	if err := json.Unmarshal(f.finish["no_result"], &none); err != nil || none.Code != "secrets-unavailable" || none.Started {
		t.Fatalf("finish %s", f.finish)
	}
}

func TestContainerSeesConnectorPaths(t *testing.T) {
	sd := &secretDir{path: "/tmp/x"}
	sd.env = []envVar{{name: "AWS_WEB_IDENTITY_TOKEN_FILE", value: "connectors/apply/id_token", path: true}, {name: "AWS_ROLE_ARN", value: "arn"}}
	got := sd.vars(ContainerSecretsDir)
	if got[0] != "AWS_WEB_IDENTITY_TOKEN_FILE=/run/oyzu/secrets/connectors/apply/id_token" || got[1] != "AWS_ROLE_ARN=arn" {
		t.Fatalf("vars = %v", got)
	}
	sd.unset = []string{"AWS_PROFILE"}
	if env := sd.scrub([]string{"AWS_PROFILE=x", "HOME=/h"}); len(env) != 1 || env[0] != "HOME=/h" {
		t.Fatalf("scrub = %v", env)
	}
}
