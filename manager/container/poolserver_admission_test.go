package container

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/oyzuai/fleet/assertion"
	"github.com/oyzuai/fleet/poolserver"
	"github.com/oyzuai/fleet/runnerclient"
)

type admissionSource struct{}
func (admissionSource) CommitExists(context.Context, string, string) (bool, error) { return true, nil }
func (admissionSource) Source(context.Context, string) (runnerclient.Source, error) { panic("not needed") }

func TestPoolClaimsUseActualDriverQualification(t *testing.T) {
	for _, mode := range []string{"passed", "failed", "pending", "absent"} {
		t.Run(mode, func(t *testing.T) {
			e := newFakeEngine()
			e.present = true
			if mode == "failed" { e.probeExit = 1 }
			d, _ := sandboxDriver(e, EgressEnforce)
			if mode == "passed" || mode == "failed" {
				if capacity := settle(t, d); len(capacity.Ready) == 0 { t.Fatal("expected slots ready even after failed egress probe") }
			}
			facts, err := d.Facts(context.Background())
			if err != nil { t.Fatal(err) }
			var cfg poolserver.Config
			cfg.Account, cfg.PublicURL, cfg.StateDir = "test", "https://pool.test", t.TempDir()
			cfg.Repositories = []string{"oyzuai/fleet"}
			cfg.Callers.TailnetUsers = []string{"test@example.com"}
			cfg.GitHubApp.AppID = 5467712
			h := sha256.Sum256([]byte("enroll"))
			cfg.EnrollmentTokenSHA256 = hex.EncodeToString(h[:])
			pool, err := poolserver.New(cfg, poolserver.Options{Source: admissionSource{}})
			if err != nil { t.Fatal(err) }
			ts := httptest.NewServer(pool)
			defer ts.Close()
			req, _ := http.NewRequest("POST", ts.URL+"/api/v1alpha1/accounts/test/runs", bytes.NewBufferString(`{"repository":{"provider":"github","name":"oyzuai/fleet"},"commit":"0123456789abcdef0123456789abcdef01234567","ref":"refs/heads/main","operation":{"kind":"build"}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Tailscale-User-Login", "test@example.com")
			resp, err := ts.Client().Do(req)
			if err != nil { t.Fatal(err) }
			resp.Body.Close()
			if resp.StatusCode != 201 { t.Fatalf("create: %d", resp.StatusCode) }
			c := runnerclient.New(ts.URL, ts.Client())
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			enrolled, err := c.Enroll(context.Background(), "enroll", "driver", pub)
			if err != nil { t.Fatal(err) }
			jwt, _ := assertion.Sign(priv, enrolled.KeyID, assertion.TypeLogin, assertion.New(enrolled.ManagerID, "oyzu-runs", "once", time.Now(), time.Minute))
			access, err := c.Login(context.Background(), jwt)
			if err != nil { t.Fatal(err) }
			if mode != "absent" {
				if err := c.Report(context.Background(), access.Token, runnerclient.Report{Facts: facts, Slots: runnerclient.Slots{Max: 1, Ready: 1}}); err != nil { t.Fatal(err) }
			}
			claim, err := c.Claim(context.Background(), access.Token)
			if err != nil || (claim != nil) != (mode == "passed") { t.Fatalf("facts=%v claim=%+v err=%v", facts, claim, err) }
		})
	}
}
