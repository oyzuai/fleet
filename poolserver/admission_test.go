package poolserver

import (
	"context"
	"testing"
	"time"

	"github.com/oyzuai/fleet/manager"
	"github.com/oyzuai/fleet/runnerclient"
)

func TestClaimsRequireFreshCompleteQualification(t *testing.T) {
	for _, mode := range []string{"absent", "isolation", "egress", "untrusted", "stale", "future", "zero-timestamp"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			run := f.create(t)
			id := f.loginWithoutReport(t)
			ctx := context.Background()
			facts := qualifiedFacts()
			switch mode {
			case "isolation":
				delete(facts, manager.FactIsolation)
			case "egress":
				facts[manager.FactEgress] = manager.EgressOpen
			case "untrusted":
				delete(facts, manager.FactUntrusted)
			}
			if mode != "absent" {
				if err := f.c.Report(ctx, id.access, runnerclient.Report{Facts: facts, Slots: runnerclient.Slots{Max: 1, Ready: 1}}); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "stale":
				f.now.Add(30)
			case "future":
				f.now.Add(-1)
			case "zero-timestamp":
				f.s.mu.Lock()
				f.s.state.Meta.Managers[id.enrolled.ManagerID].ReportedAt = time.Time{}
				f.s.mu.Unlock()
			}
			demand, err := f.c.Demand(ctx, id.access)
			if err != nil || demand.Eligible != 0 || demand.Ready != 0 {
				t.Fatalf("unqualified demand: %+v %v", demand, err)
			}
			claim, err := f.c.Claim(ctx, id.access)
			if err != nil || claim != nil {
				t.Fatalf("unqualified claim: %+v %v", claim, err)
			}
			f.s.mu.Lock()
			attempt := f.s.state.Runs[run.ID].Run.Attempt
			f.s.mu.Unlock()
			if attempt != 0 {
				t.Fatalf("refusal consumed attempt %d", attempt)
			}
			if err := f.c.Report(ctx, id.access, runnerclient.Report{Facts: qualifiedFacts()}); err != nil {
				t.Fatal(err)
			}
			demand, err = f.c.Demand(ctx, id.access)
			if err != nil || demand.Ready != 1 {
				t.Fatalf("qualified demand: %+v %v", demand, err)
			}
			claim, err = f.c.Claim(ctx, id.access)
			if err != nil || claim == nil || claim.Attempt != 1 {
				t.Fatalf("qualified claim: %+v %v", claim, err)
			}
		})
	}
}
