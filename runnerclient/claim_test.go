package runnerclient

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestClaimCarriesTheEgressAllowList(t *testing.T) {
	var c Claim
	body := `{"job_id":7,"attempt":1,"startup_token":"st","egress":{"allow":[{"host":"registry.npmjs.org","port":443},{"host":"*.example.com","port":0}]}}`
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatal(err)
	}
	want := []EgressAllow{{Host: "registry.npmjs.org", Port: 443}, {Host: "*.example.com", Port: 0}}
	if !slices.Equal(c.Egress.Allow, want) {
		t.Fatalf("allow = %+v", c.Egress.Allow)
	}
	// A runs that predates egress sends none.
	var old Claim
	if err := json.Unmarshal([]byte(`{"job_id":7,"attempt":1,"startup_token":"st"}`), &old); err != nil || len(old.Egress.Allow) != 0 {
		t.Fatalf("old claim = %+v, %v", old, err)
	}
}
