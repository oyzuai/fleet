package runnerclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestFinishCarriesTestFailuresAndOmitsUnavailableCoordinates(t *testing.T) {
	want := []TestFailure{
		{Scope: "api:test", Name: "rejects anonymous", Classname: "api", Path: "tests/api_test.go", Line: 17, Message: "expected 401; got 200"},
		{Scope: "api:test", Name: "connects", Message: "connection refused"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/runner/v1/job/finish" || r.Header.Get("Authorization") != "Bearer current-attempt" {
			t.Errorf("finish request: %s", r.URL.Path)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var got []TestFailure
		if err := json.Unmarshal(raw["test_failures"], &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("finish failures = %+v, %v; want %+v", got, err, want)
		}
		var records []map[string]json.RawMessage
		if err := json.Unmarshal(raw["test_failures"], &records); err != nil {
			t.Error(err)
		} else if len(records) != 2 {
			t.Errorf("finish carried %d failures", len(records))
		} else {
			for _, field := range []string{"classname", "path", "line"} {
				if _, present := records[1][field]; present {
					t.Errorf("unavailable %s was not omitted", field)
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	code := 3
	if err := New(server.URL, server.Client()).Finish(context.Background(), "current-attempt", Outcome{
		State: "failed", ExitCode: &code, Summary: "Build failed.", TestFailures: want,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFinishWithoutTestFailuresPreservesWireShape(t *testing.T) {
	raw, err := json.Marshal(Outcome{State: "succeeded", Summary: "Build passed."})
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if _, present := record["test_failures"]; present {
		t.Fatal("absent test failures were serialized")
	}
}
