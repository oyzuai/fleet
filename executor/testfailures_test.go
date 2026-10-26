package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/oyzuai/fleet/runnerclient"
)

const failingJUnit = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites><testsuite name="API" file="tests/api_test.go" line="17">
  <testcase name="passes"/><testcase name="skipped"><skipped/></testcase>
  <testcase classname="api" name="rejects missing token"><failure message="expected 401">got 200</failure></testcase>
  <testsuite name="nested"><testcase classname="db" name="connects" path="tests/db_test.go" line="23"><error message="connection refused"/></testcase></testsuite>
</testsuite></testsuites>`

func testReportRecord(target, name, body string) map[string]any {
	sum := sha256.Sum256([]byte(body))
	return map[string]any{
		"id": "native-test", "action": target + ":test", "target": target, "kind": "test", "format": "junit",
		"status": "collected", "path": name, "digest": "sha256:" + hex.EncodeToString(sum[:]),
		"summary": map[string]int{"passed": 1, "failed": 2, "skipped": 1, "total": 4},
	}
}

func testReportManifest(t *testing.T, run, status string, reports ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": "v1alpha1", "kind": "build-manifest", "runId": run, "status": status,
		"targets": []map[string]string{{"id": "api"}}, "artifacts": []any{}, "reports": reports,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeTestReport(t *testing.T, directory, name, body string) {
	t.Helper()
	file := filepath.Join(directory, "dist", filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func unmaskedTestText(text string) string { return text }

func TestReadTestFailuresFromListedManifestReports(t *testing.T) {
	report := testReportRecord("api", "api/reports/junit.xml", failingJUnit)
	raw := testReportManifest(t, "current-build", "failed", report)
	directory := writeManifest(t, string(raw))
	writeTestReport(t, directory, "api/reports/junit.xml", failingJUnit)
	// Neither an unlisted report nor another report kind may create failures.
	writeTestReport(t, directory, "unlisted.xml", `<testsuite><testcase name="unlisted"><failure/></testcase></testsuite>`)
	coverage := testReportRecord("api", "api/reports/coverage.xml", failingJUnit)
	coverage["kind"] = "coverage"
	missing := testReportRecord("api", "api/reports/missing.xml", failingJUnit)
	missing["status"] = "missing"
	wrongFormat := testReportRecord("api", "api/reports/native.json", failingJUnit)
	wrongFormat["format"] = "native-json"
	raw = testReportManifest(t, "current-build", "failed", report, coverage, missing, wrongFormat)
	got, err := readTestFailures(directory, nil, raw, unmaskedTestText)
	want := []runnerclient.TestFailure{
		{Scope: "api:test", Name: "rejects missing token", Classname: "api", Path: "tests/api_test.go", Line: 17, Message: "expected 401\ngot 200"},
		{Scope: "api:test", Name: "connects", Classname: "db", Path: "tests/db_test.go", Line: 23, Message: "connection refused"},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("test failures = %+v, %v; want %+v", got, err, want)
	}
}

func TestTestFailuresRequireAFreshFinalManifest(t *testing.T) {
	report := testReportRecord("api", "api/reports/junit.xml", failingJUnit)
	directory := t.TempDir()
	writeTestReport(t, directory, "api/reports/junit.xml", failingJUnit)
	for _, status := range []string{"succeeded", "failed", "interrupted"} {
		raw := testReportManifest(t, "current-build", status, report)
		previous := testReportManifest(t, "old-build", "succeeded", report)
		got, err := readTestFailures(directory, previous, raw, unmaskedTestText)
		if err != nil || len(got) != 2 {
			t.Fatalf("%s build failures = %+v, %v", status, got, err)
		}
	}
	current := testReportManifest(t, "current-build", "failed", report)
	for _, tc := range []struct {
		name     string
		previous []byte
		current  []byte
	}{
		{"no manifest", nil, nil},
		{"unchanged", current, current},
		{"same run rewritten", testReportManifest(t, "current-build", "succeeded", report), current},
		{"no run identity", nil, testReportManifest(t, "", "failed", report)},
		{"still running", nil, testReportManifest(t, "current-build", "running", report)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readTestFailures(directory, tc.previous, tc.current, unmaskedTestText)
			if err != nil || len(got) != 0 {
				t.Fatalf("stale/incomplete manifest returned %+v, %v", got, err)
			}
		})
	}
}

func TestTestFailuresRefuseUnsafeOrUnverifiedReports(t *testing.T) {
	directory := t.TempDir()
	writeTestReport(t, directory, "api/reports/junit.xml", failingJUnit)
	for _, name := range []string{"../secret.xml", "/tmp/report.xml", `C:/report.xml`, `api\report.xml`, ".git/report.xml", "api/./report.xml"} {
		t.Run(name, func(t *testing.T) {
			raw := testReportManifest(t, "current-build", "failed", testReportRecord("api", name, failingJUnit))
			got, err := readTestFailures(directory, nil, raw, unmaskedTestText)
			if err == nil || len(got) != 0 {
				t.Fatalf("unsafe report returned %+v, %v", got, err)
			}
		})
	}
	for _, body := range []string{"different bytes", ""} {
		report := testReportRecord("api", "api/reports/junit.xml", body)
		raw := testReportManifest(t, "current-build", "failed", report)
		got, err := readTestFailures(directory, nil, raw, unmaskedTestText)
		if err == nil || len(got) != 0 {
			t.Fatalf("unverified report returned %+v, %v", got, err)
		}
	}
	for _, body := range []string{`<testsuite><testcase name="partial"><failure/></testcase>`, `<not-junit/>`, `<!DOCTYPE testsuite><testsuite/>`} {
		report := testReportRecord("api", "api/reports/invalid.xml", body)
		writeTestReport(t, directory, "api/reports/invalid.xml", body)
		raw := testReportManifest(t, "current-build", "failed", report)
		got, err := readTestFailures(directory, nil, raw, unmaskedTestText)
		if err == nil || len(got) != 0 {
			t.Fatalf("malformed report returned %+v, %v", got, err)
		}
	}
}

func TestTestFailuresConfineSymlinksAndManifest(t *testing.T) {
	directory, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "report.xml"), []byte(failingJUnit), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "dist", "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	raw := testReportManifest(t, "current-build", "failed", testReportRecord("api", "escape/report.xml", failingJUnit))
	got, err := readTestFailures(directory, nil, raw, unmaskedTestText)
	if err == nil || len(got) != 0 {
		t.Fatalf("report symlink escaped checkout: %+v, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(outside, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "manifest.json"), filepath.Join(directory, "dist", "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if got := nativeCompletionRecord(directory); got != nil {
		t.Fatal("read a manifest outside the checkout")
	}
}

func TestTestFailuresBoundReports(t *testing.T) {
	directory := t.TempDir()
	writeTestReport(t, directory, "large.xml", "")
	if err := os.Truncate(filepath.Join(directory, "dist", "large.xml"), maxJUnitReport+1); err != nil {
		t.Fatal(err)
	}
	raw := testReportManifest(t, "current-build", "failed", testReportRecord("api", "large.xml", ""))
	got, err := readTestFailures(directory, nil, raw, unmaskedTestText)
	if err == nil || len(got) != 0 {
		t.Fatalf("oversize report returned %+v, %v", got, err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := readJUnitReport(root, "dist", maxJUnitReport); err == nil {
		t.Fatal("accepted a directory as a JUnit report")
	}
	if _, err := readJUnitReport(root, "dist/large.xml", 0); err == nil {
		t.Fatal("read past the total report budget")
	}
}

func TestJUnitFailuresLocationsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, xml, path, message string
		line                     int
	}{
		{"suite file", `<testsuite file="test.py" line="5"><testcase name="a"><failure/></testcase></testsuite>`, "test.py", "Test failed.", 5},
		{"case path", `<testsuites><testsuite file="suite.py" line="5"><testcase name="a" path="case.py" line="12"><error type="Error"/></testcase></testsuite></testsuites>`, "case.py", "Error", 12},
		{"failure path", `<testsuite><testcase name="a" file="case.py" line="12"><failure path="failure.py" line="24" message="bad &amp; worse"/></testcase></testsuite>`, "failure.py", "bad & worse", 24},
		{"error file", `<testsuite><testcase name="a"><error file="error.py" line="13">bad</error></testcase></testsuite>`, "error.py", "bad", 13},
		{"no source", `<testsuite><testcase name="a" classname="not/a/file"><failure>bad</failure></testcase></testsuite>`, "", "bad", 0},
		{"traversal source", `<testsuite><testcase name="a" file="../secret" line="3"><failure>bad</failure></testcase></testsuite>`, "", "bad", 0},
		{"absolute source", `<testsuite><testcase name="a" file="/etc/passwd" line="3"><failure>bad</failure></testcase></testsuite>`, "", "bad", 0},
		{"negative line", `<testsuite><testcase name="a" file="test.py" line="-3"><failure>bad</failure></testcase></testsuite>`, "test.py", "bad", 0},
		{"different source no inherited line", `<testsuite file="suite.py" line="5"><testcase name="a" file="test.py"><failure>bad</failure></testcase></testsuite>`, "test.py", "bad", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := junitFailures([]byte(tc.xml), "api:test", maxTestFailures, unmaskedTestText)
			if err != nil || len(got) != 1 || got[0].Path != tc.path || got[0].Line != tc.line || got[0].Message != tc.message {
				t.Fatalf("JUnit failure = %+v, %v", got, err)
			}
		})
	}
	long := "a" + strings.Repeat("界", 400)
	body := `<testsuite><testcase name="` + long + `" classname="` + long + `"><failure message="` + long + `"/></testcase></testsuite>`
	got, err := junitFailures([]byte(body), "api:test", maxTestFailures, unmaskedTestText)
	if err != nil || len(got) != 1 {
		t.Fatalf("long failure = %+v, %v", got, err)
	}
	for _, text := range []string{got[0].Name, got[0].Classname, got[0].Message} {
		if len(text) > maxTestText || !utf8.ValidString(text) || len(text) < maxTestText-3 {
			t.Fatalf("invalid bounded UTF-8 text: %d bytes", len(text))
		}
	}
	mask := func(text string) string { return replaceForms(text, maskForms("secret-token")) }
	body = `<testsuite><testcase name="secret-token" classname="secret-token" file="secret-token.py" line="1"><failure message="secret-token">secret-token</failure></testcase></testsuite>`
	got, err = junitFailures([]byte(body), "api:test", maxTestFailures, mask)
	if err != nil || strings.Contains(got[0].Name+got[0].Classname+got[0].Path+got[0].Message, "secret-token") {
		t.Fatalf("failure leaked masked credentials: %+v, %v", got, err)
	}
}

func TestTestFailuresCapAcrossReports(t *testing.T) {
	directory := t.TempDir()
	body := `<testsuite>` + strings.Repeat(`<testcase name="fails"><failure message="bad"/></testcase>`, 150) + `</testsuite>`
	writeTestReport(t, directory, "first.xml", body)
	writeTestReport(t, directory, "second.xml", body)
	raw := testReportManifest(t, "current-build", "failed", testReportRecord("api", "first.xml", body), testReportRecord("web", "second.xml", body))
	got, err := readTestFailures(directory, nil, raw, unmaskedTestText)
	if err != nil || len(got) != maxTestFailures || got[149].Scope != "api:test" || got[150].Scope != "web:test" {
		t.Fatalf("bounded failures = %d, %v", len(got), err)
	}
}

func TestRunSendsTestFailuresForSuccessfulAndFailedBuilds(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name, state := "success", "succeeded"
		code := 0
		if fail {
			name, state, code = "failure", "failed", 3
		}
		t.Run(name, func(t *testing.T) {
			runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
			raw := testReportManifest(t, "current-build", state, testReportRecord("api", "api/reports/junit.xml", failingJUnit))
			t.Setenv("FAKE_OYZU_MANIFEST", string(raw))
			t.Setenv("FAKE_OYZU_JUNIT", failingJUnit)
			if fail {
				t.Setenv("FAKE_OYZU_FAIL", "1")
			}
			if err := Run(context.Background(), cfg); err != nil {
				t.Fatal(err)
			}
			got := runs.finished
			if got == nil || got.State != state || got.ExitCode == nil || *got.ExitCode != code || len(got.TestFailures) != 2 || got.TestFailures[0].Scope != "api:test" {
				t.Fatalf("build outcome = %+v", got)
			}
			if fail && len(got.Outputs) != 0 {
				t.Fatal("failed build published successful artifact outputs")
			}
		})
	}
}

func TestRunDoesNotSendStaleTestFailures(t *testing.T) {
	runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
	raw := testReportManifest(t, "checked-in-build", "failed", testReportRecord("api", "api/reports/junit.xml", failingJUnit))
	t.Setenv("FAKE_GIT_COMPLETION", string(raw))
	t.Setenv("FAKE_GIT_JUNIT", failingJUnit)
	t.Setenv("FAKE_OYZU_FAIL", "1")
	if err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got := runs.finished; got == nil || got.State != "failed" || len(got.TestFailures) != 0 {
		t.Fatalf("stale failures were sent: %+v", got)
	}
}

func TestRunBadJUnitPreservesNativeExitAndMasksFailureMessages(t *testing.T) {
	for _, body := range []string{`<testsuite>`, `<testsuite><testcase name="case"><failure message="oyzu_job_ok ghs_secret oyzu_start_ok"/></testcase></testsuite>`} {
		runs, cfg, _ := setup(t, buildJob("build", "oyzu", "build"))
		raw := testReportManifest(t, "current-build", "failed", testReportRecord("api", "api/reports/junit.xml", body))
		t.Setenv("FAKE_OYZU_MANIFEST", string(raw))
		t.Setenv("FAKE_OYZU_JUNIT", body)
		t.Setenv("FAKE_OYZU_FAIL", "1")
		if err := Run(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		got := runs.finished
		if got == nil || got.State != "failed" || got.ExitCode == nil || *got.ExitCode != 3 {
			t.Fatalf("bad report changed native outcome: %+v", got)
		}
		for _, failure := range got.TestFailures {
			if strings.Contains(failure.Message, "oyzu_job_ok") || strings.Contains(failure.Message, "ghs_secret") || strings.Contains(failure.Message, "oyzu_start_ok") {
				t.Fatalf("unmasked test failure: %+v", failure)
			}
		}
	}
}
