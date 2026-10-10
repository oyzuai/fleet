package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	type req struct {
		method, path, query, contentType, auth string
		body                                   []byte
	}
	var mu sync.Mutex
	var seen []req
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, req{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), b})
		mu.Unlock()
		const base = "/api/v1/namespaces/oyzu-jobs"
		switch r.Method + " " + r.URL.Path {
		case "POST " + base + "/secrets", "PATCH " + base + "/secrets/s1":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{}`))
		case "POST " + base + "/pods":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"metadata":{"name":"p1","uid":"u-1"}}`))
		case "GET " + base + "/pods/p1":
			_, _ = w.Write([]byte(`{"status":{"phase":"Failed","containerStatuses":[{"name":"job","state":{"terminated":{"exitCode":3}}}]}}`))
		case "GET " + base + "/pods":
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"p1","labels":{"oyzu.io/job":"9"}}}]}`))
		case "DELETE " + base + "/pods/p1":
			_, _ = w.Write([]byte(`{}`))
		case "GET " + base + "/secrets":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"secrets is forbidden"}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"kind":"Status","message":"not found"}`))
		}
	}))
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(srv.URL, "", tokenFile, "oyzu-jobs")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.CreateSecret(ctx, Secret{Metadata: ObjectMeta{Name: "s1"}, Data: map[string][]byte{"k": []byte("v")}}); err != nil {
		t.Fatal(err)
	}
	uid, err := c.CreatePod(ctx, Pod{Metadata: ObjectMeta{Name: "p1"}})
	if err != nil || uid != "u-1" {
		t.Fatalf("CreatePod = %q, %v", uid, err)
	}
	// The token is read again for every request.
	if err := os.WriteFile(tokenFile, []byte("tok-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.SetSecretOwner(ctx, "s1", OwnerReference{APIVersion: "v1", Kind: "Pod", Name: "p1", UID: "u-1"}); err != nil {
		t.Fatal(err)
	}
	st, err := c.GetPod(ctx, "p1")
	if err != nil || st.Phase != "Failed" || st.ContainerStatuses[0].State.Terminated.ExitCode != 3 {
		t.Fatalf("GetPod = %+v, %v", st, err)
	}
	if _, err := c.GetPod(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPod(missing) = %v", err)
	}
	pods, err := c.ListPods(ctx, "oyzu.io/manager=7")
	if err != nil || len(pods) != 1 || pods[0].Labels[LabelJob] != "9" {
		t.Fatalf("ListPods = %+v, %v", pods, err)
	}
	if _, err := c.ListSecrets(ctx, "oyzu.io/manager=7"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("ListSecrets on 403 = %v", err)
	}
	if err := c.DeletePod(ctx, "p1", 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePod(ctx, "gone", time.Second); err != nil {
		t.Fatalf("DeletePod(missing) = %v", err)
	}
	if err := c.DeleteSecret(ctx, "gone"); err != nil {
		t.Fatalf("DeleteSecret(missing) = %v", err)
	}

	if seen[0].auth != "Bearer tok-1" || seen[2].auth != "Bearer tok-2" {
		t.Fatalf("auth = %q then %q", seen[0].auth, seen[2].auth)
	}
	var secret map[string]any
	_ = json.Unmarshal(seen[0].body, &secret)
	if secret["kind"] != "Secret" || secret["apiVersion"] != "v1" || secret["data"].(map[string]any)["k"] != "dg==" {
		t.Fatalf("secret body = %s", seen[0].body)
	}
	if seen[2].method != "PATCH" || seen[2].contentType != "application/merge-patch+json" {
		t.Fatalf("owner patch = %+v", seen[2])
	}
	if seen[5].query != "labelSelector=oyzu.io%2Fmanager%3D7" {
		t.Fatalf("list query = %q", seen[5].query)
	}
	var del map[string]any
	_ = json.Unmarshal(seen[7].body, &del)
	if del["gracePeriodSeconds"] != float64(30) || del["propagationPolicy"] != "Background" {
		t.Fatalf("delete body = %s", seen[7].body)
	}
	methods := []string{}
	for _, r := range seen {
		methods = append(methods, r.method)
	}
	if !slices.Equal(methods, []string{"POST", "POST", "PATCH", "GET", "GET", "GET", "GET", "DELETE", "DELETE", "DELETE"}) {
		t.Fatalf("requests = %v", methods)
	}
}

func TestInClusterNeedsTheCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := InCluster("oyzu-jobs"); err == nil {
		t.Fatal("InCluster worked outside a cluster")
	}
}
