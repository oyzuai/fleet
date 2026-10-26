package poolserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// GitHubApp keeps the signing key exclusively inside the server. Installation
// source tokens are minted afresh for one repository with contents:read.
// Cached check-write tokens stay inside the server.
type GitHubApp struct {
	key           *rsa.PrivateKey
	appID         int64
	client        *http.Client
	now           func() time.Time
	base          string
	mu            sync.Mutex
	installations map[string]int64
	checkTokens   map[string]checkCredential
}

func newGitHubApp(c Config, o Options) (*GitHubApp, error) {
	key := o.AppKey
	if key == nil {
		f, err := openPrivateFile(c.GitHubApp.PrivateKeyFile)
		if err != nil {
			return nil, errors.New("GitHub App private key unavailable")
		}
		b, err := io.ReadAll(io.LimitReader(f, 64<<10))
		_ = f.Close()
		if err != nil {
			return nil, errors.New("GitHub App private key unavailable")
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("invalid GitHub App private key")
		}
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
			if e != nil {
				return nil, errors.New("invalid GitHub App private key")
			}
			key, _ = k.(*rsa.PrivateKey)
		}
	}
	if key == nil || key.N.BitLen() < 2048 {
		return nil, errors.New("GitHub App requires an RSA key of at least 2048 bits")
	}
	return &GitHubApp{key: key, appID: c.GitHubApp.AppID, client: o.HTTPClient, now: o.Now, base: "https://api.github.com", installations: map[string]int64{}, checkTokens: map[string]checkCredential{}}, nil
}
func (a *GitHubApp) jwt() (string, error) {
	now := a.now()
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	b, _ := json.Marshal(map[string]any{"iss": a.appID, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix()})
	input := h + "." + base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(input))
	sig, e := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), e
}
func (a *GitHubApp) request(ctx context.Context, method, path, token string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return 0, e
		}
		rd = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if e != nil {
		return 0, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := a.client.Do(req)
	if e != nil {
		return 0, errors.New("GitHub unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, errors.New("GitHub request refused")
	}
	if out != nil {
		e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return resp.StatusCode, e
}
func (a *GitHubApp) Source(ctx context.Context, repo string) (runnerclient.Source, error) {
	if !repositoryRE.MatchString(repo) {
		return runnerclient.Source{}, errors.New("invalid repository")
	}
	jwt, e := a.jwt()
	if e != nil {
		return runnerclient.Source{}, e
	}
	a.mu.Lock()
	id := a.installations[repo]
	a.mu.Unlock()
	if id == 0 {
		var ins struct {
			ID int64 `json:"id"`
		}
		_, e = a.request(ctx, "GET", "/repos/"+repo+"/installation", jwt, nil, &ins)
		if e != nil || ins.ID <= 0 {
			return runnerclient.Source{}, errors.New("repository installation unavailable")
		}
		id = ins.ID
		a.mu.Lock()
		a.installations[repo] = id
		a.mu.Unlock()
	}
	body := map[string]any{"repositories": []string{strings.Split(repo, "/")[1]}, "permissions": map[string]string{"contents": "read"}}
	var out struct {
		Token        string            `json:"token"`
		Expires      time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	status, e := a.request(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", id), jwt, body, &out)
	if e != nil {
		if status == 404 || status == 403 {
			a.mu.Lock()
			delete(a.installations, repo)
			a.mu.Unlock()
		}
		return runnerclient.Source{}, errors.New("source credential unavailable")
	}
	if out.Token == "" || !out.Expires.After(a.now()) || out.Expires.After(a.now().Add(time.Hour)) || out.Permissions["contents"] != "read" || len(out.Repositories) != 1 || !strings.EqualFold(out.Repositories[0].FullName, repo) {
		return runnerclient.Source{}, errors.New("source credential scope mismatch")
	}
	for name, permission := range out.Permissions {
		if name != "contents" && !(name == "metadata" && permission == "read") {
			return runnerclient.Source{}, errors.New("source credential has excess permissions")
		}
	}
	return runnerclient.Source{Token: out.Token, Expires: out.Expires, Repository: repo}, nil
}
func (a *GitHubApp) CommitExists(ctx context.Context, repo, sha string) (bool, error) {
	if !repositoryRE.MatchString(repo) || !commitRE.MatchString(sha) {
		return false, errors.New("invalid commit source")
	}
	s, e := a.Source(ctx, repo)
	if e != nil {
		return false, e
	}
	var out struct {
		SHA string `json:"sha"`
	}
	status, e := a.request(ctx, "GET", "/repos/"+repo+"/commits/"+sha, s.Token, nil, &out)
	if status == 404 {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return out.SHA == sha, nil
}
