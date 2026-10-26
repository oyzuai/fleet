package poolserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type checkCredential struct {
	token   string
	expires time.Time
}

// checkToken uses the existing App issuer but never the source-token path.
// Its single-repository, checks-only token stays within the server.
func (a *GitHubApp) checkToken(ctx context.Context, repo string) (string, error) {
	if !repositoryRE.MatchString(repo) {
		return "", errors.New("invalid repository")
	}
	a.mu.Lock()
	cached := a.checkTokens[repo]
	a.mu.Unlock()
	if cached.token != "" && a.now().Before(cached.expires.Add(-5*time.Minute)) {
		return cached.token, nil
	}
	jwt, err := a.jwt()
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	id := a.installations[repo]
	a.mu.Unlock()
	if id == 0 {
		var installation struct {
			ID int64 `json:"id"`
		}
		if _, err = a.request(ctx, "GET", "/repos/"+repo+"/installation", jwt, nil, &installation); err != nil || installation.ID <= 0 {
			return "", errors.New("repository installation unavailable")
		}
		id = installation.ID
		a.mu.Lock()
		a.installations[repo] = id
		a.mu.Unlock()
	}
	body := map[string]any{"repositories": []string{strings.Split(repo, "/")[1]}, "permissions": map[string]string{"checks": "write"}}
	var out struct {
		Token        string            `json:"token"`
		Expires      time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	status, err := a.request(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", id), jwt, body, &out)
	if err != nil {
		if status == 403 || status == 404 {
			a.mu.Lock()
			delete(a.installations, repo)
			a.mu.Unlock()
		}
		return "", errors.New("check credential unavailable")
	}
	if out.Token == "" || !out.Expires.After(a.now()) || out.Expires.After(a.now().Add(time.Hour)) || out.Permissions["checks"] != "write" || len(out.Repositories) != 1 || !strings.EqualFold(out.Repositories[0].FullName, repo) {
		return "", errors.New("check credential scope mismatch")
	}
	for name, permission := range out.Permissions {
		if name != "checks" && !(name == "metadata" && permission == "read") {
			return "", errors.New("check credential has excess permissions")
		}
	}
	a.mu.Lock()
	a.checkTokens[repo] = checkCredential{token: out.Token, expires: out.Expires}
	a.mu.Unlock()
	return out.Token, nil
}

// checkRequest refreshes rejected credentials once. Check identity recovery and
// annotation progress remain with the normal delivery path.
func (a *GitHubApp) checkRequest(ctx context.Context, repo, method, path string, body, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := a.checkToken(ctx, repo)
		if err != nil {
			return err
		}
		status, err := a.request(ctx, method, path, token, body, out)
		if status != http.StatusUnauthorized {
			return err
		}
		a.mu.Lock()
		if a.checkTokens[repo].token == token {
			delete(a.checkTokens, repo)
		}
		a.mu.Unlock()
		if attempt == 1 {
			return err
		}
	}
	return errors.New("check credential unavailable")
}

func (a *GitHubApp) ensureCheck(ctx context.Context, rr *runRecord, scope, name string) (int64, error) {
	externalID := "oyzu:" + rr.Run.ID + ":" + hash([]byte(scope))
	// A create response may be lost after GitHub accepted it, before the ID
	// was persisted. Recover that check by its stable external ID on retry.
	for page := 1; ; page++ {
		var out struct {
			Checks []struct {
				ID         int64  `json:"id"`
				ExternalID string `json:"external_id"`
			} `json:"check_runs"`
		}
		path := fmt.Sprintf("/repos/%s/commits/%s/check-runs?check_name=%s&filter=all&per_page=100&page=%d", rr.Run.Repository.Name, rr.Run.Commit, url.QueryEscape(name), page)
		if err := a.checkRequest(ctx, rr.Run.Repository.Name, "GET", path, nil, &out); err != nil {
			return 0, err
		}
		for _, check := range out.Checks {
			if check.ExternalID == externalID && check.ID > 0 {
				return check.ID, nil
			}
		}
		if len(out.Checks) < 100 {
			break
		}
	}
	var out struct {
		ID int64 `json:"id"`
	}
	body := map[string]any{"name": name, "head_sha": rr.Run.Commit, "external_id": externalID, "status": "in_progress"}
	if err := a.checkRequest(ctx, rr.Run.Repository.Name, "POST", "/repos/"+rr.Run.Repository.Name+"/check-runs", body, &out); err != nil {
		return 0, err
	}
	if out.ID <= 0 {
		return 0, errors.New("missing GitHub check ID")
	}
	return out.ID, nil
}
