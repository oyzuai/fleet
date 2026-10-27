package poolserver

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

var errPrivateRepository = errors.New("commit runs of private repositories need a GitHub App (see docs/pool-server.md)")

type anonymousRepository struct {
	facts   *repositoryFacts
	private bool
	expires time.Time
}
type anonymousGitHub struct {
	api          *GitHubApp
	mu           sync.Mutex
	repositories map[string]anonymousRepository
}

func newAnonymousGitHub(o Options) *anonymousGitHub {
	return &anonymousGitHub{api: &GitHubApp{client: o.HTTPClient, now: o.Now, base: "https://api.github.com"}, repositories: map[string]anonymousRepository{}}
}
func (a *anonymousGitHub) repositoryFacts(ctx context.Context, repo string) (*repositoryFacts, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cached, ok := a.repositories[repo]
	if !ok || !cached.expires.After(a.api.now()) {
		var out struct {
			ID      int64 `json:"id"`
			Private bool  `json:"private"`
			Owner   struct {
				ID int64 `json:"id"`
			} `json:"owner"`
		}
		status, err := a.api.request(ctx, "GET", "/repos/"+repo, "", nil, &out)
		if status != 404 && err != nil {
			return nil, err
		}
		cached = anonymousRepository{private: status == 404 || out.Private, expires: a.api.now().Add(10 * time.Minute)}
		if !cached.private {
			if out.ID <= 0 || out.Owner.ID <= 0 {
				return nil, errors.New("repository IDs unavailable")
			}
			cached.facts = &repositoryFacts{RepositoryID: strconv.FormatInt(out.ID, 10), RepositoryOwnerID: strconv.FormatInt(out.Owner.ID, 10)}
		}
		a.repositories[repo] = cached
	}
	if cached.private {
		return nil, errPrivateRepository
	}
	return cached.facts, nil
}
func (a *anonymousGitHub) CommitExists(ctx context.Context, repo, sha string) (bool, error) {
	if !repositoryRE.MatchString(repo) || !commitRE.MatchString(sha) {
		return false, errors.New("invalid commit source")
	}
	if _, err := a.repositoryFacts(ctx, repo); err != nil {
		return false, err
	}
	var out struct {
		SHA string `json:"sha"`
	}
	status, err := a.api.request(ctx, "GET", "/repos/"+repo+"/commits/"+sha, "", nil, &out)
	if status == 404 {
		return false, nil
	}
	return out.SHA == sha, err
}
func (a *anonymousGitHub) Source(ctx context.Context, repo string) (runnerclient.Source, error) {
	if !repositoryRE.MatchString(repo) {
		return runnerclient.Source{}, errors.New("invalid repository")
	}
	if _, err := a.repositoryFacts(ctx, repo); err != nil {
		return runnerclient.Source{}, err
	}
	return runnerclient.Source{Repository: repo}, nil
}
