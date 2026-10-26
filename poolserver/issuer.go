package poolserver

// Job identity belongs to the pool server: verified creator facts, repository
// source facts and the persisted run source enter its tokens. Executors choose
// an audience, never the claims that authorize shared-cache writes.
import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oyzuai/fleet/runnerclient"
)

// creatorFacts is the verified creator authority persisted with a run. A nil
// record (including runs predating job tokens) grants no Actions claims.
type creatorFacts struct {
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id,omitempty"`
	RepositoryOwnerID string `json:"repository_owner_id,omitempty"`
	Ref               string `json:"ref"`
	RefType           string `json:"ref_type,omitempty"`
	EventName         string `json:"event_name,omitempty"`
	JobWorkflowRef    string `json:"job_workflow_ref,omitempty"`
}

// repositoryFacts identifies repository source without granting creator authority.
type repositoryFacts struct {
	RepositoryID      string `json:"repository_id"`
	RepositoryOwnerID string `json:"repository_owner_id"`
}

type jobIssuer struct {
	key ed25519.PrivateKey
	kid string
}

func loadJobIssuer(dir string) (*jobIssuer, error) {
	path, err := filepath.Abs(filepath.Join(dir, "issuer.key"))
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return nil, err
		}
		if err = atomicJSON(path, seed); err != nil {
			return nil, fmt.Errorf("create issuer key: %w", err)
		}
	} else if err != nil {
		return nil, err
	}
	f, err := openPrivateFile(path)
	if err != nil {
		return nil, fmt.Errorf("open issuer key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0600 {
		return nil, errors.New("issuer key must be 0600")
	}
	var seed []byte
	if err = decodeJSON(io.LimitReader(f, 1024), &seed); err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid issuer key")
	}
	key := ed25519.NewKeyFromSeed(seed)
	return &jobIssuer{key: key, kid: hash(key.Public().(ed25519.PublicKey))}, nil
}

func (i *jobIssuer) jwks() any {
	return map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": i.kid,
		"x": base64.RawURLEncoding.EncodeToString(i.key.Public().(ed25519.PublicKey)),
	}}}
}

func (s *Server) issueJobToken(w http.ResponseWriter, r *http.Request, rr *runRecord) {
	var in struct {
		Audience string `json:"audience"`
	}
	if !parseBody(w, r, &in) {
		return
	}
	if in.Audience == "" || len(in.Audience) > 2048 || strings.ContainsAny(in.Audience, "\x00\r\n") {
		problem(w, 422, "REQUEST_INVALID", "A bounded audience is required.")
		return
	}
	facts := creatorFacts{Repository: rr.Run.Repository.Name, Ref: rr.Run.Ref}
	if rr.Creator != nil {
		facts = *rr.Creator
	} else if rr.RepositoryFacts != nil {
		facts.RepositoryID = rr.RepositoryFacts.RepositoryID
		facts.RepositoryOwnerID = rr.RepositoryFacts.RepositoryOwnerID
	}
	sourceKind := "commit"
	if rr.Run.Source != nil {
		sourceKind = "snapshot"
	}
	now := s.now()
	expires := now.Add(10 * time.Minute)
	claims := struct {
		creatorFacts
		Issuer     string `json:"iss"`
		Audience   string `json:"aud"`
		Subject    string `json:"sub"`
		IssuedAt   int64  `json:"iat"`
		NotBefore  int64  `json:"nbf"`
		Expiry     int64  `json:"exp"`
		RunID      string `json:"run_id"`
		SHA        string `json:"sha"`
		SourceKind string `json:"source_kind"`
	}{
		creatorFacts: facts,
		Issuer:       s.cfg.PublicURL,
		Audience:     in.Audience,
		Subject:      "repo:" + facts.Repository + ":ref:" + facts.Ref,
		IssuedAt:     now.Unix(),
		NotBefore:    now.Unix(),
		Expiry:       expires.Unix(),
		RunID:        rr.Run.ID,
		SHA:          rr.Run.Commit,
		SourceKind:   sourceKind,
	}
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": s.issuer.kid, "typ": "JWT"})
	body, err := json.Marshal(claims)
	if err != nil {
		problem(w, 500, "INTERNAL_ERROR", "Token unavailable.")
		return
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	sig := ed25519.Sign(s.issuer.key, []byte(unsigned))
	respond(w, 200, runnerclient.IDToken{Token: unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), Expires: expires})
}
