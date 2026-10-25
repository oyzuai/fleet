package poolserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg        Config
	now        func() time.Time
	source     SourceProvider
	oidc       *oidcVerifier
	mu         sync.Mutex
	state      diskState
	changed    chan struct{}
	storageErr error
}

func New(c Config, o Options) (*Server, error) {
	if err := c.defaults(); err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	source := o.Source
	if source == nil {
		app, err := newGitHubApp(c, o)
		if err != nil {
			return nil, err
		}
		source = app
	}
	d, err := loadState(c.StateDir)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: c, now: o.Now, source: source, state: d, changed: make(chan struct{})}
	s.oidc = &oidcVerifier{audience: c.PublicURL, client: o.HTTPClient, now: o.Now, jwksURL: "https://token.actions.githubusercontent.com/.well-known/jwks"}
	if err = s.expire(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reap expires leases even when no requests arrive. The caller owns its context.
func (s *Server) Reap(ctx context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.mu.Lock()
			err := s.expire()
			s.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Request-Id", randomToken()[:24])
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		s.mu.Lock()
		err := s.storageErr
		s.mu.Unlock()
		if err != nil {
			problem(w, 503, "SERVICE_UNAVAILABLE", "State storage is unavailable.")
		} else {
			w.WriteHeader(204)
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/runner/v1/") {
		s.runner(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1alpha1/") {
		s.runs(w, r)
		return
	}
	problem(w, 404, "REQUEST_INVALID", "Route not found.")
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func problem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:oyzu:problem:" + strings.ToLower(strings.ReplaceAll(code, "_", "-")), "title": http.StatusText(status), "status": status, "code": code, "detail": detail, "request_id": w.Header().Get("X-Request-Id")})
}
func parseBody(w http.ResponseWriter, r *http.Request, v any) bool {
	return parseBodyLimit(w,r,v,2<<20)
}
func parseBodyLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err := decodeJSON(r.Body, v); err != nil {
		problem(w, 400, "REQUEST_INVALID", "Expected a bounded JSON request with known fields.")
		return false
	}
	return true
}
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(v, "Bearer ")
}
func (s *Server) persist(w http.ResponseWriter, d diskState) bool {
	if err := s.commit(d); err != nil {
		problem(w, 503, "SERVICE_UNAVAILABLE", "State storage is unavailable.")
		return false
	}
	return true
}

type caller struct {
	ID, Actor string
	Claims    *oidcClaims
}

func (s *Server) caller(r *http.Request) (caller, error) {
	// An explicit bearer must authenticate itself, even on a tailnet request.
	if r.Header.Get("Authorization") != "" {
		c, err := s.oidc.verify(r.Context(), bearer(r))
		if err != nil {
			return caller{}, err
		}
		for _, rule := range s.cfg.Callers.GitHub {
			if rule.Repository == c.Repository {
				for _, pattern := range rule.Refs {
					if refMatches(pattern, c.Ref) {
						if c.RunID == "" || c.RunAttempt == "" || c.Subject == "" || !commitRE.MatchString(c.SHA) {
							return caller{}, errors.New("missing identity claims")
						}
						return caller{ID: "github:" + hash([]byte(c.Repository+"\x00"+c.RunID+"\x00"+c.RunAttempt+"\x00"+c.Subject)), Actor: c.Repository + " Actions", Claims: c}, nil
					}
				}
			}
		}
		return caller{}, errors.New("caller not allowed")
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return caller{}, err
	}
	ip := net.ParseIP(host)
	login := r.Header.Get("Tailscale-User-Login")
	if ip != nil && ip.IsLoopback() && login != "" && contains(s.cfg.Callers.TailnetUsers, login) {
		return caller{ID: "tailnet:" + login, Actor: login}, nil
	}
	return caller{}, errors.New("caller not allowed")
}
func refMatches(pattern, ref string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == ref
	}
	if !strings.HasPrefix(ref, parts[0]) {
		return false
	}
	rest := ref[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(rest, p)
		if i < 0 {
			return false
		}
		rest = rest[i+len(p):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}
