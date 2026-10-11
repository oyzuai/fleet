package vm

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// assignmentWait is how long an agent's assignment request waits for a job
// before the manager answers that there is none yet.
const assignmentWait = 25 * time.Second

// maxRequest bounds an agent's request body: an identity document and its
// signature are a few kilobytes.
const maxRequest = 64 << 10

// readyRequest is an agent's check-in and assignment request.
type readyRequest struct {
	Proof Proof `json:"proof"`
}

// exitRequest reports how the executor exited.
type exitRequest struct {
	Proof  Proof  `json:"proof"`
	Code   int    `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// assignmentResponse gives an instance its one job.
type assignmentResponse struct {
	JobID          int64     `json:"job_id"`
	Attempt        int       `json:"attempt"`
	StartupToken   string    `json:"startup_token"`
	StartupExpires time.Time `json:"startup_expires_at"`
}

// Handler serves this pool's instance agents. The manager listens on it
// inside the pool's private network only; it is never exposed to the
// internet, and the manager still makes only outbound connections to runs.
//
//	POST /v1/ready       a booted instance checks in, proving its identity
//	POST /v1/assignment  waits for and returns the instance's job; served
//	                     again until it is acknowledged, then 409
//	POST /v1/started     acknowledges the assignment once the executor has
//	                     its startup token; the agent retries it until it
//	                     succeeds
//	POST /v1/exit        reports how the executor exited
func (d *Driver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ready", func(w http.ResponseWriter, r *http.Request) {
		var req readyRequest
		if !decode(w, r, &req) {
			return
		}
		if err := d.checkIn(r.Context(), req.Proof, r.RemoteAddr); err != nil {
			d.refuse(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/assignment", func(w http.ResponseWriter, r *http.Request) {
		var req readyRequest
		if !decode(w, r, &req) {
			return
		}
		c, err := d.assignment(r.Context(), req.Proof, r.RemoteAddr, assignmentWait)
		if err != nil {
			d.refuse(w, r, err)
			return
		}
		if c == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(assignmentResponse{
			JobID: c.JobID, Attempt: c.Attempt, StartupToken: c.StartupToken, StartupExpires: c.StartupExpires,
		}); err != nil {
			// Not acknowledged, so the agent can collect it again.
			d.log().Warn("sending an assignment failed; the instance may collect it again", "remote", r.RemoteAddr, "error", err)
		}
	})
	mux.HandleFunc("POST /v1/started", func(w http.ResponseWriter, r *http.Request) {
		var req readyRequest
		if !decode(w, r, &req) {
			return
		}
		if err := d.acknowledge(r.Context(), req.Proof, r.RemoteAddr); err != nil {
			d.refuse(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/exit", func(w http.ResponseWriter, r *http.Request) {
		var req exitRequest
		if !decode(w, r, &req) {
			return
		}
		if err := d.reportExit(r.Context(), req.Proof, r.RemoteAddr, req.Code, req.Detail); err != nil {
			d.refuse(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequest)).Decode(v); err != nil {
		http.Error(w, "the request body is not valid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

// refuse answers a request the manager will not serve. The reason is logged
// with the caller's address but not echoed beyond its class, so a stranger
// learns nothing about which instances exist.
func (d *Driver) refuse(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusForbidden
	switch {
	case errors.Is(err, ErrAlreadyHanded):
		status = http.StatusConflict
	case errors.Is(err, ErrNotAssigned):
		status = http.StatusConflict
	case r.Context().Err() != nil:
		return
	}
	d.log().Warn("refused an instance agent's request", "path", r.URL.Path, "remote", r.RemoteAddr, "error", err)
	http.Error(w, http.StatusText(status), status)
}
