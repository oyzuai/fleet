// Package poolserver serves the standalone runs and runner APIs. It requires
// one process with exclusive ownership of its state directory.
package poolserver

import (
 "context"
 "crypto/rsa"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "os"
 "regexp"
 "strings"
 "time"

 "github.com/oyzuai/fleet/runnerclient"
)

type Config struct {
 Account string `json:"account"`
 Listen string `json:"listen"`
 PublicURL string `json:"public_url"`
 StateDir string `json:"state_dir"`
 Repositories []string `json:"repositories"`
 EnrollmentTokenSHA256 string `json:"enrollment_token_sha256"`
 Audience string `json:"audience,omitempty"`
 Callers struct {
  TailnetUsers []string `json:"tailnet_users"`
  GitHub []GitHubCaller `json:"github"`
 } `json:"callers"`
 GitHubApp struct {
  AppID int64 `json:"app_id"`
  PrivateKeyFile string `json:"private_key_file"`
 } `json:"github_app"`
 EgressAllow []runnerclient.EgressAllow `json:"egress_allow"`
}
type GitHubCaller struct { Repository string `json:"repository"`; Refs []string `json:"refs"` }

var identifierRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var repositoryRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
var targetRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)
var taskRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?::[A-Za-z0-9][A-Za-z0-9._-]{0,99})?$`)
var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadConfig reads a private configuration. Original configuration is root
// owned 0600; systemd LoadCredential exposes a service-owned 0400 mount.
func LoadConfig(path string) (Config, error) {
 var c Config
 info, err := os.Stat(path); if err != nil { return c, err }
 if !info.Mode().IsRegular() || (info.Mode().Perm() != 0600 && info.Mode().Perm()!=0400) { return c, errors.New("configuration must be a regular file with mode 0600 or 0400") }
 if err := checkRootOwner(info); err != nil { return c, err }
 f, err := os.Open(path); if err != nil { return c, err }; defer f.Close()
 err = decodeJSON(io.LimitReader(f, 1<<20), &c)
 if err == nil { err = c.defaults() }; return c, err
}
func (c *Config) defaults() error {
 if c.Listen == "" { c.Listen = "127.0.0.1:8480" }; if c.StateDir == "" { c.StateDir = "/var/lib/oyzu-pool" }; if c.Audience == "" { c.Audience = "oyzu-runs" }
 host, _, err := net.SplitHostPort(c.Listen); if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() { return errors.New("listen must be a numeric loopback address and port") }
 u, err := url.Parse(c.PublicURL); if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") { return errors.New("public_url must be an HTTPS origin") }
 c.PublicURL = strings.TrimRight(c.PublicURL, "/")
 if !identifierRE.MatchString(c.Account) || !hashRE.MatchString(c.EnrollmentTokenSHA256) { return errors.New("invalid account or enrollment token hash") }
 if c.GitHubApp.AppID != 5467712 { return errors.New("github_app.app_id must be 5467712") }
 projects := map[string]bool{}
 for _, r := range c.Repositories { p := projectID(r); if !repositoryRE.MatchString(r) || !identifierRE.MatchString(p) || projects[p] { return fmt.Errorf("invalid or colliding repository project: %s", r) }; projects[p] = true }
 for _, rule := range c.Callers.GitHub { if !contains(c.Repositories, rule.Repository) || len(rule.Refs) == 0 { return errors.New("GitHub caller must name a listed repository and refs") }; for _, ref := range rule.Refs { if !strings.HasPrefix(ref,"refs/") || strings.ContainsAny(ref,"?[]\\") { return errors.New("ref patterns support literal refs and * only") } } }
 for _, a := range c.EgressAllow { if a.Host == "" || strings.ContainsAny(a.Host,"/ :@\\") || a.Port < 0 || a.Port > 65535 { return errors.New("invalid egress destination") } }
 return nil
}
func projectID(repo string) string { parts := strings.Split(repo,"/"); s := strings.ToLower(parts[len(parts)-1]); return strings.Trim(regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(s,"-"),"-") }
func contains(a []string,b string) bool { for _, v := range a { if v == b { return true } }; return false }
func decodeJSON(r io.Reader, out any) error { d:=json.NewDecoder(r); d.DisallowUnknownFields(); if err:=d.Decode(out); err!=nil{return err}; var extra any; if d.Decode(&extra)!=io.EOF{return errors.New("expected one JSON value")};return nil }

type Repository struct { Provider string `json:"provider"`; Name string `json:"name"` }
type Operation struct { Kind string `json:"kind"`; Targets []string `json:"targets,omitempty"`; AffectedBase string `json:"affected_base,omitempty"`; Task string `json:"task,omitempty"` }
type RunCreate struct { Repository Repository `json:"repository"`; Commit string `json:"commit"`; Ref string `json:"ref,omitempty"`; Operation Operation `json:"operation"` }
type Reason struct { Code string `json:"code"`; Message string `json:"message"` }
type Trigger struct { Kind string `json:"kind"`; Actor string `json:"actor,omitempty"` }
type Links struct { Self string `json:"self"`; Logs string `json:"logs"`; Result string `json:"result"` }
type Run struct {
 ID string `json:"id"`; Account string `json:"account"`; Project string `json:"project"`
 Repository Repository `json:"repository"`; Commit string `json:"commit"`; Ref string `json:"ref,omitempty"`; Operation Operation `json:"operation"`; Trigger Trigger `json:"trigger"`
 State string `json:"state"`; Reason *Reason `json:"reason,omitempty"`; Attempt int `json:"attempt"`; ExitCode *int `json:"exit_code,omitempty"`
 CancelRequestedAt *time.Time `json:"cancel_requested_at,omitempty"`; CreatedAt time.Time `json:"created_at"`; StartedAt *time.Time `json:"started_at,omitempty"`; FinishedAt *time.Time `json:"finished_at,omitempty"`; Links Links `json:"links"`
}
func finished(r Run) bool { return r.State != "queued" && r.State != "running" }

// SourceProvider must mint read-only, single-repository credentials. Production
// uses GitHubApp; injection lets tests avoid any live credentials or network.
type SourceProvider interface {
 CommitExists(context.Context,string,string) (bool,error)
 Source(context.Context,string) (runnerclient.Source,error)
}
type Options struct {
 HTTPClient *http.Client
 Now func() time.Time
 Source SourceProvider
 // AppKey is only an in-memory alternative to reading the configured key.
 AppKey *rsa.PrivateKey
}
