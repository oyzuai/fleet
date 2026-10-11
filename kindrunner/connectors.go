package kindrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oyzuai/fleet/kindprotocol"
	"github.com/oyzuai/fleet/runnerclient"
)

// A kind receives its target's connectors (IMPL-448) beside its secrets, in
// OYZU_SECRETS_DIR:
//
//	connectors/<role>/connector.json  what the connector is, never a value
//	connectors/<role>/<field>         each secret setting, mode 0400
//	connectors/<role>/id_token        a job ID token, for a federating mechanism
//
// role is apply or observe. A read-only operation (observe, drift, watch)
// gets only observe; every other operation gets both. Each of the target's
// named bindings (IMPL-628) is written the same way to
// connectors/named/<alias>/, one connector per alias: its observe side for a
// read-only operation and its apply side otherwise, or its only side, which
// connector.json's role names. For an aws connector
// that federates, the runner also points the AWS SDKs' default chain at the
// role and the token, and removes any other AWS credentials from a built-in
// kind's environment, so a kind that loads the default configuration
// assumes the connector's role and nothing else.
const (
	ConnectorsDir     = "connectors"
	ConnectorFile     = "connector.json"
	ConnectorIDToken  = "id_token"
	NamedConnectorDir = "named"
	awsConnectorKind  = "aws"
	awsRoleParameter  = "role_arn"
	awsSessionNameMax = 64
)

// ConnectorDescription is connector.json: what a kind needs to know about a
// connector besides the values in the files beside it.
type ConnectorDescription struct {
	Target string `json:"target"`
	Grant  string `json:"grant,omitempty"`
	Role   string `json:"role"`
	// Alias names the named binding; empty for apply or observe.
	Alias      string         `json:"alias,omitempty"`
	Identifier string         `json:"identifier"`
	Kind       string         `json:"kind"`
	Mechanism  string         `json:"mechanism"`
	Settings   map[string]any `json:"settings"`
	Parameters map[string]any `json:"parameters"`
	// SecretFiles names the files holding the mechanism's secret settings.
	SecretFiles []string `json:"secret_files"`
	// IDTokenFile names the ID token's file; IDTokenExpires is when it stops
	// working.
	IDTokenFile    string     `json:"id_token_file,omitempty"`
	IDTokenExpires *time.Time `json:"id_token_expires_at,omitempty"`
}

// awsCredentialVariables are what the AWS SDKs would use ahead of the
// connector's role.
var awsCredentialVariables = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"}

var (
	connectorField = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	connectorAlias = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	sessionUnsafe  = regexp.MustCompile(`[^A-Za-z0-9+=,.@-]`)
)

// envVar is a variable the kind receives with its secrets. A path variable's
// value is relative to the secrets directory, wherever the kind sees it.
type envVar struct {
	name, value string
	path        bool
}

// vars renders the directory's variables with base as the directory.
func (s *secretDir) vars(base string) []string {
	out := make([]string, 0, len(s.env))
	for _, v := range s.env {
		val := v.value
		if v.path {
			val = filepath.ToSlash(filepath.Join(base, v.value))
		}
		out = append(out, v.name+"="+val)
	}
	return out
}

// scrub removes the variables the directory replaces from env.
func (s *secretDir) scrub(env []string) []string {
	if len(s.unset) == 0 {
		return env
	}
	return slices.DeleteFunc(env, func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(s.unset, name)
	})
}

// connectors pulls the target's connectors into the secrets directory.
func (r *run) connectors(ctx context.Context, sd *secretDir) error {
	got, err := r.cfg.Client.KindConnectors(ctx, r.cfg.Token)
	if err != nil {
		return fmt.Errorf("pull the target's connectors: %w", err)
	}
	defer func() {
		for _, c := range got.Connectors {
			for _, s := range c.Secrets {
				clear(s.Value)
			}
		}
	}()
	primary := ""
	for _, c := range got.Connectors {
		if c.Role != "apply" && c.Role != "observe" {
			return fmt.Errorf("connector role %q is not apply or observe", c.Role)
		}
		dir := filepath.Join(sd.path, ConnectorsDir, c.Role)
		if c.Alias != "" {
			if !connectorAlias.MatchString(c.Alias) {
				return fmt.Errorf("connector binding %q is not a directory name", c.Alias)
			}
			dir = filepath.Join(sd.path, ConnectorsDir, NamedConnectorDir, c.Alias)
			if _, err := os.Stat(dir); err == nil {
				return fmt.Errorf("connector binding %s is delivered twice", c.Alias)
			}
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		desc := ConnectorDescription{Target: got.Target, Grant: got.Grant, Role: c.Role, Alias: c.Alias, Identifier: c.Identifier,
			Kind: c.Kind, Mechanism: c.Mechanism, Settings: c.Settings, Parameters: c.Parameters, SecretFiles: []string{}}
		for _, s := range c.Secrets {
			r.events.mask.Add(string(s.Value))
			if !connectorField.MatchString(s.Field) || s.Field == ConnectorIDToken {
				return fmt.Errorf("connector setting %q is not a file name", s.Field)
			}
			if err := os.WriteFile(filepath.Join(dir, s.Field), s.Value, 0o400); err != nil {
				return err
			}
			desc.SecretFiles = append(desc.SecretFiles, s.Field)
		}
		if c.IDToken != "" {
			r.events.mask.Add(c.IDToken)
			if err := os.WriteFile(filepath.Join(dir, ConnectorIDToken), []byte(c.IDToken), 0o400); err != nil {
				return err
			}
			desc.IDTokenFile, desc.IDTokenExpires = ConnectorIDToken, c.IDTokenExpires
		}
		raw, err := json.MarshalIndent(desc, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, ConnectorFile), raw, 0o400); err != nil {
			return err
		}
		if c.Alias == "" && c.Role == r.primaryRole() {
			primary = c.Role
			r.awsDefaults(sd, c)
		}
	}
	r.log.Info("kind connectors written", "target", got.Target, "count", len(got.Connectors), "primary", primary)
	return nil
}

// primaryRole is the role whose connector the operation acts through.
func (r *run) primaryRole() string {
	switch kindprotocol.Operation(r.op.Operation) {
	case kindprotocol.OpObserve, kindprotocol.OpDrift, "watch":
		return "observe"
	}
	return "apply"
}

// awsDefaults points the AWS SDKs' default chain at an aws connector's role
// and ID token.
func (r *run) awsDefaults(sd *secretDir, c runnerclient.KindConnector) {
	role, _ := c.Parameters[awsRoleParameter].(string)
	if c.Kind != awsConnectorKind || c.IDToken == "" || role == "" {
		return
	}
	session := sessionUnsafe.ReplaceAllString(fmt.Sprintf("oyzu-%d-%d-%s", r.job.ID, r.job.Attempt, c.Role), "-")
	if len(session) > awsSessionNameMax {
		session = session[:awsSessionNameMax]
	}
	sd.env = append(sd.env,
		envVar{name: "AWS_ROLE_ARN", value: role},
		envVar{name: "AWS_WEB_IDENTITY_TOKEN_FILE", value: filepath.Join(ConnectorsDir, c.Role, ConnectorIDToken), path: true},
		envVar{name: "AWS_ROLE_SESSION_NAME", value: session})
	sd.unset = append(sd.unset, awsCredentialVariables...)
}
