package runnerclient

// ExecutionCapabilityHeader is sent at job/start by executors that enforce
// version-1 launch configuration. Servers refuse required configuration to
// older executors before returning a job token or launch inputs.
const ExecutionCapabilityHeader = "Oyzu-Execution-Config"

func (c *ExecutionConfig) IsRequired() bool {
	if c == nil {
		return false
	}
	if c.Required || c.Proxy != nil && c.Proxy.Required {
		return true
	}
	for _, b := range c.Bundles {
		if b.Required {
			return true
		}
	}
	for _, consumer := range c.Consumers {
		for _, format := range consumer.Formats {
			if format.Required {
				return true
			}
		}
	}
	return false
}

// ExecutionConfig is the resolved, job-scoped execution configuration. Version
// is 1. The server resolves scope inheritance before releasing this document.
// Bundle bodies are launch inputs, never execution evidence.
type ExecutionConfig struct {
	Version   int                 `json:"version"`
	Revision  string              `json:"revision"`
	Required  bool                `json:"required,omitempty"`
	Bundles   []ExecutionCABundle `json:"bundles,omitempty"`
	Proxy     *ExecutionProxy     `json:"proxy,omitempty"`
	Consumers []TrustConsumer     `json:"consumers,omitempty"`
}

// ExecutionCABundle contains canonical PEM CA certificates and its SHA-256 hex
// digest. A missing required bundle is an explicit launch failure.
type ExecutionCABundle struct {
	PEM      string `json:"pem"`
	Digest   string `json:"digest"`
	Required bool   `json:"required,omitempty"`
}

// ExecutionProxy never contains URL userinfo. CredentialRef identifies a secret
// or connector; executors without an adapter for it fail instead of connecting
// directly or handing the reference to a workload as a password.
type ExecutionProxy struct {
	HTTPS         string   `json:"https,omitempty"`
	HTTP          string   `json:"http,omitempty"`
	Bypass        []string `json:"bypass,omitempty"`
	CredentialRef string   `json:"credential_ref,omitempty"`
	Required      bool     `json:"required,omitempty"`
}

// TrustConsumer declares the formats a builder, scanner or publisher consumes.
type TrustConsumer struct {
	Name    string        `json:"name"`
	Formats []TrustFormat `json:"formats"`
}

// TrustFormat names pem, node or java-pkcs12. Unknown required formats fail.
type TrustFormat struct {
	Name     string `json:"name"`
	Required bool   `json:"required,omitempty"`
}

// ExecutionEvidence is safe to persist. It deliberately cannot contain PEM,
// proxy URLs, bypass entries or credential references.
type ExecutionEvidence struct {
	Revision      string   `json:"revision"`
	BundleDigests []string `json:"bundle_digests,omitempty"`
	ProxyHosts    []string `json:"proxy_hosts,omitempty"`
	Formats       []string `json:"formats,omitempty"`
}
