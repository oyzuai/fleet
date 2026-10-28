# Execution trust and proxies

The additive `job.execution_config` field on `job/start` carries resolved
configuration. Managers still hand out startup tokens only; every executor
fetches its own configuration, including each per-target job in a split run.
Fleet has no account, organization or project models. The service must resolve
inheritance, authorize settings and select consumer declarations before startup.

```json
{
  "version": 1,
  "revision": "execution-revision-123",
  "required": true,
  "bundles": [{"pem": "<canonical CA PEM>", "digest": "<SHA-256 hex>", "required": true}],
  "proxy": {"https": "http://proxy.example:3128", "http": "http://proxy.example:3128", "bypass": [".internal.example", "10.0.0.0/8"], "required": true},
  "consumers": [{"name": "scanner", "formats": [{"name": "java-pkcs12", "required": true}]}]
}
```

`pem`, `node` and `java-pkcs12` are supported formats. PEM and Node projections
are produced whenever there are additional anchors. Java is produced only when
a consumer requests it. It is encoded in Go using SSLMate go-pkcs12 v0.7.3,
without a JDK or keytool, and uses the conventional non-secret password
`changeit`. No private keys enter that store. A required failed projection stops
the job; an optional failed Java projection is omitted from applied evidence.

Bundles accept only PEM X.509 CA certificates, reject junk and private keys,
and verify SHA-256 over canonical PEM. Proxy endpoints accept HTTP or HTTPS
without userinfo, query, fragment or a non-root path. Bypass entries accept
hosts, domains, optional ports, IP addresses, CIDRs and `*`; a leading dot or
`*.` matches subdomains only. Proxy authentication references have a typed
`credential_ref` field, but no credential adapter is implemented yet; supplying
one fails explicitly. The executor never falls back to direct routing after
an upstream proxy or TLS failure.

The projection owns these read-only files until the job finishes:

| File | Contents |
| --- | --- |
| `ca.pem` | Executor system PEM roots plus corporate CAs and, with egress grants, the job CA |
| `corporate-ca.pem` | Corporate anchors only |
| `additional-ca.pem` | Corporate anchors plus the job CA, if any |
| `truststore.p12` | The combined trust set, for a declared Java consumer |

`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
`PIP_CERT` and `CARGO_HTTP_CAINFO` name the combined set. `NODE_EXTRA_CA_CERTS`
names the additional set, preserving Node's own roots. Java consumers receive
truststore path, type and password properties through `JAVA_TOOL_OPTIONS`, with
existing options preserved. Proxy settings populate `HTTPS_PROXY`, `HTTP_PROXY`
and `NO_PROXY` and their lowercase forms; an explicit configuration clears
ambient `ALL_PROXY` fallbacks. No TLS verification is disabled.

The credential proxy keeps its existing job-only CA and credential boundary.
When corporate configuration is present, its upstream TLS also trusts corporate
anchors, and both intercepted traffic and opaque CONNECT tunnels use the
corporate proxy and bypass list. With no `execution_config`, the legacy proxy,
environment and CA-file behavior are unchanged.

Build, checkout and maintenance processes receive the same projected environment.
Anonymous public checkouts retain that trust without adding an Authorization header
when no source token was issued.
Build trust files live under the checkout's `.git/oyzu-execution` so source
capture cannot include them. Kinds use their execution work directory. Image
kinds bind the trust directory at `/run/oyzu/trust:ro`; built-in kinds receive
local file paths. Files are mode 0444 and their directory is mode 0555, cleaned
up after execution or a failed projection. A same-user process can change file
permissions: this is read-only by convention for process pools, not an isolation
guarantee against hostile code running as that same OS user.

Windows executors must provision a system PEM bundle through `SSL_CERT_FILE`
when additional trust needs projection; Go cannot export the Windows root store.
Failure to find system PEM roots fails projection rather than replacing public
roots with corporate trust alone.

| Reason code | Meaning |
| --- | --- |
| `EXECUTION_CONFIG_INVALID` | Invalid version, revision, PEM, digest or proxy setting |
| `TRUST_BUNDLE_UNAVAILABLE` | A required bundle is empty |
| `TRUST_FORMAT_UNSUPPORTED` | Required format is unsupported |
| `TRUST_PROJECTION_FAILED` | System roots or materialization failed |
| `PROXY_CONFIG_UNSUPPORTED` | A proxy credential reference has no supported adapter |

Build outcomes and kind finish requests carry `execution`: revision, canonical
bundle digests, proxy hostnames and applied formats. It contains no PEM, proxy
URL, bypass list or credential reference. Failed validation returns a sanitized
reason and does not copy invalid input into evidence. The receiving service must
validate and persist this record; fleet cannot establish that persistence.

Executors send `Oyzu-Execution-Config: 1` on job/start. The server must refuse
required configurations to old executors with `EXECUTION_CONFIG_UNSUPPORTED`
before releasing launch inputs. Any required bundle, proxy or consumer format
makes the configuration required.

Current limits: existing container/Kubernetes manager drivers launch the executor with
writable work volumes and no Docker socket; they cannot run Docker image kinds.
The nested image launch and read-only build-container mount integration remain
unimplemented. Platform's prepared Linux proof runs a built-in scanner in its
container-pool image; it does not establish nested container launch coverage.
Driver-fake tests exercise missing-required-trust refusal across process,
container, Kubernetes and VM assignments; they are not read-only mount proofs.
No daemon configuration or host trust store is modified.
