// The build witness and publication intent use per-job ephemeral Ed25519 keys.
// The durable consumer trust anchor is oyzu publish's keyless subject signature.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const manifestPath = 'dist/manifest.json';
const manifest = JSON.parse(fs.readFileSync(manifestPath));
assert.equal(manifest.status, 'succeeded');
const logical = new Map((manifest.targets ?? []).map(t => [t.id, t.extensions?.['oyzu.dev/platforms']?.target ?? t.id]));
const image = manifest.artifacts.filter(a => (logical.get(a.target) ?? a.target) === 'executor-image' && a.name === 'image');
assert.equal(image.length, 1);
const artifact = image[0];
const bytes = fs.readFileSync(path.resolve('dist', artifact.path));
const sha = data => crypto.createHash('sha256').update(data).digest('hex');
assert.equal(artifact.digest, `sha256:${sha(bytes)}`);
assert.equal(artifact.size, bytes.length);
const builder = crypto.generateKeyPairSync('ed25519');
const publisher = crypto.generateKeyPairSync('ed25519');
const publicKey = pair => pair.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
const seed = publisher.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64');
const builderId = 'https://github.com/oyzuai/fleet/.github/workflows/release.yml';
const statement = { _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'executor-image/image', digest: { sha256: sha(bytes) } }], predicateType: 'https://slsa.dev/provenance/v1', predicate: {
  buildDefinition: { buildType: 'https://oyzu.dev/buildtypes/release-local-witness/v1alpha1', externalParameters: { command: 'oyzu build executor-image' }, resolvedDependencies: [{ uri: 'git+https://github.com/oyzuai/fleet', digest: { gitCommit: process.env.GITHUB_SHA } }] },
  runDetails: { builder: { id: builderId } },
} };
const payload = Buffer.from(JSON.stringify(statement));
const payloadType = 'application/vnd.in-toto+json';
const pae = Buffer.concat([Buffer.from(`DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `), payload]);
fs.mkdirSync('.oyzu/release-evidence', { recursive: true });
fs.writeFileSync('.oyzu/release-evidence/executor.sigstore.json', JSON.stringify({ mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json', verificationMaterial: { publicKey: { hint: `sha256:${sha(Buffer.from(publicKey(builder), 'base64'))}` } }, dsseEnvelope: { payloadType, payload: payload.toString('base64'), signatures: [{ sig: crypto.sign(null, pae, builder.privateKey).toString('base64') }] } }));
assert.match(process.env.GITHUB_REF, /^refs\/tags\/v[0-9A-Za-z.-]+$/);
fs.appendFileSync('oyzu.toml', `
[publish.requirements.provenance]
bundlePath = ".oyzu/release-evidence/executor.sigstore.json"
publicKey = "${publicKey(builder)}"
builderId = "${builderId}"
[publish.requirements.signing]
keyEnv = "OYZU_RELEASE_PUBLICATION_SEED"
publicKey = "${publicKey(publisher)}"
[publish.requirements.signing.subject]
signer = "sigstore"
identity = "${builderId}@${process.env.GITHUB_REF}"
issuer = "https://token.actions.githubusercontent.com"
`);
console.log(`::add-mask::${seed}`);
fs.appendFileSync(process.env.GITHUB_ENV, `OYZU_RELEASE_PUBLICATION_SEED=${seed}\n`);
