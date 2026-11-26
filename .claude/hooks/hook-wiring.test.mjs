import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, chmodSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const repo = resolve(import.meta.dirname, '../..');
const root = mkdtempSync(join(tmpdir(), 'hook-wiring-'));
process.on('exit', () => rmSync(root, { recursive: true, force: true }));
const trusted = join(root, 'trusted project');
const nested = join(root, 'untrusted', 'nested');
const marker = join(root, 'cwd-runner-executed');
for (const path of [join(trusted, '.claude/hooks'), join(root, 'untrusted/.claude/hooks'), nested]) mkdirSync(path, { recursive: true });
writeFileSync(join(root, 'untrusted/.claude/hooks/hook-runner.mjs'), `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'executed'); process.exit(0);`);
const env = { ...process.env, CLAUDE_PROJECT_DIR: trusted, CODEX_PROJECT_ROOT: trusted, XDG_STATE_HOME: join(root, 'state'), LOCALAPPDATA: join(root, 'state') };
const config = client => JSON.parse(readFileSync(join(repo, client === 'claude' ? '.claude/settings.json' : '.codex/hooks.json'), 'utf8'));
const hook = (client, name) => config(client).hooks?.[name]?.flatMap(group => group.hooks).find(h => /hook-runner/.test(h.command)) ?? { command: ':' };
const run = (h, extra = {}) => spawnSync('/bin/sh', ['-c', h.command], { cwd: nested, env, input: '{}', encoding: 'utf8', ...extra });

test('round3: configured hooks deny unloaded mutation and missing runners', () => {
  // Test the configured command, so an absent hook on the base fails as exit 0.
  const input = JSON.stringify({ cwd: nested, session_id: 'unloaded-wiring', tool_name: 'Edit', tool_input: { file_path: 'x' } });
  for (const client of ['claude', 'codex']) {
    const ownEnv = { ...env, CLAUDE_PROJECT_DIR: repo, CODEX_PROJECT_ROOT: repo };
    assert.equal(run(hook(client, 'PreToolUse'), { input, env: ownEnv }).status, 2, `${client}: unloaded Edit must exit 2`);
    for (const name of ['SessionStart', 'PreToolUse']) {
      assert.equal(run(hook(client, name)).status, 2, `${client} ${name}: missing runner must exit 2`);
    }
  }
  assert.equal(existsSync(marker), false, 'cwd code must never execute');
});

test('round3: Claude uses plain shell commands and maps failing or missing node to exit 2', () => {
  const bin = join(root, 'failing-bin'); mkdirSync(bin);
  writeFileSync(join(bin, 'node'), '#!/bin/sh\nexit 47\n'); chmodSync(join(bin, 'node'), 0o755);
  const empty = join(root, 'empty-bin'); mkdirSync(empty);
  for (const name of ['SessionStart', 'PreToolUse']) {
    const h = hook('claude', name);
    const mode = name === 'SessionStart' ? 'session-start' : 'pre-tool-use';
    assert.equal(h.command, `node "$CLAUDE_PROJECT_DIR/.claude/hooks/hook-runner.mjs" ${mode} claude || exit 2`);
    assert.equal(h.args, undefined); assert.equal(h.onFailure, undefined);
    for (const path of [bin, empty]) assert.equal(run(h, { env: { ...env, PATH: path } }).status, 2);
  }
});

test('round3: Codex uses only the trusted root across nested and non-repository cwd', () => {
  // A zero-exit fixture at the trusted root distinguishes it from the cwd decoy.
  const runner = join(trusted, '.claude/hooks/hook-runner.mjs');
  writeFileSync(runner, 'process.exit(0)');
  for (const name of ['SessionStart', 'PreToolUse']) {
    const h = hook('codex', name);
    assert.notEqual(h.command, ':', 'Codex hook must exist');
    for (const cwd of [nested, root]) assert.equal(run(h, { cwd }).status, 0, h.command);
    assert.equal(existsSync(marker), false);
    for (const value of ['', '.', join(root, 'missing-project')])
      assert.equal(run(h, { env: { ...env, CODEX_PROJECT_ROOT: value } }).status, 2, `untrusted root ${value}`);
  }
  rmSync(runner);
});
