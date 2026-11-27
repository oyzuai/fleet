import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { guard, statePath } from './context-guard.mjs';

const repository = new URL('../../', import.meta.url);
const config = JSON.parse(readFileSync(new URL('.claude/settings.json', repository), 'utf8'));

test('round3 A: configured Claude shell hooks return 2 for missing or failing Node and hook', t => {
  const root = mkdtempSync(join(tmpdir(), 'hook shell spaces-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, 'bin'); mkdirSync(bin);
  const shell = process.platform === 'win32'
    ? resolve(spawnSync('git', ['--exec-path'], { encoding: 'utf8' }).stdout.trim(), '../../../bin/bash.exe') : '/bin/sh';
  for (const [event, mode] of [['SessionStart', 'session-start'], ['PreToolUse', 'pre-tool-use']]) {
    const hook = config.hooks[event].flatMap(group => group.hooks).find(hook => hook.command.includes('hook-runner') || hook.command === 'node');
    assert.deepEqual(Object.keys(hook).sort(), ['command', 'timeout', 'type']);
    assert.equal(hook.command, `node "$CLAUDE_PROJECT_DIR/.claude/hooks/hook-runner.mjs" ${mode} claude || exit 2`);
    const run = (path, project = root) => spawnSync(shell, ['-c', hook.command], {
      env: { ...process.env, PATH: path, CLAUDE_PROJECT_DIR: project }, input: '{}', encoding: 'utf8',
    });
    assert.equal(run(bin).status, 2, 'missing Node');
    writeFileSync(join(bin, 'node'), '#!/bin/sh\nexit 17\n', { mode: 0o755 });
    assert.equal(run(bin).status, 2, 'failing Node');
    rmSync(join(root, '.claude/hooks/hook-runner.mjs'), { force: true });
    assert.equal(run(dirname(process.execPath)).status, 2, 'missing hook');
    mkdirSync(join(root, '.claude/hooks'), { recursive: true });
    writeFileSync(join(root, '.claude/hooks/hook-runner.mjs'), 'process.exit(23)');
    assert.equal(run(dirname(process.execPath)).status, 2, 'failing hook');
    writeFileSync(join(root, '.claude/hooks/hook-runner.mjs'), 'process.exit(0)');
    assert.equal(run(dirname(process.execPath)).status, 0, 'successful hook');
    rmSync(join(bin, 'node'));
  }
});

test('round3 B: Codex runs the bound project hook, or derives the repository root, never a cwd walk-up', t => {
  const root = mkdtempSync(join(tmpdir(), 'codex trusted root-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const trusted = join(root, 'trusted'), nested = join(trusted, 'nested'), clone = join(root, 'clone');
  for (const directory of [trusted, nested, clone]) {
    mkdirSync(join(directory, '.claude/hooks'), { recursive: true });
    mkdirSync(join(directory, '.codex'), { recursive: true });
    writeFileSync(join(directory, '.codex/hooks.json'), '{}');
    writeFileSync(join(directory, '.claude/hooks/hook-runner.mjs'), directory === trusted ? 'process.exit(2)' : 'process.exit(0)');
  }
  const codex = JSON.parse(readFileSync(new URL('.codex/hooks.json', repository), 'utf8'));
  for (const event of ['SessionStart', 'PreToolUse']) {
    const hook = codex.hooks[event][0].hooks[0];
    const code = /^node -e "([^"]+)"/.exec(hook.command)?.[1];
    assert.ok(code);
    const run = (cwd, boundRoot) => spawnSync(process.execPath, ['-e', code, event === 'SessionStart' ? 'session-start' : 'pre-tool-use', 'codex'], {
      cwd, env: { ...process.env, OYZU_CONTEXT_PROJECT_ROOT: boundRoot ?? '' }, input: '{}', encoding: 'utf8',
    });
    for (const cwd of [nested, clone, root]) {
      assert.equal(run(cwd, trusted).status, 2, cwd);
      assert.equal(run(cwd).status, 2, 'no binding and no Git repository to derive one from');
    }
    writeFileSync(join(trusted, '.claude/hooks/hook-runner.mjs'), 'process.exit(0)');
    assert.equal(run(clone, trusted).status, 0);
    assert.equal(run(clone, '.').status, 2, 'relative binding');
    rmSync(join(trusted, '.codex/hooks.json'));
    assert.equal(run(clone, trusted).status, 2, 'missing root hook configuration');
    writeFileSync(join(trusted, '.codex/hooks.json'), '{}');
    writeFileSync(join(trusted, '.claude/hooks/hook-runner.mjs'), 'process.exit(2)');
  }
});

test('round3 C: unloaded sessions cannot execute a cwd-relative repair script', t => {
  const root = mkdtempSync(join(tmpdir(), 'guard-repair-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const client of ['claude', 'codex']) {
    const denial = guard({ session_id: root, cwd: root, tool_name: 'Bash', tool_input: { command: `node .claude/hooks/context-guard.mjs session-start ${client}` } }, client);
    assert.match(denial ?? '', /unloaded/);
  }
});

test('round3 D: GitHub MCP uses a read-only allowlist and shell publication bypasses deny', t => {
  const root = mkdtempSync(join(tmpdir(), 'guard-publication-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const event = { session_id: root, cwd: root, tool_name: 'Bash', tool_input: { command: '' } };
  for (const client of ['claude', 'codex']) {
    const state = statePath(event, client); mkdirSync(dirname(state), { recursive: true });
    writeFileSync(state, JSON.stringify({ status: 'loaded', commit: 'a'.repeat(40) }));
    t.after(() => rmSync(state, { force: true }));
    for (const prefix of ['mcp__github__', 'mcp__codex_apps__github__']) {
      for (const operation of ['update_pull_request', 'delete_file', 'add_issue_comment', 'submit_pull_request_review', 'fork_repository', 'unknown_operation'])
        assert.ok(guard({ ...event, tool_name: prefix + operation }, client), prefix + operation);
      for (const operation of ['get_pull_request', 'list_issues', 'search_code'])
        assert.equal(guard({ ...event, tool_name: prefix + operation }, client), null, prefix + operation);
    }
    for (const command of ['git send-pack origin HEAD:dev', 'git -c x=y send-pack origin HEAD:dev', 'curl -X POST https://api.github.com/repos/o/r/pulls', 'wget https://uploads.github.com/repos/o/r/releases/1/assets', `node -e 'fetch("https://api.github.com/repos/o/r/pulls")'`, 'gh alias set publish "pr create"', 'gh alias list'])
      assert.ok(guard({ ...event, tool_input: { command } }, client), command);
    assert.equal(guard({ ...event, tool_input: { command: 'gh pr list' } }, client), null);
    assert.equal(guard({ ...event, tool_input: { command: 'node tooling/check-docs.mjs' } }, client), null);
  }
});

test('round3 E: Codex child deadlines leave time to deny before the outer timeout', () => {
  const codex = JSON.parse(readFileSync(new URL('.codex/hooks.json', repository), 'utf8'));
  for (const event of ['SessionStart', 'PreToolUse']) {
    const hook = codex.hooks[event][0].hooks[0];
    const code = /^node -e "([^"]+)"/.exec(hook.command)?.[1];
    // Inspect the effective options of the real wrapper without waiting 28 seconds.
    const probe = `require('node:child_process').spawnSync=(exe,args,options)=>{require('node:fs').writeSync(1,String(options.timeout));return {status:0}};${code}`;
    const result = spawnSync(process.execPath, ['-e', probe, event === 'SessionStart' ? 'session-start' : 'pre-tool-use', 'codex'], {
      env: { ...process.env, OYZU_CONTEXT_PROJECT_ROOT: fileURLToPath(repository) }, encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    assert.ok(Number(result.stdout.trim()) > 0 && Number(result.stdout.trim()) < hook.timeout * 1000, result.stdout);
  }
});

test('round3 B2: with no binding Codex derives the session repository root instead of locking out every session', t => {
  const root = mkdtempSync(join(tmpdir(), 'codex derived root-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, '.claude/hooks'), { recursive: true });
  mkdirSync(join(root, '.codex'), { recursive: true });
  mkdirSync(join(root, 'sub/dir'), { recursive: true });
  writeFileSync(join(root, '.codex/hooks.json'), '{}');
  writeFileSync(join(root, '.claude/hooks/hook-runner.mjs'), 'process.exit(0)');
  assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
  const codex = JSON.parse(readFileSync(new URL('.codex/hooks.json', repository), 'utf8'));
  for (const event of ['SessionStart', 'PreToolUse']) {
    const code = /^node -e "([^"]+)"/.exec(codex.hooks[event][0].hooks[0].command)?.[1];
    const env = { ...process.env }; delete env.OYZU_CONTEXT_PROJECT_ROOT;
    const run = cwd => spawnSync(process.execPath, ['-e', code, event === 'SessionStart' ? 'session-start' : 'pre-tool-use', 'codex'], { cwd, env, input: '{}', encoding: 'utf8' });
    assert.equal(run(join(root, 'sub/dir')).status, 0, 'unset binding inside the repository must work');
    writeFileSync(join(root, '.claude/hooks/hook-runner.mjs'), 'process.exit(2)');
    assert.equal(run(join(root, 'sub/dir')).status, 2, 'a denying guard still denies');
    writeFileSync(join(root, '.claude/hooks/hook-runner.mjs'), 'process.exit(0)');
  }
});
