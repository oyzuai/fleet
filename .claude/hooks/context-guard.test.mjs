import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { guard, statePath, startSession } from './context-guard.mjs';

const sha = 'a'.repeat(40);
const root = mkdtempSync(join(tmpdir(), 'context-guard-'));
const event = { session_id: 'one', cwd: root, tool_name: 'Bash', tool_input: { command: 'node build.mjs' } };
const call = (command, extra = {}) => guard({ ...event, tool_input: { command }, ...extra }, 'claude');
process.on('exit', () => rmSync(root, { recursive: true, force: true }));

test('missing, unloaded, invalid and cross-session state deny writes; safe reads permit repair', () => {
  assert.match(call('node build.mjs'), /context.*unloaded/i);
  for (const command of ['git status --short', 'git log -1', 'git diff', 'ls -la', 'cat AGENTS.md'])
    assert.equal(call(command), null, command);
  for (const command of ['cat AGENTS.md > x', 'ls; node build.mjs', 'git branch new', 'git diff --output=x', 'cat $(touch x)', 'git show --ext-diff', 'git -c alias.x=push x'])
    assert.ok(call(command), command);
  assert.ok(call('', { tool_name: 'Edit', tool_input: { file_path: 'x' } }));
  mkdirSync(resolve(statePath(event, 'claude'), '..'), { recursive: true });
  writeFileSync(statePath(event, 'claude'), JSON.stringify({ status: 'unloaded' }));
  assert.ok(call('node build.mjs'));
  writeFileSync(statePath(event, 'claude'), JSON.stringify({ status: 'loaded' }));
  assert.ok(call('node build.mjs'));
  writeFileSync(statePath(event, 'claude'), '{');
  assert.ok(call('node build.mjs'));
  writeFileSync(statePath(event, 'claude'), JSON.stringify({ status: 'loaded', commit: sha }));
  assert.equal(call('node build.mjs'), null);
  assert.ok(call('node build.mjs', { session_id: 'two' }));
  assert.ok(guard({ ...event, tool_name: 'apply_patch' }, 'codex'));
});

test('publication commands require actual body and initiative, including body files', () => {
  mkdirSync(resolve(statePath(event, 'claude'), '..'), { recursive: true });
  writeFileSync(statePath(event, 'claude'), JSON.stringify({ status: 'loaded', commit: sha }));
  for (const command of ['gh pr create --title x', 'gh --repo oyzuai/oyzu pr create --title x', 'gh "pr" "create" --title x', 'gh pr merge 123', 'git push origin HEAD:dev', 'git push origin main', 'git push --all', 'git push'])
    assert.ok(call(command), command);
  assert.equal(call('git push origin HEAD:claude/task'), null);
  assert.equal(call("gh pr create --label initiative:context --body 'Test-first: no behavior change, covered by tests'"), null);
  assert.ok(call("gh pr create --label initiative:caching --body 'Test-first: tests/cache.rs'"));
  assert.equal(call(`gh pr create --label initiative:caching --body 'Test-first: tests/cache.rs, red at ${sha}, green at ${'b'.repeat(40)}'`), null);
  writeFileSync(join(root, 'body.md'), 'Test-first: no behavior change, covered by guard tests');
  assert.equal(call('gh pr create --label initiative:context --body-file body.md'), null);
  assert.ok(call("echo 'Test-first: tests initiative:context'; gh pr create --title x"));
});

test('startup writes unloaded before loading, records only successful commit, and resets stale success', () => {
  const run = (status, stdout) => () => {
    assert.ok(call('node build.mjs'));
    return { status, stdout, stderr: '' };
  };
  assert.equal(startSession(event, 'claude', run(0, `context commit ${sha}\n`)).status, 0);
  assert.equal(call('node build.mjs'), null);
  assert.equal(startSession(event, 'claude', run(1, 'ERROR: context load FAILED')).status, 2);
  assert.ok(call('node build.mjs'));
  assert.equal(startSession(event, 'claude', run(0, '')).status, 2);
});

test('real PreToolUse entry exits 2 with denial text', () => {
  for (const tool_name of ['Bash', 'Edit', 'Write']) {
    const result = spawnSync(process.execPath, ['.claude/hooks/context-guard.mjs', 'pre-tool-use', 'claude'], {
      cwd: resolve(import.meta.dirname, '../..'), encoding: 'utf8',
      input: JSON.stringify({ ...event, tool_name, session_id: 'denial-transcript' }),
    });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /context.*unloaded/i);
    console.log(`deny transcript: ${tool_name} exit ${result.status}: ${result.stderr.trim()}`);
  }
});

// Round 2 uses an OS state directory, outside every fixture repository.
process.env.XDG_STATE_HOME = join(root, 'os-state');
process.env.LOCALAPPDATA = join(root, 'os-state');
const load = client => { const path = statePath(event, client); mkdirSync(resolve(path, '..'), { recursive: true }); writeFileSync(path, JSON.stringify({ status: 'loaded', commit: sha })); };
test('round2: every tool is matched and alternate publication tools are denied', () => {
  for (const client of ['claude', 'codex']) {
    load(client);
    for (const tool_name of ['NotebookEdit', 'mcp__github__create_pull_request', 'mcp__github__merge_pull_request', 'mcp__github__push_files', 'mcp__codex_apps__github__create_pull_request'])
      assert.ok(guard({ ...event, tool_name }, client), tool_name);
  }
});
test('round2: obfuscated, wrapped, aliased and API publication is denied', () => {
  load('claude');
  for (const command of ['g\\it push origin HEAD:dev', 'g"i"t p"u"sh origin HEAD:dev', 'env git push origin HEAD:codex/x', 'echo x | xargs git push origin HEAD:codex/x', 'sh -c "git push origin HEAD:dev"', 'gh pr new --title x', 'gh api repos/o/r/pulls -X POST', 'gh api repos/o/r/pulls --method=PATCH', 'gh api repos/o/r/pulls -f title=x', 'gh api graphql -f query=mutation'])
    assert.ok(call(command), command);
});
test('round2: exactly one literal task refspec may be pushed', () => {
  load('claude');
  for (const command of ['git push origin HEAD:claude/task', 'git push -u origin codex/task', 'git push origin refs/heads/local:refs/heads/codex/task']) assert.equal(call(command), null, command);
  for (const tail of ['HEAD:claude/x HEAD:dev', '+HEAD:claude/x', ':claude/x', 'HEAD:claude/*', '--tags HEAD:claude/x', '--all HEAD:claude/x', '--mirror HEAD:claude/x', '--delete claude/x', '--force HEAD:claude/x', 'HEAD:claude/x:dev']) assert.ok(call('git push origin ' + tail), tail);
});
test('round2: state follows the session across cwd without git or repository writes', () => {
  const elsewhere = join(root, 'elsewhere'); mkdirSync(elsewhere, { recursive: true });
  assert.equal(statePath(event, 'claude'), statePath({ ...event, cwd: elsewhere }, 'claude'));
  assert.ok(!statePath(event, 'claude').includes('.oyzu'));
  load('codex');
  assert.equal(guard({ ...event, tool_name: 'exec_command', tool_input: { cmd: ['git', 'status'] } }, 'codex'), null);
  assert.ok(guard({ ...event, tool_name: 'exec_command', tool_input: { cmd: ['git', 'push', 'origin', 'HEAD:dev'] } }, 'codex'));
});
test('round2: startup errors and timeouts invalidate success', () => {
  for (const result of [{ status: null, error: new Error('timeout') }, { status: 0, error: new Error('spawn failure'), stdout: 'context commit ' + sha + '\n' }]) {
    load('claude'); assert.equal(startSession(event, 'claude', () => result).status, 2); assert.ok(call('node build.mjs'));
  }
});

test('round2: prohibited push forms cannot accompany an allowed destination', () => {
  load('claude');
  for (const tail of ['HEAD:claude/x HEAD:dev', '+HEAD:claude/x', ':claude/x', 'HEAD:claude/*', '--tags HEAD:claude/x', '--all HEAD:claude/x', '--mirror HEAD:claude/x', '--delete claude/x']) assert.ok(call('git push origin ' + tail), tail);
});
test('round2: hook wiring matches every tool and forces shell failures to deny', () => {
  const config = JSON.parse(readFileSync(new URL('../../.claude/settings.json', import.meta.url), 'utf8'));
  const hook = config.hooks.PreToolUse[0]; assert.equal(hook.matcher, '.*');
  assert.match(hook.hooks[0].command, / \|\| exit 2$/);
  assert.equal(hook.hooks[0].onFailure, undefined);
  assert.doesNotMatch(hook.hooks[0].command, /git rev-parse/);
});

test('round2: launcher denies child errors, timeouts and missing Node', async () => {
  const { runHook } = await import('./hook-runner.mjs');
  for (const result of [{ status: 1, stderr: 'error' }, { status: null, error: new Error('ETIMEDOUT') }, { status: null, error: new Error('ENOENT') }]) {
    const denied = runHook('pre-tool-use', 'claude', '{}', () => result);
    assert.equal(denied.status, 2); assert.equal(JSON.parse(denied.stdout).hookSpecificOutput.permissionDecision, 'deny');
  }
});

test('round2: repeated API method flags cannot hide a write', () => {
  load('claude'); assert.ok(call('gh api repos/o/r/pulls -X GET -X POST'));
});

test('round2: real launch failures and process timeouts return a blocking decision', async () => {
  const { runHook } = await import('./hook-runner.mjs');
  for (const run of [
    (exe, args, options) => spawnSync(join(root, 'missing-node'), args, options),
    (exe, args, options) => spawnSync(exe, ['-e', 'setTimeout(() => {}, 10000)'], { ...options, timeout: 50 }),
  ]) assert.equal(JSON.parse(runHook('pre-tool-use', 'claude', '{}', run).stdout).hookSpecificOutput.permissionDecision, 'deny');
  const result = spawnSync(process.execPath, [new URL('./hook-runner.mjs', import.meta.url).pathname.replace(/^\/(?:([A-Za-z]):)/, '$1:'), 'pre-tool-use', 'claude'], { input: '{invalid', encoding: 'utf8' });
  assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, 'deny');
});


test('round3: unloaded sessions cannot execute cwd repair code', () => {
  for (const client of ['claude', 'codex']) {
    const unloaded = { ...event, session_id: 'unloaded-repair' };
    for (const command of ['node .claude/hooks/context-guard.mjs session-start claude', 'node .claude/hooks/context-guard.mjs session-start codex'])
      assert.match(guard({ ...unloaded, tool_input: { command } }, client), /context.*unloaded/i, command);
  }
});

test('round3: GitHub MCP permits only get, list and search tools after loading', () => {
  for (const client of ['claude', 'codex']) {
    load(client);
    for (const action of ['update_issue', 'delete_file', 'add_comment', 'fork_repository', 'create_branch', 'submit_pull_request_review', 'unknown_write'])
      assert.ok(guard({ ...event, tool_name: 'mcp__github__' + action }, client), action);
    for (const action of ['get_file_contents', 'list_issues', 'search_code']) {
      assert.equal(guard({ ...event, tool_name: 'mcp__github__' + action }, client), null, action);
      assert.ok(guard({ ...event, session_id: 'unloaded-mcp', tool_name: 'mcp__github__' + action }, client));
    }
  }
});

test('round3: send-pack, direct GitHub API and gh aliases are denied', () => {
  load('claude');
  for (const command of [
    'git send-pack origin HEAD:main', 'git-send-pack origin HEAD:main',
    'git -C . send-pack origin HEAD:main', 'git --git-dir=.git send-pack origin HEAD:main',
    'env git send-pack origin HEAD:main', 'g"i"t send-pack origin HEAD:main',
    'curl -X POST https://api.github.com/repos/o/r/pulls',
    'curl https://API.GITHUB.COM/repos/o/r/pulls -d @body.json',
    `node -e "fetch('https://api.github.com/repos/o/r/pulls',{method:'POST'})"`,
    `node -e "require('https').request({hostname:'api.github.com',method:'POST'})"`,
    'gh alias set publish "pr create"', 'gh alias import aliases.yml', 'gh alias list',
  ]) assert.ok(call(command), command);
});
