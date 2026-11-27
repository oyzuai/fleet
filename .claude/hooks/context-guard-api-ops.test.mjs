import { test } from 'node:test';
import assert from 'node:assert/strict';
import { guard } from './context-guard.mjs';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

function loadedEvent(command) {
  const state = mkdtempSync(join(tmpdir(), 'guard-api-'));
  process.env.XDG_STATE_HOME = state; process.env.LOCALAPPDATA = state;
  const event = { cwd: state, session_id: 'api-ops', tool_name: 'Bash', tool_input: { command } };
  const key = createHash('sha256').update('claude\0api-ops').digest('hex');
  mkdirSync(join(state, 'oyzu/context/sessions'), { recursive: true });
  writeFileSync(join(state, 'oyzu/context/sessions', key + '.json'), JSON.stringify({ status: 'loaded', commit: 'a'.repeat(40) }));
  return event;
}

test('routine PR and ruleset operations through gh api are allowed', () => {
  for (const command of [
    'gh api -X PATCH repos/oyzuai/oyzu/pulls/3503 -F body=@/tmp/body.md',
    'gh api repos/oyzuai/oyzu/issues/3503/labels -f labels[]=initiative:caching',
    'gh api -X POST repos/oyzuai/oyzu/issues/3503/comments -f body=hello',
    'gh api -X PUT repos/oyzuai/oyzu/rulesets/26342255 --input /tmp/ruleset.json',
    'gh api -X POST repos/oyzuai/oyzu/pulls/3503/ccr/ready_for_review',
  ]) assert.equal(guard(loadedEvent(command), 'claude'), null, command);
});

test('merges, direct ref/content writes, releases and pull-request creation stay denied', () => {
  for (const command of [
    'gh api -X PUT repos/oyzuai/oyzu/pulls/3503/merge',
    'gh api -X POST repos/oyzuai/oyzu/git/refs -f ref=refs/heads/dev -f sha=abc',
    'gh api -X PATCH repos/oyzuai/oyzu/git/refs/heads/dev -f sha=abc',
    'gh api -X PUT repos/oyzuai/oyzu/contents/README.md -f message=x',
    'gh api -X POST repos/oyzuai/oyzu/releases -f tag_name=v1',
    'gh api -X POST repos/oyzuai/oyzu/pulls -f title=x -f head=a -f base=dev',
    'gh api -X PUT repos/oyzuai/oyzu/pulls/3503/ccr/auto_merge',
    'gh api -X POST repos/oyzuai/oyzu/actions/workflows/ci.yml/dispatches -f ref=dev',
    'gh api -if query=mutation{mergePullRequest} graphql',
    'gh api -iFtag_name=v1 repos/o/r/releases',
    'gh api -X PUT repos/o/r/rulesets/1 -f enforcement=disabled',
    'gh pr review 1 --approve',
    'gh repo sync o/r --branch dev --force',
    'gh run rerun 123',
  ]) assert.notEqual(guard(loadedEvent(command), 'claude'), null, command);
});

test('review round: combined flags, decoy fields, URL tricks and destructive writes are denied', () => {
  for (const command of [
    'gh api -iXPUT repos/o/r/pulls/1/merge',
    'gh api -iX PUT repos/o/r/pulls/1/merge',
    'gh api -f repos/a/b/issues=1 -X PUT repos/o/r/pulls/1/merge',
    'gh api -X PUT repos/o/r/pulls/1/merge#x',
    'gh api -X PUT repos/o/r/PULLS/1/MERGE',
    'gh api -X PUT repos/o/r/pulls/1/merge/',
    'gh api -X DELETE repos/o/r',
    'gh api -X DELETE repos/o/r/rulesets/1',
    'gh api -X POST repos/o/r/statuses/abc -f state=success',
    'gh api -X POST repos/o/r/pulls/1/reviews -f event=APPROVE',
    'gh api -X PUT repos/o/r/pulls/1/update-branch',
    'gh api -X POST repos/o/r/issues/1/comments repos/o/r/pulls/1/merge',
    'gh release create v1',
    'gh workflow run ci.yml',
    'gh repo edit --visibility public',
    'python3 -c "import urllib.request as u; u.urlopen(\'https://api.github.com/repos/o/r/pulls/1/merge\')"',
  ]) assert.notEqual(guard(loadedEvent(command), 'claude'), null, command);
});

test('review round: any GitHub MCP server is held to read-only tools', () => {
  const event = loadedEvent('true');
  for (const tool of ['mcp__plugin_engineering_github__merge_pull_request', 'mcp__other_github__push_files'])
    assert.notEqual(guard({ ...event, tool_name: tool }, 'claude'), null, tool);
  assert.equal(guard({ ...event, tool_name: 'mcp__plugin_engineering_github__get_file_contents' }, 'claude'), null);
});
