import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, join, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export function statePath(event, client) {
  if (!event.session_id || typeof event.session_id !== 'string' || !event.cwd) throw new Error('Hook requires session_id and cwd.');
  const key = createHash('sha256').update(client + '\0' + event.session_id).digest('hex');
  const root = process.platform === 'win32'
    ? process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local')
    : process.platform === 'darwin' ? join(homedir(), 'Library', 'Application Support')
    : process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state');
  if (!isAbsolute(root)) throw new Error('OS state directory must be absolute.');
  return join(root, 'oyzu', 'context', 'sessions', key + '.json');
}

export function startSession(event, client, run = spawnSync) {
  const path = statePath(event, client);
  mkdirSync(resolve(path, '..'), { recursive: true });
  writeFileSync(path, JSON.stringify({ status: 'unloaded' }));
  let bash = 'bash';
  if (process.platform === 'win32') {
    const git = spawnSync('git', ['--exec-path'], { encoding: 'utf8' });
    const candidate = resolve(git.stdout?.trim() || '.', '../../../bin/bash.exe');
    if (git.status === 0 && existsSync(candidate)) bash = candidate;
  }
  const result = run(bash, [join(import.meta.dirname, '../load-context.sh')], {
    cwd: event.cwd, encoding: 'utf8', timeout: 20_000, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, CLAUDE_PROJECT_DIR: resolve(import.meta.dirname, '../..'), OYZU_CONTEXT_CLIENT: client },
  });
  const commit = /^context commit ([a-f0-9]{40})\r?$/m.exec(result.stdout ?? '')?.[1];
  if (result.status === 0 && !result.error && !result.signal && commit) writeFileSync(path, JSON.stringify({ status: 'loaded', commit }));
  return { status: result.status === 0 && !result.error && !result.signal && commit ? 0 : 2, stdout: result.stdout ?? '', stderr: `${result.stderr ?? ''}${result.error?.message ?? ''}` };
}

// Deliberately narrow: no expansions, operators, redirections or executable Git options.
function readOnly(command) {
  if (/[\n\r;&|<>`$(){}\\]/.test(command)) return false;
  if (/^\s*(?:ls|cat|pwd)\b[^]*$/.test(command)) return true;
  return /^\s*git\s+(?:status|log|show|diff|rev-parse|ls-files)\b/.test(command)
    && !/--(?:output|ext-diff|textconv|exec|open-files-in-pager)\b/.test(command);
}

function tokens(command) {
  // Publication commands with shell operators/expansions must be issued separately.
  if (/[;&|<>`$\r\n\\]/.test(command)) return null;
  const words = command.match(/"[^"\\]*"|'[^']*'|[^\s"']+/g) ?? [];
  if (words.join(' ').replace(/\s/g, '') !== command.trim().replace(/\s/g, '')) return null;
  return words.map(word => /^['"]/.test(word) ? word.slice(1, -1) : word);
}

function publication(command, cwd) {
  const literal = command.replace(/['"\\]/g, '');
  if (/\bgit(?:\b[^]*?\b|-)send-pack\b/i.test(literal) || /\bapi\.github\.com\b/i.test(literal) || /\bgh\b[^]*?\balias\b/.test(literal))
    return 'Direct GitHub API, send-pack and gh alias commands are denied; use the guarded publication path.';
  const create = /\bgh\b[^]*?\bpr\s+(?:create|new)\b/.test(literal);
  const merge = /\bgh\b[^]*?\bpr\s+merge\b/.test(literal);
  const push = /\bgit\b[^]*?\bpush\b/.test(literal);
  const api = /\bgh\b[^]*?\bapi\b/.test(literal);
  if (!create && !merge && !push && !api) return null;
  const words = tokens(command);
  if (!words || words[0] !== (push ? 'git' : 'gh')) return 'Run publication as a separate, literal command with a Test-first: body and initiative:* label.';
  if (api) {
    const methods = words.flatMap((word, i) => word === '-X' || word === '--method' ? [words[i + 1]]
      : /^(?:--method=|-X.)/.test(word) ? [word.replace(/^(?:--method=|-X)/, '')] : []);
    if (methods.some(verb => !['GET', 'HEAD', 'OPTIONS'].includes(verb)) || words.some(w => /^(?:-f|-F|--field|--raw-field|--input)/.test(w)))
      return 'GitHub API writes are denied; use the PR metadata gate.';
    return null;
  }
  if (push) {
    const args = words.slice(2).filter(w => w !== '-u' && w !== '--set-upstream');
    const [remote, refspec] = args;
    const refs = refspec?.split(':') ?? [];
    const [source, destination = source] = refs;
    const validRef = ref => typeof ref === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(ref)
      && !ref.includes('..') && !ref.includes('//') && !/[/.]$/.test(ref) && !ref.endsWith('.lock');
    if (words[1] === 'push' && args.length === 2 && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(remote)
      && refs.length <= 2 && validRef(source) && validRef(destination)
      && /^(?:refs\/heads\/)?(?:claude|codex)\/.+/.test(destination)) return null;
    return 'Push denied. Use one literal refspec to claude/* or codex/*, without force, deletion, tags or bulk options.';
  }
  const option = (long, short) => {
    const i = words.findIndex(word => word === long || word === short);
    return i >= 0 ? words[i + 1] : words.find(word => word.startsWith(`${long}=`))?.slice(long.length + 1);
  };
  let body = option('--body', '-b');
  const bodyFile = option('--body-file', '-F');
  if (bodyFile && bodyFile !== '-') {
    try { body = readFileSync(resolve(cwd, bodyFile), 'utf8'); } catch { return 'Cannot read PR body file.'; }
  }
  let labels = words.flatMap((word, i) => word === '--label' || word === '-l' ? [words[i + 1] ?? ''] : word.startsWith('--label=') ? [word.slice(8)] : []).flatMap(word => word.split(','));
  if (merge) {
    const target = words[words.findIndex((word, i) => word === 'pr' && words[i + 1] === 'merge') + 2];
    const selector = target && !target.startsWith('-') ? [target] : [];
    const repo = option('--repo', '-R');
    const result = spawnSync('gh', ['pr', 'view', ...selector, ...(repo ? ['--repo', repo] : []), '--json', 'body,labels'], {
      cwd, encoding: 'utf8', timeout: 5_000, env: { ...process.env, GH_PROMPT_DISABLED: '1' },
    });
    if (result.status !== 0) return 'Cannot verify the current PR body and initiative:* label; merge denied.';
    try {
      const pr = JSON.parse(result.stdout);
      body = pr.body;
      labels = pr.labels.map(label => label.name);
    } catch { return 'Invalid PR metadata; merge denied.'; }
  }
  if (labels.filter(label => /^initiative:[a-z0-9][a-z0-9-]*$/.test(label)).length !== 1) return 'PR creation requires exactly one initiative:* label.';
  if (!/^Test-first:[ \t]*\S.*$/m.test(body ?? '')) return 'PR body requires a non-empty Test-first: line.';
  if (labels.includes('initiative:caching') && !/^Test-first:[ \t]*\S.*?,\s*red at [a-f0-9]{40},\s*green at [a-f0-9]{40}[ \t]*$/m.test(body))
    return 'Caching PRs require Test-first: <tests>, red at <base SHA>, green at <head SHA>.';
  return null;
}

export function guard(event, client) {
  const input = event.tool_input?.command ?? event.tool_input?.cmd ?? '';
  if (typeof input !== 'string' && (!Array.isArray(input) || !input.every(word => typeof word === 'string'))) return 'Invalid shell command input; denied.';
  const command = Array.isArray(input) ? input.map(word => /^[A-Za-z0-9_./:=@+-]+$/.test(word) ? word : JSON.stringify(word)).join(' ') : input;
  const tool = event.tool_name ?? '';
  if (tool === 'NotebookEdit' || /github.*(?:create|merge|push_files)/i.test(tool)
    || (tool.startsWith('mcp__github__') && !/^mcp__github__(?:get_|list_|search_)/.test(tool)))
    return 'Notebook and GitHub publication tools are denied; use the guarded command path.';
  let loaded = false;
  try {
    const state = JSON.parse(readFileSync(statePath(event, client), 'utf8'));
    loaded = state.status === 'loaded' && /^[a-f0-9]{40}$/.test(state.commit);
  } catch { /* Missing or malformed state denies mutations. */ }
  if (!loaded) {
    if (!['Bash', 'exec_command', 'shell', 'shell_command'].includes(event.tool_name) || !readOnly(command))
      return 'Shared context is unloaded for this session. Read AGENTS.md, repair context access, then retry the SessionStart hook.';
  }
  return publication(command, event.cwd);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const event = JSON.parse(readFileSync(0, 'utf8'));
    const [mode, client] = process.argv.slice(2);
    if (!['claude', 'codex'].includes(client)) throw new Error('Expected claude or codex client.');
    if (mode === 'session-start') {
      const result = startSession(event, client);
      process.stdout.write(result.stdout);
      process.stderr.write(result.stderr);
      if (result.status) console.error('Shared context is unloaded. Repair access and retry SessionStart before editing.');
      process.exitCode = result.status;
    } else if (mode === 'pre-tool-use') {
      const denial = guard(event, client);
      if (denial) { console.error(denial); process.exitCode = 2; }
    } else throw new Error('Unknown hook mode.');
  } catch (error) { console.error(`Context hook denied: ${error.message}`); process.exitCode = 2; }
}
