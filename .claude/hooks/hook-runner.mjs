import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export function runHook(mode, client, input, run = spawnSync) {
  try {
    const result = run(process.execPath, [join(import.meta.dirname, 'context-guard.mjs'), mode, client], {
      input, encoding: 'utf8', timeout: mode === 'session-start' ? 27_000 : 7_000, maxBuffer: 8 * 1024 * 1024,
    });
    if (result.status === 0 && !result.error && !result.signal) return { status: 0, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
    throw new Error(result.stderr || result.error?.message || 'Hook failed or timed out.');
  } catch (error) {
    const reason = 'Context hook denied: ' + error.message;
    const stdout = mode === 'pre-tool-use' ? JSON.stringify({ hookSpecificOutput: {
      hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason,
    } }) + '\n' : '';
    return { status: 2, stdout, stderr: reason + '\n' };
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = runHook(process.argv[2], process.argv[3], readFileSync(0, 'utf8'));
  process.stdout.write(result.stdout); process.stderr.write(result.stderr); process.exitCode = result.status;
}
