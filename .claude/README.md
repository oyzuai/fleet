# Session context

Claude runs `.claude/hooks/hook-runner.mjs` at SessionStart and before every tool.
Codex uses the same runner through `.codex/hooks.json`. Review and trust the
native hook definitions before use. These files do not install account hooks.

For Codex, the trusted launcher must set `CODEX_PROJECT_ROOT` to the absolute
checkout root before starting the session. This is a deployment requirement,
not an assumed Codex-provided variable. A missing, relative or inaccessible root
fails closed. The runner never searches the tool cwd for executable code.

The loader refreshes the sibling `context` checkout on `main`, verifies its
canonical origin and clean state, and reads the committed constitution, index,
working agreements, maintainer profile and client adapter. It prints the exact
context commit and root. Bash, Git, Node.js 24+ and repository access are required.
Shared skills are refreshed separately without replacing existing packages.

State is stored per client/session in the OS state directory, outside the repo.
Failed context loading invalidates prior success. Until context loads, mutations
are denied and only narrow shell reads are allowed. Repair access outside the
unloaded tool session, then retry the trusted SessionStart hook. A cwd repair
script is not an exception. Runner failures and timeouts deny with exit 2.

Publication requires a Test-first line and exactly one initiative label. Pushes
allow one literal task-branch refspec. GitHub MCP writes, direct GitHub API calls,
`git send-pack` and `gh alias` are denied. Hooks are guardrails, not a sandbox;
normal review, signing and publication authority still apply.

Run `node --test .claude/hooks/*.test.mjs` and
`bash .claude/test-load-context.sh`. Tests use disposable local fixtures and
remove them on exit. The loader integration test redirects Git to local bare
remotes and forbids network protocols.
