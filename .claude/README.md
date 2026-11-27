# Session context

Claude runs `.claude/hooks/hook-runner.mjs` at SessionStart and before every tool.
Codex uses the same runner through `.codex/hooks.json`. Review and trust the
native hook definitions before use. These files do not install account hooks.

For Codex, the trusted launcher can set `OYZU_CONTEXT_PROJECT_ROOT` to the
absolute checkout root. Otherwise, the hook derives the root with
`git rev-parse --show-toplevel`. A relative or inaccessible root, missing hook
configuration, or runner outside that root fails closed. The runner never walks
up from the tool cwd to search for executable code.

The loader refreshes the sibling `context` checkout on `main`, verifies its
canonical origin and clean state, and reads the committed constitution, index,
working agreements, maintainer profile and client adapter. It prints the exact
context commit and root. Bash, Git, Node.js 24+ and repository access are required.
An unusable sibling is preserved while the loader tries a private clean clone
in the OS state directory. If refresh fails, a clean cached `main` checkout at
its last-fetched `origin/main` is accepted with an offline warning. Shared skills
are refreshed separately without replacing existing packages.

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
