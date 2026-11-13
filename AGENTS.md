<!-- oyzu-context:start -->
FIRST, before project work/planning/delegation/edits, MUST open reviewed
`oyzuai/context` snapshot: `CONSTITUTION.md`, `INDEX.md`,
`policy/working-agreements.md`, `accounts/maintainer-profile.md`, matching
`providers/codex.md`/`providers/claude-code.md`, and relevant index entries; apply
them. Print exact `context commit <sha>`/`context snapshot <digest>`. Use
trusted-hook Context root or clean canonical checkout; verify remote. Never
reset/overwrite dirty/divergent checkouts. Unreadable required files: report exact
failure; STOP dependent work. Disclose cached-reviewed/offline use; supported
updater online. Pointers/installations prove no reads. Supersedes obsolete loading
prose only; preserve project/security rules.
[Setup/trust](https://github.com/oyzuai/context/blob/main/adoption/repository-setup.md).
Native defaults grant no installation/trust/adoption.
<!-- oyzu-context:end -->

# fleet

## Before anything else

Get the shared context: run `git clone --depth 1 https://github.com/oyzuai/context ../context`, or `git -C ../context pull --ff-only` if it exists. Read `CONSTITUTION.md` and `INDEX.md` there, open the entries and skills your task touches, and print `context commit <sha>`.

Generic skills live in https://github.com/oyzuai/agent-workflows under `skills/`; clone it the same way when a task needs one. This repo's rules below add to the context; they never weaken the constitution's gates.

The Oyzu pool manager and executor. Preserve isolation, identity, access checks and the public runner contract. This repository targets `main`.

Load relevant entries, including [CI policy](https://github.com/oyzuai/context/blob/main/decisions/verification-execution.md), [branch model](https://github.com/oyzuai/context/blob/main/decisions/branch-model.md) and [documentation ownership](https://github.com/oyzuai/context/blob/main/rules/documentation-ownership.md).

For assigned implementation load [implement-item](https://github.com/oyzuai/agent-workflows/blob/main/skills/implement-item/SKILL.md); for intake load [write-brief](https://github.com/oyzuai/agent-workflows/blob/main/skills/write-brief/SKILL.md); for issue work load [classify-issues](https://github.com/oyzuai/agent-workflows/blob/main/skills/classify-issues/SKILL.md) and its catalog. These procedures grant no extra authority.

## Commands

Use Oyzu-managed tools; never install toolchains or fall back to host tools.

```sh
eval "$(oyzu activate bash)"
oyzu build --full
git diff --check
```

For instruction changes use the existing platform Node toolchain to run `node ../agent-workflows/checks/instructions.mjs . ../context ../agent-workflows` from this checkout; no additional Node pin or installation is required. The shared check enforces instruction budgets and duplicate paragraphs. Follow the actual CI policy above; report each result as it ran.
