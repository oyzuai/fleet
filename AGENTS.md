# fleet

The Oyzu pool manager and executor. Preserve isolation, identity, access checks and the public runner contract. This repository targets `main`.

Read the shared [constitution](https://github.com/oyzuai/context/blob/main/CONSTITUTION.md) and [index](https://github.com/oyzuai/context/blob/main/INDEX.md) at session start and record the context commit. Load relevant entries, including [CI policy](https://github.com/oyzuai/context/blob/main/decisions/verification-execution.md), [branch model](https://github.com/oyzuai/context/blob/main/decisions/branch-model.md) and [documentation ownership](https://github.com/oyzuai/context/blob/main/rules/documentation-ownership.md).

For assigned implementation load [implement-item](https://github.com/oyzuai/agent-workflows/blob/main/skills/implement-item/SKILL.md); for intake load [write-brief](https://github.com/oyzuai/agent-workflows/blob/main/skills/write-brief/SKILL.md); for issue work load [classify-issues](https://github.com/oyzuai/agent-workflows/blob/main/skills/classify-issues/SKILL.md) and its catalog. These procedures grant no extra authority.

## Commands

Use Oyzu-managed tools; never install toolchains or fall back to host tools.

```sh
eval "$(oyzu activate bash)"
oyzu build --full
git diff --check
```

For instruction changes use the existing platform Node toolchain to run `node ../agent-workflows/checks/instructions.mjs . ../context ../agent-workflows` from this checkout; no additional Node pin or installation is required. The shared check enforces instruction budgets and duplicate paragraphs. Follow the actual CI policy above; report each result as it ran.

## Standing authorization for draft pull requests

Proactively commit and push the current task's scoped changes to a task branch and open a draft PR without asking for additional user permission.
