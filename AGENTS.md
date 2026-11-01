# Repository instructions

## Issue taxonomy

Before creating, splitting, transferring or reclassifying an issue in any
`oyzuai` repository, read and apply the shared
[`classify-issues` skill](https://github.com/oyzuai/agent-workflows/blob/main/skills/classify-issues/SKILL.md) and its bundled
[taxonomy catalog](https://github.com/oyzuai/agent-workflows/blob/main/skills/classify-issues/references/taxonomy.json).
Explicitly fetch these files with repository tools if the skill is not installed;
a link is not an automatic import. Apply exactly one `type:*` and one or two
`area:*` labels, with relevant optional ecosystem, surface, host and concern
labels. Leave priority unset without recorded triage. Preserve `agent:*` and
other workflow labels; read back the issue to verify classification. Keep the
vocabulary in the shared catalog rather than copying it into this repository.
This applies only to authorized issue work and grants no additional authority.

## Verification execution policy

Maintainer decision (2026-10-25): GitHub Actions is enabled again, on the
self-hosted Linux runners of the OVH build server. This supersedes the
2026-10-24 pause. oyzuai/oyzu's Linux jobs run there in a fresh container per
job (`oyzu-wsl` for pull requests and branches, `oyzu-main` for main); the
server is configured in the platform repository's `deploy/ovh-farm`.

- Workflows run on push, pull request, schedule and dispatch as their
  definitions say. Use their results together with the applicable bounded local
  checks and real user-flow proofs. Record the revision, run and result; report
  a failed, skipped or not-run check as exactly that, never as passed.
- GitHub-hosted runners stay off by default. Leave `OYZU_HOSTED_RUNNERS` unset,
  and run a hosted-only job (macOS, Windows, release, signing, toolchain images)
  only with Micah's approval for that run.
- Don't move CI back onto the desktop's WSL runner, change runner counts or
  labels outside `deploy/ovh-farm`, or arrange other paid or cloud CI without
  Micah's approval.
- Preserve required safety, trust/compliance checks, observed failures and
  honest platform coverage. Do not silently change branch protection or
  merge/approval authority.
- Carry this policy into coordinator/worker briefs and relay it to existing
  workers; editing a file does not prove running sessions reloaded it.

## Be practical

Follow the shared [finite acceptance contract](https://github.com/oyzuai/agent-workflows/blob/main/policy/working-agreements.md#finite-acceptance-contract): agree the outcome, required evidence and non-goals; advance the next failing user scenario or binding safeguard; ask before expanding scope. Keep first-proof inputs stable, rerun only invalidated evidence, and give milestone/blocker updates with no more than an hour of silence during active work. Format and run applicable lightweight checks before meaningful commits.

Keep permanent docs about supported behavior, limitations and reproducible configuration; put run-specific receipts, temporary paths and chronology in PR evidence. Preserve required isolation, enforced egress, access control, secret handling, signing, provenance, compliance and repository checks. Clean only task-owned disposable output. Use draft PRs, complete independent review and required checks before marking ready, and never merge or approve your own change. This delivery order does not waive the tool, schema, CI or security rules below.

## Branches and throughput

Maintainer decision (2026-11-01). This replaces the earlier trunk-based rule of the same day.

- **This repository merges to `main`.** Merge once the change is verified locally and rebased on main's tip. A commit that breaks main is reverted within minutes unless a fix is already in flight. (oyzuai/oyzu integrates on `dev` and promotes `main` only to cut a release; see its AGENTS.md.)
- **Short-lived branches, unfinished work behind a gate.** Each branch holds one coherent change and merges within about a day. Land incomplete work behind an internal, off-by-default gate. A gate is not a new user setting. Remove the gate when the feature ships.
- **Keep every agent slot busy.** Refill a Codex slot as soon as its row finishes, following the maintainers' coordination runbook. Give each row a whole task with a concrete definition of done.
