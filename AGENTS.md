# Repository instructions

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

Maintainer decision (2026-10-25): do the task, run the tests that matter, and say
plainly whether they passed or failed; the command and pass/fail is enough. Keep
user-facing documentation up to date: whenever a change alters what users see or
do, update the existing user-facing docs in the same change. Don't write other
docs (status or qualification files, proof files, internal write-ups) or new
scripts unless the change needs them or the task asks. Keep PR descriptions short.
Clean up builds, workspaces, containers and images you created (never other
people's data) and say how much disk you used. Never skip signing, provenance,
access-control or compliance checks, and never hide a failure. Open PRs as drafts;
once the work is done and checked, mark the PR ready for review, and only then ask
Micah to look at it. Never ask him to review or check a draft. Where another rule
here asks for more, this one wins.
