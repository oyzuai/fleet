#!/usr/bin/env bash
# SessionStart loader. The context-guard wrapper records per-session state.
set -u
export GIT_TERMINAL_PROMPT=0
project_dir="${CLAUDE_PROJECT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
context_dir="$(dirname -- "$project_dir")/context"
error() {
  # SessionStart stdout enters the session; stderr also reaches the operator.
  printf 'ERROR: %s\n' "$*" >&2
  printf 'ERROR: %s\n' "$*"
}
# Name the first failing check so a blocked session says why, not just "FAILED".
refuse() { failure_reason="$*"; return 1; }
# A usable checkout is a clean main of oyzuai/context at its fetched origin/main.
prepare_checkout() {
  local dir="$1"
  if [ -e "$dir" ]; then
    git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { refuse "$dir is not a Git work tree"; return 1; }
    [ -z "$(git -C "$dir" rev-parse --show-prefix)" ] || { refuse "$dir is not the checkout root"; return 1; }
    [ "$(git -C "$dir" symbolic-ref --short HEAD 2>/dev/null)" = main ] || { refuse "$dir is not on branch main (detached or another branch)"; return 1; }
    case "$(git -C "$dir" config --get remote.origin.url 2>/dev/null)" in
      https://github.com/oyzuai/context|https://github.com/oyzuai/context.git|git@github.com:oyzuai/context.git) ;;
      *) refuse "$dir origin is not oyzuai/context"; return 1 ;;
    esac
    [ -z "$(git -C "$dir" status --porcelain)" ] || { refuse "$dir checkout has local changes"; return 1; }
    if git -C "$dir" pull --ff-only origin main >/dev/null 2>&1; then
      [ "$(git -C "$dir" rev-parse HEAD)" = "$(git -C "$dir" rev-parse refs/remotes/origin/main)" ] || { refuse "$dir HEAD differs from origin/main after pull"; return 1; }
    else
      # Offline or unreachable remote: a clean main checkout at its own last-fetched
      # origin/main is still the reviewed snapshot. Disclose it.
      [ "$(git -C "$dir" rev-parse HEAD)" = "$(git -C "$dir" rev-parse refs/remotes/origin/main 2>/dev/null)" ] || { refuse "$dir could not be refreshed and is not at its last fetched origin/main"; return 1; }
      printf 'WARNING: oyzuai/context could not be refreshed; using the cached clean main checkout at %s. Cached-reviewed offline use; refresh before relying on recent changes.\n' "$(git -C "$dir" rev-parse HEAD)"
    fi
  else
    mkdir -p "$(dirname -- "$dir")" 2>/dev/null
    git clone --quiet --branch main https://github.com/oyzuai/context.git "$dir" >/dev/null 2>&1 || { refuse "could not clone oyzuai/context into $dir"; return 1; }
  fi
}
load_context() {
  failure_reason=''
  if ! prepare_checkout "$context_dir"; then
    # The sibling checkout may be a worktree, detached, dirty or on another branch
    # (for example while someone edits context). Never reset or touch it; use a
    # private clean clone in the OS state directory instead and say so.
    sibling_reason="$failure_reason"
    case "$(uname -s 2>/dev/null)" in
      MINGW*|MSYS*|CYGWIN*) state_root="${LOCALAPPDATA:-$HOME/AppData/Local}" ;;
      Darwin) state_root="$HOME/Library/Application Support" ;;
      *) state_root="${XDG_STATE_HOME:-$HOME/.local/state}" ;;
    esac
    fallback_dir="$state_root/oyzu/context/checkout"
    if prepare_checkout "$fallback_dir"; then
      printf 'WARNING: sibling context checkout unusable (%s); loaded the private clean clone at %s instead. The sibling was not touched.\n' "$sibling_reason" "$fallback_dir"
      context_dir="$fallback_dir"
    else
      failure_reason="$sibling_reason; fallback: $failure_reason"
      return 1
    fi
  fi
  # Read one committed snapshot so the printed SHA identifies the actual text.
  commit="$(git -C "$context_dir" rev-parse HEAD)" || return 1
  constitution="$(git -C "$context_dir" show "$commit:CONSTITUTION.md" 2>/dev/null)" || return 1
  index="$(git -C "$context_dir" show "$commit:INDEX.md" 2>/dev/null)" || return 1
  client="${OYZU_CONTEXT_CLIENT:-claude}"
  case "$client" in codex) provider=codex ;; claude) provider=claude-code ;; *) return 1 ;; esac
  agreements="$(git -C "$context_dir" show "$commit:policy/working-agreements.md" 2>/dev/null)" || return 1
  profile="$(git -C "$context_dir" show "$commit:accounts/maintainer-profile.md" 2>/dev/null)" || return 1
  adapter="$(git -C "$context_dir" show "$commit:providers/$provider.md" 2>/dev/null)" || return 1
  printf '%s\n\n%s\n\n%s\n\n%s\n\n%s\n\ncontext commit %s\nContext root: %s\n' "$constitution" "$index" "$agreements" "$profile" "$adapter" "$commit" "$context_dir"
}

# Refresh the generic skill source separately: a context failure must not hide it.
load_skills() {
  workflows_dir="$(dirname -- "$project_dir")/agent-workflows"
  if [ "$project_dir" = "$workflows_dir" ]; then
    : # This repository is already the source checkout.
  elif [ -e "$workflows_dir" ]; then
    git -C "$workflows_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
    [ -z "$(git -C "$workflows_dir" rev-parse --show-prefix)" ] || return 1
    [ "$(git -C "$workflows_dir" symbolic-ref --short HEAD)" = main ] || return 1
    case "$(git -C "$workflows_dir" config --get remote.origin.url 2>/dev/null)" in
      https://github.com/oyzuai/agent-workflows|https://github.com/oyzuai/agent-workflows.git|git@github.com:oyzuai/agent-workflows.git) ;;
      *) return 1 ;;
    esac
    git -C "$workflows_dir" pull --ff-only origin main >/dev/null 2>&1 || return 1
  else
    git clone --quiet --branch main https://github.com/oyzuai/agent-workflows.git "$workflows_dir" >/dev/null 2>&1 || return 1
  fi
  mkdir -p "$project_dir/.claude/skills" || return 1
  # Context may also carry skills; generic procedures are owned by agent-workflows.
  for source_root in "$workflows_dir/skills" "$context_dir/skills" "$project_dir/.agents/skills"; do
    [ -d "$source_root" ] || continue
    for source in "$source_root"/*; do
      [ -f "$source/SKILL.md" ] || continue
      destination="$project_dir/.claude/skills/$(basename -- "$source")"
      if [ -L "$destination" ] && [ "$(readlink -- "$destination")" = "$source" ]; then
        continue
      fi
      # Do not overwrite a user's package or a link owned by another source.
      if [ -e "$destination" ] || [ -L "$destination" ]; then
        printf 'warning: skill collision at %s; preserving existing package.\n' "$destination" >&2
        continue
      fi
      ln -s -- "$source" "$destination" || return 1
    done
  done
  for checkout in "$context_dir" "$workflows_dir"; do
    timestamp="$(git -C "$checkout" log -1 --format=%ct 2>/dev/null)" || continue
    case "$timestamp" in ''|*[!0-9]*) continue ;; esac
    if [ "$(( $(date +%s) - timestamp ))" -gt 86400 ]; then
      printf 'warning: %s latest commit is more than a day old; verify freshness.\n' "$checkout" >&2
    fi
  done
  printf 'skills source commit %s\n' "$(git -C "$workflows_dir" rev-parse HEAD)"
}

context_status=0
load_context || { context_status=1; error "shared oyzuai/context could not be refreshed or loaded; context load FAILED${failure_reason:+ ($failure_reason)}. Check repository access and retry before relying on shared context."; }
load_skills || error 'shared skills could not be refreshed or linked; using existing skills. Check repository access and skill paths.'
exit "$context_status"
