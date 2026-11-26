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
load_context() {
  if [ -e "$context_dir" ]; then
    git -C "$context_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
    [ -z "$(git -C "$context_dir" rev-parse --show-prefix)" ] || return 1
    [ "$(git -C "$context_dir" symbolic-ref --short HEAD)" = main ] || return 1
    case "$(git -C "$context_dir" config --get remote.origin.url 2>/dev/null)" in
      https://github.com/oyzuai/context|https://github.com/oyzuai/context.git|git@github.com:oyzuai/context.git) ;;
      *) return 1 ;;
    esac
    [ -z "$(git -C "$context_dir" status --porcelain)" ] || return 1
    git -C "$context_dir" pull --ff-only origin main >/dev/null 2>&1 || return 1
    [ "$(git -C "$context_dir" rev-parse HEAD)" = "$(git -C "$context_dir" rev-parse refs/remotes/origin/main)" ] || return 1
  else
    git clone --quiet --branch main https://github.com/oyzuai/context.git "$context_dir" >/dev/null 2>&1 || return 1
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
load_context || { context_status=1; error 'shared oyzuai/context could not be refreshed or loaded; context load FAILED. Check repository access and retry before relying on shared context.'; }
load_skills || error 'shared skills could not be refreshed or linked; using existing skills. Check repository access and skill paths.'
exit "$context_status"
