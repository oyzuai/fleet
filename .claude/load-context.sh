#!/usr/bin/env bash
# SessionStart: shared context is optional; repository work stays usable offline.
set -u
export GIT_TERMINAL_PROMPT=0
project_dir="${CLAUDE_PROJECT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
context_dir="$(dirname -- "$project_dir")/context"
warn() { printf '%s\n' 'warning: shared oyzuai/context could not be refreshed or loaded; continuing without shared context.' >&2; }
load_context() {
  if [ -e "$context_dir" ]; then
    git -C "$context_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 1
    [ -z "$(git -C "$context_dir" rev-parse --show-prefix)" ] || return 1
    [ "$(git -C "$context_dir" symbolic-ref --short HEAD)" = main ] || return 1
    case "$(git -C "$context_dir" config --get remote.origin.url 2>/dev/null)" in
      https://github.com/oyzuai/context|https://github.com/oyzuai/context.git|git@github.com:oyzuai/context.git) ;;
      *) return 1 ;;
    esac
    git -C "$context_dir" pull --ff-only origin main >/dev/null 2>&1 || return 1
  else
    git clone --quiet --branch main https://github.com/oyzuai/context.git "$context_dir" >/dev/null 2>&1 || return 1
  fi
  # Read one committed snapshot so the printed SHA identifies the actual text.
  commit="$(git -C "$context_dir" rev-parse HEAD)" || return 1
  constitution="$(git -C "$context_dir" show "$commit:CONSTITUTION.md" 2>/dev/null)" || return 1
  index="$(git -C "$context_dir" show "$commit:INDEX.md" 2>/dev/null)" || return 1
  printf '%s\n\n%s\n\ncontext commit %s\n' "$constitution" "$index" "$commit"
}
load_context || warn
exit 0
