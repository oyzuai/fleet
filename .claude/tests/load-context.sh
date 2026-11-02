#!/usr/bin/env bash
# Exercise the SessionStart loader offline with disposable source fixtures.
set -eu
hook="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/load-context.sh"
fixture="$(mktemp -d -t oyzu-loader-XXXXXX)"
trap 'rm -rf -- "$fixture"' EXIT
export CLAUDE_PROJECT_DIR="$fixture/project"
mkdir -p "$fixture/project/.agents/skills" "$fixture/context" "$fixture/agent-workflows/skills/coordinate-issues"
printf 'generic\n' > "$fixture/agent-workflows/skills/coordinate-issues/SKILL.md"
# The real oyzu collision sorts before these repo packages.
for name in coordinate-issues contract-change dependency-change docs-change publish-plugin release-cli rust-change; do
  mkdir -p "$fixture/project/.agents/skills/$name"
  printf '%s\n' "$name" > "$fixture/project/.agents/skills/$name/SKILL.md"
done
git() {
  local location="$2"
  shift 2
  case "$1" in
    rev-parse) case "$2" in --is-inside-work-tree) echo true ;; --show-prefix) echo ;; HEAD) echo fixture-sha ;; esac ;;
    symbolic-ref) echo main ;;
    config) case "$location" in */context) echo https://github.com/oyzuai/context.git ;; *) echo https://github.com/oyzuai/agent-workflows.git ;; esac ;;
    pull) [ "${FAIL_REFRESH:-0}" = 0 ] ;;
    show) echo "committed $2" ;;
    log) if [ "${OLD:-0}" = 1 ]; then echo 1; else date +%s; fi ;;
    *) return 1 ;;
  esac
}
export -f git
check_links() {
  [ "$(readlink "$CLAUDE_PROJECT_DIR/.claude/skills/coordinate-issues")" = "$fixture/agent-workflows/skills/coordinate-issues" ]
  [ "$(cat "$CLAUDE_PROJECT_DIR/.claude/skills/coordinate-issues/SKILL.md")" = generic ]
  for name in contract-change dependency-change docs-change publish-plugin release-cli rust-change; do
    [ -L "$CLAUDE_PROJECT_DIR/.claude/skills/$name" ]
    [ "$(cat "$CLAUDE_PROJECT_DIR/.claude/skills/$name/SKILL.md")" = "$name" ]
  done
}
bash "$hook" > "$fixture/out" 2> "$fixture/err"
grep -q 'context commit fixture-sha' "$fixture/out"
grep -q 'skills source commit fixture-sha' "$fixture/out"
grep -q 'skill collision' "$fixture/err"
check_links
# Repeat loading must still preserve precedence and discover every later package.
bash "$hook" > "$fixture/out" 2> "$fixture/err"
check_links
OLD=1 bash "$hook" > "$fixture/out" 2> "$fixture/err"
grep -q 'more than a day old' "$fixture/err"
FAIL_REFRESH=1 bash "$hook" > "$fixture/out" 2> "$fixture/err"
grep -q 'shared oyzuai/context could not' "$fixture/err"
grep -q 'shared skills could not' "$fixture/err"
check_links
# An existing user-owned directory also stays intact without blocking later links.
rm -- "$CLAUDE_PROJECT_DIR/.claude/skills/coordinate-issues"
mkdir "$CLAUDE_PROJECT_DIR/.claude/skills/coordinate-issues"
printf 'user-owned\n' > "$CLAUDE_PROJECT_DIR/.claude/skills/coordinate-issues/SKILL.md"
bash "$hook" > "$fixture/out" 2> "$fixture/err"
grep -q 'skill collision' "$fixture/err"
[ "$(cat "$CLAUDE_PROJECT_DIR/.claude/skills/coordinate-issues/SKILL.md")" = user-owned ]
for name in contract-change dependency-change docs-change publish-plugin release-cli rust-change; do
  [ -L "$CLAUDE_PROJECT_DIR/.claude/skills/$name" ]
done
printf '%s\n' 'PASS: discovery, collision continuation/precedence, repeat load, stale warning, offline continuation, user-package preservation'
