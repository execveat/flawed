#!/usr/bin/env bash
# PreToolUse hook: blocks direct pytest invocations.
# All test execution must go through mise. See CLAUDE.md "Quality Gate".
set -euo pipefail

COMMAND=$(jq -r '.tool_input.command // ""')

# Match direct pytest invocations but not mise-mediated ones.
# Catches: pytest, uv run pytest, python -m pytest, python3 -m pytest
# Ignores: mise run test (which internally calls uv run pytest)
# Works across && ; | chains and multiline commands.
if echo "$COMMAND" | grep -qE '(^|[;&|][[:space:]]*)(uv[[:space:]]+run[[:space:]]+|python3?[[:space:]]+-m[[:space:]]+)?pytest([[:space:]]|$)'; then
  # Show the blocked command for clarity
  blocked_cmd=$(echo "$COMMAND" | head -1 | cut -c1-80)
  cat >&2 <<EOF
BLOCKED: Direct pytest is forbidden. Use mise run test instead.

Your command:  ${blocked_cmd}
Correct form:  mise run test -- tests/unit/          # scoped
               mise run test -- -k 'pattern'         # filtered
               mise run test                         # all (incremental)
EOF
  exit 2
fi

exit 0
