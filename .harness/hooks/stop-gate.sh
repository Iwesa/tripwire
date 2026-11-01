#!/usr/bin/env bash
# Stop - definition-of-done gate. Claude cannot finish a turn with a red suite.
# stop_hook_active guards against an infinite block loop.
input="$(cat)"
active="$(printf '%s' "$input" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("stop_hook_active", False))' 2>/dev/null)"
[ "$active" = "True" ] && exit 0
root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
out="$(cd "$root/backend" && python3 -m unittest discover -s tests -t . 2>&1)"
if [ $? -ne 0 ]; then printf 'Cannot stop: test suite is red.\n%s\n' "$(printf '%s' "$out" | tail -40)" >&2; exit 2; fi
exit 0
