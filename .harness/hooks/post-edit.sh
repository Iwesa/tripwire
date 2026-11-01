#!/usr/bin/env bash
# PostToolUse(Edit|Write|MultiEdit) - sensor: run the fast suite after any backend .py edit.
# Exit 2 sends the failure output back to Claude so it fixes it in the same turn.
input="$(cat)"
file="$(printf '%s' "$input" | python3 -c 'import sys,json; d=json.load(sys.stdin).get("tool_input",{}); print(d.get("file_path",""))' 2>/dev/null)"
case "$file" in
  */backend/*.py|*/backend/evals/*.json)
    root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
    out="$(cd "$root/backend" && python3 -m unittest discover -s tests -t . 2>&1)"
    if [ $? -ne 0 ]; then printf 'Tests failed after editing %s:\n%s\n' "$file" "$(printf '%s' "$out" | tail -40)" >&2; exit 2; fi
    ;;
esac
exit 0
