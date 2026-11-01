#!/usr/bin/env bash
# PreToolUse(Bash) - deterministic guard. Exit 2 = BLOCK and feed the reason back to Claude.
# Why a hook and not a CLAUDE.md line: instructions are advice, hooks are enforcement.
input="$(cat)"
cmd="$(printf '%s' "$input" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))' 2>/dev/null)"
python3 - "$cmd" <<'PY'
import re, sys
cmd = sys.argv[1]
RULES = [
    (r"rm\s+-rf?\s+(/|~|\$HOME)(\s|$)", "destructive rm on / or home"),
    (r"git\s+push\s+.*(--force|-f\b)", "no force pushes"),
    (r"\b(cat|less|more|head|tail|source|bat)\s+[^|;&]*\.env(\s|$)", "do not read .env (secrets) - use .env.example"),
    (r"\b(printenv|env)\s*($|[|;&])", "do not dump the environment (secrets)"),
    (r"echo\s+\$\{?(PAYPAL|ANTHROPIC)\w*", "do not echo secrets"),
    # Tripwire invariant: SANDBOX ONLY. Any live PayPal host is forbidden.
    (r"(^|[^\w.-])(api-m|api)\.paypal\.com", "LIVE PayPal host referenced - this project is sandbox-only"),
    (r"curl[^|;&]*\|\s*(ba)?sh", "no curl | sh"),
]
for rx, why in RULES:
    if re.search(rx, cmd):
        sys.stderr.write(f"BLOCKED by guard-bash: {why}\n")
        sys.exit(2)
PY
exit $?
