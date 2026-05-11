#!/bin/bash
set -euo pipefail

input="$(cat)"
command="$(printf '%s' "$input" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("command",""))')"

if [[ "$command" =~ ^git\ commit ]]; then
  echo '{
    "permission":"ask",
    "user_message":"Run `make quality-gate` before committing to ensure lint and tests are green.",
    "agent_message":"Quality gate reminder triggered for commit command."
  }'
  exit 0
fi

echo '{ "permission": "allow" }'
