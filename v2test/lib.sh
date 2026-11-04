# Helpers for the safer-runner v2 real-runner suite. Source me.
RESULTS="${RUNNER_TEMP:-/tmp}/v2-results.tsv"
FLOWLOG=/var/log/safer-runner/proxy-flows.jsonl
# Stand-in "attacker" IP: a real, always-up HTTPS/HTTP server that is NOT on any allowlist.
ATTACKER_IP=1.1.1.1

# record <id> <PASS|FAIL|INFO> <detail>
record() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RESULTS"
  echo "[$2] $1 :: $3"
}
pass_if() { # pass_if <id> <condition-exit-code> <detail>
  if [ "$2" -eq 0 ]; then record "$1" PASS "$3"; else record "$1" FAIL "$3"; fi
}

# api.github.com/zen, authenticated: unauthenticated calls hit GitHub's per-IP rate limit (403)
# on shared runner egress IPs. curl args (e.g. -o/-w) are passed through.
gh_zen() { curl -sS -m 20 -H "Authorization: Bearer ${GH_TOKEN:-}" "$@" https://api.github.com/zen; }

ip4() { getent ahostsv4 "$1" | awk '{print $1; exit}'; }
mark() { wc -c < "$FLOWLOG"; }
flows_since() { tail -c +"$(( $1 + 1 ))" "$FLOWLOG"; }
# jq filter over flow records written since a mark
flows_q() { flows_since "$1" | jq -c "select($2)" 2>/dev/null; }

# expect_blocked <id> <desc> <jq-select-for-block-record> <cmd...>
# PASS iff the command fails or returns 403 AND the proxy logged a matching BLOCK record.
expect_blocked() {
  local id=$1 desc=$2 sel=$3; shift 3
  local m out rc rec; m=$(mark)
  out=$("$@" 2>&1); rc=$?
  sleep 0.5
  rec=$(flows_q "$m" "$sel" | head -1)
  if { [ $rc -ne 0 ] || [ "${out: -3}" = 403 ]; } && [ -n "$rec" ]; then
    record "$id" PASS "$desc -> refused (rc=$rc out='${out: -80}'); $rec"
  else
    record "$id" FAIL "$desc -> rc=$rc out='${out: -120}'; proxy record: ${rec:-<none>}"
  fi
}

# never_reached <id> <desc> <ip> <cmd...>: PASS iff the proxy never opened a server connection to <ip>
never_reached() {
  local id=$1 desc=$2 ip=$3; shift 3
  local m out rc hit seen; m=$(mark)
  out=$("$@" 2>&1); rc=$?
  sleep 0.5
  hit=$(flows_q "$m" ".ev==\"server-connect\" and (.peername // \"\" | startswith(\"$ip:\"))" | head -1)
  seen=$(flows_q "$m" "(.dst // \"\" | startswith(\"$ip:\"))" | head -1)
  if [ -z "$hit" ] && [ -n "$seen" ]; then
    record "$id" PASS "$desc -> attacker IP $ip never contacted (client dialled it; rc=$rc '${out: -60}'); $seen"
  else
    record "$id" FAIL "$desc -> reached=${hit:-no} seen=${seen:-<no record of the dialled IP>} rc=$rc"
  fi
}

finish() {
  echo "=== RESULTS"; column -t -s $'\t' "$RESULTS" || cat "$RESULTS"
  {
    echo "## v2 suite: $1"
    echo '| id | result | detail |'; echo '|---|---|---|'
    sed 's/|/\\|/g' "$RESULTS" | awk -F'\t' '{print "| "$1" | "$2" | "$3" |"}'
  } >> "$GITHUB_STEP_SUMMARY"
  if grep -q $'\tFAIL\t' "$RESULTS"; then echo "::error::$(grep -c $'\tFAIL\t' "$RESULTS") check(s) failed"; exit 1; fi
}

# expect_upstream_refused <id> <desc> <forbidden-ip-or-empty> <jq-select> <cmd...>
# PASS iff the request did not succeed (curl error or non-2xx/3xx), the proxy logged a matching
# record (the upstream IP guard), and it never opened a server connection to <forbidden-ip>.
expect_upstream_refused() {
  local id=$1 desc=$2 ip=$3 sel=$4; shift 4
  local m out rc rec hit=""; m=$(mark)
  out=$("$@" 2>&1); rc=$?
  sleep 0.5
  rec=$(flows_q "$m" "$sel" | head -1)
  [ -n "$ip" ] && hit=$(flows_q "$m" ".ev==\"server-connect\" and (.peername // \"\" | startswith(\"$ip:\"))" | head -1)
  if { [ $rc -ne 0 ] || ! [[ "${out: -3}" =~ ^[23][0-9][0-9]$ ]]; } && [ -n "$rec" ] && [ -z "$hit" ]; then
    record "$id" PASS "$desc -> refused (rc=$rc out='${out: -80}'); $rec"
  else
    record "$id" FAIL "$desc -> rc=$rc out='${out: -120}'; guard record: ${rec:-<none>}; reached: ${hit:-no}"
  fi
}

