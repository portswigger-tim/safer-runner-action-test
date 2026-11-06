# Helpers for the safer-runner real-runner suite. Source me.
RESULTS="${RUNNER_TEMP:-/tmp}/safer-runner-results.tsv"
FLOWLOG=/var/log/safer-runner/proxy-flows.jsonl
# Stand-in "attacker" IP: a real, always-up HTTPS/HTTP server that is NOT on any allowlist.
ATTACKER_IP=1.1.1.1

# record <id> <PASS|FAIL|INFO> <detail>
# Newlines/tabs in the detail (e.g. a curl error followed by -w output) would split the TSV row
# and the summary table, so they are flattened to spaces.
record() {
  local detail=${3//[$'\n\r\t']/ }
  printf '%s\t%s\t%s\n' "$1" "$2" "$detail" >> "$RESULTS"
  echo "[$2] $1 :: $detail"
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

# Refused names in GitHub's zones (DNS + proxy), minus the suite's own probes: a name the
# exact-by-default GitHub list misses shows up here (e.g. a bare apex) before it breaks a job.
github_refusals() {
  local zones='(^|\.)(github\.com|githubusercontent\.com|githubapp\.com|ghcr\.io|blob\.core\.windows\.net)$'
  local probes='^(srst-?|[swc][0-9a-f]{20}\.|c[0-9]+\.github\.com$|gist\.|raw\.githubusercontent)'
  local names
  names=$( { grep -oE ' (BLOCK|WOULD_BLOCK) [A-Z]+ [^ ]+' /var/log/safer-runner/dns.log 2>/dev/null | awk '{print $3}' | sed 's/\.$//'
             jq -r 'select((.verdict=="BLOCK" or .verdict=="WOULD_BLOCK") and (.reason=="sni-not-allowed" or .reason=="host-not-allowed")) | (.sni // .host // empty)' "$FLOWLOG" 2>/dev/null; } \
           | tr 'A-Z' 'a-z' | grep -E "$zones" | grep -vE "$probes" | sort | uniq -c | sort -rn | head -20 | awk '{printf "%s(%s) ", $2, $1}' || true)
  if [ -z "$names" ]; then record G.github-refusals PASS "no refused names in GitHub zones (DNS or proxy)"
  else record G.github-refusals INFO "REFUSED in GitHub zones: $names"; fi
}

finish() {
  github_refusals
  echo "=== RESULTS"; column -t -s $'\t' "$RESULTS" || cat "$RESULTS"
  {
    echo "## safer-runner suite: $1"
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


# expect_passed <id> <desc> <jq-select-for-record> <cmd...>
# PASS iff the proxy logged a matching record that is not a BLOCK and the response did not come
# from the proxy's refusal (403 + x-safer-runner: blocked). For http-filter allow decisions.
expect_passed() {
  local id=$1 desc=$2 sel=$3; shift 3
  local m out rc rec; m=$(mark)
  out=$("$@" 2>&1); rc=$?
  sleep 0.5
  rec=$(flows_q "$m" "($sel) and .verdict != \"BLOCK\"" | head -1)
  if [ -n "$rec" ] && ! grep -qi 'x-safer-runner: blocked' <<<"$out"; then
    record "$id" PASS "$desc -> passed (rc=$rc out='${out: -60}'); $rec"
  else
    record "$id" FAIL "$desc -> rc=$rc out='${out: -120}'; proxy record: $(flows_q "$m" "$sel" | head -1)"
  fi
}

# render_report: run the action's own post-step reporter now, with the job's inputs, into
# $REPORT, so a step can assert on the summary the real post step will publish at job end.
# (All it changes is deleting the CA key on disk early; the running proxy keeps it in memory.)
render_report() {
  local js
  js=$(ls -d "$RUNNER_WORKSPACE"/../_actions/portswigger-tim/safer-runner-action/*/dist/post/index.js 2>/dev/null | head -1)
  REPORT="${RUNNER_TEMP:-/tmp}/safer-runner-report.md"; : > "$REPORT"
  [ -n "$js" ] || { record report.render FAIL "action post bundle not found under _actions"; return 1; }
  env "INPUT_ALLOWED-DOMAINS=${ALLOWED:-}" "INPUT_PASSTHROUGH-DOMAINS=${PASSTHROUGH:-}" \
    GITHUB_STEP_SUMMARY="$REPORT" node "$js" > "${REPORT%.md}.log" 2>&1
  [ -s "$REPORT" ] || { record report.render FAIL "no report written: $(tail -3 "${REPORT%.md}.log")"; return 1; }
}

# report_has <id> <fixed-string> <desc>: PASS iff the rendered report contains the string
report_has() {
  grep -qF -- "$2" "$REPORT"; pass_if "$1" $? "$3 (report contains '$2')"
}
