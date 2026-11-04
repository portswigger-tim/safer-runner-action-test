#!/usr/bin/env bash
# safer-runner v2 real-runner checks. usage: checks.sh <must-pass|must-fail|analyze|strict>
set -u
cd "$(dirname "$0")/.."
source v2test/lib.sh

must_pass() {
  local code issuer out
  record ctx.os INFO "$(. /etc/os-release; echo "$PRETTY_NAME") $(uname -r); $(sudo --version 2>/dev/null | head -1)"
  out=$(jq -c . /var/log/safer-runner/selftest.json 2>&1)
  jq -e 'length == 2 and all(.ok)' /var/log/safer-runner/selftest.json >/dev/null 2>&1
  pass_if S.action-selftests $? "$out"

  for v in NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA REQUESTS_CA_BUNDLE PIP_CERT SSL_CERT_FILE GIT_SSL_CAINFO AWS_CA_BUNDLE CURL_CA_BUNDLE; do
    [ -n "${!v:-}" ] || { record A.env FAIL "$v not exported to later steps"; return; }
  done
  record A.env PASS "CA env vars exported via GITHUB_ENV (NODE_EXTRA_CA_CERTS=$NODE_EXTRA_CA_CERTS)"

  code=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' https://api.github.com/zen 2>&1)
  issuer=$(echo | timeout 15 openssl s_client -connect api.github.com:443 -servername api.github.com 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
  [ "$code" = 200 ] && grep -q safer-runner <<<"$issuer"
  pass_if A.curl $? "https://api.github.com/zen -> $code, cert $issuer"

  rm -rf /tmp/hw
  out=$(git clone -q --depth 1 https://github.com/octocat/Hello-World.git /tmp/hw 2>&1)
  pass_if A.git-clone $? "${out:-cloned $(git -C /tmp/hw rev-parse --short HEAD 2>/dev/null)}"

  out=$(node -e 'fetch("https://github.com/robots.txt").then(r=>{console.log(r.status);process.exit(r.status==200?0:1)}).catch(e=>{console.log(String(e.cause||e));process.exit(1)})' 2>&1)
  pass_if A.node-fetch $? "node $(node --version): $out"

  out=$(python3 -c "import urllib.request as u;print(u.urlopen('https://github.com/robots.txt',timeout=20).status)" 2>&1)
  pass_if A.python-urllib $? "$(tail -1 <<<"$out")"

  rm -rf /tmp/venv
  out=$( { python3 -m venv /tmp/venv && /tmp/venv/bin/pip install -q requests && /tmp/venv/bin/python -c "import requests;print(requests.get('https://github.com/robots.txt',timeout=20).status_code)"; } 2>&1)
  pass_if A.pip-requests $? "pip install via PIP_CERT + requests via REQUESTS_CA_BUNDLE: $(tail -1 <<<"$out")"

  out=$(npm view left-pad version 2>&1)
  pass_if A.npm $? "npm view left-pad -> $(tail -1 <<<"$out")"

  mkdir -p /tmp/j && cat > /tmp/j/Main.java <<'J'
public class Main { public static void main(String[] a) throws Exception {
  var c = java.net.http.HttpClient.newHttpClient();
  var r = c.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create("https://github.com/robots.txt")).build(),
                 java.net.http.HttpResponse.BodyHandlers.discarding());
  System.out.println(r.statusCode()); System.exit(r.statusCode() == 200 ? 0 : 1); } }
J
  out=$(timeout 120 java /tmp/j/Main.java 2>&1)
  pass_if A.java $? "java ($JAVA_HOME): $(tail -1 <<<"$out")"

  out=$(timeout 120 docker pull -q alpine:3.20 2>&1); record A.docker-pull INFO "rc=$? $(tail -1 <<<"$out")"
}

must_fail() {
  local OBJ_IP GH_IP m out rc rec
  OBJ_IP=$(ip4 objects.githubusercontent.com); GH_IP=$(ip4 github.com)
  record ctx.ips INFO "objects.githubusercontent.com=$OBJ_IP github.com=$GH_IP attacker=$ATTACKER_IP"

  expect_blocked C3.resolve-cotenant "curl --resolve octocat.github.io:443:$OBJ_IP (shared GitHub Pages/objects IP)" \
    '.ev=="tls" and .sni=="octocat.github.io" and .layer=="sni" and .verdict=="BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "octocat.github.io:443:$OBJ_IP" https://octocat.github.io/
  expect_blocked C3.resolve-attacker-k "curl -k --resolve evil.example.com:443:$GH_IP" \
    '.ev=="tls" and .sni=="evil.example.com" and .layer=="sni" and .verdict=="BLOCK"' \
    curl -k -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "evil.example.com:443:$GH_IP" https://evil.example.com/

  never_reached E.sni-spoof-repoint "allowed SNI pipelines.actions.githubusercontent.com dialled at attacker IP" "$ATTACKER_IP" \
    curl -k -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "pipelines.actions.githubusercontent.com:443:$ATTACKER_IP" https://pipelines.actions.githubusercontent.com/
  never_reached F.http-host-spoof-repoint "plain HTTP Host: api.github.com dialled at attacker IP" "$ATTACKER_IP" \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' -H 'Host: api.github.com' "http://$ATTACKER_IP/"

  expect_blocked G.fronting-evil "https://github.com/ with Host: evil.example.com" \
    '.ev=="https" and .reason=="host-sni-mismatch" and .verdict=="BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' -H 'Host: evil.example.com' https://github.com/
  expect_blocked G.fronting-allowed "https://github.com/ with Host: api.github.com (both allowed, Host!=SNI)" \
    '.ev=="https" and .reason=="host-sni-mismatch" and .host=="api.github.com"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' -H 'Host: api.github.com' https://github.com/

  expect_blocked I.ip-literal-tls "https://$ATTACKER_IP/" \
    ".ev==\"tls\" and .layer==\"sni\" and .verdict==\"BLOCK\" and (.dst|startswith(\"$ATTACKER_IP:\"))" \
    curl -k -sS -m 15 -o /dev/null -w '%{http_code}' "https://$ATTACKER_IP/"
  expect_blocked I.no-sni "openssl s_client -noservername to github.com ($GH_IP)" \
    '.ev=="tls" and .reason=="no-sni" and .verdict=="BLOCK"' \
    bash -c "openssl s_client -connect $GH_IP:443 -noservername </dev/null 2>&1 | grep -q 'BEGIN CERTIFICATE'"
  expect_blocked H.http-attacker-ip "http://$ATTACKER_IP/ (IP-literal Host)" \
    '.ev=="http" and .verdict=="BLOCK" and .reason=="ip-literal-host"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' "http://$ATTACKER_IP/"
  expect_blocked H.http-disallowed-host "http://example.org/ (resolved to attacker IP by the client)" \
    '.ev=="http" and .verdict=="BLOCK" and .host=="example.org"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "example.org:80:$ATTACKER_IP" http://example.org/

  out=$(curl -sS -m 15 -o /dev/null https://example.org/ 2>&1); rc=$?
  [ $rc -ne 0 ]; pass_if D.dns-refused-https "https://example.org (not allowlisted) -> rc=$rc '${out: -80}'"

  # A hole punched in the REDIRECT must still be stopped by the filter REJECT (fail closed).
  m=$(mark)
  sudo iptables -t nat -I SAFER_RUNNER_NAT 1 -d "$ATTACKER_IP/32" -j RETURN
  out=$(curl -k -sS -m 8 -o /dev/null -w '%{http_code}' "https://$ATTACKER_IP/" 2>&1); rc=$?
  sudo iptables -t nat -D SAFER_RUNNER_NAT 1
  sleep 0.5; rec=$(flows_q "$m" "(.dst // \"\" | startswith(\"$ATTACKER_IP:\"))" | head -1)
  [ $rc -ne 0 ] && [ -z "$rec" ]
  pass_if B.fail-closed-hole "REDIRECT bypassed for $ATTACKER_IP (proxy never saw it) -> rc=$rc '${out: -80}'"

  out=$(timeout 8 bash -c "echo > /dev/tcp/$ATTACKER_IP/853" 2>&1); rc=$?
  [ $rc -ne 0 ]; pass_if B.non-http-port "tcp $ATTACKER_IP:853 (DoT) -> rc=$rc ${out: -60}"
  out=$(curl -6 -sS -m 8 -o /dev/null 'https://[2606:4700:4700::1111]/' 2>&1); rc=$?
  [ $rc -ne 0 ]; pass_if B.ipv6 "IPv6 literal -> rc=$rc ${out: -60}"

  for r in 168.63.129.16 8.8.8.8 127.0.0.53; do
    out=$(dig +short +time=3 +tries=1 "@$r" example.org A 2>&1)
    if grep -qE '^[0-9]+\.' <<<"$out"; then record "DNS.direct-$r" FAIL "dig @$r example.org -> $out"; else
      record "DNS.direct-$r" PASS "dig @$r example.org -> '${out:-<no answer>}' (answered by our dnsmasq)"; fi
  done
  out=$(dig +short +time=3 +tries=1 @168.63.129.16 api.github.com A 2>&1)
  record DNS.allowed-via-azure INFO "dig @168.63.129.16 api.github.com -> $(tr '\n' ' ' <<<"$out")"
  grep -q 'query\[A\] example.org' /var/log/safer-runner/dns.log
  pass_if DNS.redirected-to-dnsmasq $? "dnsmasq logged the direct-IP queries for example.org"

  rec=$(jq -c 'select(.ev=="tls" and .layer=="sni" and .verdict=="BLOCK")' "$FLOWLOG" | wc -l)
  [ "$rec" -gt 0 ]; pass_if S.sni-layer-block-fired "$rec SNI-layer BLOCK records (enforcement happened at the ClientHello, not only Host)"
}

analyze() {
  local out rc m rec
  m=$(mark)
  out=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.org/ 2>&1)
  sleep 0.5; rec=$(flows_q "$m" '.ev=="tls" and .sni=="example.org" and .verdict=="WOULD_BLOCK" and .passthrough==true' | head -1)
  [ "$out" = 200 ] && [ -n "$rec" ]
  pass_if Z.not-allowlisted-works "https://example.org -> $out (passed through by SNI, logged WOULD_BLOCK): $rec"
  m=$(mark)
  out=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -H 'Host: api.github.com' https://github.com/ 2>&1)
  sleep 0.5; rec=$(flows_q "$m" '.ev=="https" and .reason=="host-sni-mismatch" and .verdict=="WOULD_BLOCK"' | head -1)
  [ -n "$rec" ]; pass_if Z.fronting-logged "fronting in analyze -> $out, logged: $rec"
  out=$(dig +short +time=3 +tries=1 @8.8.8.8 example.org A 2>&1)
  grep -q 'query\[A\] example.org' /var/log/safer-runner/dns.log
  pass_if Z.dns-redirected "dig @8.8.8.8 answered via dnsmasq: $(tr '\n' ' ' <<<"$out")"
}

strict() {
  local out
  out=$(sudo -n true 2>&1); [ $? -ne 0 ]
  pass_if P.sudo-disabled "sudo -n true -> ${out: -100}"
  out=$(docker ps 2>&1); [ $? -ne 0 ]
  pass_if P.docker-disabled "docker ps -> ${out: -100}"
  out=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' https://api.github.com/zen 2>&1)
  [ "$out" = 200 ]; pass_if A.curl "api.github.com -> $out"
  local OBJ_IP; OBJ_IP=$(ip4 objects.githubusercontent.com)
  expect_blocked C3.resolve-cotenant "curl --resolve octocat.github.io:443:$OBJ_IP" \
    '.ev=="tls" and .sni=="octocat.github.io" and .verdict=="BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "octocat.github.io:443:$OBJ_IP" https://octocat.github.io/
}

"${1//-/_}"
