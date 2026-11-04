#!/usr/bin/env bash
# safer-runner v2 real-runner checks.
# usage: checks.sh <must-pass|must-fail|sudo-must-fail|ssrf|analyze|strict|privilege-removed|privilege-retained|baseline>
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

  code=$(gh_zen -o /dev/null -w '%{http_code}' 2>&1)
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

  out=$(timeout 120 docker pull -q alpine:3.20 2>&1); record A.docker-pull INFO "rc=$? $(tail -1 <<<"$out" | cut -c1-160)"

  # ~300 MiB of a GitHub release asset through the MITM (single stream, informational)
  out=$(curl -sS -L -m 120 -r 0-314572799 -o /dev/null -w '%{size_download} %{time_total}' \
    'https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz' 2>&1)
  record D.throughput-mitm INFO "$(awk '{ if ($2>0) printf "%.0f MiB in %.1fs = %.0f MiB/s", $1/1048576, $2, $1/1048576/$2; else print }' <<<"$out")"
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
  [ $rc -ne 0 ]; pass_if D.dns-refused-https $? "https://example.org (not allowlisted) -> rc=$rc '${out: -80}'"

  out=$(timeout 8 bash -c "echo > /dev/tcp/$ATTACKER_IP/853" 2>&1); rc=$?
  [ $rc -ne 0 ]; pass_if B.non-http-port $? "tcp $ATTACKER_IP:853 (DoT) -> rc=$rc ${out: -60}"
  out=$(curl -6 -sS -m 8 -o /dev/null 'https://[2606:4700:4700::1111]/' 2>&1); rc=$?
  [ $rc -ne 0 ]; pass_if B.ipv6 $? "IPv6 literal -> rc=$rc ${out: -60}"

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
  [ "$rec" -gt 0 ]; pass_if S.sni-layer-block-fired $? "$rec SNI-layer BLOCK records (enforcement happened at the ClientHello, not only Host)"
}

# Needs sudo: only meaningful in the advisory job (enforce + disable-sudo: false).
sudo_must_fail() {
  local m out rc rec t0 code
  # A hole punched in the REDIRECT must still be stopped by the filter REJECT (fail closed).
  m=$(mark)
  sudo iptables -t nat -I SAFER_RUNNER_NAT 1 -d "$ATTACKER_IP/32" -j RETURN
  out=$(curl -k -sS -m 8 -o /dev/null -w '%{http_code}' "https://$ATTACKER_IP/" 2>&1); rc=$?
  sudo iptables -t nat -D SAFER_RUNNER_NAT 1
  sleep 0.5; rec=$(flows_q "$m" "(.dst // \"\" | startswith(\"$ATTACKER_IP:\"))" | head -1)
  [ $rc -ne 0 ] && [ -z "$rec" ]
  pass_if B.fail-closed-hole $? "REDIRECT bypassed for $ATTACKER_IP (proxy never saw it) -> rc=$rc '${out: -80}'"

  # H1, addon layer alone: /etc/hosts makes the PROXY resolve allowlisted names to internal
  # addresses without dnsmasq (whose stop-dns-rebind would otherwise refuse them first). The
  # client dials a public IP, so the only thing that can refuse is the proxy's IP guard.
  printf '169.254.169.254 imds-hosts.nip.io\n127.0.0.1 lo-hosts.nip.io\n10.0.0.1 rfc1918-hosts.nip.io\nfd00::1 ula-hosts.nip.io\n169.254.169.254 pt-hosts.sslip.io\n' | sudo tee -a /etc/hosts >/dev/null
  local n ip
  for pair in imds-hosts:169.254.169.254 lo-hosts:127.0.0.1 rfc1918-hosts:10.0.0.1; do
    n="${pair%%:*}.nip.io"; ip="${pair#*:}"
    expect_upstream_refused "H1.guard-http-$ip" "proxy resolves $n -> $ip (/etc/hosts); plain HTTP dialled at $ATTACKER_IP" "$ip" \
      ".ev==\"upstream\" and .host==\"$n\" and .verdict==\"BLOCK\" and .reason==\"upstream-ip-forbidden\"" \
      curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Metadata: true' --resolve "$n:80:$ATTACKER_IP" "http://$n/metadata/instance?api-version=2021-02-01"
    expect_upstream_refused "H1.guard-https-$ip" "proxy resolves $n -> $ip (/etc/hosts); HTTPS (intercept) dialled at $ATTACKER_IP" "$ip" \
      ".ev==\"upstream\" and .host==\"$n\" and .verdict==\"BLOCK\"" \
      curl -k -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "$n:443:$ATTACKER_IP" "https://$n/"
  done
  expect_upstream_refused "H1.guard-passthrough-imds" "proxy resolves passthrough name pt-hosts.sslip.io -> 169.254.169.254 (/etc/hosts)" 169.254.169.254 \
    '.ev=="upstream" and .host=="pt-hosts.sslip.io" and .verdict=="BLOCK" and .reason=="upstream-ip-forbidden"' \
    curl -k -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "pt-hosts.sslip.io:443:$ATTACKER_IP" https://pt-hosts.sslip.io/
  expect_upstream_refused "H1.guard-ula" "proxy resolves ula-hosts.nip.io -> fd00::1 (/etc/hosts)" "" \
    '.ev=="upstream" and .host=="ula-hosts.nip.io" and .verdict=="BLOCK" and .reason=="upstream-ip-forbidden"' \
    curl -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "ula-hosts.nip.io:80:$ATTACKER_IP" http://ula-hosts.nip.io/
  sudo sed -i '/-hosts\.\(nip\|sslip\)\.io$/d' /etc/hosts

  # Proxy crash: systemd restarts it (same CA from tmpfs) and traffic recovers (GA gate preview)
  sudo systemctl kill -s KILL safer-runner-proxy
  t0=$(date +%s.%N)
  for _ in $(seq 1 30); do
    code=$(gh_zen -m 5 -o /dev/null -w '%{http_code}' 2>/dev/null) && [ "$code" = 200 ] && break
    sleep 0.5
  done
  record X.proxy-kill-recovery INFO "SIGKILL -> api.github.com $code after $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')s; restarts=$(systemctl show -p NRestarts --value safer-runner-proxy)"
}

# H1: allowlisted names (nip.io / sslip.io are allowlisted in these jobs) that resolve to
# internal addresses must never be reached through the proxy.
ssrf() {
  local out n
  # dnsmasq layer: stop-dns-rebind drops private answers; public answers under the same suffix still resolve
  for n in 169.254.169.254.nip.io 127.0.0.1.nip.io 10.0.0.1.nip.io 192.168.1.1.nip.io; do
    out=$(dig +short +time=3 +tries=2 @127.0.0.1 "$n" A 2>&1)
    if grep -qE '^[0-9]+\.' <<<"$out"; then record "H1.dns-rebind-$n" FAIL "dig $n -> $out"; else
      record "H1.dns-rebind-$n" PASS "dig $n -> '${out:-<no answer>}' (rebind answer dropped)"; fi
  done
  grep -q 'DNS-rebind' /var/log/safer-runner/dns.log
  pass_if H1.dns-rebind-logged $? "dnsmasq logged: $(grep -m1 'DNS-rebind' /var/log/safer-runner/dns.log | cut -c1-160)"
  out=$(dig +short +time=3 +tries=2 @127.0.0.1 1.1.1.1.nip.io A 2>&1)
  [ "$out" = 1.1.1.1 ]; pass_if H1.dns-public-still-resolves $? "dig 1.1.1.1.nip.io -> $out"

  # end to end: IMDS by an allowlisted name (no --resolve) must not answer
  out=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Metadata: true' 'http://169.254.169.254.nip.io/metadata/instance?api-version=2021-02-01' 2>&1); local rc=$?
  { [ $rc -ne 0 ] || [ "${out: -3}" != 200 ]; }
  pass_if H1.imds-by-name $? "http://169.254.169.254.nip.io/metadata/instance -> rc=$rc '${out: -80}'"

  # through the proxy, dnsmasq refuses: the proxy's lookup fails -> upstream-unresolved
  expect_upstream_refused H1.proxy-imds-http "Host 169.254.169.254.nip.io dialled at $ATTACKER_IP (plain HTTP)" 169.254.169.254 \
    '.ev=="upstream" and .host=="169.254.169.254.nip.io" and .verdict=="BLOCK"' \
    curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Metadata: true' --resolve "169.254.169.254.nip.io:80:$ATTACKER_IP" 'http://169.254.169.254.nip.io/metadata/instance?api-version=2021-02-01'
  expect_upstream_refused H1.proxy-loopback-https "SNI 127.0.0.1.nip.io dialled at $ATTACKER_IP (intercept)" 127.0.0.1 \
    '.ev=="upstream" and .host=="127.0.0.1.nip.io" and .verdict=="BLOCK"' \
    curl -k -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "127.0.0.1.nip.io:443:$ATTACKER_IP" https://127.0.0.1.nip.io/
  expect_upstream_refused H1.proxy-rfc1918-http "Host 10.0.0.1.nip.io dialled at $ATTACKER_IP" 10.0.0.1 \
    '.ev=="upstream" and .host=="10.0.0.1.nip.io" and .verdict=="BLOCK"' \
    curl -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "10.0.0.1.nip.io:80:$ATTACKER_IP" http://10.0.0.1.nip.io/

  # CGNAT: dnsmasq 2.91 (24.04) passes 100.64/10 answers, 2.92 (26.04) drops them too. The client
  # dials a public IP (--resolve), so whichever layer refuses, the proxy must log a BLOCK and
  # never connect to 100.64.0.1 (reason upstream-ip-forbidden on 2.91, upstream-unresolved on 2.92).
  out=$(dig +short +time=3 +tries=2 @127.0.0.1 100.64.0.1.nip.io A 2>&1)
  record H1.dns-cgnat INFO "dig 100.64.0.1.nip.io -> '${out:-<dropped by dnsmasq>}' ($(grep -m1 -o 'started, version [0-9.]*' /var/log/safer-runner/dns.log))"
  expect_upstream_refused H1.guard-cgnat-http "Host 100.64.0.1.nip.io dialled at $ATTACKER_IP (plain HTTP)" 100.64.0.1 \
    '.ev=="upstream" and .host=="100.64.0.1.nip.io" and .verdict=="BLOCK"' \
    curl -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "100.64.0.1.nip.io:80:$ATTACKER_IP" http://100.64.0.1.nip.io/
  expect_upstream_refused H1.guard-cgnat-https "SNI 100.64.0.1.nip.io dialled at $ATTACKER_IP (intercept)" 100.64.0.1 \
    '.ev=="upstream" and .host=="100.64.0.1.nip.io" and .verdict=="BLOCK"' \
    curl -k -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "100.64.0.1.nip.io:443:$ATTACKER_IP" https://100.64.0.1.nip.io/
  # passthrough connections get the same guard (100-64-0-1.sslip.io is a passthrough-domain here)
  expect_upstream_refused H1.guard-cgnat-passthrough "SNI 100-64-0-1.sslip.io dialled at $ATTACKER_IP (passthrough, SNI only)" 100.64.0.1 \
    '.ev=="upstream" and .host=="100-64-0-1.sslip.io" and .verdict=="BLOCK"' \
    curl -k -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "100-64-0-1.sslip.io:443:$ATTACKER_IP" https://100-64-0-1.sslip.io/

  # legitimate: a public answer under the same allowlisted suffix is connected to (and pinned)
  local m rec; m=$(mark)
  out=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' http://1.1.1.1.nip.io/ 2>&1)
  sleep 0.5; rec=$(flows_q "$m" '.ev=="server-connect" and (.peername // "" | startswith("1.1.1.1:")) and (.address // "" | startswith("1.1.1.1.nip.io:"))' | head -1)
  [ -n "$rec" ]; pass_if H1.public-name-connects $? "http://1.1.1.1.nip.io/ -> $out; $rec"
}

# H2: the privilege state the job ended up with
privilege() { # privilege <expect-sudo: yes|no>
  local out rc retained
  retained=$(jq -r '.sudoRetained' /etc/safer-runner/setup-complete 2>&1)
  if [ "$1" = no ]; then
    out=$(sudo -n true 2>&1); rc=$?
    [ $rc -ne 0 ]; pass_if H2.sudo-removed $? "sudo -n true -> rc=$rc ${out: -100}"
    [ "$retained" = false ]; pass_if H2.marker-not-advisory $? "setup-complete sudoRetained=$retained"
    # the runner user can't stop the proxy unit (polkit) or signal it (other uid)
    out=$(systemctl stop safer-runner-proxy 2>&1 </dev/null); rc=$?
    [ $rc -ne 0 ] && systemctl is-active -q safer-runner-proxy
    pass_if H2.unit-stop-denied $? "systemctl stop (no sudo) -> rc=$rc '${out: -80}'; unit $(systemctl is-active safer-runner-proxy)"
    out=$(kill -9 "$(systemctl show -p MainPID --value safer-runner-proxy)" 2>&1); rc=$?
    [ $rc -ne 0 ] && systemctl is-active -q safer-runner-proxy
    pass_if H2.proxy-kill-denied $? "kill -9 <proxy pid> -> rc=$rc '${out: -80}'"
    out=$(gh_zen -o /dev/null -w '%{http_code}' 2>&1)
    [ "$out" = 200 ]; pass_if H2.proxy-still-up $? "api.github.com -> $out"
  else
    out=$(sudo -n true 2>&1); rc=$?
    [ $rc -eq 0 ]; pass_if H2.sudo-retained $? "sudo -n true -> rc=$rc (explicit disable-sudo: false)"
    [ "$retained" = true ]; pass_if H2.marker-advisory $? "setup-complete sudoRetained=$retained (summary header says ADVISORY)"
  fi
}

# M1: the integrity baseline is root-owned and out of the runner's reach
baseline() {
  local f=/etc/safer-runner/validation-state.json out rc
  out=$(stat -c '%U:%G %a' "$f" 2>&1)  # stat needs only search permission on the (0755) directory
  [ "$out" = "root:root 600" ]; pass_if M1.baseline-root-0600 $? "$f -> $out"
  [ ! -e /tmp/safer-runner-validation-state.json ]; pass_if M1.no-tmp-baseline $? "/tmp/safer-runner-validation-state.json absent"
  out=$( (echo '{}' > "$f") 2>&1); rc=$?
  [ $rc -ne 0 ]; pass_if M1.runner-cannot-write $? "runner write -> rc=$rc ${out: -80}"
  out=$(cat "$f" 2>&1); rc=$?
  [ $rc -ne 0 ]; pass_if M1.runner-cannot-read $? "runner cat -> rc=$rc ${out: -80}"
  out=$(sudo -n cat "$f" 2>&1 | jq -r '.files | length' 2>&1)
  [[ "$out" =~ ^[1-9][0-9]*$ ]]; pass_if M1.validation-read-allowed $? "sudo -n cat (exact allowlist entry) -> $out files in baseline"
}

analyze() {
  local out rc m rec
  m=$(mark)
  out=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.org/ 2>&1)
  sleep 0.5; rec=$(flows_q "$m" '.ev=="tls" and .sni=="example.org" and .verdict=="WOULD_BLOCK" and .passthrough==true' | head -1)
  [ "$out" = 200 ] && [ -n "$rec" ]
  pass_if Z.not-allowlisted-works $? "https://example.org -> $out (passed through by SNI, logged WOULD_BLOCK): $rec"
  m=$(mark)
  out=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -H 'Host: api.github.com' https://github.com/ 2>&1)
  sleep 0.5; rec=$(flows_q "$m" '.ev=="https" and .reason=="host-sni-mismatch" and .verdict=="WOULD_BLOCK"' | head -1)
  [ -n "$rec" ]; pass_if Z.fronting-logged $? "fronting in analyze -> $out, logged: $rec"
  out=$(dig +short +time=3 +tries=1 @8.8.8.8 example.org A 2>&1)
  grep -q 'query\[A\] example.org' /var/log/safer-runner/dns.log
  pass_if Z.dns-redirected $? "dig @8.8.8.8 answered via dnsmasq: $(tr '\n' ' ' <<<"$out")"
  # H1 in analyze: the upstream IP guard logs WOULD_BLOCK (monitoring only), it does not refuse
  m=$(mark)
  out=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' http://100.64.0.1.nip.io/ 2>&1)
  sleep 0.5; rec=$(flows_q "$m" '.ev=="upstream" and .host=="100.64.0.1.nip.io" and .verdict=="WOULD_BLOCK" and .reason=="upstream-ip-forbidden"' | head -1)
  [ -n "$rec" ]; pass_if Z.upstream-guard-logged $? "http://100.64.0.1.nip.io/ -> '${out: -40}', logged: $rec"
  out=$(sudo -n true 2>&1); [ $? -eq 0 ]; pass_if Z.analyze-keeps-sudo $? "sudo -n true in analyze (default disable-sudo off)"
}

strict() {
  local out
  out=$(sudo -n true 2>&1); [ $? -ne 0 ]
  pass_if P.sudo-disabled $? "sudo -n true -> ${out: -100}"
  privilege no
  baseline
  out=$(docker ps 2>&1); [ $? -ne 0 ]
  pass_if P.docker-disabled $? "docker ps -> ${out: -100}"
  out=$(gh_zen -o /dev/null -w '%{http_code}' 2>&1)
  [ "$out" = 200 ]; pass_if A.curl $? "api.github.com -> $out"
  local OBJ_IP; OBJ_IP=$(ip4 objects.githubusercontent.com)
  expect_blocked C3.resolve-cotenant "curl --resolve octocat.github.io:443:$OBJ_IP" \
    '.ev=="tls" and .sni=="octocat.github.io" and .verdict=="BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "octocat.github.io:443:$OBJ_IP" https://octocat.github.io/
}

privilege_removed() { privilege no; }
privilege_retained() { privilege yes; }

trap 'record "harness.$1" FAIL "checks.sh $1 aborted (line $LINENO)"' EXIT
"${1//-/_}"
trap - EXIT
