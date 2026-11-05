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
  jq -e 'length == 3 and all(.ok) and any(.name == "dns-exact")' /var/log/safer-runner/selftest.json >/dev/null 2>&1
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
  # ghcr: registry API on ghcr.io (exact) + blobs 307'd to pkg-containers.githubusercontent.com (exact): no *.ghcr.io
  out=$(timeout 120 docker pull -q ghcr.io/containerd/busybox:1.36 2>&1); rc=$?
  if docker info >/dev/null 2>&1; then pass_if A.ghcr-pull $rc "docker pull ghcr.io/containerd/busybox:1.36 -> $(tail -1 <<<"$out" | cut -c1-160)"
  else record A.ghcr-pull INFO "no docker access in this job: $(tail -1 <<<"$out" | cut -c1-120)"; fi

  dns_resolver

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
      record "DNS.direct-$r" PASS "dig @$r example.org -> '${out:-<no answer>}' (answered by our resolver)"; fi
  done
  out=$(dig +short +time=3 +tries=1 @168.63.129.16 api.github.com A 2>&1)
  record DNS.allowed-via-azure INFO "dig @168.63.129.16 api.github.com -> $(tr '\n' ' ' <<<"$out")"
  grep -q ' BLOCK A example.org. ' /var/log/safer-runner/dns.log
  pass_if DNS.redirected-to-resolver $? "CoreDNS logged (BLOCK) the direct-IP queries for example.org"

  dns_exact

  rec=$(jq -c 'select(.ev=="tls" and .layer=="sni" and .verdict=="BLOCK")' "$FLOWLOG" | wc -l)
  [ "$rec" -gt 0 ]; pass_if S.sni-layer-block-fired $? "$rec SNI-layer BLOCK records (enforcement happened at the ClientHello, not only Host)"
}

# CoreDNS resolver on the real runner (the spike's NOT-VERIFIED items: non-root :53 bind via an
# ambient capability under systemd-run, StandardOutput=append log file + mode, coexistence with
# GitHub's 127.0.0.100 egress resolver, amd64)
dns_resolver() {
  local pid out caps
  record ctx.arch INFO "$(uname -m); listeners on :53: $(ss -Hlun 'sport = :53' | awk '{print $4}' | sort -u | tr '\n' ' ')"
  systemctl is-active -q safer-runner-dns; pass_if R.unit-active $? "safer-runner-dns: $(systemctl is-active safer-runner-dns) restarts=$(systemctl show -p NRestarts --value safer-runner-dns)"
  pid=$(systemctl show -p MainPID --value safer-runner-dns)
  out=$(ps -o user:32=,uid=,comm= -p "$pid" 2>&1)
  caps=$(awk '/^Cap(Eff|Prm|Bnd|Amb)/{printf "%s=%s ", $1, $2}' "/proc/$pid/status" 2>&1)
  [[ "$out" =~ ^dns-[0-9a-f]+\ +6[0-9]{4}\ +coredns$ ]] && grep -q 'CapEff:=0000000000000400' <<<"$caps"
  pass_if R.non-root-cap-bind $? "pid $pid: $out; $caps"
  ss -Hlun 'sport = :53' | grep -q '127.0.0.1:53'; pass_if R.bound-127.0.0.1 $? "$(ss -Hlun 'sport = :53' | awk '{print $4}' | tr '\n' ' ')"
  out=$(stat -c '%U:%G %a' /var/log/safer-runner/dns.log 2>&1)
  [ "$out" = "root:root 644" ] && grep -q ' ALLOW A github.com. ' /var/log/safer-runner/dns.log
  pass_if R.log-file $? "dns.log $out, readable without sudo; $(grep -m1 -o 'CoreDNS-[0-9.]*' /var/log/safer-runner/dns.log) $(grep -m1 -o 'linux/[a-z0-9]*' /var/log/safer-runner/dns.log)"
  grep -q '^nameserver 127.0.0.1$' /etc/resolv.conf; pass_if R.resolv-conf $? "$(grep nameserver /etc/resolv.conf | tr '\n' ' ')"
  if ss -Hlun 'sport = :53' | grep -q '127.0.0.100:53'; then
    out=$(getent hosts github.com | head -1); [ -n "$out" ]
    pass_if R.coexists-127.0.0.100 $? "GitHub egress resolver present on 127.0.0.100:53 alongside ours; github.com -> $out"
  else
    record R.coexists-127.0.0.100 INFO "no 127.0.0.100 resolver on this VM"
  fi
  # wildcard entries resolve (.docker.io expands to docker.io + *.docker.io; meta's *.actions...)
  for n in registry-1.docker.io pipelines.actions.githubusercontent.com hosted-compute-watchdog-prod-iad-01.githubapp.com 1.1.1.1.nip.io docker.io; do
    out=$(getent ahostsv4 "$n" | awk '{print $1; exit}')
    [ -n "$out" ]; pass_if "R.wildcard-$n" $? "$n -> ${out:-<none>}"
  done
}

# exact-FQDN: a name under an exact entry is refused ON THE RUNNER (BLOCK block, never the ALLOW/
# forwarding block), for every query type and transport; the name never gets an upstream= line.
dns_exact() {
  local secret parent n out st
  secret="s$(head -c 10 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  for parent in objects.githubusercontent.com pypi.org release-assets.githubusercontent.com; do
    n="$secret.$parent"
    for q in "A" "TXT" "AAAA +tcp"; do
      st=$(dig +time=3 +tries=1 $n $q 2>&1 | grep -o 'status: [A-Z]*')
      [ "$st" = "status: NXDOMAIN" ]; pass_if "X.exact-$parent-${q// /}" $? "dig $n $q -> $st"
    done
    sleep 0.5
    grep -q " BLOCK A $n. NXDOMAIN" /var/log/safer-runner/dns.log && ! grep -q "$n. .*upstream=" /var/log/safer-runner/dns.log
    pass_if "X.exact-$parent-not-forwarded" $? "$(grep -c "$n" /var/log/safer-runner/dns.log) BLOCK lines, $(grep -c "$n. .*upstream=" /var/log/safer-runner/dns.log) forwarded"
  done
  out=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://www.pypi.org/ 2>&1); local rc=$?
  [ $rc -ne 0 ]; pass_if X.exact-user-entry-subdomain $? "https://www.pypi.org (only pypi.org listed) -> rc=$rc '${out: -60}'"
  out=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://pypi.org/simple/ 2>&1)
  [[ "$out" =~ ^[23] ]]; pass_if X.exact-user-entry-apex $? "https://pypi.org/simple/ -> $out"
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

  # H1, addon layer via /etc/hosts (also covers ULA, which public wildcard DNS can't give us).
  # The client dials a public IP, so the only thing that can refuse is the proxy's IP guard.
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

  # exact-FQDN on the wire: a name under an exact entry never leaves the VM; a name under a
  # wildcard entry does (the control proves the capture works - wildcards stay a DNS channel)
  local secret ctl pcap=/tmp/dns-wire.pcap
  secret="w$(head -c 10 /dev/urandom | od -An -tx1 | tr -d ' \n')"; ctl="c$RANDOM$RANDOM.github.com"
  sudo timeout 12 tcpdump -i any -nn -U -s 0 -w "$pcap" 'port 53 and not net 127.0.0.0/8' 2>/dev/null &
  sleep 2
  dig +time=2 +tries=1 "$secret.objects.githubusercontent.com" A >/dev/null 2>&1
  dig +time=2 +tries=1 +tcp "$secret.pypi.org" TXT >/dev/null 2>&1
  dig +time=2 +tries=1 "$ctl" A >/dev/null 2>&1
  wait
  out=$(sudo tcpdump -nn -r "$pcap" 2>/dev/null)
  ! grep -q "$secret" <<<"$out" && grep -q "${ctl%%.*}" <<<"$out"
  pass_if X.exact-not-on-wire $? "pcap ($(wc -l <<<"$out") pkts off-host :53): secret seen $(grep -c "$secret" <<<"$out")x, wildcard control seen $(grep -c "${ctl%%.*}" <<<"$out")x"

  # resolver crash: systemd restarts it and resolution recovers
  sudo systemctl kill -s KILL safer-runner-dns
  t0=$(date +%s.%N); out=""
  for _ in $(seq 1 30); do
    out=$(dig +short +time=1 +tries=1 github.com A | head -1); [ -n "$out" ] && break
    sleep 0.5
  done
  [ -n "$out" ]
  pass_if X.dns-kill-recovery $? "SIGKILL CoreDNS -> github.com $out after $(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')s; restarts=$(systemctl show -p NRestarts --value safer-runner-dns)"
}

# H1: allowlisted names (nip.io / sslip.io are allowlisted in these jobs) that resolve to
# internal addresses must never be reached through the proxy.
ssrf() {
  local out n
  # No DNS-layer rebind drop any more (CoreDNS replaced dnsmasq): internal answers are returned
  # as-is and the PROXY's upstream IP guard refuses them, logging the address.
  for n in 169.254.169.254.nip.io 127.0.0.1.nip.io 10.0.0.1.nip.io 100.64.0.1.nip.io; do
    out=$(dig +short +time=3 +tries=2 @127.0.0.1 "$n" A 2>&1)
    record "H1.dns-answer-$n" INFO "dig $n -> '${out:-<no answer>}' (no DNS-layer rebind drop, by design)"
  done
  out=$(dig +short +time=3 +tries=2 @127.0.0.1 1.1.1.1.nip.io A 2>&1)
  [ "$out" = 1.1.1.1 ]; pass_if H1.dns-public-still-resolves $? "dig 1.1.1.1.nip.io -> $out"

  # IMDS by an allowlisted name, dialled directly: 169.254.169.254:80 is exempt from the REDIRECT
  # (the platform needs it), so this reaches IMDS exactly like the IP literal does. Informational.
  out=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Metadata: true' 'http://169.254.169.254.nip.io/metadata/instance?api-version=2021-02-01' 2>&1); local rc=$?
  record H1.imds-by-name INFO "http://169.254.169.254.nip.io/metadata/instance -> rc=$rc '${out: -60}' (same reachability as http://169.254.169.254/, by design)"

  # through the proxy: the IP guard refuses and logs the internal address it resolved
  expect_upstream_refused H1.proxy-imds-http "Host 169.254.169.254.nip.io dialled at $ATTACKER_IP (plain HTTP)" 169.254.169.254 \
    '.ev=="upstream" and .host=="169.254.169.254.nip.io" and .verdict=="BLOCK" and .reason=="upstream-ip-forbidden" and ((.resolved // []) | tostring | contains("169.254.169.254"))' \
    curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Metadata: true' --resolve "169.254.169.254.nip.io:80:$ATTACKER_IP" 'http://169.254.169.254.nip.io/metadata/instance?api-version=2021-02-01'
  expect_upstream_refused H1.proxy-loopback-https "SNI 127.0.0.1.nip.io dialled at $ATTACKER_IP (intercept)" 127.0.0.1 \
    '.ev=="upstream" and .host=="127.0.0.1.nip.io" and .verdict=="BLOCK" and .reason=="upstream-ip-forbidden" and ((.resolved // []) | tostring | contains("127.0.0.1"))' \
    curl -k -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "127.0.0.1.nip.io:443:$ATTACKER_IP" https://127.0.0.1.nip.io/
  expect_upstream_refused H1.proxy-rfc1918-http "Host 10.0.0.1.nip.io dialled at $ATTACKER_IP" 10.0.0.1 \
    '.ev=="upstream" and .host=="10.0.0.1.nip.io" and .verdict=="BLOCK" and .reason=="upstream-ip-forbidden" and ((.resolved // []) | tostring | contains("10.0.0.1"))' \
    curl -sS -m 10 -o /dev/null -w '%{http_code}' --resolve "10.0.0.1.nip.io:80:$ATTACKER_IP" http://10.0.0.1.nip.io/

  # CGNAT (dnsmasq 2.91 used to pass it, 2.92 dropped it): now always the proxy's IP guard
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
  grep -q ' WOULD_BLOCK A example.org. ' /var/log/safer-runner/dns.log
  pass_if Z.dns-redirected $? "dig @8.8.8.8 answered via CoreDNS, labelled WOULD_BLOCK: $(tr '\n' ' ' <<<"$out")"
  out=$(dig +short +time=3 +tries=1 "srst$RANDOM.objects.githubusercontent.com" A 2>&1)
  grep -q ' WOULD_BLOCK A srst[0-9]*.objects.githubusercontent.com. ' /var/log/safer-runner/dns.log
  pass_if Z.dns-exact-would-block $? "subdomain of an exact entry is labelled WOULD_BLOCK in analyze (still forwarded)"
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
