#!/usr/bin/env bash
# safer-runner v2 P2: container egress checks (ported from the spike, spike/v2-containers p2/).
# usage: containers.sh <section> [args]
#   pull | service <svc-id> | traffic | dns | posture | front-door | failclosed | restart
#   | build | probe-log <expect: contained|open> | analyze
set -u
here=$(cd "$(dirname "$0")" && pwd)
source "$here/lib.sh"
DNSLOG=/var/log/safer-runner/dns.log
OK_URL=https://github.com/robots.txt        # allowlisted (GitHub list)
FD_URL=https://productionresultssa0.blob.core.windows.net/  # allowlisted multi-tenant front door
CURL=curlimages/curl:8.11.1
DEB=buildpack-deps:bookworm-curl
PY=python:3.12-slim
NODE=node:22-slim
JAVA=eclipse-temurin:21-jdk
NGINX=nginx:alpine
IMAGES="$CURL $DEB $PY $NODE $JAVA $NGINX"

# drun <docker run args...> -> sets R (last non-empty output line) and RC. Call it directly,
# never inside $(...): a subshell would lose both.
drun() { local out; out=$(timeout 150 docker run --rm "$@" 2>&1); RC=$?; R=$(grep -v '^\s*$' <<<"$out" | tail -1 | cut -c1-160); }
# a section that dies (set -u, a typo) must fail the job, not vanish behind `|| true`
trap 'rc=$?; [ $rc -ne 0 ] && record "harness.${1:-?}" FAIL "section exited $rc before finishing"' EXIT
# container_rec <mark> <jq-cond>: first flow record from the container listener matching cond
container_rec() { flows_q "$1" ".source==\"container\" and ($2)" | head -1; }
dns_seen() { local n; n=$(grep -c "$1" "$DNSLOG" 2>/dev/null); echo "${n:-0}"; }

case "$1" in

pull) # F1: the runner pulled the service image BEFORE the action; dockerd must trust the CA now
  record ctx.docker INFO "$(docker version --format 'client {{.Client.Version}} server {{.Server.Version}}' 2>&1) daemon.json=$(sudo -n cat /etc/docker/daemon.json 2>/dev/null | tr -d '\n ')"
  out=$(timeout 180 docker pull -q busybox:1.37 2>&1 | tail -1); rc=$?
  [ $rc -eq 0 ] && ! grep -q x509 <<<"$out"
  pass_if F1.pull-after-service $? "docker pull busybox (dockerd did TLS before the action): rc=$rc ${out:0:160}"
  # ghcr: registry API on ghcr.io (exact) + blobs 307'd to pkg-containers.githubusercontent.com (exact), no *.ghcr.io
  out=$(timeout 180 docker pull -q ghcr.io/containerd/busybox:1.36 2>&1 | tail -1); rc=$?
  [ $rc -eq 0 ] && ! grep -qi 'error' <<<"$out"
  pass_if A.ghcr-pull $? "docker pull ghcr.io/containerd/busybox:1.36 -> rc=$rc ${out:0:160}"
  : > "$RUNNER_TEMP/pull.txt"
  for i in $IMAGES; do (timeout 300 docker pull -q "$i" >/dev/null 2>&1; echo "$i rc=$?" >> "$RUNNER_TEMP/pull.txt") & done; wait
  ! grep -qv 'rc=0' "$RUNNER_TEMP/pull.txt"; pass_if F1.pulls $? "$(sort "$RUNNER_TEMP/pull.txt" | tr '\n' ' ')"
  ;;

service) # the job's service container (started by the runner BEFORE the action), by name
  sid=$2
  m=$(mark); r=$(docker exec "$sid" python3 -c "import urllib.request as u;print(u.urlopen('$OK_URL',timeout=20).status)" 2>&1 | tail -1); sleep 0.5
  rec=$(container_rec "$m" '.sni=="github.com" and .reason=="container-sni-only"')
  [ "$r" = 200 ] && [ -n "$rec" ]; pass_if S.allowed-by-name $? "service (no CA) $OK_URL -> $r; ${rec:0:200}"
  r=$(docker exec "$sid" python3 -c "import urllib.request as u;print(u.urlopen('https://example.org',timeout=10).status)" 2>&1 | tail -1)
  [ "$r" != 200 ]; pass_if S.denied $? "service https://example.org -> ${r:0:120}"
  r=$(docker exec "$sid" python3 -c "import socket;socket.create_connection(('1.1.1.1',853),timeout=5).close();print('connected')" 2>&1 | tail -1)
  [ "$r" != connected ]; pass_if S.port853 $? "service tcp 1.1.1.1:853 -> ${r:0:120}"
  ;;

probe-log) # health-cmd probe inside the service: run under default enforce (no docker access for steps)
  sleep 15; log=$(tail -5 /tmp/svcout/log 2>/dev/null)
  record S.probe INFO "$(tr '\n' ' ' <<<"$log")"
  grep -q 'https-github.com 200' <<<"$log" && grep -q 'https-example.org ERR' <<<"$log" && grep -q 'tcp-1.1.1.1:853 ERR' <<<"$log"
  pass_if S.contained-default-enforce $? "service: github.com by name OK, example.org + 1.1.1.1:853 refused (docker removed from steps)"
  ;;

traffic) # G1-G3 / T1-T3 / T5-T7
  drun $CURL -sS -m 15 -o /dev/null -w '%{http_code}' https://example.org; r=$R; [ $RC -ne 0 ]
  pass_if G1.https-denied-dns $? "container https://example.org (DNS) -> rc=$RC $r"
  m=$(mark); drun --add-host example.org:$ATTACKER_IP $CURL -sS -m 15 -o /dev/null -w '%{http_code}' https://example.org; r=$R; sleep 0.5
  rec=$(container_rec "$m" '.verdict=="BLOCK" and .sni=="example.org"')
  [ $RC -ne 0 ] && [ -n "$rec" ]; pass_if G1.https-denied-proxy $? "container https://example.org forced to $ATTACKER_IP -> rc=$RC $r; ${rec:0:200}"
  drun $DEB bash -c 'timeout 5 bash -c "</dev/tcp/1.1.1.1/853" && echo OPEN || echo closed'; r=$R; [ "$r" = closed ]
  pass_if G2.port853 $? "container tcp 1.1.1.1:853 -> $r"
  drun $CURL -sS -m 8 -o /dev/null -w '%{http_code}' -H Metadata:true 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'; r=$R; [ "$r" != 200 ]
  pass_if G3.imds $? "container -> IMDS -> $r"
  m=$(mark); drun $CURL -sS -m 20 -o /dev/null -w '%{http_code}' "$OK_URL"; r=$R; sleep 0.5
  rec=$(container_rec "$m" '.sni=="github.com" and .reason=="container-sni-only" and .repointed==true')
  [ "$r" = 200 ] && [ -n "$rec" ]; pass_if T1.allowed-no-ca $? "container (no CA) $OK_URL -> $r; ${rec:0:200}"
  m=$(mark); drun --add-host example.org:$ATTACKER_IP $CURL -sS -m 10 -o /dev/null -w '%{http_code}' http://example.org; r=$R; sleep 0.5
  rec=$(container_rec "$m" '.verdict=="BLOCK" and .reason=="host-not-allowed"')
  [ "$r" != 200 ] && [ -n "$rec" ]; pass_if T2.http-denied $? "container http://example.org -> $r; ${rec:0:200}"
  drun $CURL -sS -m 10 -k -o /dev/null -w '%{http_code}' https://1.1.1.1; r=$R; [ $RC -ne 0 ]
  pass_if T3.ip-literal $? "container https://1.1.1.1 -> rc=$RC $r"
  docker network create v2net >/dev/null 2>&1
  docker run -d --rm --name web --network v2net $NGINX >/dev/null; sleep 2
  drun --network v2net $CURL -sS -m 10 -o /dev/null -w '%{http_code}' http://web/; r=$R; [ "$r" = 200 ]
  pass_if T5.c2c $? "container -> nginx container on a user network :80 -> $r"
  docker rm -f web >/dev/null 2>&1
  ( sudo -n python3 -m http.server 80 --bind 0.0.0.0 --directory /tmp >/dev/null 2>&1 & ); sleep 1
  drun $CURL -sS -m 10 -o /dev/null -w '%{http_code}' http://172.17.0.1/; r=$R; [ "$r" = 200 ]
  pass_if T6.c2host $? "container -> host 172.17.0.1:80 -> $r"
  sudo -n pkill -f 'http.server 80' || true
  m=$(mark); drun --network host --add-host example.org:$ATTACKER_IP $CURL -sS -m 10 -o /dev/null https://example.org; r=$R; sleep 0.5
  rec=$(flows_q "$m" '.verdict=="BLOCK" and .sni=="example.org" and (.source // "host")=="host"' | head -1)
  [ $RC -ne 0 ] && [ -n "$rec" ]; pass_if T7.hostnet $? "--network host container = host path (source host): rc=$RC; ${rec:0:200}"
  ;;

dns) # N1-N3
  for net in bridge v2net; do
    docker network create v2net >/dev/null 2>&1
    tag="x$RANDOM$RANDOM"
    out=$(timeout 40 docker run --rm --network $net $DEB bash -c "
      echo denied: \$(getent hosts $tag.example.org || echo NXDOMAIN)
      echo allowed: \$(getent hosts github.com | head -1 || echo FAILED)" 2>&1)
    sleep 1; seen=$(dns_seen "$tag.example.org")
    grep -q 'denied: NXDOMAIN' <<<"$out" && [ "$seen" -gt 0 ]
    pass_if "N.$net-filtered" $? "denied name NXDOMAIN and seen by our resolver ($seen): $(tr '\n' ' ' <<<"$out")"
    grep -q 'allowed: [0-9]' <<<"$out"; pass_if "N.$net-allowed" $? "allowlisted name resolves ($net)"
  done
  tag="t$RANDOM$RANDOM"
  out=$(timeout 40 docker run --rm $PY python3 -c "
import socket,struct,random
q=struct.pack('>HHHHHH',random.randint(0,65535),0x0100,1,0,0,0)+b''.join(bytes([len(p)])+p.encode() for p in '$tag.tunnel.example.org'.split('.'))+b'\x00\x00\x01\x00\x01'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5);s.sendto(q,('8.8.8.8',53))
d,a=s.recvfrom(512);print('rcode',d[3]&15,'from',a)" 2>&1 | tail -1)
  sleep 1; seen=$(dns_seen "$tag.tunnel")
  [ "$seen" -gt 0 ]; pass_if N3.direct-8.8.8.8 $? "raw DNS to 8.8.8.8 from a container answered by our resolver ($seen): $out"
  ;;

posture) # container-tls sni-only (default): no CA in any image; host still intercepted
  drun $NODE node -e "fetch('$OK_URL').then(r=>console.log(r.status)).catch(e=>{console.log(String(e.cause||e));process.exit(1)})"; r=$R
  [ "$r" = 200 ]; pass_if P.node-no-ca $? "node:22 fetch $OK_URL -> $r"
  drun -v "$here:/t:ro" $JAVA java /t/Get.java "$OK_URL"; r=$R; [ "$r" = 200 ]
  pass_if P.java-no-ca $? "temurin HttpURLConnection -> $r"
  drun $PY sh -c "pip install -q --disable-pip-version-check --root-user-action=ignore requests >/dev/null 2>&1; python3 -c \"import requests;print(requests.get('$OK_URL',timeout=20).status_code)\""; r=$R
  [ "$r" = 200 ]; pass_if P.requests-no-ca $? "pip install requests + requests.get (certifi) -> $r"
  m=$(mark); out=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$OK_URL" 2>&1); sleep 0.5
  rec=$(flows_q "$m" '.ev=="tls" and .sni=="github.com" and .verdict=="INTERCEPT" and .source=="host"' | head -1)
  [ -n "$rec" ]; pass_if P.host-still-intercepted $? "host curl $OK_URL -> $out; ${rec:0:200}"
  drun $DEB curl -sS -m 15 -o /dev/null -w '%{http_code}' --connect-to ::github.com:443 -H 'Host: gist.github.com' https://github.com/; r=$R
  record P.fronting-under-sni-only INFO "container SNI github.com + Host gist.github.com -> $r (documented limitation of sni-only)"
  ;;

front-door) # <enforce|analyze>: Azure Storage stays intercepted for containers in enforce
  m=$(mark); drun $CURL -sS -m 15 -o /dev/null -w '%{http_code}' "$FD_URL"; r=$R; sleep 0.5
  if [ "$2" = enforce ]; then
    rec=$(container_rec "$m" '.reason=="container-front-door" and .verdict=="INTERCEPT"')
    [ $RC -ne 0 ] && [ -n "$rec" ]; pass_if P.front-door-intercepted $? "container (no CA) $FD_URL -> rc=$RC $r (TLS fails: intercepted); ${rec:0:200}"
  else
    rec=$(container_rec "$m" '.reason=="container-sni-only"')
    [ -n "$rec" ]; pass_if P.front-door-analyze-passthrough $? "analyze never breaks a container: $FD_URL -> $r; ${rec:0:200}"
  fi
  ;;

failclosed) # T4: a hole in the DNAT still fails closed in DOCKER-USER (needs sudo: advisory job)
  sudo -n iptables -t nat -I SAFER_RUNNER_CNAT 1 -p tcp --dport 443 -j RETURN
  drun $CURL -sS -m 10 -k -o /dev/null -w '%{http_code}' https://1.1.1.1; r=$R
  n=$(sudo -n iptables -L SAFER_RUNNER_CFWD -v -n | awk '/REJECT/ && /tcp/ {print $1; exit}')
  sudo -n iptables -t nat -D SAFER_RUNNER_CNAT -p tcp --dport 443 -j RETURN
  [ $RC -ne 0 ] && [ "${n:-0}" != 0 ]; pass_if T4.failclosed $? "443 DNAT removed: container https://1.1.1.1 -> rc=$RC $r (SAFER_RUNNER_CFWD tcp REJECT pkts=$n)"
  sleep 2; n=$(grep -c 'SaferRunner-CDrop' /var/log/safer-runner/firewall.log 2>/dev/null)
  [ "${n:-0}" -gt 0 ]; pass_if T4.cdrop-logged $? "CDrop lines in firewall.log: $n"
  ;;

restart) # T8: rules survive dockerd restarting (it re-creates its own chains)
  sudo -n systemctl restart docker; sleep 3
  n=$(sudo -n iptables -S DOCKER-USER | grep -c SAFER_RUNNER_CFWD); p=$(sudo -n iptables -t nat -S PREROUTING | grep -c SAFER_RUNNER_CNAT)
  drun --add-host example.org:$ATTACKER_IP $CURL -sS -m 10 -o /dev/null https://example.org; r=$R
  [ "$n" -ge 2 ] && [ "$p" -ge 2 ] && [ $RC -ne 0 ]
  pass_if T8.restart-survival $? "after dockerd restart: DOCKER-USER jumps=$n PREROUTING jumps=$p; forced example.org rc=$RC"
  ;;

build) # docker build RUN under sni-only: allowlisted works with no CA, denied refused
  d=$(mktemp -d)
  printf 'FROM %s\nRUN curl -sS -m 20 -o /dev/null -w "allowed:%%{http_code}\\n" %s || echo allowed:FAIL\nRUN curl -sS -m 10 -o /dev/null https://example.org && echo denied:OPEN || echo denied:refused\n' "$DEB" "$OK_URL" > "$d/Dockerfile"
  out=$(timeout 300 docker build --no-cache --progress plain "$d" 2>&1)
  res=$(grep -oE 'allowed:[A-Z0-9]+|denied:[a-zA-Z]+' <<<"$out" | sort -u | tr '\n' ' ')
  grep -q 'allowed:200' <<<"$res" && grep -q 'denied:refused' <<<"$res"
  pass_if B.build-run $? "docker build RUN: $res"
  ;;

analyze) # analyze must not break containers
  drun $CURL -sS -m 20 -o /dev/null -w '%{http_code}' "$OK_URL"; r=$R; [ "$r" = 200 ]
  pass_if AZ.allowed-no-ca $? "container (no CA) $OK_URL -> $r"
  m=$(mark); drun $CURL -sS -m 20 -o /dev/null -w '%{http_code}' https://example.org; r=$R; sleep 0.5
  rec=$(container_rec "$m" '.verdict=="WOULD_BLOCK"')
  [ "$r" = 200 ] && [ -n "$rec" ]; pass_if AZ.would-block-works $? "container https://example.org -> $r; ${rec:0:200}"
  drun $DEB bash -c 'timeout 5 bash -c "</dev/tcp/1.1.1.1/853" && echo OPEN || echo closed'; r=$R
  sleep 2; n=$(grep -c 'SaferRunner-CEgress' /var/log/safer-runner/firewall.log 2>/dev/null)
  [ "$r" = OPEN ] && [ "${n:-0}" -gt 0 ]; pass_if AZ.port853-logged $? "container tcp 1.1.1.1:853 -> $r; CEgress lines: $n"
  ;;
esac
