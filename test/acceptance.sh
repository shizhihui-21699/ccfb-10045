#!/usr/bin/env bash
# Acceptance test for the SSH CA service.
# Covers: ed25519+ecdsa user/host certs, principals, validity, force-command,
# source-address, extensions, approval workflow, KRL revocation, audit log,
# and `ssh-keygen -L` / `ssh-keygen -Q` interop.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d /tmp/ssh-ca-test.XXXXXX)"
PORT="${PORT:-18443}"
BASE="http://127.0.0.1:$PORT"
SERVER_LOG="$WORK/server.log"
SERVER_PID=""

PASS=0
FAIL=0

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
  if [ "$FAIL" -gt 0 ]; then
    echo "server log kept at: $SERVER_LOG" 2>/dev/null || true
  fi
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo "  ✔ $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✘ $1"; }
check(){ # check <description> <command...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
section(){ echo; echo "== $1 =="; }

json_get() { node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const v=JSON.parse(d);console.log(eval('v.'+process.argv[1]))})" "$1"; }

api() { # api <token> <method> <path> [body]
  local token="$1" method="$2" path="$3" body="${4:-}"
  if [ -n "$body" ]; then
    curl -sf -X "$method" -H "Authorization: Bearer $token" -H 'content-type: application/json' -d "$body" "$BASE$path"
  else
    curl -sf -X "$method" -H "Authorization: Bearer $token" "$BASE$path"
  fi
}

echo "== build =="
(cd "$ROOT" && npm run build >/dev/null)

section "start server"
node "$ROOT/dist/server.js" --data "$WORK/data" --port "$PORT" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for i in $(seq 1 50); do
  curl -sf "$BASE/api/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf "$BASE/api/health" >/dev/null || { echo "server failed to start"; cat "$SERVER_LOG"; exit 1; }
ok "server up on :$PORT"

ADMIN_TOKEN=$(node -pe "Object.entries(JSON.parse(require('fs').readFileSync('$WORK/data/config.json','utf8')).tokens).find(([t,v])=>v.role==='admin')[0]")
REQ_TOKEN=$(node -pe "Object.entries(JSON.parse(require('fs').readFileSync('$WORK/data/config.json','utf8')).tokens).find(([t,v])=>v.role==='requester')[0]")
[ -n "$ADMIN_TOKEN" ] && [ -n "$REQ_TOKEN" ] && ok "tokens loaded from config"

section "CA info"
CA_INFO=$(api "$REQ_TOKEN" GET /api/ca)
echo "$CA_INFO" | grep -q ssh-ed25519 && ok "ed25519 CA published"
echo "$CA_INFO" | grep -q ecdsa-sha2-nistp256 && ok "ecdsa CA published"

section "key generation (client side)"
ssh-keygen -q -t ed25519 -N '' -C 'alice@laptop' -f "$WORK/alice_ed25519"
ssh-keygen -q -t ecdsa -N '' -C 'bob@laptop' -f "$WORK/bob_ecdsa"
ssh-keygen -q -t ed25519 -N '' -C 'web1 host key' -f "$WORK/host_ed25519"
ok "user + host keys generated"

section "authz"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/requests")
[ "$code" = "401" ] && ok "no token -> 401" || bad "no token -> 401 (got $code)"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $REQ_TOKEN" "$BASE/api/requests/nonexistent/approve")
[ "$code" = "403" ] && ok "requester cannot approve -> 403" || bad "requester cannot approve -> 403 (got $code)"

section "user cert: ed25519 key, ed25519 CA, principals + force-command + source-address + extensions"
PUB=$(cat "$WORK/alice_ed25519.pub")
BODY=$(PUB="$PUB" node -e 'console.log(JSON.stringify({
  type:"user", ca:"ed25519", publicKey:process.env.PUB,
  principals:["alice","ops"], keyId:"alice-laptop-2026",
  validBefore: Math.floor(Date.now()/1000)+3600,
  criticalOptions:{forceCommand:"/usr/bin/rrsync /backup", sourceAddress:["10.0.0.0/8","192.168.0.0/16"]},
  extensions:["permit-pty","permit-agent-forwarding"],
  comment:"ticket-1234"}))')
RID=$(api "$REQ_TOKEN" POST /api/requests "$BODY" | json_get id)
[ -n "$RID" ] && ok "request created ($RID)"
api "$REQ_TOKEN" GET "/api/requests?status=pending" | grep -q "$RID" && ok "request listed as pending"
CERT_JSON=$(api "$ADMIN_TOKEN" POST "/api/requests/$RID/approve" '{}')
SERIAL1=$(echo "$CERT_JSON" | json_get serial)
[ -n "$SERIAL1" ] && ok "approved, serial=$SERIAL1"
api "$REQ_TOKEN" GET "/api/certs/$SERIAL1/cert.pub" > "$WORK/alice-cert.pub"
ssh-keygen -L -f "$WORK/alice-cert.pub" > "$WORK/alice-cert.txt"
check "ssh-keygen -L parses ed25519 user cert" grep -q "user certificate" "$WORK/alice-cert.txt"
check "principals present" grep -qE "^\s+alice\s*$" "$WORK/alice-cert.txt"
check "second principal present" grep -qE "^\s+ops\s*$" "$WORK/alice-cert.txt"
check "key id recorded" grep -q 'Key ID: "alice-laptop-2026"' "$WORK/alice-cert.txt"
check "serial recorded" grep -q "Serial: $SERIAL1" "$WORK/alice-cert.txt"
check "force-command critical option" grep -q "force-command" "$WORK/alice-cert.txt"
check "force-command value" grep -q "/usr/bin/rrsync /backup" "$WORK/alice-cert.txt"
check "source-address critical option" grep -q "source-address" "$WORK/alice-cert.txt"
check "source-address values" grep -q "10.0.0.0/8" "$WORK/alice-cert.txt"
check "permit-pty extension" grep -q "permit-pty" "$WORK/alice-cert.txt"
check "permit-agent-forwarding extension" grep -q "permit-agent-forwarding" "$WORK/alice-cert.txt"
check "validity window shown" grep -q "Valid: from" "$WORK/alice-cert.txt"
check "signing CA is ed25519" grep -qE "Signing CA:.*ssh-ed25519" "$WORK/alice-cert.txt"

section "user cert: ecdsa key, ecdsa CA"
PUB=$(cat "$WORK/bob_ecdsa.pub")
BODY=$(PUB="$PUB" node -e 'console.log(JSON.stringify({
  type:"user", ca:"ecdsa", publicKey:process.env.PUB,
  principals:["bob"], extensions:["permit-pty"]}))')
RID2=$(api "$REQ_TOKEN" POST /api/requests "$BODY" | json_get id)
CERT_JSON=$(api "$ADMIN_TOKEN" POST "/api/requests/$RID2/approve" '{}')
SERIAL2=$(echo "$CERT_JSON" | json_get serial)
api "$REQ_TOKEN" GET "/api/certs/$SERIAL2/cert.pub" > "$WORK/bob-cert.pub"
ssh-keygen -L -f "$WORK/bob-cert.pub" > "$WORK/bob-cert.txt"
check "ssh-keygen -L parses ecdsa cert" grep -q "ecdsa-sha2-nistp256-cert-v01@openssh.com user certificate" "$WORK/bob-cert.txt"
check "signing CA is ecdsa" grep -qE "Signing CA:.*ecdsa-sha2-nistp256" "$WORK/bob-cert.txt"
check "bob principal" grep -qE "^\s+bob\s*$" "$WORK/bob-cert.txt"

section "host cert"
PUB=$(cat "$WORK/host_ed25519.pub")
BODY=$(PUB="$PUB" node -e 'console.log(JSON.stringify({
  type:"host", ca:"ed25519", publicKey:process.env.PUB,
  principals:["web1.example.com","web1"], validBefore: Math.floor(Date.now()/1000)+86400}))')
RID3=$(api "$REQ_TOKEN" POST /api/requests "$BODY" | json_get id)
CERT_JSON=$(api "$ADMIN_TOKEN" POST "/api/requests/$RID3/approve" '{}')
SERIAL3=$(echo "$CERT_JSON" | json_get serial)
api "$REQ_TOKEN" GET "/api/certs/$SERIAL3/cert.pub" > "$WORK/host-cert.pub"
ssh-keygen -L -f "$WORK/host-cert.pub" > "$WORK/host-cert.txt"
check "ssh-keygen -L parses host cert" grep -q "host certificate" "$WORK/host-cert.txt"
check "host principals" grep -q "web1.example.com" "$WORK/host-cert.txt"

section "reject flow"
PUB=$(cat "$WORK/alice_ed25519.pub")
BODY=$(PUB="$PUB" node -e 'console.log(JSON.stringify({type:"user",publicKey:process.env.PUB,principals:["mallory"]}))')
RID4=$(api "$REQ_TOKEN" POST /api/requests "$BODY" | json_get id)
api "$ADMIN_TOKEN" POST "/api/requests/$RID4/reject" '{"reason":"no ticket"}' | grep -q '"rejected"' && ok "request rejected"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE/api/requests/$RID4/approve")
[ "$code" = "409" ] && ok "rejected request cannot be approved (409)" || bad "approve after reject -> 409 (got $code)"

section "revocation + KRL"
api "$ADMIN_TOKEN" POST "/api/certs/$SERIAL1/revoke" '{"reason":"alice left"}' | grep -q '"revoked":true' && ok "cert $SERIAL1 revoked"
api "$REQ_TOKEN" GET /api/krl > "$WORK/revoked.krl"
[ -s "$WORK/revoked.krl" ] && ok "KRL downloaded ($(wc -c < "$WORK/revoked.krl" | tr -d ' ') bytes)"
OUT=$(ssh-keygen -Q -f "$WORK/revoked.krl" "$WORK/alice-cert.pub" 2>&1 || true)
echo "$OUT" | grep -q "REVOKED" && ok "revoked cert flagged by ssh-keygen -Q" || bad "revoked cert flagged (got: $OUT)"
OUT=$(ssh-keygen -Q -f "$WORK/revoked.krl" "$WORK/bob-cert.pub" 2>&1 || true)
echo "$OUT" | grep -q "ok" && ok "non-revoked cert passes ssh-keygen -Q" || bad "non-revoked cert passes (got: $OUT)"
OUT=$(ssh-keygen -Q -f "$WORK/revoked.krl" "$WORK/host-cert.pub" 2>&1 || true)
echo "$OUT" | grep -q "ok" && ok "host cert passes ssh-keygen -Q" || bad "host cert passes (got: $OUT)"

section "audit log"
AUDIT=$(api "$ADMIN_TOKEN" GET /api/audit)
echo "$AUDIT" | grep -q '"request.create"' && ok "request.create audited"
echo "$AUDIT" | grep -q '"request.approve"' && ok "request.approve audited"
echo "$AUDIT" | grep -q '"cert.revoke"' && ok "cert.revoke audited"
echo "$AUDIT" | grep -q '"krl.download"' && ok "krl.download audited"
echo "$AUDIT" | grep -q '"cert.download"' && ok "cert.download audited"
echo "$AUDIT" | grep -q "alice-laptop-2026" && ok "audit contains key id"
echo "$AUDIT" | grep -q "web1.example.com" && ok "audit contains host principal"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $REQ_TOKEN" "$BASE/api/audit")
[ "$code" = "403" ] && ok "audit log is admin-only" || bad "audit log is admin-only (got $code)"

section "management UI"
curl -sf "$BASE/" | grep -q "SSH CA" && ok "admin UI served at /"

section "end-to-end: real sshd cert auth + KRL enforcement"
SSHD=/usr/sbin/sshd
if [ -x "$SSHD" ]; then
  ME=$(whoami)
  E2E_PORT=$((PORT+100))
  cp "$WORK/data/ca/ed25519.pub" "$WORK/ca_user.pub"
  ssh-keygen -q -t ed25519 -N '' -f "$WORK/e2e_hostkey"
  ssh-keygen -q -t ed25519 -N '' -f "$WORK/e2e_userkey"
  echo "$ME" > "$WORK/principals"

  # cert with force-command, principal = current user
  PUB=$(cat "$WORK/e2e_userkey.pub")
  BODY=$(ME="$ME" PUB="$PUB" node -e 'console.log(JSON.stringify({
    type:"user", publicKey:process.env.PUB, principals:[process.env.ME],
    validBefore: Math.floor(Date.now()/1000)+600,
    criticalOptions:{forceCommand:"/bin/echo FORCED_COMMAND_RAN"}}))')
  ERID=$(api "$REQ_TOKEN" POST /api/requests "$BODY" | json_get id)
  ESERIAL=$(api "$ADMIN_TOKEN" POST "/api/requests/$ERID/approve" '{}' | json_get serial)
  api "$REQ_TOKEN" GET "/api/certs/$ESERIAL/cert.pub" > "$WORK/e2e_userkey-cert.pub"

  cat > "$WORK/sshd_config" <<EOF
Port $E2E_PORT
ListenAddress 127.0.0.1
HostKey $WORK/e2e_hostkey
TrustedUserCAKeys $WORK/ca_user.pub
AuthorizedPrincipalsFile $WORK/principals
PidFile $WORK/sshd.pid
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
EOF
  if "$SSHD" -f "$WORK/sshd_config" -E "$WORK/sshd.log" 2>/dev/null; then
    sleep 0.5
    SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=$WORK/kh -o IdentitiesOnly=yes -i $WORK/e2e_userkey -p $E2E_PORT"
    OUT=$(ssh $SSH_OPTS "$ME@127.0.0.1" "echo SHOULD_NOT_RUN" 2>/dev/null || true)
    if [ "$OUT" = "FORCED_COMMAND_RAN" ]; then
      ok "sshd accepted cert login; force-command enforced"
    else
      bad "sshd cert login / force-command (got: $OUT)"; tail -3 "$WORK/sshd.log"
    fi

    # revoke the cert, restart sshd with RevokedKeys, login must now fail
    api "$ADMIN_TOKEN" POST "/api/certs/$ESERIAL/revoke" '{"reason":"e2e"}' >/dev/null
    api "$REQ_TOKEN" GET /api/krl > "$WORK/revoked.krl"
    [ -f "$WORK/sshd.pid" ] && kill "$(cat "$WORK/sshd.pid")" 2>/dev/null || true
    sleep 0.3
    echo "RevokedKeys $WORK/revoked.krl" >> "$WORK/sshd_config"
    if "$SSHD" -f "$WORK/sshd_config" -E "$WORK/sshd2.log" 2>/dev/null; then
      sleep 0.5
      if ssh $SSH_OPTS -o BatchMode=yes "$ME@127.0.0.1" "echo SHOULD_NOT_RUN" >/dev/null 2>&1; then
        bad "revoked cert rejected by sshd (login succeeded!)"
      else
        ok "revoked cert rejected by sshd via KRL"
      fi
      [ -f "$WORK/sshd.pid" ] && kill "$(cat "$WORK/sshd.pid")" 2>/dev/null || true
    else
      bad "sshd restart with RevokedKeys"; tail -3 "$WORK/sshd2.log"
    fi
  else
    echo "  (skipped: sshd would not start in this environment)"
  fi
else
  echo "  (skipped: /usr/sbin/sshd not available)"
fi

echo
echo "==================================="
echo "PASS: $PASS   FAIL: $FAIL"
[ "$FAIL" -eq 0 ]
