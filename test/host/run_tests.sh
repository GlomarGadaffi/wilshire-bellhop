#!/bin/bash
# littlessh integration tests against a real OpenSSH client
cd "$(dirname "$0")"
PORT=${1:-2222}
OPTS="-p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"
PASS=0; FAIL=0
ok(){ echo "PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "FAIL: $1"; FAIL=$((FAIL+1)); }

pkill -f './harness' 2>/dev/null; sleep 0.3
setsid ./harness $PORT >server.log 2>&1 </dev/null &
SRV=$!
sleep 0.5

# 1. exec with password auth
out=$(timeout 10 sshpass -p hunter2 ssh $OPTS admin@127.0.0.1 "status please" 2>c1.log)
rc=$?
[ "$out" = "exec:status please" ] && [ $rc -eq 0 ] && ok "exec+password (rc=$rc out='$out')" \
  || bad "exec+password (rc=$rc out='$out')"

# 2. exit status propagation (harness exits 0; check a clean rc again w/ banner visible)
grep -q "authorized use only" c1.log && ok "userauth banner delivered" || bad "banner missing"

# 3. wrong password rejected
timeout 10 sshpass -p wrong ssh $OPTS -o NumberOfPasswordPrompts=1 admin@127.0.0.1 true 2>/dev/null
[ $? -ne 0 ] && ok "wrong password rejected" || bad "wrong password accepted!"

# 4. interactive shell with pty
out=$(printf 'hello world\rexit\r' | timeout 10 sshpass -p hunter2 ssh -tt $OPTS admin@127.0.0.1 2>/dev/null)
echo "$out" | grep -q "echo:hello world" && echo "$out" | grep -q "bye" \
  && ok "interactive pty shell" || bad "interactive pty shell: '$out'"

# 5. ECDSA publickey auth
rm -f id_ecdsa id_ecdsa.pub
ssh-keygen -q -t ecdsa -b 256 -N "" -f id_ecdsa
out=$(timeout 10 ssh $OPTS -i id_ecdsa -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no keyuser@127.0.0.1 "whoami-test" 2>c5.log)
[ "$out" = "exec:whoami-test" ] && ok "ecdsa publickey auth" || { bad "ecdsa publickey auth: '$out'"; tail -3 c5.log; }

# 6. unauthorized key for wrong user falls through and fails
timeout 10 ssh $OPTS -i id_ecdsa -o IdentitiesOnly=yes -o PasswordAuthentication=no \
   -o KbdInteractiveAuthentication=no nobody@127.0.0.1 true 2>/dev/null
[ $? -ne 0 ] && ok "unauthorized key rejected" || bad "unauthorized key accepted!"

# 7. larger-than-window output (exercise fragmentation): exec returns short,
#    so push via interactive: send a line, expect echo, plus 100 more lines
big=$(python3 -c "print('x'*200)")
out=$(printf "$big\rexit\r" | timeout 10 sshpass -p hunter2 ssh -tt $OPTS admin@127.0.0.1 2>/dev/null)
echo "$out" | grep -q "echo:$big" && ok "long line round-trip" || bad "long line round-trip"

kill $SRV 2>/dev/null
pkill -f './harness' 2>/dev/null
echo "=== server.log ==="; tail -20 server.log
echo "RESULT: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
