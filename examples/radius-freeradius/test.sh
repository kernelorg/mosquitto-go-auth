#!/usr/bin/env bash
# End-to-end check of the RADIUS backend against FreeRADIUS.
set -uo pipefail
cd "$(dirname "$0")"

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; failures=$((failures + 1)); }

# Run a shell snippet in the client container (the broker image has no shell).
mq() { docker compose run --rm -T --no-deps client "$*"; }

../../build-image.sh linux/amd64 mosquitto-go-auth-radius:local || exit 1
docker compose up -d || exit 1

echo "waiting for the broker..."
for _ in $(seq 1 30); do
	mq "mosquitto_pub -h mosquitto -u mqttadmin -P adminpass -t probe -m 1" >/dev/null 2>&1 && break
	sleep 1
done

# 1. sensor1 publishes to its own topic; the superuser receives it.
out=$(mq 'mosquitto_sub -h mosquitto -u mqttadmin -P adminpass -t "sensors/#" -C 1 -W 10 & sleep 1; \
	mosquitto_pub -h mosquitto -u sensor1 -P sensorpass -i sensor1-dev -t sensors/sensor1/temp -m 21.5; wait')
[ "$out" = "21.5" ] && pass "sensor1 published 21.5 to sensors/sensor1/temp, mqttadmin received it" \
	|| fail "expected payload 21.5, got: '$out'"

# 2. Wrong password is rejected by RADIUS.
out=$(mq 'mosquitto_pub -h mosquitto -u sensor1 -P wrong -t sensors/sensor1/temp -m 1' 2>&1)
echo "$out" | grep -qi "not authori[sz]ed" && pass "wrong password rejected: $out" || fail "wrong password accepted: $out"

# 3. Unknown user is rejected.
out=$(mq 'mosquitto_pub -h mosquitto -u nobody -P nothing -t sensors/x -m 1' 2>&1)
echo "$out" | grep -qi "not authori[sz]ed" && pass "unknown user rejected" || fail "unknown user accepted: $out"

# 4. ACL from Filter-Id: publishing to another user's topic is refused (MQTT v5 reason code).
out=$(mq 'mosquitto_pub -h mosquitto -V 5 -q 1 -d -u sensor1 -P sensorpass -t sensors/other/temp -m 1' 2>&1)
echo "$out" | grep -q "Not authorized" && pass "sensor1 denied on sensors/other/temp" || fail "sensor1 could publish to sensors/other/temp: $out"

# 5. Explicit deny rule wins over readwrite.
out=$(mq 'mosquitto_pub -h mosquitto -V 5 -q 1 -d -u sensor1 -P sensorpass -t sensors/sensor1/private -m 1' 2>&1)
echo "$out" | grep -q "Not authorized" && pass "sensor1 denied on sensors/sensor1/private" || fail "deny rule ignored: $out"

# 6. Group file: sensor2 has no Filter-Id, only Mikrotik-Group=sensors.
out=$(mq 'mosquitto_sub -h mosquitto -u sensor2 -P sensorpass -t "sensors/sensor2/#" -C 1 -W 10 & sleep 1; \
	mosquitto_pub -h mosquitto -u sensor2 -P sensorpass -t sensors/sensor2/hum -m 55; wait')
[ "$out" = "55" ] && pass "sensor2 authorized through the group file" || fail "group file rules not applied, got: '$out'"

# 7. Common rule from the group file: everybody may read broadcast/#.
out=$(mq 'mosquitto_sub -h mosquitto -u sensor1 -P sensorpass -t "broadcast/#" -C 1 -W 10 & sleep 1; \
	mosquitto_pub -h mosquitto -u mqttadmin -P adminpass -t broadcast/hello -m hi; wait')
[ "$out" = "hi" ] && pass "sensor1 received broadcast/hello" || fail "common rule not applied, got: '$out'"

# 8. Subscribing to a topic outside the rules yields nothing.
out=$(mq 'mosquitto_sub -h mosquitto -u sensor1 -P sensorpass -t "sensors/other/#" -C 1 -W 4 & sleep 1; \
	mosquitto_pub -h mosquitto -u mqttadmin -P adminpass -t sensors/other/temp -m secret; wait' 2>/dev/null)
[ -z "$out" ] && pass "sensor1 cannot read sensors/other/#" || fail "sensor1 read a foreign topic: '$out'"

# 9. Websockets listener (conf.d/websockets.conf): a real HTTP upgrade handshake on 9001 must answer 101.
out=$(mq 'printf "GET /mqtt HTTP/1.1\r\nHost: mosquitto\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n" | nc -w 3 mosquitto 9001 | head -1' 2>/dev/null | tr -d "\r")
echo "$out" | grep -q "101" && pass "websockets handshake on 9001: $out" || fail "websockets handshake on 9001 failed: '$out'"

echo
if [ "$failures" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "$failures CHECK(S) FAILED"; fi
exit "$failures"
