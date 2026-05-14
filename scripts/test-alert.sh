#!/bin/bash
# SOC 告警测试脚本
# 用法: bash scripts/test-alert.sh [alarm_id]

set -e

ALARM_ID="${1:-test-$(date +%s)}"
BASE="http://localhost:2026"
EMAIL="admin@soc-triage.com"
PASSWORD="S0cTr1age!2026"

echo "=== 1. 登录 ==="
LOGIN=$(curl -s -D - -X POST "$BASE/api/v1/auth/login/local" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$EMAIL&password=$PASSWORD")

CSRF=$(echo "$LOGIN" | grep -o 'csrf_token=[^;]*' | cut -d= -f2)
ACCESS=$(echo "$LOGIN" | grep -o 'access_token=[^;]*' | cut -d= -f2)

if [ -z "$ACCESS" ]; then
  echo "  注册新用户..."
  curl -s -X POST "$BASE/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"name\":\"Admin\"}" > /dev/null
  LOGIN=$(curl -s -D - -X POST "$BASE/api/v1/auth/login/local" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$EMAIL&password=$PASSWORD")
  CSRF=$(echo "$LOGIN" | grep -o 'csrf_token=[^;]*' | cut -d= -f2)
  ACCESS=$(echo "$LOGIN" | grep -o 'access_token=[^;]*' | cut -d= -f2)
fi
echo "  OK"

AUTH=(-H "X-CSRF-Token: $CSRF" -b "access_token=$ACCESS; csrf_token=$CSRF")

echo "=== 2. 发送告警: $ALARM_ID ==="
curl -s -X POST "$BASE/api/soc/webhooks/siem_splunk" \
  -H "Content-Type: application/json" \
  "${AUTH[@]}" \
  -d "{
    \"alarm_id\": \"$ALARM_ID\",
    \"alert_time\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"defense_line\": \"endpoint\",
    \"alert_name\": \"Endpoint_Abnormal_Process_Outbound\",
    \"raw_evidence\": {
      \"src_ip\": \"10.23.45.$((RANDOM % 255))\",
      \"dst_ip\": \"192.168.1.100\",
      \"process_name\": \"powershell.exe\",
      \"process_hash\": \"$(uuidgen | tr -d - | head -c 12)\"
    }
  }" | python3 -m json.tool

echo ""
echo "=== 3. 等待研判 (10s) ==="
sleep 10

echo "=== 4. 日志 ==="
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
tail -20 "$SCRIPT_DIR/../logs/gateway.log" | grep -iE "run.*success|run.*error|dispatch|anthropic|deepseek|model|403" || echo "  (无匹配日志，查看完整日志: tail -50 logs/gateway.log)"

echo ""
echo "=== 5. 前端查看 ==="
echo "  http://localhost:2026/workspace/soc/alerts"
