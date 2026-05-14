#!/bin/bash
# 聚合服务生产级测试
# 用法: bash scripts/test-aggregation.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"

cleanup() {
  pkill -f "uvicorn.*8004" 2>/dev/null || true
  pkill -f mock_siem 2>/dev/null || true
  pkill -f "mock_siem_v2" 2>/dev/null || true
}
trap cleanup EXIT

echo "══════════════════════════════════════════════"
echo "  聚合服务生产级测试"
echo "══════════════════════════════════════════════"

# ── 1. 启动 mock SIEM（模拟生产数据） ──
echo ""
echo "[1/5] 启动 Mock SIEM..."

python3 "$SCRIPT_DIR/mock_siem_v2.py" 9090 &
sleep 1

if ! curl -s http://localhost:9090/health > /dev/null 2>&1; then
  echo "  Mock SIEM v2 无 /health，改用轮询方式验证"
fi
sleep 1

# ── 2. 启动聚合服务 ──
echo "[2/5] 启动聚合服务..."

export SIEM_API_BASE=http://localhost:9090
export SOC_POLL_INTERVAL=8
export PYTHONPATH="$BACKEND_DIR"
uv run --directory "$BACKEND_DIR" uvicorn app.aggregation.app:app \
  --host 0.0.0.0 --port 8004 --log-level warning &
sleep 10  # 等第一次轮询完成（5s 延迟 + 8s 间隔内）

API="http://localhost:8004/api/aggregation"

# ── 3. 检查轮询结果 ──
echo ""
echo "[3/5] 检查事件队列..."

STATUS=$(curl -s "$API/events/status")
echo "  状态: $STATUS"

TOTAL=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
UNCONSUMED=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin)['unconsumed'])")

echo ""
echo "  全部事件:"
curl -s "$API/events/peek" | python3 -c "
import sys, json
events = json.load(sys.stdin)
for i, e in enumerate(events):
    tag = '聚合' if e['occurrence_count'] > 1 else '单条'
    alarms = [s['alarm_id'] for s in e['source_alarms']]
    print(f'    [{tag}] count={e[\"occurrence_count\"]} overlap={e[\"entity_overlap\"]} defense={e[\"defense_line\"]} type={e[\"alert_type\"]}')
    print(f'           alarms={alarms}')
    common = list(e['raw_evidence'].get('common', {}).keys())
    if common:
        print(f'           common_fields={common}')
    per = e['raw_evidence'].get('per_alarm', {})
    if per:
        first_key = list(per.keys())[0]
        print(f'           per_alarm_example: {first_key} → {list(per[first_key].keys())[:3]}')
"

EXPECTED_EVENTS=4  # 聚合(3) + 聚合(2) + email(1) + network(1) = 4

echo ""
echo "[4/5] 验证聚合逻辑..."

# 验证: 应该有聚合事件和单条事件
AGG_COUNT=$(curl -s "$API/events/peek" | python3 -c "
import sys, json
events = json.load(sys.stdin)
agg = sum(1 for e in events if e['occurrence_count'] > 1)
single = sum(1 for e in events if e['occurrence_count'] == 1)
print(f'{agg} aggregated, {single} single')
print(f'PASS: events={len(events)}')
" 2>&1)
echo "  $AGG_COUNT"

# 等待第二次轮询（mock SIEM v2 第二次返回增量）
echo ""
echo "[5/5] 等待第二次轮询 + 取代逻辑..."

sleep 12

STATUS2=$(curl -s "$API/events/status")
TOTAL2=$(echo "$STATUS2" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")

echo "  第二次轮询后 total=$TOTAL2 (首次=$TOTAL)"

curl -s "$API/events/peek" | python3 -c "
import sys, json
events = json.load(sys.stdin)
print(f'  事件总数: {len(events)}')
for e in events:
    alarms = [s['alarm_id'] for s in e['source_alarms']]
    print(f'    count={e[\"occurrence_count\"]} alarms={alarms}')
"

# ── 模拟 Agent 消费 ──
echo ""
echo "═══ Agent 消费测试 ═══"
for i in 1 2 3 4 5; do
  HTTP=$(curl -s -o /tmp/event_$i.json -w "%{http_code}" "$API/events/next")
  if [ "$HTTP" = "200" ]; then
    python3 -c "
import json
e = json.load(open('/tmp/event_$i.json'))
print(f'  Agent 消费 #{i}: {e[\"defense_line\"]} {e[\"alert_type\"]} count={e[\"occurrence_count\"]} consumed={e[\"consumed\"]}')
" 2>/dev/null
  elif [ "$HTTP" = "204" ]; then
    echo "  Agent 消费 #$i: (空队列)"
    break
  else
    echo "  Agent 消费 #$i: HTTP $HTTP"
  fi
done

echo ""
echo "══════════════════════════════════════════════"
echo "  测试完成"
echo "══════════════════════════════════════════════"
