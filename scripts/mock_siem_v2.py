"""Mock SIEM v2 — 生产级模拟数据，支持分页和多轮轮询。

Usage: python scripts/mock_siem_v2.py [port]

模拟场景：
  Poll #1 (page 0-1): 8 条端点告警 + 2 条网络告警 + 1 条邮件告警
    - endpoint 告警共享 process_hash + hostname，不同 src_ip
    - 部分 endpoint 告警 src_ip 为列表（多个 IP）
    - network 告警有不同 dst_ip
    - email 告警独立
  Poll #2 (增量): 3 条新端点告警（与 Poll #1 的第二个分组重叠）
    - 测试跨轮次合并 + 取代逻辑
  Poll #3+: 无新告警

"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Poll #1: 生产场景（11 条告警） ──
POLL1_ALERTS = [
    # ── 端点告警组 1（共享 process_hash=abc123, hostname=prod-db-01，不同 src_ip） ──
    {"id":"ep-001","created_at":"2026-05-14T09:00:01Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.45.1","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},
    {"id":"ep-002","created_at":"2026-05-14T09:00:15Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.45.2","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},
    {"id":"ep-003","created_at":"2026-05-14T09:00:30Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.45.3","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},
    {"id":"ep-004","created_at":"2026-05-14T09:00:45Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.45.4","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},
    {"id":"ep-005","created_at":"2026-05-14T09:01:00Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.45.5","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},

    # ── 端点告警组 2（不同的 process_hash 和 hostname） ──
    {"id":"ep-006","created_at":"2026-05-14T09:02:00Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.99.1","dst_ip":"10.0.0.1","process_name":"rundll32.exe","process_hash":"deadbeef0001","hostname":"web-server-01"}},
    {"id":"ep-007","created_at":"2026-05-14T09:02:15Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.99.2","dst_ip":"10.0.0.1","process_name":"rundll32.exe","process_hash":"deadbeef0001","hostname":"web-server-01"}},
    {"id":"ep-008","created_at":"2026-05-14T09:02:30Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.99.3","dst_ip":"10.0.0.1","process_name":"rundll32.exe","process_hash":"deadbeef0001","hostname":"web-server-01"}},

    # ── 网络告警（独立） ──
    {"id":"net-001","created_at":"2026-05-14T09:03:00Z","defense_line":"network","name":"Network_C2_Communication","raw_evidence":{"src_ip":"10.23.45.1","dst_ip":"203.0.113.99","process_name":"powershell.exe","process_hash":"abc123def456"}},
    {"id":"net-002","created_at":"2026-05-14T09:03:15Z","defense_line":"network","name":"Network_C2_Communication","raw_evidence":{"src_ip":"10.23.45.1","dst_ip":"203.0.113.100","process_name":"powershell.exe","process_hash":"abc123def456"}},

    # ── src_ip 为列表的端点告警（测试列表支持） ──
    {"id":"ep-009","created_at":"2026-05-14T09:04:00Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":["10.23.50.1","10.23.50.2","10.23.50.3"],"dst_ip":"192.168.1.100","process_name":"wscript.exe","process_hash":"cafebabe9999","hostname":"app-server-01"}},

    # ── 邮件告警（独立防线） ──
    {"id":"email-001","created_at":"2026-05-14T09:05:00Z","defense_line":"email","name":"Email_Phishing_Link_Click","raw_evidence":{"src_ip":"198.51.100.1","target_user":"zhangsan@corp.com","url":"http://evil.com/phish","subject":"Invoice Payment Required"}},
]

# ── Poll #2: 增量（3 条新告警，与分组 2 重叠） ──
POLL2_ALERTS = [
    {"id":"ep-010","created_at":"2026-05-14T09:10:00Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.99.4","dst_ip":"10.0.0.1","process_name":"rundll32.exe","process_hash":"deadbeef0001","hostname":"web-server-01"}},
    {"id":"ep-011","created_at":"2026-05-14T09:10:15Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","raw_evidence":{"src_ip":"10.23.99.5","dst_ip":"10.0.0.1","process_name":"rundll32.exe","process_hash":"deadbeef0001","hostname":"web-server-01"}},
    {"id":"net-003","created_at":"2026-05-14T09:11:00Z","defense_line":"network","name":"Network_C2_Communication","raw_evidence":{"src_ip":"10.23.99.1","dst_ip":"203.0.113.200","process_name":"rundll32.exe","process_hash":"deadbeef0001"}},
]

_request_count = {"value": 0}


class MockSiemV2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "/api/v1/alerts" in self.path:
            _request_count["value"] += 1
            count = _request_count["value"]

            if count == 1:
                alerts = POLL1_ALERTS
            elif count == 2:
                alerts = POLL2_ALERTS
            else:
                alerts = []

            # 模拟分页（page 0 返回首页，page 1 返回空）
            page = 0
            size = len(alerts)

            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            page = int(qs.get("page", [0])[0])
            psize = int(qs.get("size", [100])[0])

            start = page * psize
            items = alerts[start:start + psize]

            self._json(200, {"items": items, "total": len(alerts)})
        elif "/health" in self.path:
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"  [mock-siem] {args[0]}")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    server = HTTPServer(("0.0.0.0", port), MockSiemV2Handler)
    print(f"Mock SIEM v2 on :{port} (production-like data)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
