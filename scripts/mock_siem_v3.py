"""Mock SIEM v3 — 20 条多样化告警，覆盖 6 条防线。

场景分布:
  endpoint ×8:  4组恶意软件(不同hash/host) + 1条勒索 + 1条列表IP + 1条Webshell
  network ×4:   2组C2通信 + 1条端口扫描(单条)
  email ×3:     2条钓鱼链接(同域名) + 1条恶意附件(独立)
  account ×3:   2条爆破(同用户) + 1条异地登录(独立)
  server ×1:    权限提升
  app ×1:       SQL注入
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

ALERTS = [
    # ══════ 终端 — 恶意软件组1 (Emotet, prod-db) ══════
    {"id":"ep-001","created_at":"2026-05-16T08:00:01Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","severity":"high","raw_evidence":{"src_ip":"10.23.45.1","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},
    {"id":"ep-002","created_at":"2026-05-16T08:00:15Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","severity":"high","raw_evidence":{"src_ip":"10.23.45.2","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},
    {"id":"ep-003","created_at":"2026-05-16T08:00:30Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","severity":"high","raw_evidence":{"src_ip":"10.23.45.3","dst_ip":"192.168.1.100","process_name":"powershell.exe","process_hash":"abc123def456","hostname":"prod-db-01"}},

    # ══════ 终端 — 恶意软件组2 (CobaltStrike, web-server) ══════
    {"id":"ep-004","created_at":"2026-05-16T08:02:00Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","severity":"high","raw_evidence":{"src_ip":"10.23.99.1","dst_ip":"10.0.0.1","process_name":"rundll32.exe","process_hash":"deadbeef0001","hostname":"web-server-01"}},
    {"id":"ep-005","created_at":"2026-05-16T08:02:15Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","severity":"high","raw_evidence":{"src_ip":"10.23.99.2","dst_ip":"10.0.0.1","process_name":"rundll32.exe","process_hash":"deadbeef0001","hostname":"web-server-01"}},

    # ══════ 终端 — 恶意软件组3 (列表src_ip, app-server) ══════
    {"id":"ep-006","created_at":"2026-05-16T08:04:00Z","defense_line":"endpoint","name":"Endpoint_Abnormal_Process_Outbound","severity":"high","raw_evidence":{"src_ip":["10.23.50.1","10.23.50.2","10.23.50.3"],"dst_ip":"192.168.1.100","process_name":"wscript.exe","process_hash":"cafebabe9999","hostname":"app-server-01"}},

    # ══════ 终端 — 勒索软件 (单条) ══════
    {"id":"ep-007","created_at":"2026-05-16T08:06:00Z","defense_line":"endpoint","name":"Endpoint_Ransomware_Detected","severity":"critical","raw_evidence":{"src_ip":"10.23.10.99","process_name":"encryptor.exe","process_hash":"ransom111222","hostname":"file-server-01","file_extension":".locked"}},

    # ══════ 终端 — Webshell上传 (单条, 不同告警名) ══════
    {"id":"ep-008","created_at":"2026-05-16T08:08:00Z","defense_line":"endpoint","name":"Endpoint_Webshell_Detected","severity":"high","raw_evidence":{"src_ip":"10.23.20.50","dst_ip":"10.23.20.1","process_name":"cmd.exe","process_hash":"shell999000","hostname":"web-server-02","file_path":"/var/www/html/upload/shell.php"}},

    # ══════ 网络 — C2通信组1 (powershell出站) ══════
    {"id":"net-001","created_at":"2026-05-16T08:10:00Z","defense_line":"network","name":"Network_C2_Communication","severity":"high","raw_evidence":{"src_ip":"10.23.45.1","dst_ip":"203.0.113.99","src_port":"49152","dst_port":"443","protocol":"tcp","process_hash":"abc123def456"}},
    {"id":"net-002","created_at":"2026-05-16T08:10:30Z","defense_line":"network","name":"Network_C2_Communication","severity":"high","raw_evidence":{"src_ip":"10.23.45.1","dst_ip":"203.0.113.100","src_port":"49153","dst_port":"443","protocol":"tcp","process_hash":"abc123def456"}},

    # ══════ 网络 — C2通信组2 (rundll32出站) ══════
    {"id":"net-003","created_at":"2026-05-16T08:12:00Z","defense_line":"network","name":"Network_C2_Communication","severity":"high","raw_evidence":{"src_ip":"10.23.99.1","dst_ip":"198.51.100.50","src_port":"50000","dst_port":"8080","protocol":"tcp","process_hash":"deadbeef0001"}},
    {"id":"net-004","created_at":"2026-05-16T08:12:30Z","defense_line":"network","name":"Network_C2_Communication","severity":"high","raw_evidence":{"src_ip":"10.23.99.2","dst_ip":"198.51.100.51","src_port":"50001","dst_port":"8080","protocol":"tcp","process_hash":"deadbeef0001"}},

    # ══════ 网络 — 端口扫描 (单条) ══════
    {"id":"net-005","created_at":"2026-05-16T08:14:00Z","defense_line":"network","name":"Network_Port_Scan","severity":"medium","raw_evidence":{"src_ip":"10.23.200.1","dst_ip":["10.23.1.1","10.23.1.2","10.23.1.3"],"scanned_ports":"22,80,443,3306,6379"}},

    # ══════ 邮件 — 钓鱼链接组 (同域名) ══════
    {"id":"email-001","created_at":"2026-05-16T08:16:00Z","defense_line":"email","name":"Email_Phishing_Link_Click","severity":"high","raw_evidence":{"src_ip":"198.51.100.1","target_user":"zhangsan@corp.com","url":"http://evil.com/phish/login","domain":"evil.com","subject":"Password Reset Required"}},
    {"id":"email-002","created_at":"2026-05-16T08:16:30Z","defense_line":"email","name":"Email_Phishing_Link_Click","severity":"high","raw_evidence":{"src_ip":"198.51.100.2","target_user":"lisi@corp.com","url":"http://evil.com/phish/invoice","domain":"evil.com","subject":"Invoice Overdue"}},

    # ══════ 邮件 — 恶意附件 (单条, 不同于钓鱼) ══════
    {"id":"email-003","created_at":"2026-05-16T08:18:00Z","defense_line":"email","name":"Email_Malicious_Attachment","severity":"high","raw_evidence":{"src_ip":"203.0.113.50","target_user":"wangwu@corp.com","attachment_name":"invoice.exe","attachment_hash":"malware111222","subject":"Your Invoice #12345"}},

    # ══════ 账号 — 暴力破解组 (同用户) ══════
    {"id":"acct-001","created_at":"2026-05-16T08:20:00Z","defense_line":"account","name":"Account_Brute_Force","severity":"medium","raw_evidence":{"src_ip":"10.99.99.1","target_user":"admin","auth_service":"VPN","attempt_count":"500","status":"locked"}},
    {"id":"acct-002","created_at":"2026-05-16T08:20:30Z","defense_line":"account","name":"Account_Brute_Force","severity":"medium","raw_evidence":{"src_ip":"10.99.99.2","target_user":"admin","auth_service":"VPN","attempt_count":"300","status":"locked"}},

    # ══════ 账号 — 异地登录 (单条) ══════
    {"id":"acct-003","created_at":"2026-05-16T08:22:00Z","defense_line":"account","name":"Account_Impossible_Travel","severity":"high","raw_evidence":{"src_ip":"8.8.8.8","target_user":"ceo@corp.com","location_from":"Beijing","location_to":"Moscow","time_delta_hours":"2"}},

    # ══════ 服务器 — 权限提升 ══════
    {"id":"srv-001","created_at":"2026-05-16T08:24:00Z","defense_line":"server","name":"Server_Privilege_Escalation","severity":"critical","raw_evidence":{"src_ip":"10.23.30.1","hostname":"dc-01","target_user":"NT AUTHORITY\\SYSTEM","method":"Token Manipulation","process_name":"cmd.exe","process_hash":"esc111222333"}},

    # ══════ 应用 — SQL注入 ══════
    {"id":"app-001","created_at":"2026-05-16T08:26:00Z","defense_line":"application","name":"App_SQL_Injection","severity":"high","raw_evidence":{"src_ip":"10.23.40.1","dst_ip":"10.23.40.100","url":"/api/users?id=1' OR '1'='1","method":"GET","user_agent":"sqlmap/1.6","status":"403"}},
]

_request_count = {"value": 0}


class MockSiemV3Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "/api/v1/alerts" in self.path:
            _request_count["value"] += 1
            count = _request_count["value"]

            if count == 1:
                alerts = ALERTS
            else:
                alerts = []

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
        print(f"  [siem] {args[0]}")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    server = HTTPServer(("0.0.0.0", port), MockSiemV3Handler)
    print(f"Mock SIEM v3 on :{port} (20 alerts, 6 defense lines)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
