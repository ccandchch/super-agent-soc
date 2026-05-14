"""Mock SIEM API — returns test alerts for aggregation testing.

Usage: python scripts/mock_siem.py [port]
Defaults to port 9090.
"""

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

MOCK_ALERTS = [
    {
        "id": "siem-001", "created_at": "2026-05-12T10:00:01Z",
        "defense_line": "endpoint", "name": "Endpoint_Abnormal_Process_Outbound",
        "raw_evidence": {"src_ip": "10.23.45.1", "dst_ip": "192.168.1.100", "process_name": "powershell.exe", "process_hash": "abc123def456", "hostname": "prod-db-01"},
    },
    {
        "id": "siem-002", "created_at": "2026-05-12T10:00:15Z",
        "defense_line": "endpoint", "name": "Endpoint_Abnormal_Process_Outbound",
        "raw_evidence": {"src_ip": "10.23.45.2", "dst_ip": "192.168.1.100", "process_name": "powershell.exe", "process_hash": "abc123def456", "hostname": "prod-db-01"},
    },
    {
        "id": "siem-003", "created_at": "2026-05-12T10:00:30Z",
        "defense_line": "endpoint", "name": "Endpoint_Abnormal_Process_Outbound",
        "raw_evidence": {"src_ip": "10.23.45.3", "dst_ip": "192.168.1.100", "process_name": "powershell.exe", "process_hash": "abc123def456", "hostname": "prod-db-01"},
    },
    {
        "id": "siem-004", "created_at": "2026-05-12T10:00:45Z",
        "defense_line": "endpoint", "name": "Endpoint_Abnormal_Process_Outbound",
        "raw_evidence": {"src_ip": "10.23.45.4", "dst_ip": "192.168.1.100", "process_name": "powershell.exe", "process_hash": "abc123def456", "hostname": "prod-db-01"},
    },
    {
        "id": "siem-005", "created_at": "2026-05-12T10:01:00Z",
        "defense_line": "endpoint", "name": "Endpoint_Abnormal_Process_Outbound",
        "raw_evidence": {"src_ip": "10.23.45.5", "dst_ip": "192.168.1.100", "process_name": "powershell.exe", "process_hash": "abc123def456", "hostname": "prod-db-01"},
    },
    # Different alert — should NOT be aggregated with the above
    {
        "id": "siem-006", "created_at": "2026-05-12T10:01:15Z",
        "defense_line": "email", "name": "Email_Phishing_Link_Click",
        "raw_evidence": {"src_ip": "10.99.99.99", "target_user": "zhangsan@corp.com", "url": "http://evil.com/phish"},
    },
]

_request_count = {"value": 0}


class MockSiemHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/v1/alerts"):
            page = 0
            size = 100
            _request_count["value"] += 1
            count = _request_count["value"]

            # First poll returns 5 endpoint alerts, second poll returns the email alert
            if count == 1:
                alerts = MOCK_ALERTS[:5]
            elif count == 2:
                alerts = MOCK_ALERTS[5:]
            else:
                alerts = []

            resp = {"items": alerts[page * size : (page + 1) * size], "total": len(alerts)}
            self._json(200, resp)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        self._json(200, {"status": "ok"})

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"[mock-siem] {args[0]}")


if __name__ == "__main__":
    port = int(__import__("sys").argv[1]) if len(__import__("sys").argv) > 1 else 9090
    server = HTTPServer(("0.0.0.0", port), MockSiemHandler)
    print(f"Mock SIEM API running on http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
