"""Mock sandbox MCP server."""
import json
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sandbox")

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

@mcp.tool()
def get_report(hash_value: str) -> str:
    """Retrieve a sandbox analysis report for a file hash.

    Args:
        hash_value: SHA-256 hash of the file.
    """
    report = {
        "hash": hash_value,
        "analysis_date": "2026-05-10T09:00:00Z",
        "environment": "Windows 10 x64",
        "verdict": "malicious",
        "score": 8.5,
        "behaviors": [
            {"category": "persistence", "description": "Created scheduled task", "severity": "high"},
            {"category": "network", "description": "HTTP POST to C2 server", "severity": "high"},
            {"category": "process", "description": "Injected into svchost.exe", "severity": "critical"},
            {"category": "file", "description": "Dropped payload in AppData", "severity": "medium"},
        ],
        "network_connections": [
            {"ip": "203.0.113.50", "port": 443, "protocol": "HTTPS", "domain": "evil-c2.example.com"},
        ],
        "mutexes": ["Global\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"],
        "dropped_files": ["C:\\Users\\admin\\AppData\\Local\\Temp\\payload.dll"],
        "screenshots_available": True,
    }
    return json.dumps(report, indent=2)

@mcp.tool()
def submit_file(file_path: str) -> str:
    """Submit a file for sandbox analysis.

    Args:
        file_path: Path to the file to analyze.
    """
    response = {
        "task_id": "task-20260510-001",
        "file_path": file_path,
        "status": "submitted",
        "submitted_at": _now(),
        "estimated_completion": "5 minutes",
        "message": "File submitted for analysis. Use get_report() with the hash to retrieve results.",
    }
    return json.dumps(response, indent=2)

if __name__ == "__main__":
    mcp.run(transport="sse", host="localhost", port=8103)
