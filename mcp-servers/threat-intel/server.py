"""Mock threat intelligence MCP server."""
import json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("threat-intel")

MOCK_DATA = {
    "malicious": {"verdict": "malicious", "confidence": 0.95, "sources": ["VT", "AlienVault"], "tags": ["emotet", "trojan"], "last_seen": "2026-05-10T10:00:00Z"},
    "suspicious": {"verdict": "suspicious", "confidence": 0.60, "sources": ["AbuseIPDB"], "tags": ["scanner"], "last_seen": "2026-05-09T00:00:00Z"},
    "clean": {"verdict": "clean", "confidence": 0.98, "sources": ["VT"], "tags": [], "last_seen": "2026-05-10T12:00:00Z"},
    "unknown": {"verdict": "unknown", "confidence": 0.0, "sources": [], "tags": [], "last_seen": None},
}

def _mock(input_str: str) -> dict:
    return list(MOCK_DATA.values())[hash(input_str) % 4]

@mcp.tool()
def query_ip(ip: str) -> str:
    result = _mock(ip)
    result["geo"] = {"country": "US", "city": "New York"}
    return json.dumps(result, indent=2)

@mcp.tool()
def query_hash(hash_value: str) -> str:
    result = _mock(hash_value)
    result["family"] = "emotet" if result["verdict"] == "malicious" else None
    result["first_seen"] = "2026-01-15T00:00:00Z"
    return json.dumps(result, indent=2)

@mcp.tool()
def query_domain(domain: str) -> str:
    result = _mock(domain)
    result["category"] = "malware" if result["verdict"] == "malicious" else "business"
    return json.dumps(result, indent=2)

@mcp.tool()
def query_url(url: str) -> str:
    result = _mock(url)
    result["category"] = "phishing" if result["verdict"] == "malicious" else "benign"
    return json.dumps(result, indent=2)

if __name__ == "__main__":
    mcp.run(transport="sse", host="localhost", port=8101)
