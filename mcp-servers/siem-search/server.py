"""Mock SIEM search MCP server."""
import json
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("siem-search")

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

@mcp.tool()
def search_events(entity: str, entity_type: str, time_window: str = "24h") -> str:
    """Search SIEM events for a given entity.

    Args:
        entity: The entity value to search (IP, domain, hash, etc.).
        entity_type: Type of the entity (ip, domain, hash, user).
        time_window: Lookback window (e.g., "24h", "7d").
    """
    results = [
        {
            "timestamp": _now(),
            "event_type": "alert",
            "severity": "high",
            "source": "IDS",
            "message": f"Suspicious activity from {entity}",
            "entity": entity,
            "entity_type": entity_type,
        },
        {
            "timestamp": _now(),
            "event_type": "traffic",
            "severity": "medium",
            "source": "Firewall",
            "message": f"Multiple connection attempts involving {entity}",
            "entity": entity,
            "entity_type": entity_type,
        },
        {
            "timestamp": _now(),
            "event_type": "auth",
            "severity": "low",
            "source": "AD",
            "message": f"Failed login from {entity}",
            "entity": entity,
            "entity_type": entity_type,
        },
    ]
    return json.dumps({"time_window": time_window, "total": len(results), "events": results}, indent=2)

@mcp.tool()
def get_alert_context(alert_id: str) -> str:
    """Retrieve full context for a given alert.

    Args:
        alert_id: The alert identifier.
    """
    context = {
        "alert_id": alert_id,
        "status": "open",
        "created_at": "2026-05-10T08:30:00Z",
        "severity": "high",
        "title": "Potential C2 Communication Detected",
        "description": "Host 192.168.1.100 communicated with known malicious IP.",
        "affected_assets": ["192.168.1.100", "web-server-01"],
        "related_iocs": ["10.0.0.99", "e8f2b3a1c9d4e5f6a7b8c9d0e1f2a3b4"],
        "timeline": [
            {"time": "2026-05-10T08:00:00Z", "event": "Initial connection observed"},
            {"time": "2026-05-10T08:15:00Z", "event": "Data exfiltration suspected"},
            {"time": "2026-05-10T08:30:00Z", "event": "Alert generated"},
        ],
        "recommendations": [
            "Isolate affected host",
            "Block IOC at firewall",
            "Initiate incident response playbook",
        ],
    }
    return json.dumps(context, indent=2)

if __name__ == "__main__":
    mcp.run(transport="sse", host="localhost", port=8102)
