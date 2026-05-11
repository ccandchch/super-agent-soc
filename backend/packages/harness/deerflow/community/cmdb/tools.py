import json
import httpx
from langchain.tools import tool
from deerflow.config import get_app_config

@tool("query_asset", parse_docstring=True)
def query_asset_tool(query: str) -> str:
    """Query CMDB for asset information by IP address or hostname.

    Args:
        query: IP address or hostname to look up.
    """
    config = get_app_config().get_tool_config("query_asset")
    api_base_url = config.model_extra.get("api_base_url") if config else None
    api_key = config.model_extra.get("api_key") if config else None

    if not api_base_url:
        return json.dumps({
            "asset_id": f"asset-{query}",
            "hostname": query,
            "business_criticality": "high",
            "department": "Engineering",
            "network_zone": "internal-db",
            "patch_status": "latest",
            "owner": "ops-team",
        }, indent=2, ensure_ascii=False)

    try:
        resp = httpx.get(
            f"{api_base_url}/api/v1/assets/lookup",
            params={"q": query},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)})
