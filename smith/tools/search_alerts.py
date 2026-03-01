"""Search alerts for a term across all text fields."""

import json
import pandas as pd
from tools import state


def search_alerts(search_term, limit=50):
    """
    Search alerts for a term across all text fields.

    Args:
        search_term: Term to search for (case-insensitive)
        limit: Maximum number of results to return

    Returns:
        JSON string with matching alerts
    """
    if state.ALERTS_DF is None:
        return json.dumps({"error": "Alerts data not loaded"})

    try:
        # Search across all string columns
        mask = state.ALERTS_DF.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False).any(), axis=1)
        results = state.ALERTS_DF[mask].head(limit)

        if len(results) == 0:
            return json.dumps({"message": f"No alerts found containing '{search_term}'", "count": 0})

        alerts = []
        for _, row in results.iterrows():
            alerts.append({
                "alert_name": row.get('alert_name', 'N/A'),
                "first_seen": str(row.get('first_seen', 'N/A')),
                "hostname": row.get('hostname', 'N/A'),
                "process": row.get('process', 'N/A'),
                "commandline": row.get('commandline', 'N/A'),
                "details": {k: str(v) for k, v in row.to_dict().items() if pd.notna(v) and str(v) != 'N/A'}
            })

        return json.dumps({
            "search_term": search_term,
            "count": len(alerts),
            "alerts": alerts
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "search_alerts",
    "description": "Search alerts for a specific term across all fields. Use this to find alerts related to specific programs, IPs, commands, or any other text.",
    "input_schema": {
        "type": "object",
        "properties": {
            "search_term": {
                "type": "string",
                "description": "Term to search for (case-insensitive)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results to return (default 50)"
            }
        },
        "required": ["search_term"]
    }
}
