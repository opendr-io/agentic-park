"""Query security alerts by name, hostname, or time range."""

import json
import pandas as pd
from tools import state


def query_alerts(alert_name=None, hostname=None, start_time=None, end_time=None, limit=50):
    """
    Query security alerts.

    Args:
        alert_name: Optional alert name to filter (partial match, case-insensitive)
        hostname: Optional hostname to filter
        start_time: Optional start timestamp (YYYY-MM-DD HH:MM:SS)
        end_time: Optional end timestamp (YYYY-MM-DD HH:MM:SS)
        limit: Maximum number of alerts to return (default 50)

    Returns:
        JSON string with alert details
    """
    if state.ALERTS_DF is None:
        return json.dumps({"error": "Alerts data not loaded"})

    try:
        results = state.ALERTS_DF.copy()

        # Filter by alert name
        if alert_name:
            results = results[results['alert_name'].str.contains(alert_name, case=False, na=False)]

        # Filter by hostname
        if hostname:
            results = results[results['hostname'] == hostname]

        # Filter by time range
        if start_time:
            results = results[pd.to_datetime(results['first_seen']) >= pd.to_datetime(start_time)]
        if end_time:
            results = results[pd.to_datetime(results['last_seen']) <= pd.to_datetime(end_time)]

        # Sort by first_seen
        results = results.sort_values('first_seen', ascending=False)

        # Limit results
        results = results.head(limit)

        if len(results) == 0:
            return json.dumps({"message": "No alerts found matching criteria", "count": 0})

        # Format output
        alerts = []
        for _, row in results.iterrows():
            alert = {
                "alert_name": row.get('alert_name', 'N/A'),
                "first_seen": str(row.get('first_seen', 'N/A')),
                "last_seen": str(row.get('last_seen', 'N/A')),
                "hostname": row.get('hostname', 'N/A'),
                "process": row.get('process', 'N/A'),
                "commandline": row.get('commandline', 'N/A'),
                "user": row.get('username', 'N/A')
            }

            # Add optional fields if present
            for field, key in [
                ('processid', 'processid'),
                ('pid', 'pid'),
                ('destinationip', 'destination_ip'),
                ('destinationport', 'destination_port'),
                ('sourceip', 'source_ip'),
                ('sourceport', 'source_port'),
                ('parentimage', 'parent_image'),
                ('parentprocessid', 'parent_processid'),
                ('servicename', 'servicename'),
            ]:
                if pd.notna(row.get(field)):
                    alert[key] = row.get(field, 'N/A')

            alerts.append(alert)

        return json.dumps({
            "count": len(alerts),
            "total_found": len(state.ALERTS_DF) if alert_name is None else len(state.ALERTS_DF[state.ALERTS_DF['alert_name'].str.contains(alert_name, case=False, na=False)]),
            "alerts": alerts
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "query_alerts",
    "description": "Query security alerts. Filter by alert name, hostname, or time range. Use this to find specific alerts or patterns in the alert data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "alert_name": {
                "type": "string",
                "description": "Optional alert name to filter (partial match, case-insensitive)"
            },
            "hostname": {
                "type": "string",
                "description": "Optional hostname to filter"
            },
            "start_time": {
                "type": "string",
                "description": "Optional start timestamp in format 'YYYY-MM-DD HH:MM:SS'"
            },
            "end_time": {
                "type": "string",
                "description": "Optional end timestamp in format 'YYYY-MM-DD HH:MM:SS'"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of alerts to return (default 50)"
            }
        },
        "required": []
    }
}
