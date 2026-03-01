"""Query new service alerts."""

import json
import pandas as pd
from tools import state

# Field definitions for new service alerts
SERVICE_FIELDS = [
    'timestamp', 'hostname', 'username', 'event',
    'servicename', 'displayname', 'status', 'start',
    'executable', 'sid'
]


def query_new_services(hostname=None, servicename=None, status=None, start_time=None, end_time=None, limit=100):
    """
    Query new service alerts.

    Each new service alert has the following fields:
        timestamp, hostname, username, event, servicename,
        displayname, status, start, executable, sid

    Args:
        hostname: Hostname to filter by
        servicename: Service name to filter by (case-insensitive, partial match)
        status: Service status to filter by (e.g., 'running', 'stopped')
        start_time: Optional start timestamp (YYYY-MM-DD HH:MM:SS)
        end_time: Optional end timestamp (YYYY-MM-DD HH:MM:SS)
        limit: Maximum number of events to return (default 100)

    Returns:
        JSON string with new service alert details
    """
    if state.NEW_DF is None:
        return json.dumps({"error": "Alert data not loaded"})

    try:
        # Filter to only new service events
        results = state.NEW_DF[
            state.NEW_DF['event'].str.contains('new service', case=False, na=False)
        ].copy()

        if len(results) == 0:
            return json.dumps({"message": "No new service alerts found", "count": 0})

        # Filter by hostname
        if hostname:
            results = results[results['hostname'].str.contains(hostname, case=False, na=False)]

        # Filter by service name
        if servicename:
            results = results[results['servicename'].str.contains(servicename, case=False, na=False)]

        # Filter by status
        if status:
            results = results[results['status'].str.contains(status, case=False, na=False)]

        # Filter by time range
        if start_time:
            results = results[pd.to_datetime(results['timestamp']) >= pd.to_datetime(start_time)]
        if end_time:
            results = results[pd.to_datetime(results['timestamp']) <= pd.to_datetime(end_time)]

        # Sort by timestamp
        results = results.sort_values('timestamp')

        total_matching = len(results)

        # Limit results
        results = results.head(limit)

        if len(results) == 0:
            return json.dumps({"message": "No new service alerts found matching criteria", "count": 0})

        # Format output using defined fields
        events = []
        for _, row in results.iterrows():
            event = {}
            for field in SERVICE_FIELDS:
                val = row.get(field)
                if pd.notna(val):
                    event[field] = str(val)
                else:
                    event[field] = 'N/A'
            events.append(event)

        return json.dumps({
            "count": len(events),
            "total_matching": total_matching,
            "events": events
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "query_new_services",
    "description": "Query new service alerts. Returns services with fields: timestamp, hostname, username, event, servicename, displayname, status, start, executable, sid. Filter by hostname, service name, or status.",
    "input_schema": {
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "Hostname to filter by"
            },
            "servicename": {
                "type": "string",
                "description": "Service name to filter by (partial match, case-insensitive)"
            },
            "status": {
                "type": "string",
                "description": "Service status to filter by (e.g., 'running', 'stopped')"
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
                "description": "Maximum number of events to return (default 100)"
            }
        },
        "required": []
    }
}
