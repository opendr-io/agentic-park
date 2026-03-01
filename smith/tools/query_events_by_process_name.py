"""Query events by process name."""

import json
import pandas as pd
from tools import state


def query_events_by_process_name(process_name, hostname=None, start_time=None, end_time=None, limit=50):
    """
    Query events by process name, optionally scoped by hostname and time window.

    Args:
        process_name: Process name to search for (e.g., "powershell.exe")
        hostname: Hostname to filter by (recommended to avoid cross-host confusion)
        start_time: Optional start timestamp (YYYY-MM-DD HH:MM:SS)
        end_time: Optional end timestamp (YYYY-MM-DD HH:MM:SS)
        limit: Maximum number of events to return (default 50)

    Returns:
        JSON string with event details
    """
    all_events = state.get_all_events()
    if all_events is None:
        return json.dumps({"error": "Event stream not loaded"})

    try:
        # Filter by process name (case-insensitive partial match)
        results = all_events[all_events['process'].str.contains(process_name, case=False, na=False)].copy()

        # Filter by hostname
        if hostname:
            results = results[results['hostname'].str.upper() == hostname.upper()]

        # Filter by time range if provided
        if start_time:
            results = results[pd.to_datetime(results['timestamp']) >= pd.to_datetime(start_time)]
        if end_time:
            results = results[pd.to_datetime(results['timestamp']) <= pd.to_datetime(end_time)]

        # Sort by timestamp
        results = results.sort_values('timestamp')

        # Limit results
        results = results.head(limit)

        if len(results) == 0:
            return json.dumps({"message": f"No events found for process '{process_name}'", "count": 0})

        # Format output
        events = []
        for _, row in results.iterrows():
            events.append({
                "timestamp": str(row.get('timestamp', 'N/A')),
                "category": row.get('category', 'N/A'),
                "pid": int(row.get('processid', 0)),
                "process": row.get('process', 'N/A'),
                "commandline": row.get('commandline', 'N/A'),
                "parent_pid": int(row.get('parentprocessid', 0)) if pd.notna(row.get('parentprocessid')) else None,
                "user": row.get('username', 'N/A'),
                "hostname": row.get('hostname', 'N/A')
            })

        return json.dumps({
            "count": len(events),
            "events": events
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "query_events_by_process_name",
    "description": "Query events by process name. Use this to find all instances of a specific process (e.g., 'powershell.exe'). The search is case-insensitive and supports partial matches. Provide hostname and time window to scope results to a specific alert context.",
    "input_schema": {
        "type": "object",
        "properties": {
            "process_name": {
                "type": "string",
                "description": "The process name to search for (e.g., 'powershell.exe')"
            },
            "hostname": {
                "type": "string",
                "description": "Hostname to filter by. Recommended when investigating a specific alert."
            },
            "start_time": {
                "type": "string",
                "description": "Optional start timestamp (YYYY-MM-DD HH:MM:SS)"
            },
            "end_time": {
                "type": "string",
                "description": "Optional end timestamp (YYYY-MM-DD HH:MM:SS)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of events to return (default 50)"
            }
        },
        "required": ["process_name"]
    }
}
