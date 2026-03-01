"""Query network connection events."""

import json
import pandas as pd
from tools import state


def query_network_events(ip_address=None, port=None, start_time=None, end_time=None, limit=50):
    """
    Query network connection events.

    Args:
        ip_address: Optional IP address to filter (source or destination)
        port: Optional port number to filter (source or destination)
        start_time: Optional start timestamp (YYYY-MM-DD HH:MM:SS)
        end_time: Optional end timestamp (YYYY-MM-DD HH:MM:SS)
        limit: Maximum number of events to return (default 50)

    Returns:
        JSON string with network events
    """
    all_events = state.get_all_events()
    if all_events is None:
        return json.dumps({"error": "Event stream not loaded"})

    try:
        # Filter for network events
        results = all_events[all_events['category'].isin(['network_connection', 'network_termination'])].copy()

        # Filter by IP if provided
        if ip_address:
            results = results[
                (results['sourceip'] == ip_address) |
                (results['destinationip'] == ip_address)
            ]

        # Filter by port if provided
        if port:
            results = results[
                (results['sourceport'] == int(port)) |
                (results['destinationport'] == int(port))
            ]

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
            return json.dumps({"message": "No network events found matching criteria", "count": 0})

        # Format output
        events = []
        for _, row in results.iterrows():
            events.append({
                "timestamp": str(row.get('timestamp', 'N/A')),
                "category": row.get('category', 'N/A'),
                "pid": int(row.get('processid', 0)),
                "process": row.get('process', 'N/A'),
                "source_ip": row.get('sourceip', 'N/A'),
                "source_port": row.get('sourceport', 'N/A'),
                "dest_ip": row.get('destinationip', 'N/A'),
                "dest_port": row.get('destinationport', 'N/A'),
                "status": row.get('status', 'N/A'),
                "asname": row.get('asname', 'N/A'),
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
    "name": "query_network_events",
    "description": "Query network connection events. Use this to find network activity, optionally filtered by IP address, port, or time range. Returns both connection and termination events.",
    "input_schema": {
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "Optional IP address to filter (matches source or destination)"
            },
            "port": {
                "type": "integer",
                "description": "Optional port number to filter (matches source or destination)"
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
                "description": "Maximum number of events to return (default 50)"
            }
        },
        "required": []
    }
}
