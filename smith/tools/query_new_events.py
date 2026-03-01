"""Query behavioral anomaly detection events."""

import json
import pandas as pd
from tools import state


def query_new_events(event_type=None, hostname=None, start_time=None, end_time=None, limit=100):
    """
    Query behavioral anomaly detection events.

    Args:
        event_type: Type of event (e.g., "new autorun found", "new driver found", "new scheduled task found", "new service")
        hostname: Hostname to filter by
        start_time: Optional start timestamp (YYYY-MM-DD HH:MM:SS)
        end_time: Optional end timestamp (YYYY-MM-DD HH:MM:SS)
        limit: Maximum number of events to return (default 100)

    Returns:
        JSON string with event details
    """
    if state.NEW_DF is None:
        return json.dumps({"error": "Behavioral anomaly data not loaded"})

    try:
        results = state.NEW_DF.copy()

        # Filter by event type
        if event_type:
            results = results[results['event'].str.contains(event_type, case=False, na=False)]

        # Filter by hostname
        if hostname:
            results = results[results['hostname'] == hostname]

        # Filter by time range
        if start_time:
            results = results[pd.to_datetime(results['timestamp']) >= pd.to_datetime(start_time)]
        if end_time:
            results = results[pd.to_datetime(results['timestamp']) <= pd.to_datetime(end_time)]

        # Sort by timestamp
        results = results.sort_values('timestamp')

        # Limit results
        results = results.head(limit)

        if len(results) == 0:
            return json.dumps({"message": "No events found matching criteria", "count": 0})

        # Format output
        events = []
        for _, row in results.iterrows():
            event = {
                "timestamp": str(row.get('timestamp', 'N/A')),
                "hostname": row.get('hostname', 'N/A'),
                "event": row.get('event', 'N/A'),
            }

            # Include alert metadata if available
            if 'alert_name' in row and pd.notna(row.get('alert_name')):
                event['alert_name'] = row.get('alert_name')
            if 'alert_description' in row and pd.notna(row.get('alert_description')):
                event['alert_description'] = row.get('alert_description')

            # Add relevant fields based on event type
            if 'autorun' in str(row.get('event', '')).lower():
                event['source'] = row.get('source', 'N/A')
                event['entry'] = row.get('entry', 'N/A')
                event['path'] = row.get('path', 'N/A')
            elif 'driver' in str(row.get('event', '')).lower():
                event['description'] = row.get('desc', 'N/A')
                event['signer'] = row.get('signer', 'N/A')
                event['is_signed'] = row.get('is_signed', 'N/A')
                event['device_id'] = row.get('device_id', 'N/A')
            elif 'task' in str(row.get('event', '')).lower():
                event['task_name'] = row.get('task_name', 'N/A')
                event['task_to_run'] = row.get('task_to_run', 'N/A')
                event['status'] = row.get('status', 'N/A')
                event['author'] = row.get('author', 'N/A')
                event['next_run'] = row.get('next_run', 'N/A')
            elif 'service' in str(row.get('event', '')).lower():
                event['username'] = row.get('username', 'N/A')
                event['servicename'] = row.get('servicename', 'N/A')
                event['displayname'] = row.get('displayname', 'N/A')
                event['status'] = row.get('status', 'N/A')
                event['start'] = row.get('start', 'N/A')
                event['executable'] = row.get('executable', 'N/A')
                event['pid'] = row.get('pid', 'N/A')
                event['sid'] = row.get('sid', 'N/A')

            events.append(event)

        return json.dumps({
            "count": len(events),
            "total_found": len(state.NEW_DF) if event_type is None else len(state.NEW_DF[state.NEW_DF['event'].str.contains(event_type, case=False, na=False)]),
            "events": events
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "query_new_events",
    "description": "Query behavioral anomaly detection events. Filter by event type (autorun, driver, scheduled task, service), hostname, or time range.",
    "input_schema": {
        "type": "object",
        "properties": {
            "event_type": {
                "type": "string",
                "description": "Type of event to filter (e.g., 'autorun', 'driver', 'task', 'service')"
            },
            "hostname": {
                "type": "string",
                "description": "Hostname to filter by"
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
