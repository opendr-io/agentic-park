"""Query all events for a specific process ID."""

import json
import pandas as pd
from tools import state


def query_events_by_pid(pid, hostname=None, start_time=None, end_time=None, limit=100):
    """
    Query all events for a specific PID, scoped by hostname and time window.

    Args:
        pid: Process ID to search for
        hostname: Hostname to filter by (strongly recommended - PIDs are reused across time)
        start_time: Optional start timestamp (YYYY-MM-DD HH:MM:SS)
        end_time: Optional end timestamp (YYYY-MM-DD HH:MM:SS)
        limit: Maximum number of events to return (default 100)

    Returns:
        JSON string with event details
    """
    all_events = state.get_all_events()
    if all_events is None:
        return json.dumps({"error": "Event stream not loaded"})

    try:
        pid_int = int(pid)
        df = all_events

        # Pre-filter by hostname
        if hostname:
            df = df[df['hostname'].str.upper() == hostname.upper()]

        # Pre-filter by time range
        if start_time:
            df = df[pd.to_datetime(df['timestamp']) >= pd.to_datetime(start_time)]
        if end_time:
            df = df[pd.to_datetime(df['timestamp']) <= pd.to_datetime(end_time)]

        # Events where this PID is the process itself
        own_events = df[df['processid'] == pid_int].copy()

        # Events where this PID is the parent (child processes spawned by this PID)
        child_events = df[
            (df['parentprocessid'] == pid_int) &
            (df['category'] == 'process_creation')
        ].copy()

        # Combine and deduplicate
        results = pd.concat([own_events, child_events]).drop_duplicates().sort_values('timestamp')

        # Warn if no hostname filter was used and results span multiple hosts
        warning = None
        if not hostname and len(results) > 0:
            hosts = results['hostname'].dropna().unique()
            if len(hosts) > 1:
                warning = f"WARNING: PID {pid} found on {len(hosts)} different hosts ({', '.join(hosts)}). Use hostname parameter to scope results to one host."
            elif not start_time and not end_time:
                time_span = pd.to_datetime(results['timestamp'])
                span_minutes = (time_span.max() - time_span.min()).total_seconds() / 60
                if span_minutes > 30:
                    warning = f"WARNING: Events for PID {pid} span {span_minutes:.0f} minutes. PIDs are reused over time - use start_time/end_time to scope to the alert window."

        # Limit results
        results = results.head(limit)

        if len(results) == 0:
            return json.dumps({"message": f"No events found for PID {pid}", "count": 0})

        # Format output
        events = []
        for _, row in results.iterrows():
            event = {
                "timestamp": str(row.get('timestamp', 'N/A')),
                "category": row.get('category', 'N/A'),
                "pid": int(row.get('processid', 0)),
                "process": row.get('process', 'N/A'),
                "commandline": row.get('commandline', 'N/A'),
                "parent_pid": int(row.get('parentprocessid', 0)) if pd.notna(row.get('parentprocessid')) else None,
                "parent_image": row.get('parentimage', 'N/A'),
                "user": row.get('username', 'N/A'),
                "hostname": row.get('hostname', 'N/A'),
            }

            # Add network info if present
            if pd.notna(row.get('destinationip')):
                event['network'] = {
                    "source_ip": row.get('sourceip', 'N/A'),
                    "source_port": row.get('sourceport', 'N/A'),
                    "dest_ip": row.get('destinationip', 'N/A'),
                    "dest_port": row.get('destinationport', 'N/A'),
                    "status": row.get('status', 'N/A')
                }

            events.append(event)

        response = {
            "count": len(events),
            "events": events
        }
        if warning:
            response["warning"] = warning

        return json.dumps(response, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "query_events_by_pid",
    "description": "Query all events for a specific process ID (PID), including child processes it spawned. IMPORTANT: PIDs are reused over time, so you MUST provide the hostname and a time window (start_time/end_time) to get accurate results. Use ±30 minutes around the alert timestamp as the window.",
    "input_schema": {
        "type": "object",
        "properties": {
            "pid": {
                "type": "integer",
                "description": "The process ID to search for"
            },
            "hostname": {
                "type": "string",
                "description": "Hostname to filter by. ALWAYS provide this to avoid PID reuse confusion across hosts."
            },
            "start_time": {
                "type": "string",
                "description": "Start timestamp (YYYY-MM-DD HH:MM:SS). Set to ~30 minutes before the alert time."
            },
            "end_time": {
                "type": "string",
                "description": "End timestamp (YYYY-MM-DD HH:MM:SS). Set to ~30 minutes after the alert time."
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of events to return (default 100)"
            }
        },
        "required": ["pid"]
    }
}
