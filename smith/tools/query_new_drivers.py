"""Query new driver alerts."""

import json
import pandas as pd
from tools import state

# Field definitions for new driver alerts
DRIVER_FIELDS = [
    'timestamp', 'hostname', 'event', 'desc', 'signer',
    'device_id', 'driver_version', 'friendly_name', 'is_signed',
    'pdo', 'ec2_instance_id', 'sid'
]


def query_new_drivers(hostname=None, signer=None, desc=None, is_signed=None, start_time=None, end_time=None, limit=100):
    """
    Query new driver alerts.

    Each new driver alert has the following fields:
        timestamp, hostname, event, desc, signer, device_id,
        driver_version, friendly_name, is_signed, pdo, ec2_instance_id, sid

    Args:
        hostname: Hostname to filter by
        signer: Driver signer to filter by (case-insensitive, partial match)
        desc: Driver description to filter by (case-insensitive, partial match)
        is_signed: Filter by signed status ('True' or 'False')
        start_time: Optional start timestamp (YYYY-MM-DD HH:MM:SS)
        end_time: Optional end timestamp (YYYY-MM-DD HH:MM:SS)
        limit: Maximum number of events to return (default 100)

    Returns:
        JSON string with new driver alert details
    """
    if state.NEW_DF is None:
        return json.dumps({"error": "Alert data not loaded"})

    try:
        # Filter to only new driver events
        results = state.NEW_DF[
            state.NEW_DF['event'].str.contains('new driver', case=False, na=False)
        ].copy()

        if len(results) == 0:
            return json.dumps({"message": "No new driver alerts found", "count": 0})

        # Filter by hostname
        if hostname:
            results = results[results['hostname'].str.contains(hostname, case=False, na=False)]

        # Filter by signer
        if signer:
            results = results[results['signer'].str.contains(signer, case=False, na=False)]

        # Filter by description
        if desc:
            results = results[results['desc'].str.contains(desc, case=False, na=False)]

        # Filter by signed status
        if is_signed is not None:
            results = results[results['is_signed'].astype(str).str.lower() == str(is_signed).lower()]

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
            return json.dumps({"message": "No new driver alerts found matching criteria", "count": 0})

        # Format output using defined fields
        events = []
        for _, row in results.iterrows():
            event = {}
            for field in DRIVER_FIELDS:
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
    "name": "query_new_drivers",
    "description": "Query new driver alerts. Returns drivers with fields: timestamp, hostname, event, desc, signer, device_id, driver_version, friendly_name, is_signed, pdo, ec2_instance_id, sid. Filter by hostname, signer, description, or signed status.",
    "input_schema": {
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "Hostname to filter by"
            },
            "signer": {
                "type": "string",
                "description": "Driver signer to filter by (partial match, case-insensitive)"
            },
            "desc": {
                "type": "string",
                "description": "Driver description to filter by (partial match, case-insensitive)"
            },
            "is_signed": {
                "type": "string",
                "description": "Filter by signed status ('True' or 'False')"
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
