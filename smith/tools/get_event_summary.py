"""Get summary statistics of behavioral anomaly events."""

import json
from tools import state


def get_event_summary():
    """
    Get summary statistics of behavioral anomaly events.

    Returns:
        JSON string with summary statistics
    """
    if state.NEW_DF is None:
        return json.dumps({"error": "Behavioral anomaly data not loaded"})

    try:
        summary = {
            "total_events": len(state.NEW_DF),
            "hostnames": state.NEW_DF['hostname'].value_counts().to_dict(),
            "date_range": {
                "first_event": str(state.NEW_DF['timestamp'].min()),
                "last_event": str(state.NEW_DF['timestamp'].max())
            }
        }

        if 'event' in state.NEW_DF.columns:
            summary["event_types"] = state.NEW_DF['event'].value_counts().to_dict()

        if 'alert_name' in state.NEW_DF.columns:
            summary["alert_names"] = state.NEW_DF['alert_name'].value_counts().to_dict()

        return json.dumps(summary, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "get_event_summary",
    "description": "Get summary statistics of all behavioral anomaly events including counts by type, hostnames, and date range.",
    "input_schema": {
        "type": "object",
        "properties": {},
        "required": []
    }
}
