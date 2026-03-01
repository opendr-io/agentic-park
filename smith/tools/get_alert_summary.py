"""Get summary statistics of all security alerts."""

import json
from tools import state


def get_alert_summary():
    """
    Get summary statistics of all security alerts.

    Returns:
        JSON string with summary statistics
    """
    if state.ALERTS_DF is None:
        return json.dumps({"error": "Alerts data not loaded"})

    try:
        summary = {
            "total_alerts": len(state.ALERTS_DF),
            "alert_types": state.ALERTS_DF['alert_name'].value_counts().to_dict(),
            "hostnames": state.ALERTS_DF['hostname'].value_counts().to_dict(),
            "date_range": {
                "first_alert": str(state.ALERTS_DF['first_seen'].min()),
                "last_alert": str(state.ALERTS_DF['last_seen'].max())
            }
        }

        # Top processes triggering alerts
        if 'process' in state.ALERTS_DF.columns:
            summary['top_processes'] = state.ALERTS_DF['process'].value_counts().head(10).to_dict()

        return json.dumps(summary, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "get_alert_summary",
    "description": "Get summary statistics of all security alerts including counts by type, hostnames, date range, and top processes.",
    "input_schema": {
        "type": "object",
        "properties": {},
        "required": []
    }
}
