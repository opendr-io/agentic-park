"""Find commonalities across alerts by grouping on shared field values."""

import json
import pandas as pd
from tools import state


def find_alert_correlations(fields=None, alert_name=None, hostname=None, severity=None, min_group_size=2):
    """
    Find alerts that share common field values (e.g. same processid, same
    destination IP, same parent process).

    Args:
        fields: List of field names to correlate on (e.g. ["processid", "destinationip"]).
                If omitted, automatically checks all useful fields.
        alert_name: Optional filter — only consider alerts matching this name
        hostname: Optional filter — only consider alerts on this hostname
        severity: Optional filter — only consider alerts with this severity
        min_group_size: Minimum number of alerts sharing a value to report (default 2)

    Returns:
        JSON string with groups of alerts sharing common values
    """
    if state.ALERTS_DF is None:
        return json.dumps({"error": "Alerts data not loaded"})

    try:
        df = state.ALERTS_DF.copy()

        # Apply filters
        if alert_name:
            df = df[df['alert_name'].str.contains(alert_name, case=False, na=False)]
        if hostname:
            df = df[df['hostname'].str.upper() == hostname.upper()]
        if severity:
            df = df[df['severity'].str.upper() == severity.upper()]

        if len(df) < 2:
            return json.dumps({"message": "Fewer than 2 alerts match filters — nothing to correlate", "count": 0})

        # Default fields to check if none specified
        if not fields:
            fields = [
                'processid', 'pid', 'parentprocessid',
                'destinationip', 'sourceip',
                'process', 'parentimage', 'commandline',
                'servicename',
            ]

        # Only check fields that actually exist in the data
        fields = [f for f in fields if f in df.columns]

        correlations = []

        for field in fields:
            # Drop NaN/empty values for this field
            valid = df[df[field].notna() & (df[field].astype(str).str.strip() != '')]
            if len(valid) < 2:
                continue

            # Group by shared values
            groups = valid.groupby(valid[field].astype(str))

            for value, group in groups:
                if len(group) < min_group_size:
                    continue

                alerts_in_group = []
                for _, row in group.iterrows():
                    entry = {
                        "alert_hash": str(row.get('alert_hash', ''))[:8],
                        "alert_name": row.get('alert_name', 'N/A'),
                        "hostname": row.get('hostname', 'N/A'),
                        "timestamp": str(row.get('timestamp', 'N/A')),
                    }
                    # Include the correlated field plus a few key identifiers
                    for extra in ['process', 'processid', 'pid', 'commandline', 'severity']:
                        if extra != field and extra in row.index and pd.notna(row.get(extra)):
                            entry[extra] = row[extra]
                    alerts_in_group.append(entry)

                correlations.append({
                    "shared_field": field,
                    "shared_value": str(value),
                    "count": len(group),
                    "alerts": alerts_in_group,
                })

        if not correlations:
            return json.dumps({
                "message": "No commonalities found across the checked fields",
                "fields_checked": fields,
                "alerts_examined": len(df),
            })

        # Sort by group size descending
        correlations.sort(key=lambda c: c['count'], reverse=True)

        return json.dumps({
            "correlations_found": len(correlations),
            "alerts_examined": len(df),
            "correlations": correlations[:20],
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "find_alert_correlations",
    "description": "Find alerts that share common field values — e.g. same processid, same destination IP, same parent process. Use this to discover patterns and connections between alerts.",
    "input_schema": {
        "type": "object",
        "properties": {
            "fields": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Field names to correlate on (e.g. ['processid', 'destinationip']). Omit to check all useful fields automatically."
            },
            "alert_name": {
                "type": "string",
                "description": "Optional: only consider alerts matching this name (partial, case-insensitive)"
            },
            "hostname": {
                "type": "string",
                "description": "Optional: only consider alerts on this hostname"
            },
            "severity": {
                "type": "string",
                "description": "Optional: only consider alerts with this severity (e.g. HIGH, CRITICAL)"
            },
            "min_group_size": {
                "type": "integer",
                "description": "Minimum alerts sharing a value to report (default 2)"
            }
        },
        "required": []
    }
}
