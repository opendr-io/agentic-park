"""Check false positive journal for similar prior classifications."""

import json
import pandas as pd
from pathlib import Path


FP_JOURNAL_PATH = Path('exports/false_positives.csv')


def check_fp_journal(alert_name, process=None):
    """
    Search the false positive journal for prior FP classifications
    matching the given alert name or process.

    Returns only matching rows — not the entire journal.

    Args:
        alert_name: Alert name to search for (substring, case-insensitive)
        process: Optional process name to also search for

    Returns:
        JSON string with matching FP entries
    """
    if not FP_JOURNAL_PATH.exists():
        return json.dumps({"message": "No false positive journal exists yet.", "matches": []})

    try:
        df = pd.read_csv(FP_JOURNAL_PATH)
    except Exception:
        return json.dumps({"message": "Could not read false positive journal.", "matches": []})

    if df.empty:
        return json.dumps({"message": "False positive journal is empty.", "matches": []})

    # Search alert_name column
    term = alert_name.lower()
    mask = df['alert_name'].fillna('').str.lower().str.contains(term, regex=False)

    # Also search by process name if provided
    if process:
        proc_term = process.lower()
        proc_mask = df['reason'].fillna('').str.lower().str.contains(proc_term, regex=False)
        mask = mask | proc_mask

    matches = df[mask]

    if matches.empty:
        return json.dumps({
            "message": f"No prior false positive decisions found for '{alert_name}'.",
            "matches": []
        })

    results = []
    for _, row in matches.iterrows():
        results.append({
            "alert_name": row.get('alert_name', ''),
            "hostname": row.get('hostname', ''),
            "analyzed_by": row.get('analyzed_by', ''),
            "reason": row.get('reason', ''),
            "timestamp": row.get('timestamp', ''),
        })

    return json.dumps({
        "message": f"Found {len(results)} prior false positive classification(s).",
        "matches": results
    }, indent=2)


SCHEMA = {
    "name": "check_fp_journal",
    "description": (
        "Check the FP journal for alerts that YOU (or another analyst) previously classified "
        "as false positives at runtime. Use this to see if a similar alert was already analyzed "
        "and dismissed. Searches by alert name or process. This is the runtime decision log, "
        "not the pre-built known-benign database."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "alert_name": {
                "type": "string",
                "description": "The alert name to search for in prior FP decisions (case-insensitive substring match)"
            },
            "process": {
                "type": "string",
                "description": "Optional process name to also search for in FP reasons"
            }
        },
        "required": ["alert_name"]
    }
}
