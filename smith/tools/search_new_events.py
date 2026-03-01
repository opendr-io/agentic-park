"""Search behavioral anomaly events across all text fields."""

import json
import pandas as pd
from tools import state


def search_new_events(search_term, limit=50):
    """
    Search behavioral anomaly events for a term across all text fields.

    Args:
        search_term: Term to search for (case-insensitive)
        limit: Maximum number of results to return

    Returns:
        JSON string with matching events
    """
    if state.NEW_DF is None:
        return json.dumps({"error": "Behavioral anomaly data not loaded"})

    try:
        # Search across all string columns
        mask = state.NEW_DF.apply(lambda row: row.astype(str).str.contains(search_term, case=False, na=False).any(), axis=1)
        results = state.NEW_DF[mask].head(limit)

        if len(results) == 0:
            return json.dumps({"message": f"No events found containing '{search_term}'", "count": 0})

        events = []
        for _, row in results.iterrows():
            events.append({
                "timestamp": str(row.get('timestamp', 'N/A')),
                "event": row.get('event', 'N/A'),
                "hostname": row.get('hostname', 'N/A'),
                "details": {k: str(v) for k, v in row.to_dict().items() if pd.notna(v) and str(v) != 'N/A'}
            })

        return json.dumps({
            "search_term": search_term,
            "count": len(events),
            "events": events
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "search_new_events",
    "description": "Search behavioral anomaly events for a specific term across all fields. Use this to find events related to specific programs, paths, or descriptions.",
    "input_schema": {
        "type": "object",
        "properties": {
            "search_term": {
                "type": "string",
                "description": "Term to search for (case-insensitive)"
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of results to return (default 50)"
            }
        },
        "required": ["search_term"]
    }
}
