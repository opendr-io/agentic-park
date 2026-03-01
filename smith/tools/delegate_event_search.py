"""Delegate event stream queries to the dedicated event search agent."""

import json
import traceback
from logger import get_logger

logger = get_logger('delegate_event_search')


def delegate_event_search(query, alert_timestamp=None, hostname=None):
    """
    Delegate an event stream query to the event search agent.

    Args:
        query: Natural language query about system events
        alert_timestamp: Alert timestamp — used to auto-scope to ±10 min window
        hostname: Hostname from the alert — used to scope results

    Returns:
        JSON string with the event search agent's response
    """
    try:
        from agents import run_event_search

        # Build scoping context from structured parameters
        scoping = []
        if hostname:
            scoping.append(f"Hostname: {hostname}")
        if alert_timestamp:
            scoping.append(f"Alert timestamp: {alert_timestamp}")
            scoping.append("Search within ±30 minutes of the alert timestamp.")

        if scoping:
            enriched = f"{query}\n\nAlert context:\n" + "\n".join(scoping)
        else:
            enriched = query

        response = run_event_search.answer_question(enriched, silent=True)
        return json.dumps({"response": response})

    except Exception as e:
        logger.error(f"Event search delegation failed: {e}\n{traceback.format_exc()}")
        return json.dumps({"error": f"Event search agent error: {str(e)}"})


SCHEMA = {
    "name": "delegate_event_search",
    "description": (
        "Delegate an event stream query to the event search specialist agent. "
        "Use this tool when you need to investigate process activity, network connections, "
        "or build process trees from the system event stream. "
        "ALWAYS provide alert_timestamp and hostname from the alert being analyzed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Natural language query for the event search agent. "
                    "Describe what you need: PID lookup, process tree, network connections, etc."
                )
            },
            "alert_timestamp": {
                "type": "string",
                "description": (
                    "Timestamp of the alert being investigated (YYYY-MM-DD HH:MM:SS). "
                    "The event search agent will automatically scope to ±30 minutes."
                )
            },
            "hostname": {
                "type": "string",
                "description": "Hostname from the alert. Used to scope results to the correct host."
            }
        },
        "required": ["query", "alert_timestamp", "hostname"]
    }
}
