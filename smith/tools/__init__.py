"""
Tool definitions for Claude-based agents.

Exports:
    ALERT_TOOLS          - Schema list for the alert analyst agent
    NEW_TOOLS            - Schema list for the behavioral anomaly analyst agent
    EVENT_SEARCH_TOOLS   - Schema list for the event search agent
    process_alert_tool_call(name, input)        - Dispatch an alert analyst tool call
    process_new_tool_call(name, input)          - Dispatch a new analyst tool call
    process_event_search_tool_call(name, input) - Dispatch an event search tool call
"""

import json

from tools import state  # noqa: F401 - re-export for convenient access

# Alert analyst tools (alerts only + delegation to event search)
from tools.query_alerts import query_alerts, SCHEMA as _query_alerts_schema
from tools.get_alert_summary import get_alert_summary, SCHEMA as _get_alert_summary_schema
from tools.search_alerts import search_alerts, SCHEMA as _search_alerts_schema
from tools.delegate_event_search import delegate_event_search, SCHEMA as _delegate_event_search_schema

# Event search agent tools
from tools.query_events_by_pid import query_events_by_pid, SCHEMA as _query_events_by_pid_schema
from tools.query_events_by_process_name import query_events_by_process_name, SCHEMA as _query_events_by_process_name_schema
from tools.build_process_tree import build_process_tree, SCHEMA as _build_process_tree_schema
from tools.lookup_ip_info import lookup_ip_info, SCHEMA as _lookup_ip_info_schema
from tools.query_network_events import query_network_events, SCHEMA as _query_network_events_schema

# New analyst tools
from tools.query_new_events import query_new_events, SCHEMA as _query_new_events_schema
from tools.get_event_summary import get_event_summary, SCHEMA as _get_event_summary_schema
from tools.search_new_events import search_new_events, SCHEMA as _search_new_events_schema
from tools.query_new_services import query_new_services, SCHEMA as _query_new_services_schema
from tools.query_new_drivers import query_new_drivers, SCHEMA as _query_new_drivers_schema

# Shared tools (available to multiple agents)
from tools.check_fp_journal import check_fp_journal, SCHEMA as _check_fp_journal_schema
from tools.find_alert_correlations import find_alert_correlations, SCHEMA as _find_alert_correlations_schema
from tools.check_known_fps import check_known_fps, SCHEMA as _check_known_fps_schema

# Schema lists for bind_tools()
ALERT_TOOLS = [
    _query_alerts_schema,
    _get_alert_summary_schema,
    _search_alerts_schema,
    _find_alert_correlations_schema,
    _delegate_event_search_schema,
    _check_fp_journal_schema,
    _check_known_fps_schema,
]

EVENT_SEARCH_TOOLS = [
    _query_events_by_pid_schema,
    _query_events_by_process_name_schema,
    _build_process_tree_schema,
    _lookup_ip_info_schema,
    _query_network_events_schema,
]

NEW_TOOLS = [
    _query_new_events_schema,
    _query_new_services_schema,
    _query_new_drivers_schema,
    _get_event_summary_schema,
    _search_new_events_schema,
    _delegate_event_search_schema,
    _check_fp_journal_schema,
    _check_known_fps_schema,
]

# Dispatch tables
_ALERT_DISPATCH = {
    "query_alerts": query_alerts,
    "get_alert_summary": get_alert_summary,
    "search_alerts": search_alerts,
    "find_alert_correlations": find_alert_correlations,
    "delegate_event_search": delegate_event_search,
    "check_fp_journal": check_fp_journal,
    "check_known_fps": check_known_fps,
}

_EVENT_SEARCH_DISPATCH = {
    "query_events_by_pid": query_events_by_pid,
    "query_events_by_process_name": query_events_by_process_name,
    "build_process_tree": build_process_tree,
    "lookup_ip_info": lookup_ip_info,
    "query_network_events": query_network_events,
}

_NEW_DISPATCH = {
    "query_new_events": query_new_events,
    "query_new_services": query_new_services,
    "query_new_drivers": query_new_drivers,
    "get_event_summary": get_event_summary,
    "search_new_events": search_new_events,
    "delegate_event_search": delegate_event_search,
    "check_fp_journal": check_fp_journal,
    "check_known_fps": check_known_fps,
}


def process_alert_tool_call(tool_name, tool_input):
    """Process a tool call from the alert analyst agent."""
    fn = _ALERT_DISPATCH.get(tool_name)
    if fn:
        return fn(**tool_input)
    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def process_event_search_tool_call(tool_name, tool_input):
    """Process a tool call from the event search agent."""
    fn = _EVENT_SEARCH_DISPATCH.get(tool_name)
    if fn:
        return fn(**tool_input)
    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def process_new_tool_call(tool_name, tool_input):
    """Process a tool call from the behavioral anomaly analyst agent."""
    fn = _NEW_DISPATCH.get(tool_name)
    if fn:
        return fn(**tool_input)
    return json.dumps({"error": f"Unknown tool: {tool_name}"})
