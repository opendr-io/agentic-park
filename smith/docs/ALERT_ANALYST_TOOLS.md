# Agent Tools Reference

## All Tools (17 unique)

| # | Tool | Description | Used by |
|---|---|---|---|
| 1 | `query_alerts` | Filter alerts by name, hostname, time range | Alert |
| 2 | `get_alert_summary` | Overview stats — counts by alert type, host, date range | Alert |
| 3 | `search_alerts` | Full-text search across all alert fields | Alert |
| 4 | `find_alert_correlations` | Find alerts sharing field values (same PID, IP, process, etc.) | Alert |
| 5 | `check_known_fps` | Check pre-built whitelist of known benign software | Alert, New |
| 6 | `check_fp_journal` | Check runtime log of prior analyst FP decisions | Alert, New |
| 7 | `delegate_event_search` | Ask the Event Search agent a question | Alert, New |
| 8 | `query_events_by_pid` | Process events for a specific PID on a host | Event Search |
| 9 | `query_events_by_process_name` | Find events matching a process name | Event Search |
| 10 | `build_process_tree` | Build parent-child process chain from a PID | Event Search |
| 11 | `query_network_events` | Network connections filtered by IP or port | Event Search |
| 12 | `lookup_ip_info` | IP geolocation and organization info | Event Search |
| 13 | `query_new_events` | Query new/anomalous events by type and host | New |
| 14 | `query_new_services` | Query newly installed services | New |
| 15 | `query_new_drivers` | Query newly loaded drivers | New |
| 16 | `get_event_summary` | Overview of new event types and counts | New |
| 17 | `search_new_events` | Full-text search across new/anomalous events | New |

---

## Alert Analyst (7 tools)

### Query & Search

| Tool | Description | Key params |
|---|---|---|
| `query_alerts` | Filter alerts by name, hostname, time range | `alert_name`, `hostname`, `start_time`, `end_time`, `limit` |
| `get_alert_summary` | Overview stats (counts by type, host, date range) | none |
| `search_alerts` | Full-text search across all alert fields | `search_term`, `limit` |

### Correlation & FP Checking

| Tool | Description | Key params |
|---|---|---|
| `find_alert_correlations` | Find alerts sharing field values (same PID, same IP, etc.) | `fields`, `alert_name`, `hostname`, `severity`, `min_group_size` |
| `check_known_fps` | Check pre-built whitelist of known benign software | `process`, `commandline` |
| `check_fp_journal` | Check runtime log of prior analyst FP decisions | `alert_name`, `process` |

### Delegation

| Tool | Description | Key params |
|---|---|---|
| `delegate_event_search` | Ask the Event Search agent a question | `question`, `hostname`, `start_time`, `end_time` |

## Event Search (5 tools)

| Tool | Description | Key params |
|---|---|---|
| `query_events_by_pid` | Process events for a specific PID | `pid`, `hostname`, `start_time`, `end_time` |
| `query_events_by_process_name` | Find events by process name | `process_name`, `hostname`, `start_time`, `end_time` |
| `build_process_tree` | Parent-child process chain | `pid`, `hostname`, `reference_timestamp` |
| `query_network_events` | Network connections by IP/port | `ip_address`, `port`, `start_time`, `end_time` |
| `lookup_ip_info` | IP geolocation and org info | `ip_address` |

## New Analyst (8 tools)

### Behavioral Anomaly Queries

| Tool | Description | Key params |
|---|---|---|
| `query_new_events` | Query new/anomalous events | `event_type`, `hostname`, `limit` |
| `query_new_services` | Query newly installed services | `servicename`, `hostname`, `status`, `limit` |
| `query_new_drivers` | Query newly loaded drivers | `desc`, `signer`, `limit` |
| `get_event_summary` | Overview of new event types and counts | none |
| `search_new_events` | Full-text search across new events | `search_term`, `limit` |

### Shared with Alert Analyst

| Tool | Description |
|---|---|
| `delegate_event_search` | Ask the Event Search agent a question |
| `check_fp_journal` | Check runtime FP decision log |
| `check_known_fps` | Check pre-built known-benign whitelist |

## FP Checking: Two Tools, Two Sources

| Tool | Source | What it checks |
|---|---|---|
| `check_known_fps` | `fp-data/system_fps.csv` + `fp-data/known_benign.txt` | Pre-built whitelist of known safe software (Edge, VS Code, Adobe, etc.) |
| `check_fp_journal` | `exports/false_positives.csv` | Runtime log of alerts analysts previously classified as FP |

## How Agents Get Tools

Tools are registered in `tools/__init__.py` as schema lists (`ALERT_TOOLS`, `EVENT_SEARCH_TOOLS`, `NEW_TOOLS`) and dispatch tables. Each agent runner binds its tool list via LangChain's `bind_tools()`.

The alert analyst accesses event data indirectly through `delegate_event_search`, which invokes the Event Search agent as a sub-agent. The event search agent's tools operate on `EVENTS_DF` (the full system event stream), while alert tools operate on `ALERTS_DF`.
