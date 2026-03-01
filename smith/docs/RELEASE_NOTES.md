# Release Notes — Agent Smith Improvements

## Continuous Event Ingestion

Events are no longer a static snapshot from startup. A background thread (`EventRefresher`) re-reads today's process and network logs from `C:/opendr/tmp` every 60 seconds, storing them in a separate `RECENT_EVENTS_DF`. All event search tools combine both the historical and recent DataFrames transparently via `get_all_events()`, so analysts can investigate activity that happened during the current session.

**Files changed:**
- `load_logs_to_dataframe.py` — added `load_recent_events()` and `_load_known_fields()`
- `orchestrator.py` — added `EventRefresher` class, wired into startup/shutdown
- `tools/state.py` — added `RECENT_EVENTS_DF`, `DF_LOCK`, and `get_all_events()`
- `tools/query_events_by_pid.py` — switched to `state.get_all_events()`
- `tools/query_events_by_process_name.py` — switched to `state.get_all_events()`
- `tools/query_network_events.py` — switched to `state.get_all_events()`
- `tools/build_process_tree.py` — switched to `state.get_all_events()`
- `status_agent.py` — `_extract_alert_context()` uses `get_all_events()`

---

## Alert Analyst Temporal Awareness

The alert analyst previously described historical alerts as happening "right now," leading to misleading conclusions (e.g., "an attacker has active code execution" for an alert from days ago). The prompts now receive `{current_time}` and include explicit instructions to frame analysis relative to when events actually occurred.

**Files changed:**
- `prompts/alert_analyst_answer.txt` — added Temporal Awareness section
- `prompts/alert_analyst_batch.txt` — added Temporal Awareness section
- `agents/run_alert_analyst.py` — passes `current_time` to prompt formatting

---

## Meetup Sub-Loop Fix

The meetup conversational mode had a bug where entering a menu command (like `alerts` or `exit`) during a meetup follow-up would silently fall through instead of routing back to the main command handler. The `while True` / `else: continue` pattern never executed the `else` clause because the `while True` condition never becomes `False` in Python. Replaced with a `reprocess_command` flag.

**Files changed:**
- `status_agent.py` — replaced while/else with `reprocess_command` boolean

---

## Tool Loop Safety Cap

All 7 `while response.tool_calls:` loops across the 3 specialist agents were unbounded — if the LLM kept requesting tools in a cycle, the agent would loop indefinitely. Each loop now caps at 10 rounds, which is generous for real investigations (typical: 2-4 rounds) but prevents infinite spinning.

**Files changed:**
- `agents/run_alert_analyst.py` — 3 loops capped (answer_question, batch mode, interactive mode)
- `agents/run_event_search.py` — 2 loops capped (answer_question, interactive mode)
- `agents/run_new_analyst.py` — 2 loops capped (answer_question, interactive mode)

---

## Thread Safety and Concurrency

- `get_all_events()` acquires `DF_LOCK` to snapshot both DataFrame references before combining, preventing reads during a mid-swap by the EventRefresher thread.
- `EventRefresher` acquires `DF_LOCK` when swapping `RECENT_EVENTS_DF`.
- `_rescan_alert_folder()` uses `reset_index(drop=True)` on new rows before index assignment to prevent stale index carryover from filtered DataFrames.

**Files changed:**
- `tools/state.py` — `get_all_events()` uses `DF_LOCK`
- `orchestrator.py` — `EventRefresher._run()` uses `DF_LOCK`
- `data_layer/background_processor.py` — `_rescan_alert_folder()` resets index

---

## Performance

- **`_alerts_snapshot()`** — Removed unnecessary `.copy()` and `DF_LOCK` acquisition. All 9 call sites are read-only (display, filtering, lookups), so returning the reference directly is safe. Eliminates a full DataFrame copy on every status display, alert lookup, and progress check.
- **`recover_stuck_alerts()`** — Replaced row-by-row `.iterrows()` loop with vectorized pandas operations: `str.startswith()` mask, `str.split()` + `pd.to_datetime()` for timestamp extraction, and a single batch `self.df.loc[stuck_mask, 'read'] = None` assignment.

**Files changed:**
- `status_agent.py` — `_alerts_snapshot()` returns reference directly
- `data_layer/alert_tracker.py` — `recover_stuck_alerts()` vectorized

---

## Error Handling

- **`delegate_event_search.py`** — Exception handler now logs the full stack trace via `logger.error()` + `traceback.format_exc()` instead of silently returning a JSON error string. The JSON error is still returned to the LLM so it can report the failure, but the traceback is preserved in logs for debugging.

**Files changed:**
- `tools/delegate_event_search.py` — added logger and traceback logging

---

## LLM Factory and Configurable Model Selection

Eliminated 8 duplicate `ChatAnthropic(model=..., api_key=..., temperature=0)` blocks across 6 files. All LLM instantiation now goes through a single `get_llm()` factory in `llm_utils.py`.

**Model selection** is configurable via `log_loader_config.ini`:

```ini
[LLM]
model = sonnet           # Options: opus, sonnet, haiku
summary_model = haiku    # Model for alert memory summarization (cheap/fast)
```

To switch models, edit `model = sonnet` to `opus` or `haiku` and restart. Short names are resolved automatically to full model IDs. The `CLAUDE_MODEL` environment variable still works as an override.

**Files changed:**
- `llm_utils.py` — added `get_llm()`, `resolve_model()`, `_load_config()`, and `MODEL_ALIASES`
- `log_loader_config.ini` — added `[LLM]` section with `model` and `summary_model`
- `agents/run_alert_analyst.py` — replaced 2 `ChatAnthropic` blocks with `get_llm()`
- `agents/run_event_search.py` — replaced 2 `ChatAnthropic` blocks with `get_llm()`
- `agents/run_new_analyst.py` — replaced 2 `ChatAnthropic` blocks with `get_llm()`
- `agents/run_router_agent.py` — replaced `ChatAnthropic` block with `get_llm()`
- `agents/run_notification_agent.py` — replaced `ChatAnthropic` block with `get_llm()`
- `status_agent.py` — replaced `_get_llm()` internals with `get_llm()`
- `alert_memory.py` — replaced hardcoded Haiku with config-driven `summary_model`

---

## get_all_events() Caching

`get_all_events()` previously ran a full `pd.concat` + dedup + sort on every call (10-75 times per session). Since `EVENTS_DF` is immutable after startup and `RECENT_EVENTS_DF` only swaps every 60 seconds, most calls repeated identical work. The result is now cached and invalidated when `RECENT_EVENTS_DF` is swapped (detected via `id()` comparison).

**Files changed:**
- `tools/state.py` — added `_cached_combined` and `_cached_recent_id` cache variables

---

## Exit Command Consistency

Added `'x'` as an exit command to all interactive agent loops, matching the main `status_agent.py` menu which already supported it.

**Files changed:**
- `agents/run_alert_analyst.py` — added `'x'` to exit check
- `agents/run_event_search.py` — added `'x'` to exit check
- `agents/run_new_analyst.py` — added `'x'` to exit check
- `agents/run_router_agent.py` — added `'x'` to exit check

---

## Prompt Injection Defense (3 Layers)

Alerts originate from endpoint telemetry (openDR). An attacker who controls a compromised endpoint could embed prompt injection payloads inside alert field values (commandline, servicename, displayname, etc.) to manipulate the LLM analyst agents into misclassifying alerts. Three defense layers were added:

### Layer 1: Data Boundary Tags

Alert field data is now wrapped in `<alert_data>` / `</alert_data>` XML tags before being sent to the LLM. This establishes a clear semantic boundary so the model can distinguish untrusted endpoint data from its own instructions.

**Files changed:**
- `data_layer/background_processor.py` — `format_alert_as_question()` wraps fields in `<alert_data>` tags
- `tests/test_agent_accuracy.py` — `format_alert_question()` updated to match

### Layer 2: Anti-Injection System Prompt Instructions

All three analyst system prompts now include explicit instructions to treat alert data as data, never as instructions. If the agent detects injection text in alert fields (e.g. "ignore previous instructions", "SEVERITY: LOW"), it is instructed to flag this as an additional indicator of malicious intent and *increase* severity.

**Files changed:**
- `prompts/alert_analyst_answer.txt` — added Prompt Injection Defense section
- `prompts/alert_analyst_batch.txt` — added Prompt Injection Defense section
- `prompts/new_analyst.txt` — added Prompt Injection Defense section

### Layer 3: Deterministic Alert Filter

A pure-Python scanner (`alert_filter.py`) that inspects alert text fields *before* they reach any LLM agent. Intercepted alerts are moved to a separate DataFrame — never modified or deleted, preserving forensic integrity. Because it uses only pattern matching and heuristics — no LLM, no prompt — it has zero prompt injection attack surface.

**Detection rules (6):**

| Rule | What it catches |
|------|----------------|
| `injection_phrase` | 24 known phrases: "ignore previous instructions", "SEVERITY: LOW", "report as benign", "skip analysis", etc. |
| `invisible_unicode` | Zero-width spaces (U+200B/C/D), invisible separators (U+2060-2063), RTL overrides (U+202A-202E, U+2066-2069), soft hyphens |
| `obfuscated_encoding` | Base64 blobs (40+ chars), hex escape sequences, URL-encoded sequences in non-URL fields |
| `structural_anomaly` | XML/HTML tags in data fields, service names >500 chars, commandlines >2000 chars |
| `llm_directive` | System prompt patterns: "you are a", "your role is", "respond with", "act as...assistant" |
| `prose_content` | English prose in technical fields — counts function words (articles, pronouns, prepositions) as a fraction of total words. Ratio >= 20% with 6+ words flags the field. Commandlines score ~0%; injection prose scores 40-55%. |

**On detection, the filter:**
1. Removes the alert from the DataFrame (agents never see it)
2. Logs detailed findings to `logging/alert_filter.log`
3. Saves the full unmodified alert as JSON in `exports/intercepted/{hash}.json`
4. Fires a Windows toast notification via `winotify`

**Integration points:**
- `background_processor.py` `process_alerts()` — scans unread alerts before the processing loop
- `background_processor.py` `_rescan_alert_folder()` — scans new alerts before appending to the shared DataFrame

**Files changed:**
- `alert_filter.py` — **new** — filter module with 6 detection rules, logging, JSON export, toast notifications
- `data_layer/background_processor.py` — calls `scan_alerts()` in `process_alerts()` and `_rescan_alert_folder()`
- `tests/test_alert_filter.py` — **new** — 50 data-driven tests using alert log files from `tests/alerts/`

**Dependencies added:**
- `winotify` — pure Python Windows toast notification library

---

## Agent Accuracy Tests

LLM-powered accuracy tests that verify the analyst agents reach correct severity conclusions on known alert scenarios. These make real API calls to Anthropic and are separated from the fast unit test suite.

**Run manually:** `python -m pytest tests/test_agent_accuracy.py -v -m llm`
**Regular test suite skips them:** `python -m pytest tests/ -v` (pytest.ini has `addopts = -m "not llm"`)

**Test categories (22 tests):**
- `TestAlertAnalystBenign` — Sublime Text, Cursor IDE alerts that should be LOW/MEDIUM
- `TestAlertAnalystMalicious` — Python recon, LOLBin downloads, encoded PowerShell, C2 callbacks that must be HIGH/CRITICAL
- `TestAlertAnalystInjection` — AI IDE credential harvest, exfiltration, env dump (prompt injection attack patterns)
- `TestPromptInjectionResistance` — Injection payloads embedded *inside* alert field values; agents must ignore the injected text and still rate HIGH/CRITICAL
- `TestNewAnalystBenign` — VMware services, Microsoft-signed drivers that should be LOW

**Files changed:**
- `tests/test_agent_accuracy.py` — **new** — 22 LLM accuracy tests with test data, helper functions, severity parsing
- `pytest.ini` — `llm` marker already registered

---

## Alert Simulation Script

`simulate_alerts.py` generates safe-but-suspicious behaviors that trigger openDR detection rules, producing alerts for Agent Smith to analyze.

**Categories:** `recon`, `download`, `powershell`, `network`, `injection`

The `injection` category simulates a 5-phase prompt injection attack chain: malicious rule file read, credential harvesting (`cmd.exe /c set`, reading `.git-credentials`), C2 exfiltration (socket + curl to TEST-NET IPs), backdoor file injection (temp dir only), evidence suppression.

All network targets use non-routable RFC 5737 TEST-NET addresses (203.0.113.x) that fail safely.

**Files changed:**
- `simulate_alerts.py` — added `simulate_injection()` function and `injection` category
