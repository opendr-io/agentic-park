# Prompt File Mapping

Which prompt files are used by which agents.

| Prompt file | Used by | Agent / Mode |
|---|---|---|
| `alert_analyst_answer.txt` | `agents/run_alert_analyst.py` | Alert Analyst — `answer_question()` (single question from router) |
| `alert_analyst_batch.txt` | `agents/run_alert_analyst.py` | Alert Analyst — `main()` batch mode |
| `alert_analyst_interactive.txt` | `agents/run_alert_analyst.py` | Alert Analyst — `main()` interactive follow-up mode |
| `alert_prompt.txt` | `agents/run_alert_analyst.py` | Alert Analyst — `load_alert_analyst_prompt()` helper (used by batch mode) |
| `event_search.txt` | `agents/run_event_search.py` | Event Search — both `answer_question()` and `main()` |
| `new_analyst.txt` | `agents/run_new_analyst.py` | New Analyst — both `answer_question()` and `main()` |
| `routing.txt` | `status_agent.py`, `main_agent.py`, `agents/run_router_agent.py` | Router (3 files reference it) |
| `meetup.txt` | `status_agent.py` | Status Agent — meetup command |
| `notification_handler.txt` | `agents/run_notification_agent.py` | Notification Agent |

## Unused

| Prompt file | Notes |
|---|---|
| `new_analyst-old.txt` | Backup of old prompt — safe to delete |
