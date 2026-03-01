# Project Structure

```
d:\jackson\
├── agents/                  # LLM agent runners
│   ├── run_alert_analyst.py
│   ├── run_event_search.py
│   ├── run_new_analyst.py
│   ├── run_notification_agent.py
│   └── run_router_agent.py
├── data_layer/              # Data processing & persistence
│   ├── extract_alert_events.py
│   ├── alert_tracker.py
│   ├── background_processor.py
│   ├── event_stream.py
│   ├── deduplicate_alerts.py
│   ├── filter_false_positives.py
│   ├── create_fp_hashes.py
│   └── match_fps.py
├── tools/                   # LangChain agent tools
├── tests/                   # 266 tests, all passing
├── prompts/                 # Prompt templates
├── exports/                 # CSV/parquet output
├── docs/                    # Documentation
├── status_agent.py          # Main orchestrator
├── orchestrator.py          # App entry point
└── main_agent.py            # Dead code (superseded by status_agent)
```
