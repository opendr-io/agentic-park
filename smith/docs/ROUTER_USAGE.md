# Router Agent - Quick Start Guide

The router agent provides a unified interface to ask security questions that are automatically routed to the appropriate specialist.

## Quick Start

```bash
python run_router_agent.py
```

That's it! The router will:
1. Load alerts from `exports/alerts_dd.csv`
2. Load behavioral anomaly events from `dump/new`
3. Load event stream from `exports/opendr_dump.parquet` (or `.csv`)
4. Enter interactive Q&A mode

## Example Session

```
ROUTER AGENT - Intelligent Security Analysis
================================================================================

I will route your questions to the appropriate specialist:
  • Alert Analyst - security alerts, detections, threats
  • Behavioral Anomaly Analyst - new system changes, persistence

Type 'exit' or 'quit' to finish
================================================================================

❓ Your question: What alerts fired for PowerShell?

📍 Routing to: Alert Analyst
📝 Question: What alerts fired for PowerShell?

================================================================================
ALERT ANALYST RESPONSE:
================================================================================

Based on the alert data, there were 12 PowerShell-related alerts:
1. Suspicious PowerShell Execution (8 events)
2. PowerShell Download Cradle (3 events)
3. Encoded PowerShell Command (1 event)
[... full analysis ...]
================================================================================

❓ Your question: Show me unsigned drivers

📍 Routing to: Behavioral Anomaly Analyst
📝 Question: Show me unsigned drivers

================================================================================
BEHAVIORAL ANOMALY ANALYST RESPONSE:
================================================================================

🔧 Using 1 tool(s)...
  • query_new_events

Found 2 unsigned drivers:
1. suspicious.sys - Installed 2025-01-15 10:23 on WORKSTATION01
2. unknown.sys - Installed 2025-01-15 14:15 on WORKSTATION02
[... full analysis ...]
================================================================================

❓ Your question: exit
```

## What Gets Routed Where

### → Alert Analyst
Questions about:
- Security alerts
- SIGMA detections
- Suspicious activity
- Threat analysis
- Process behavior
- Network connections
- Sysmon events

**Example questions:**
- "What are the top alerts?"
- "Show me network connections to suspicious IPs"
- "Analyze the PowerShell alerts"
- "What processes spawned cmd.exe?"
- "Build a process tree for PID 1234"

### → Behavioral Anomaly Analyst
Questions about:
- New system changes
- Persistence mechanisms
- New drivers
- New autoruns
- New scheduled tasks
- New services
- Configuration drift

**Example questions:**
- "What new drivers were installed?"
- "Show me unsigned autoruns"
- "List new scheduled tasks"
- "Are there suspicious new services?"
- "What persistence mechanisms were added?"

## Logging

All routing decisions and agent interactions are logged to:
```
logging/router_agent.log
```

View logs in real-time:
```bash
tail -f logging/router_agent.log
```

Example log entries:
```
[2025-01-15 14:30:45] [INFO] User question: What alerts fired for PowerShell?
[2025-01-15 14:30:46] [INFO] Routing question: What alerts fired for PowerShell?...
[2025-01-15 14:30:46] [INFO] Classification: ALERTS
[2025-01-15 14:30:46] [INFO] Forwarding to ALERT ANALYST
[2025-01-15 14:30:49] [INFO] Alert analyst response: 523 chars
```

## Memory Efficiency

The router is designed to be **extremely memory-efficient**:

- ✅ Each question starts fresh (no conversation history)
- ✅ Minimal context (2000 char summaries only)
- ✅ Response discarded after display
- ✅ Constant ~3,000 tokens per question

**No memory growth** - question #1 and question #100 use the same amount of tokens.

## Integration with Orchestrator

You can call the router from your orchestrator or other scripts:

```python
import run_router_agent

# Option 1: Let router load data automatically
router = run_router_agent.main()

# Option 2: Pass data directly
router_agent = run_router_agent.RouterAgent(
    alerts_df=alerts_df,
    new_df=new_df,
    events_df=events_df
)
router_agent.interactive_mode()

# Option 3: Single question programmatically
router_agent = run_router_agent.RouterAgent(alerts_df, new_df, events_df)
agent_type = router_agent.route_question("Show me PowerShell alerts")
response = router_agent.ask_agent("Show me PowerShell alerts", agent_type)
print(response)
```

## Agent Functions

The router calls these functions in the specialist modules:

**Alert Analyst:**
```python
run_alert_analyst.answer_question(question, events_df=None)
```

**Behavioral Anomaly Analyst:**
```python
run_new_analyst.answer_question(question, new_df=None)
```

Both functions:
- Accept a single question string
- Load minimal context (summaries only)
- Use LangChain tools
- Return response text
- Print tool calls in real-time

## Troubleshooting

**"No data available for either analyst"**
- Ensure `exports/alerts_dd.csv` exists
- Or ensure `dump/new` exists
- Run orchestrator first to generate these files

**"Alert analyst not available"**
- Check that `exports/alerts_dd.csv` has data
- Check that `exports/opendr_dump.parquet` or `.csv` exists

**"Behavioral anomaly analyst not available"**
- Check that `dump/new` file exists
- Verify it contains behavioral anomaly data

**Wrong agent selected**
- Check `logging/router_agent.log` for classification
- Rephrase question with clearer keywords
- Use "alerts" for Alert Analyst
- Use "new" or "installed" for Anomaly Analyst

**API errors**
- Check `.env` has valid `ANTHROPIC_API_KEY`
- Check rate limiting settings in `.env`
- Review `logging/router_agent.log` for errors

## Performance

**Typical Response Times:**
- Classification: ~1 second
- Simple question (no tools): 2-5 seconds
- Question with tools: 5-15 seconds
- Complex multi-tool: 15-30 seconds

**Token Usage per Question:**
- Routing classification: ~100-200 tokens
- Agent response: ~2,000-5,000 tokens
- **Total: ~3,000-5,000 tokens (constant)**

## Tips for Best Results

1. **Be specific** - "Show me PowerShell alerts from today" vs "What happened?"
2. **Use keywords** - Mention "alerts", "new", "drivers", "services" explicitly
3. **One topic per question** - Don't mix alert and anomaly questions
4. **Check routing** - Verify correct agent was selected (shown in output)
5. **Review logs** - Check `logging/router_agent.log` for debugging
