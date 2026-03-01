# Router Agent - Intelligent Question Routing

The router agent acts as an intelligent dispatcher that routes user questions to specialized security analysis agents.

## Architecture

```
┌─────────────────────────────────────────────┐
│          User Question                       │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│      Router Agent (run_router_agent.py)     │
│  1. Classifies question using Claude        │
│  2. Displays routing decision to user       │
│  3. Calls specialist agent function         │
│  4. Streams response as it arrives          │
└─────────┬───────────────────────┬───────────┘
          │                       │
          ▼                       ▼
┌──────────────────────────┐    ┌─────────────────────────┐
│ run_alert_analyst.py     │    │ run_new_analyst.py      │
│ answer_question()        │    │ answer_question()       │
│ - SIGMA alerts           │    │ - New drivers           │
│ - Detections             │    │ - New autoruns          │
│ - Threats                │    │ - New tasks             │
│ + 5 tools                │    │ - New services          │
│ + event stream           │    │ + 3 tools               │
└──────────────────────────┘    └─────────────────────────┘
```

## How It Works

### 1. Question Classification

When you ask a question, the router uses Claude to classify it:

**ALERTS Category:**
- "What alerts fired?"
- "Show me suspicious PowerShell activity"
- "Analyze the network connection alerts"
- "Are there any lateral movement detections?"

**NEW_EVENTS Category:**
- "What new drivers were installed?"
- "Show me new scheduled tasks"
- "List new autoruns"
- "Are there suspicious new services?"

**Routing Decision:**
```python
routing_prompt = "Classify this question as ALERTS, NEW_EVENTS, or GENERAL"
classification = claude.invoke(routing_prompt + question)
# Routes based on classification
```

### 2. Agent Invocation

Once classified, the router:
1. **Displays routing decision** - Shows user which agent will handle the question
2. **Repeats the question** - Confirms what's being asked
3. **Calls agent function** - Invokes `run_alert_analyst.answer_question()` or `run_new_analyst.answer_question()`
4. **Agent streams response** - Tool calls print in real-time, response prints when complete

**Example Output:**
```
❓ Your question: What new drivers were installed?

📍 Routing to: Behavioral Anomaly Analyst
📝 Question: What new drivers were installed?

================================================================================
BEHAVIORAL ANOMALY ANALYST RESPONSE:
================================================================================

🔧 Using 1 tool(s)...
  • query_new_events

Based on the behavioral anomaly data, I found 3 new drivers:
[... response continues ...]
================================================================================
```

### 3. Memory Efficiency

**What the router DOES NOT do:**
- ❌ Store full conversation history
- ❌ Keep agent responses in memory
- ❌ Maintain state between questions

**What the router DOES:**
- ✅ Creates fresh context for each question
- ✅ Loads only recent summaries (2000 chars max)
- ✅ Clears conversation after response
- ✅ Logs everything to file instead of memory

**Memory Pattern:**
```python
# For each question:
conversation = [
    SystemMessage(minimal_context),  # Only essentials
    HumanMessage(question)           # Current question
]
response = agent.invoke(conversation)
# Response printed, then discarded
# conversation cleared
```

### 4. Logging

All routing decisions and agent interactions logged to `logging/router_agent.log`:

```
[2025-01-15 14:30:22] [INFO] Router agent initialized
[2025-01-15 14:30:22] [INFO] Alert analyst ready: 1,234 alerts
[2025-01-15 14:30:22] [INFO] Behavioral anomaly analyst ready: 567 events
[2025-01-15 14:30:45] [INFO] Routing question: What new drivers were installed?
[2025-01-15 14:30:46] [INFO] Classification: NEW_EVENTS
[2025-01-15 14:30:46] [INFO] Forwarding to BEHAVIORAL ANOMALY ANALYST
[2025-01-15 14:30:47] [INFO] Anomaly analyst using 1 tool(s)
[2025-01-15 14:30:47] [INFO] Tool: query_new_events with args {'event_type': 'driver'}
[2025-01-15 14:30:49] [INFO] Anomaly analyst response: 523 chars
```

## Usage

### Standalone Mode

```bash
python run_router_agent.py
```

The router will:
1. Load `exports/alerts_dd.csv` (for alert analyst)
2. Load `dump/new` (for anomaly analyst)
3. Load `exports/opendr_dump.parquet` or `.csv` (for event stream tools)
4. Enter interactive Q&A mode

### From Orchestrator

```python
import run_router_agent

# Pass data directly
router = run_router_agent.RouterAgent(
    alerts_df=alerts_df,
    new_df=new_df,
    events_df=events_df
)

router.interactive_mode()
```

### Programmatic Usage

```python
# Single question
router = run_router_agent.RouterAgent(alerts_df, new_df, events_df)
response = router.ask_alert_analyst("What are the top alerts?")

# Or let router decide
agent = router.route_question("Show me suspicious drivers")
if agent == 'alert_analyst':
    response = router.ask_alert_analyst(question)
else:
    response = router.ask_new_analyst(question)
```

## Example Session

```
ROUTER AGENT - Intelligent Security Analysis
================================================================================

I will route your questions to the appropriate specialist:
  • Alert Analyst - for questions about security alerts and detections
  • Behavioral Anomaly Analyst - for questions about new system changes

Type 'exit' or 'quit' to finish
================================================================================

❓ Your question: What alerts fired today?
[ROUTER] Routing question: What alerts fired today?...
[ROUTER] Classification: ALERTS
[ROUTER] Forwarding to ALERT ANALYST

================================================================================
ALERT ANALYST RESPONSE:
================================================================================

Based on the alerts data, here are the key alerts from today:
1. Suspicious PowerShell execution (5 events)
2. Network connection to suspicious IP (2 events)
[... response continues ...]

❓ Your question: Show me new drivers that aren't signed
[ROUTER] Routing question: Show me new drivers that aren't signed...
[ROUTER] Classification: NEW_EVENTS
[ROUTER] Forwarding to BEHAVIORAL ANOMALY ANALYST

================================================================================
BEHAVIORAL ANOMALY ANALYST RESPONSE:
================================================================================

🔧 Using tool: query_new_events

Found 3 unsigned drivers installed:
1. unknown.sys - No signature, installed 2025-01-15 10:23
[... response continues ...]
```

## Agent Capabilities

### Alert Analyst (run_alert_analyst.py)

**Data Access:**
- Security alerts from SIGMA rules
- Full event stream for investigation

**Tools (5):**
1. `query_events_by_pid` - Get all events for a PID
2. `query_events_by_process_name` - Search by process name
3. `build_process_tree` - Build parent-child chain
4. `lookup_ip_info` - Geolocation and org info
5. `query_network_events` - Network connection search

**Best For:**
- Alert triage and analysis
- Threat investigation
- Process behavior analysis
- Network activity investigation

### Behavioral Anomaly Analyst (run_new_analyst.py)

**Data Access:**
- New system changes (drivers, autoruns, tasks, services)

**Tools (3):**
1. `query_new_events` - Filter by event type/hostname/time
2. `get_event_summary` - Statistics and overview
3. `search_new_events` - Full-text search

**Best For:**
- Persistence mechanism detection
- System change auditing
- Baseline anomaly detection
- Configuration drift analysis

## Token Efficiency

The router minimizes token usage by:

1. **Minimal Routing Classification** (~100-200 tokens)
   - Simple classification prompt
   - No conversation history needed

2. **Fresh Context Per Question** (~2,000-3,000 tokens)
   - Only system message + user question
   - No accumulated history
   - Small summaries instead of full logs

3. **No State Retention**
   - Each question independent
   - Previous responses discarded
   - Conversation cleared after each answer

**Comparison:**

| Approach | Tokens per Question | Token Growth |
|----------|---------------------|--------------|
| Monolithic agent with history | 5,000 + (500 × turns) | Quadratic |
| Router with fresh context | 2,000-5,000 | Constant |

## Error Handling

**If classification fails:**
- Defaults to alert analyst
- Logs error
- Continues operation

**If agent fails:**
- Returns error message to user
- Logs full traceback
- Continues accepting questions

**If data missing:**
- Checks availability before routing
- Returns helpful message to user
- Suggests which data to load

## Extending the Router

To add a new specialist agent:

```python
# 1. Import the agent module
import run_threat_hunter

# 2. Add to RouterAgent.__init__()
self.threat_hunting_df = threat_hunting_df
run_threat_hunter.DATA_DF = threat_hunting_df

# 3. Add classification option in route_question()
if 'THREAT_HUNT' in classification:
    return 'threat_hunter'

# 4. Create agent method
def ask_threat_hunter(self, question):
    # Similar to ask_alert_analyst()
    pass
```

## Performance

**Routing Overhead:**
- Classification: ~1 second
- Context loading: <0.1 seconds
- Total overhead: ~1-2 seconds per question

**Agent Response Time:**
- Simple query: 2-5 seconds
- With tool calls: 5-15 seconds
- Complex multi-tool: 15-30 seconds

**Memory Footprint:**
- Router object: ~1 MB
- Per-question overhead: ~500 KB (cleared after response)
- Log file: Grows ~1-2 KB per question

## Best Practices

1. **Ask Specific Questions**
   - Good: "Show me PowerShell alerts from today"
   - Bad: "What happened?"

2. **Use Domain Keywords**
   - "alerts", "detections", "threats" → Alert Analyst
   - "new", "installed", "changes" → Anomaly Analyst

3. **Monitor Logs**
   - Check `logging/router_agent.log` for routing decisions
   - Verify correct agent is being selected

4. **Clear Logs Periodically**
   - Router logs grow over time
   - Archive or clear old logs to save space
