# DataFrame Loading Strategy

The router and agents now use a **multi-tier fallback strategy** to find DataFrames, prioritizing pre-existing pipeline data.

## Loading Priority

### 1. Explicit Parameters (Highest Priority)
```python
router = RouterAgent(alerts_df=my_alerts, events_df=my_events, new_df=my_new)
```
- If you pass DataFrames explicitly, they are used
- This is how the orchestrator would call it

### 2. Pre-existing Globals (Pipeline Data)
```python
# If orchestrator already ran:
run_alert_analyst.ALERTS_DF  # Set by orchestrator step 5
run_alert_analyst.EVENTS_DF  # Set by orchestrator step 1
run_new_analyst.NEW_DF       # Set if behavioral anomaly step ran
```
- Router checks if these globals already exist
- Uses them if nothing was passed explicitly
- Logs: "Alert analyst using existing alerts_df"

### 3. Load from Files (Last Resort)
```python
# If nothing else works, load from disk:
alerts_df = pd.read_csv('exports/alerts_dd.csv')
events_df = pd.read_parquet('exports/opendr_dump.parquet')
new_df = pd.read_csv('dump/new')
```
- Only happens if parameters are None AND globals are None
- Ensures standalone mode works

## Code Flow

### Router Agent Initialization

```python
def __init__(self, alerts_df=None, new_df=None, events_df=None):
    self.alerts_df = alerts_df
    self.new_df = new_df
    self.events_df = events_df

    # Set globals if provided
    if alerts_df is not None:
        run_alert_analyst.ALERTS_DF = alerts_df
    if events_df is not None:
        run_alert_analyst.EVENTS_DF = events_df
    if new_df is not None:
        run_new_analyst.NEW_DF = new_df

    # Check for pre-existing pipeline data
    if alerts_df is None and run_alert_analyst.ALERTS_DF is not None:
        self.alerts_df = run_alert_analyst.ALERTS_DF  # Use existing
        log("Alert analyst using existing alerts_df")

    if events_df is None and run_alert_analyst.EVENTS_DF is not None:
        self.events_df = run_alert_analyst.EVENTS_DF  # Use existing
        log("Using existing events_df")

    if new_df is None and run_new_analyst.NEW_DF is not None:
        self.new_df = run_new_analyst.NEW_DF  # Use existing
        log("Using existing new_df")
```

### Alert Analyst answer_question()

```python
def answer_question(question, events_df=None, alerts_df=None):
    global EVENTS_DF, ALERTS_DF

    # Tier 1: Use provided parameters
    if events_df is not None:
        EVENTS_DF = events_df
    if alerts_df is not None:
        ALERTS_DF = alerts_df

    # Tier 2: Globals already set from pipeline (do nothing)

    # Tier 3: Load from files if still None
    if ALERTS_DF is None:
        if Path('exports/alerts_dd.csv').exists():
            ALERTS_DF = pd.read_csv('exports/alerts_dd.csv')

    if EVENTS_DF is None:
        if Path('exports/opendr_dump.parquet').exists():
            EVENTS_DF = pd.read_parquet('exports/opendr_dump.parquet')
```

## Usage Scenarios

### Scenario 1: Orchestrator Pipeline
```python
# Step 1: Load events
events_df = opendr_dump.main()  # Sets run_alert_analyst.EVENTS_DF

# Step 2-4: Extract and process alerts
alerts_df = extract_alert_events.main(events_df)
alerts_df = match_fps.main(alerts_df)
alerts_dd = deduplicate_alerts.main(alerts_df)

# Step 5: Run alert analysis (sets run_alert_analyst.ALERTS_DF)
run_alert_analyst.main(alerts_dd, events_df)

# Step 6: Run router
router = run_router_agent.main()  # No params needed!
# Router finds: alerts_df from run_alert_analyst.ALERTS_DF
#               events_df from run_alert_analyst.EVENTS_DF
```

**Result:** Router uses pipeline data automatically ✅

### Scenario 2: Standalone Router
```bash
python run_router_agent.py
```

```python
# Router main() function loads from files:
alerts_df = pd.read_csv('exports/alerts_dd.csv')
new_df = pd.read_csv('dump/new')
events_df = pd.read_parquet('exports/opendr_dump.parquet')

router = RouterAgent(alerts_df, new_df, events_df)
```

**Result:** Router loads from disk ✅

### Scenario 3: Mixed Mode
```python
# Some data from pipeline, some from params
events_df = opendr_dump.main()  # Sets global

# Later... pass only new data
router = RouterAgent(alerts_df=my_custom_alerts)
# Uses: my_custom_alerts (param)
#       events_df from global (pipeline)
```

**Result:** Hybrid approach works ✅

## Logging Examples

**When using pipeline data:**
```
[2025-01-15 14:30:22] [INFO] Router agent initialized
[2025-01-15 14:30:22] [INFO] Alert analyst using existing alerts_df: 1,234 alerts
[2025-01-15 14:30:22] [INFO] Alert analyst using existing events_df: 45,678 events
```

**When loading from files:**
```
[2025-01-15 14:30:22] [INFO] Router agent initialized
Loading alerts from exports/alerts_dd.csv...
  Loaded 1,234 alerts
Loading event stream from exports/opendr_dump.parquet...
  Loaded 45,678 events
[2025-01-15 14:30:25] [INFO] Alert analyst ready: 1,234 alerts
[2025-01-15 14:30:25] [INFO] Event stream loaded: 45,678 events
```

**When passed explicitly:**
```
[2025-01-15 14:30:22] [INFO] Router agent initialized
[2025-01-15 14:30:22] [INFO] Alert analyst ready: 1,234 alerts
[2025-01-15 14:30:22] [INFO] Behavioral anomaly analyst ready: 567 events
[2025-01-15 14:30:22] [INFO] Event stream loaded: 45,678 events
```

## Benefits

1. **Pipeline Integration** - Orchestrator doesn't need to pass DataFrames explicitly
2. **Standalone Mode** - Router works independently when run directly
3. **Flexibility** - Can mix pipeline data with custom parameters
4. **Memory Efficiency** - Reuses existing DataFrames instead of reloading
5. **Transparency** - Logs show exactly where data came from

## Testing

To verify the loading strategy:

```python
# Test 1: Pipeline mode
import run_alert_analyst
import run_router_agent

run_alert_analyst.ALERTS_DF = my_alerts  # Simulate pipeline
router = run_router_agent.RouterAgent()
assert router.alerts_df is my_alerts  # Should use pipeline data

# Test 2: Explicit mode
router = run_router_agent.RouterAgent(alerts_df=other_alerts)
assert router.alerts_df is other_alerts  # Should use param

# Test 3: File loading
run_alert_analyst.ALERTS_DF = None  # Clear globals
router = run_router_agent.RouterAgent()
assert router.alerts_df is not None  # Should load from file
```
