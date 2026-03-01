"""
Run Claude-based alert analysis.
Expects alerts_df to be passed in from orchestrator.
"""
import pandas as pd
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timedelta
from collections import deque
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage

from tools import ALERT_TOOLS, process_alert_tool_call
import tools.state as tool_state
from llm_utils import get_llm, stream_response

# Load environment variables from .env file
load_dotenv()


def load_ignore_list():
    """Load list of alert names to ignore from fp-data/ignore file."""
    ignore_file = Path('fp-data/ignore')
    if not ignore_file.exists():
        return []

    ignore_list = []
    with open(ignore_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):  # Skip empty lines and comments
                ignore_list.append(line)

    return ignore_list


def load_prompt(name):
    """Load a prompt template from the prompts/ directory."""
    prompt_file = Path('prompts') / name
    if not prompt_file.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
    with open(prompt_file, 'r', encoding='utf-8') as f:
        return f.read()


def load_known_benign():
    """Load known benign patterns from fp-data/known_benign.txt."""
    fp_file = Path('fp-data/known_benign.txt')
    if not fp_file.exists():
        return ''
    with open(fp_file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
    if not lines:
        return ''
    return (
        "\n\n## Known Benign Patterns (confirmed by security team)\n"
        "If an alert matches one of these patterns, classify it as FALSE POSITIVE with LOW severity.\n\n"
        + "\n".join(f"- {line}" for line in lines)
    )


def load_alert_prompt():
    """Load the alert analysis prompt template."""
    return load_prompt('alert_prompt.txt')


def save_alert_analysis(alert_name, analysis_text, log_file):
    """Save alert analysis to local log file for memory persistence."""
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"\n{'='*80}\n")
        f.write(f"ALERT: {alert_name}\n")
        f.write(f"TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*80}\n")
        f.write(analysis_text)
        f.write(f"\n{'='*80}\n\n")


def load_analysis_summary(log_file, max_chars=3000):
    """Load a summary of recent analyses from the log file."""
    if not Path(log_file).exists():
        return "No previous analyses found."

    with open(log_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Return last N characters as summary
    if len(content) > max_chars:
        return f"...{content[-max_chars:]}"
    return content


class TokenRateLimiter:
    """Track token usage over time and enforce rate limits."""

    def __init__(self, max_tokens_per_minute, tokens_per_request):
        """
        Initialize rate limiter.

        Args:
            max_tokens_per_minute: Maximum tokens allowed per minute
            tokens_per_request: Estimated tokens per API request
        """
        self.max_tokens_per_minute = max_tokens_per_minute
        self.tokens_per_request = tokens_per_request
        self.token_history = deque()  # (timestamp, tokens) tuples

    def _clean_old_entries(self):
        """Remove entries older than 1 minute."""
        cutoff = datetime.now() - timedelta(minutes=1)
        while self.token_history and self.token_history[0][0] < cutoff:
            self.token_history.popleft()

    def _get_current_usage(self):
        """Get total tokens used in the last minute."""
        self._clean_old_entries()
        return sum(tokens for _, tokens in self.token_history)

    def wait_if_needed(self, logger=None):
        """Wait if necessary to stay within token limits."""
        self._clean_old_entries()
        current_usage = self._get_current_usage()

        # Check if adding this request would exceed limit
        if current_usage + self.tokens_per_request > self.max_tokens_per_minute:
            # Calculate how long to wait
            if self.token_history:
                oldest_timestamp = self.token_history[0][0]
                wait_until = oldest_timestamp + timedelta(minutes=1)
                wait_seconds = (wait_until - datetime.now()).total_seconds()

                if wait_seconds > 0:
                    if logger:
                        logger.info(f"Token rate limit: {current_usage:,}/{self.max_tokens_per_minute:,} tokens used")
                        logger.info(f"Waiting {wait_seconds:.1f}s to stay within limits...")
                    else:
                        print(f"\n⏱ Token rate limit: waiting {wait_seconds:.1f}s...")

                    time.sleep(wait_seconds)
                    self._clean_old_entries()

    def record_usage(self, tokens=None):
        """Record token usage for this request."""
        if tokens is None:
            tokens = self.tokens_per_request
        self.token_history.append((datetime.now(), tokens))


def format_alert_timeline(alert_events):
    """Format alert events into a readable timeline for Claude."""
    timeline = []

    for idx, event in alert_events.iterrows():
        timeline.append(f"\n--- Event {idx + 1} ---")
        timeline.append(f"Timestamp: {event.get('timestamp', 'N/A')}")
        timeline.append(f"Alert: {event.get('alert_name', 'N/A')}")
        timeline.append(f"Process: {event.get('process', 'N/A')} (PID: {event.get('pid', 'N/A')})")

        if pd.notna(event.get('commandline')):
            timeline.append(f"Command Line: {event.get('commandline')}")

        if pd.notna(event.get('parentimage')):
            timeline.append(f"Parent Process: {event.get('parentimage')} (PID: {event.get('parentprocessid', 'N/A')})")

        if pd.notna(event.get('username')):
            timeline.append(f"User: {event.get('username')}")

        if pd.notna(event.get('hostname')):
            timeline.append(f"Hostname: {event.get('hostname')}")

        if pd.notna(event.get('sourceip')) or pd.notna(event.get('destinationip')):
            timeline.append(f"Network: {event.get('sourceip', 'N/A')}:{event.get('sourceport', 'N/A')} -> {event.get('destinationip', 'N/A')}:{event.get('destinationport', 'N/A')}")

        if pd.notna(event.get('alert_description')):
            timeline.append(f"Description: {event.get('alert_description')}")

    return "\n".join(timeline)


def setup_logging():
    """Set up logging to file."""
    import logging
    from datetime import datetime

    # Create logs directory if it doesn't exist
    logs_dir = Path('logs')
    logs_dir.mkdir(exist_ok=True)

    # Create log file with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = logs_dir / f'alert_analysis_{timestamp}.log'

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()  # Also print to console
        ]
    )

    return logging.getLogger(__name__)


def find_precomputed_analysis(question):
    """
    Search alerts_df for pre-computed analysis matching the user's question.

    Extracts keywords from the question and matches against alert_name, hostname,
    and other fields. Returns matching analyses if found.

    Args:
        question: User's question string

    Returns:
        String with pre-computed analysis context, or empty string if none found
    """
    if tool_state.ALERTS_DF is None:
        return ''

    df = tool_state.ALERTS_DF

    # Only consider open (non-closed) alerts
    if 'alert_status' in df.columns:
        df = df[df['alert_status'] != 'closed']

    # Check if analysis column exists and has any data
    if 'analysis' not in df.columns:
        return ''

    analyzed = df[df['analysis'].notna() & (df['analysis'] != '')]
    if len(analyzed) == 0:
        return ''

    # Search analyzed alerts for matches against the question
    question_lower = question.lower()

    # Try to match by alert name keywords
    matches = []
    for _, row in analyzed.iterrows():
        alert_name = str(row.get('alert_name', '')).lower()
        hostname = str(row.get('hostname', '')).lower()

        # Check if any significant words from the alert appear in the question
        alert_words = [w for w in alert_name.split() if len(w) > 3]
        hostname_match = hostname and hostname in question_lower

        name_match = any(word in question_lower for word in alert_words)

        if name_match or hostname_match:
            matches.append(row)

    if not matches:
        # If no keyword match, still provide a summary of all analyzed alerts
        # so the LLM knows what's available without needing tool calls
        severity_counts = analyzed['severity'].value_counts().to_dict() if 'severity' in analyzed.columns else {}
        alert_types = analyzed['alert_name'].value_counts().head(10).to_dict() if 'alert_name' in analyzed.columns else {}

        summary_parts = [f"Background analysis has completed for {len(analyzed)} alerts."]
        if severity_counts:
            summary_parts.append("Severity breakdown: " + ", ".join(f"{k}: {v}" for k, v in severity_counts.items()))
        if alert_types:
            summary_parts.append("Alert types analyzed: " + ", ".join(f"{k} ({v})" for k, v in alert_types.items()))

        return "\n".join(summary_parts) + "\n\n"

    # Single match: include full analysis text
    if len(matches) == 1:
        row = matches[0]
        parts = [f"Pre-computed analysis found for 1 matching alert:\n"]
        parts.append(f"--- Alert: {row.get('alert_name', 'Unknown')} ---")
        parts.append(f"Hash: {row.get('alert_hash', 'N/A')[:8]}")
        parts.append(f"Hostname: {row.get('hostname', 'N/A')}")
        parts.append(f"Timestamp: {row.get('timestamp', 'N/A')}")
        parts.append(f"Severity: {row.get('severity', 'N/A')}")
        analysis_val = row.get('analysis', 'N/A')
        if str(analysis_val) == 'file':
            from data_layer.alert_tracker import load_analysis_text
            analysis_text = load_analysis_text(row.get('alert_hash', ''))
            if analysis_text:
                analysis_val = analysis_text
        parts.append(f"Analysis:\n{analysis_val}")
        parts.append("")
    else:
        # Multiple matches: list summaries only to avoid flooding the context window
        parts = [f"Pre-computed analysis found for {len(matches)} matching alerts. Summaries:\n"]
        for row in matches[:10]:
            alert_hash = row.get('alert_hash', '')
            parts.append(f"  [{alert_hash[:8]}] {row.get('alert_name', 'Unknown')} | "
                         f"{row.get('hostname', 'N/A')} | "
                         f"{row.get('timestamp', 'N/A')} | "
                         f"Severity: {row.get('severity', 'N/A')}")
        parts.append(f"\nTo reference a specific alert's full analysis, use its hash prefix (e.g. alert [hash]).")

    return "\n".join(parts) + "\n\n"


def answer_question(question, events_df=None, alerts_df=None, silent=False, prior_messages=None):
    """
    Answer a single question about alerts (for router agent).

    Args:
        question: User's question
        events_df: Optional events DataFrame
        alerts_df: Optional alerts DataFrame
        silent: If True, suppress all print output (for background processing)
        prior_messages: Optional list of prior conversation messages for context

    Returns:
        Response text
    """
    # Use provided DataFrames or keep existing state (from pipeline)
    if events_df is not None:
        tool_state.EVENTS_DF = events_df
    if alerts_df is not None:
        tool_state.ALERTS_DF = alerts_df

    # If still None, try loading from files as last resort
    if tool_state.ALERTS_DF is None:
        alerts_file = Path('exports/alerts_dd.csv')
        if alerts_file.exists():
            tool_state.ALERTS_DF = pd.read_csv(alerts_file)

    # Check for pre-computed analysis from background processor
    precomputed = find_precomputed_analysis(question)

    # Load context from previous analyses
    memory_log = Path('exports/alert_analyses_memory.txt')
    if memory_log.exists():
        summary = load_analysis_summary(memory_log, max_chars=2000)
        context = f"Previous alert analyses summary:\n{summary}\n\n"
    else:
        context = "No previous alert analyses found.\n\n"

    # Build tools message
    tools_msg = ""
    if tool_state.ALERTS_DF is not None:
        tools_msg = f"""You have access to {len(tool_state.ALERTS_DF):,} security alerts with these tools:
- query_alerts: Filter and search alerts by name, hostname, or time
- get_alert_summary: Get overview statistics of all alerts
- search_alerts: Search for specific terms across all alert fields

"""

    if tool_state.EVENTS_DF is not None:
        tools_msg += f"""You also have access to the event stream ({len(tool_state.EVENTS_DF):,} events) via the delegate_event_search tool.
Use delegate_event_search to investigate process activity, network connections, or build process trees.
The tool requires alert_timestamp and hostname parameters which automatically scope the search to ±30 minutes of the alert."""

    # Include pre-computed analysis context if available
    precomputed_instruction = ""
    if precomputed:
        precomputed_instruction = f"""
## Pre-computed Alert Analysis (from background processor)

{precomputed}
If the user's question is answered by the pre-computed analysis above, use it directly in your response.
Only use tools if the user asks for additional detail beyond what the analysis already covers.
"""

    prompt_text = load_prompt('alert_analyst_answer.txt').format(
        context=context,
        precomputed_instruction=precomputed_instruction,
        tools_msg=tools_msg,
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    prompt_text += load_known_benign()
    system_msg = SystemMessage(content=prompt_text)

    human_msg = HumanMessage(content=question)

    # Initialize LLM with tools
    llm_with_tools = get_llm(tools=ALERT_TOOLS)

    conversation = [system_msg]
    if prior_messages:
        conversation.extend(prior_messages)
    conversation.append(human_msg)

    # Get response (may include tool calls)
    response = stream_response(llm_with_tools, conversation, silent=silent)

    # Handle tool calls if present (cap at 10 rounds to prevent infinite loops)
    tool_rounds = 0
    while response.tool_calls and tool_rounds < 10:
        tool_rounds += 1
        from langchain_core.messages import ToolMessage

        if not silent:
            print(f"\n🔧 Using {len(response.tool_calls)} tool(s)...")

        conversation.append(response)

        for tool_call in response.tool_calls:
            tool_name = tool_call['name']
            tool_input = tool_call['args']

            if not silent:
                print(f"  • {tool_name}({', '.join(f'{k}={v}' for k, v in tool_input.items())})")

            # Execute tool
            tool_result = process_alert_tool_call(tool_name, tool_input)

            tool_msg = ToolMessage(
                content=tool_result,
                tool_call_id=tool_call['id']
            )
            conversation.append(tool_msg)

        # Get next response
        response = stream_response(llm_with_tools, conversation, silent=silent)

    return response.content


def main(alerts_df, events_df=None):
    """Run Claude-based alert analysis with provided alerts DataFrame and optional events DataFrame."""
    from langchain_core.messages import HumanMessage, SystemMessage

    # Set up logging
    logger = setup_logging()
    logger.info("Starting alert analysis session")

    # Load events DataFrame if provided
    if events_df is not None:
        tool_state.EVENTS_DF = events_df
        logger.info(f"Loaded events DataFrame: {len(tool_state.EVENTS_DF):,} events")
    elif tool_state.EVENTS_DF is None:
        logger.warning("No events DataFrame available - event search delegation will be limited")
        print("\n  Warning: No event stream loaded. Event search delegation will not work.")
        print("  Run orchestrator.py to have events_df passed automatically.\n")

    # Set up local memory file for persisting analyses
    memory_log = Path('exports/alert_analyses_memory.txt')
    if memory_log.exists():
        logger.info(f"Existing analysis memory found: {memory_log}")
    else:
        logger.info(f"Creating new analysis memory log: {memory_log}")
        memory_log.parent.mkdir(parents=True, exist_ok=True)
        memory_log.touch()

    # Load ignore list
    ignore_list = load_ignore_list()

    if ignore_list:
        initial_count = len(alerts_df)
        logger.info(f"Loaded {len(ignore_list)} alert names to ignore")
        for alert_name in ignore_list:
            logger.info(f"  Ignoring: {alert_name}")

        # Filter out ignored alerts
        alerts_df = alerts_df[~alerts_df['alert_name'].isin(ignore_list)].copy()
        filtered_count = initial_count - len(alerts_df)

        logger.info(f"Filtered out {filtered_count:,} alerts ({filtered_count/initial_count*100:.1f}%)")
        logger.info(f"Remaining alerts: {len(alerts_df):,}")

    # Step 1: Get unique alert instances (alert_name + hostname + timestamp)
    # Group by these three fields to create unique alert instances
    alert_instances = alerts_df.groupby(['alert_name', 'hostname', 'timestamp']).size().reset_index(name='event_count')
    print(f"\nFound {len(alert_instances)} unique alert instances to analyze")
    logger.info(f"\nFound {len(alert_instances)} unique alert instances to analyze")

    # Show breakdown by alert type
    alert_type_counts = alert_instances.groupby('alert_name').size().to_dict()
    print(f"Alert types: {len(alert_type_counts)}")
    for alert_type, count in sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {alert_type}: {count} instances")
        logger.info(f"  - {alert_type}: {count} instances")

    # Load prompt template
    prompt_template = load_alert_prompt()

    # Initialize Claude with streaming
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        logger.error("ANTHROPIC_API_KEY not found in environment variables")
        raise ValueError("ANTHROPIC_API_KEY not set. Please set it in .env file")

    model = os.getenv('CLAUDE_MODEL', 'claude-sonnet-4-5-20250929')
    logger.info(f"Using model: {model}")

    # Load rate limiting configuration
    analysis_delay = float(os.getenv('ALERT_ANALYSIS_DELAY', '2.0'))
    logger.info(f"Time-based rate limiting: {analysis_delay}s delay between alerts")

    # Load token-based rate limiting configuration
    tokens_per_alert = int(os.getenv('TOKENS_PER_ALERT', '10000'))
    max_tokens_per_minute = int(os.getenv('MAX_TOKENS_PER_MINUTE', '40000'))

    # Initialize token rate limiter
    rate_limiter = TokenRateLimiter(max_tokens_per_minute, tokens_per_alert)
    logger.info(f"Token-based rate limiting: {tokens_per_alert:,} tokens/alert, {max_tokens_per_minute:,} max tokens/min")

    # Initialize LLM with tools for both batch and interactive mode
    # Tool calls will be scoped per alert instance via alert_memories dictionary
    llm_with_tools = get_llm(tools=ALERT_TOOLS)

    # Initialize conversation history for memory
    conversation_history = []

    # System message for context with tool instructions
    tools_available_msg = ""
    if tool_state.EVENTS_DF is not None:
        tools_available_msg = f"""

You have access to the event stream ({len(tool_state.EVENTS_DF):,} events) via the delegate_event_search tool.
Use delegate_event_search to investigate process activity, network connections, or build process trees.
The tool requires alert_timestamp and hostname parameters which automatically scope the search to ±30 minutes of the alert.
Tool results are automatically tracked in this alert's memory."""

    batch_prompt = load_prompt('alert_analyst_batch.txt').format(
        tools_available_msg=tools_available_msg,
        current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    batch_prompt += load_known_benign()
    system_msg = SystemMessage(content=batch_prompt)

    # Memory Architecture: Per-Alert-Instance Tracking
    # Each unique alert instance (alert_name + hostname + timestamp) gets its own conversation history
    # This ensures that tool query results are properly scoped to the specific alert being analyzed
    # Format: alert_memories[alert_scope] = [SystemMessage, HumanMessage, AIMessage, ToolMessage, ...]
    # where alert_scope = "alert_name|hostname|timestamp"
    alert_memories = {}

    # Step 2-5: Process each unique alert instance
    for alert_idx, row in alert_instances.iterrows():
        alert_name = row['alert_name']
        hostname = row['hostname']
        timestamp = row['timestamp']

        # Create unique alert scope identifier
        alert_scope = f"{alert_name}|{hostname}|{timestamp}"

        logger.info(f"\n{'='*80}")
        logger.info(f"Analyzing alert instance {alert_idx + 1}/{len(alert_instances)}")
        logger.info(f"  Alert: {alert_name}")
        logger.info(f"  Hostname: {hostname}")
        logger.info(f"  Timestamp: {timestamp}")
        logger.info(f"  Scope ID: {alert_scope}")
        logger.info(f"{'='*80}")

        # Initialize conversation history for this alert instance if not exists
        if alert_scope not in alert_memories:
            alert_memories[alert_scope] = [system_msg]
            logger.info(f"Created new memory for alert instance: {alert_scope}")

        # Get conversation history for this specific alert instance
        conversation_history = alert_memories[alert_scope]

        # Step 2: Get all events for this specific alert instance
        alert_events = alerts_df[
            (alerts_df['alert_name'] == alert_name) &
            (alerts_df['hostname'] == hostname) &
            (alerts_df['timestamp'] == timestamp)
        ].copy()
        logger.info(f"Found {len(alert_events)} events for this alert instance")

        # Format timeline
        timeline = format_alert_timeline(alert_events)

        # Step 3: Combine with prompt
        prompt = prompt_template.replace('{timeline}', timeline)

        logger.info(f"\nSending to Claude (timeline length: {len(timeline)} chars)")

        # Check token rate limit before making API call
        rate_limiter.wait_if_needed(logger)

        # Step 4: Send to Claude with streaming
        print(f"\n\n{'='*80}")
        print(f"ALERT INSTANCE {alert_idx + 1}/{len(alert_instances)}")
        print(f"  Alert: {alert_name}")
        print(f"  Hostname: {hostname}")
        print(f"  Timestamp: {timestamp}")
        print(f"  Events: {len(alert_events)}")
        print(f"{'='*80}\n")

        try:
            # Add current prompt to conversation history
            human_msg = HumanMessage(content=prompt)
            conversation_history.append(human_msg)

            # Use tool-enabled LLM (supports both regular responses and tool calls)
            from langchain_core.messages import AIMessage, ToolMessage

            response = stream_response(llm_with_tools, conversation_history)
            conversation_history.append(response)

            # Handle tool calls if present (cap at 10 rounds)
            tool_rounds = 0
            while response.tool_calls and tool_rounds < 10:
                tool_rounds += 1
                print(f"\n🔧 Claude is using {len(response.tool_calls)} tool(s) to investigate this alert...")
                logger.info(f"Processing {len(response.tool_calls)} tool calls for alert scope {alert_scope}")

                for tool_call in response.tool_calls:
                    tool_name = tool_call['name']
                    tool_input = tool_call['args']

                    print(f"  • {tool_name}({', '.join(f'{k}={v}' for k, v in tool_input.items())})")
                    logger.info(f"Tool call: {tool_name} with args {tool_input}")

                    # Execute the tool
                    tool_result = process_alert_tool_call(tool_name, tool_input)
                    logger.info(f"Tool result length: {len(tool_result)} chars")

                    # Add tool result to conversation history (scoped to this alert instance)
                    tool_msg = ToolMessage(
                        content=tool_result,
                        tool_call_id=tool_call['id']
                    )
                    conversation_history.append(tool_msg)

                # Get next response after tool calls
                print(f"\n💭 Analyzing tool results...")
                response = stream_response(llm_with_tools, conversation_history)
                conversation_history.append(response)

            # Extract final text response
            response_text = response.content if hasattr(response, 'content') else str(response)

            # Log the interaction
            logger.info(f"Claude's response ({len(response_text)} chars):")
            logger.info(response_text)
            logger.info(f"Conversation history for {alert_scope} now contains {len(conversation_history)} messages")

            # Free conversation history — analysis is persisted to file,
            # no need to keep in memory (each alert_scope is unique)
            del alert_memories[alert_scope]
            logger.info(f"Released conversation memory for alert scope: {alert_scope}")

            # Save analysis to local memory file (persists without sending to API)
            # Include hostname and timestamp in the save
            alert_instance_label = f"{alert_name} | {hostname} | {timestamp}"
            save_alert_analysis(alert_instance_label, response_text, memory_log)
            logger.info(f"Saved analysis to local memory: {memory_log}")

            # Record token usage for rate limiting
            rate_limiter.record_usage()

            # Analysis saved and memory released — nothing more to do for this instance

        except Exception as e:
            logger.error(f"Error analyzing alert instance '{alert_scope}': {e}")
            print(f"\nError: {e}\n")
            # Reset history for this instance on error
            alert_memories[alert_scope] = [system_msg]
            logger.info(f"Reset conversation history for {alert_scope} due to error")
            continue

        # Rate limiting: delay between alert instances (except after the last one)
        if alert_idx < len(alert_instances) - 1 and analysis_delay > 0:
            logger.info(f"Rate limiting: waiting {analysis_delay}s before next alert instance...")
            time.sleep(analysis_delay)

    logger.info(f"\n{'='*80}")
    logger.info("Alert analysis session completed")
    logger.info(f"Processed {len(alert_instances)} alert instances")
    logger.info(f"Memory tracking: {len(alert_memories)} alert scopes remaining in memory (should be 0)")

    # Log memory usage statistics
    total_messages = sum(len(history) for history in alert_memories.values())
    avg_messages = total_messages / len(alert_memories) if alert_memories else 0
    logger.info(f"Total conversation messages across all instances: {total_messages}")
    logger.info(f"Average messages per alert instance: {avg_messages:.1f}")
    logger.info(f"{'='*80}")

    # Interactive follow-up questions
    print("\n" + "="*80)
    print("INTERACTIVE MODE - Ask follow-up questions (type 'exit' or 'quit' to finish)")
    if tool_state.EVENTS_DF is not None:
        print(f"Tools enabled: Can query {len(tool_state.EVENTS_DF):,} events, build process trees, lookup IPs")
    print(f"Previous analyses saved to: {memory_log}")
    print("="*80 + "\n")

    # Load summary of previous analyses for context (doesn't send full history)
    analysis_summary = load_analysis_summary(memory_log, max_chars=3000)

    # Create new system message with analysis summary for interactive mode
    interactive_system_msg = SystemMessage(content=load_prompt('alert_analyst_interactive.txt').format(
        analysis_summary=analysis_summary,
        tools_available_msg=tools_available_msg
    ))

    # Reset conversation history for interactive mode with summary
    conversation_history = [interactive_system_msg]
    logger.info("Interactive mode: Loaded analysis summary from local memory (not sent in full)")

    while True:
        try:
            # Get user input
            user_input = input("\nYour question: ").strip()

            # Check for exit commands
            if user_input.lower() in ['exit', 'quit', 'q', 'x', '']:
                print("\nExiting interactive mode...")
                logger.info("User exited interactive mode")
                break

            # Memory report command
            if user_input.lower() in ('memory', 'mem', 'm'):
                from memory_tracker import get_tracker
                print("\n" + get_tracker().get_report() + "\n")
                continue

            # Fresh conversation per question (no unbounded history growth)
            human_msg = HumanMessage(content=user_input)
            conversation = [interactive_system_msg, human_msg]

            logger.info(f"User question: {user_input}")

            print("\nClaude's response:")
            print("-" * 80)

            # Use tool-enabled LLM for interactive mode
            from langchain_core.messages import AIMessage, ToolMessage

            # Get response (may include tool calls) — streams to screen
            response = stream_response(llm_with_tools, conversation)

            # Handle tool calls if present (cap at 10 rounds)
            tool_rounds = 0
            while response.tool_calls and tool_rounds < 10:
                tool_rounds += 1
                logger.info(f"Claude requested {len(response.tool_calls)} tool call(s)")

                conversation.append(response)

                for tool_call in response.tool_calls:
                    tool_name = tool_call['name']
                    tool_input = tool_call['args']

                    print(f"\n🔧 Using tool: {tool_name}")
                    logger.info(f"Tool call: {tool_name} with input {tool_input}")

                    tool_result = process_alert_tool_call(tool_name, tool_input)
                    logger.info(f"Tool result length: {len(tool_result)} chars")

                    tool_msg = ToolMessage(
                        content=tool_result,
                        tool_call_id=tool_call['id']
                    )
                    conversation.append(tool_msg)

                response = stream_response(llm_with_tools, conversation)

            # stream_response already printed the response
            print("-" * 80)

            logger.info(f"Claude's response ({len(response.content)} chars):")
            logger.info(response.content)

        except KeyboardInterrupt:
            print("\n\nInteractive mode interrupted by user.")
            logger.info("Interactive mode interrupted by user")
            break
        except EOFError:
            print("\n\nEnd of input detected.")
            logger.info("End of input detected")
            break
        except Exception as e:
            print(f"\n\nError during interactive mode: {e}")
            logger.error(f"Interactive mode error: {e}")
            import traceback
            logger.error(traceback.format_exc())

    # Return the original alerts_df (unchanged)
    return alerts_df


if __name__ == "__main__":
    # When run standalone, load from CSV for testing
    print("Loading alerts from CSV for standalone testing...")
    alerts_csv = Path('exports/alert_events.csv')

    if not alerts_csv.exists():
        print(f"ERROR: {alerts_csv} not found!")
        print("Run orchestrator.py or extract_alert_events.py first to generate the file.")
        sys.exit(1)

    alerts_df = pd.read_csv(alerts_csv)
    print(f"Loaded {len(alerts_df):,} alerts from {alerts_csv}")

    # Run the analyst
    try:
        main(alerts_df)
    except KeyboardInterrupt:
        print("\n\nAlert analyst interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
