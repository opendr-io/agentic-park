"""
Run Claude-based behavioral anomaly analysis.
Analyzes 'new' events like new drivers, autoruns, scheduled tasks, and services.
Expects alerts_df to be passed in from orchestrator.
"""
import pandas as pd
import os
import sys
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage

from tools import NEW_TOOLS, process_new_tool_call
import tools.state as tool_state
from llm_utils import get_llm, stream_response

# Load environment variables from .env file
load_dotenv()


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


def load_new_analyst_prompt():
    """Load the behavioral anomaly analysis prompt."""
    return load_prompt('new_analyst.txt')


def answer_question(question, new_df=None, silent=False, prior_messages=None, events_df=None):
    """
    Answer a single question about behavioral anomalies (for router agent).

    Args:
        question: User's question
        new_df: Optional new events DataFrame
        silent: If True, suppress all print output (for background processing)
        prior_messages: Optional list of prior conversation messages for context
        events_df: Optional events DataFrame for event stream searches

    Returns:
        Response text
    """
    if new_df is not None:
        tool_state.NEW_DF = new_df
    if events_df is not None:
        tool_state.EVENTS_DF = events_df

    if tool_state.NEW_DF is None:
        return "ERROR: Behavioral anomaly data not loaded"

    # Build event stream tools message
    event_stream_msg = ""
    if tool_state.EVENTS_DF is not None:
        event_stream_msg = f"""

You also have access to the event stream ({len(tool_state.EVENTS_DF):,} events) via the delegate_event_search tool.
Use delegate_event_search to investigate process activity, network connections, or build process trees.
The tool requires alert_timestamp and hostname parameters which automatically scope the search to ±30 minutes of the alert."""

    # Load prompt from file and build system message with event count
    base_prompt = load_new_analyst_prompt()
    known_benign = load_known_benign()
    system_msg = SystemMessage(content=f"""{base_prompt}

## Current Dataset

You have access to {len(tool_state.NEW_DF):,} behavioral anomaly events.
{event_stream_msg}

Use your tools to analyze these events for potential security concerns, persistence mechanisms, or suspicious activity.
Be thorough but concise in your analysis.{known_benign}""")

    human_msg = HumanMessage(content=question)

    # Initialize LLM with tools
    llm_with_tools = get_llm(tools=NEW_TOOLS)

    conversation = [system_msg]
    if prior_messages:
        conversation.extend(prior_messages)
    conversation.append(human_msg)

    # Get response (may include tool calls)
    response = stream_response(llm_with_tools, conversation, silent=silent)

    # Handle tool calls if present (cap at 10 rounds)
    tool_rounds = 0
    while response.tool_calls and tool_rounds < 10:
        tool_rounds += 1
        if not silent:
            print(f"\n🔧 Using {len(response.tool_calls)} tool(s)...")

        conversation.append(response)

        for tool_call in response.tool_calls:
            tool_name = tool_call['name']
            tool_input = tool_call['args']

            if not silent:
                print(f"  • {tool_name}")

            # Execute tool
            tool_result = process_new_tool_call(tool_name, tool_input)

            tool_msg = ToolMessage(
                content=tool_result,
                tool_call_id=tool_call['id']
            )
            conversation.append(tool_msg)

        # Get next response
        response = stream_response(llm_with_tools, conversation, silent=silent)

    return response.content


def main(alerts_df=None):
    """Run Claude-based behavioral anomaly analysis.

    Args:
        alerts_df: DataFrame with parsed alert events (from extract_alert_events).
                   If None, will be loaded via extract_alert_events.
    """
    print("\n" + "="*80)
    print("BEHAVIORAL ANOMALY ANALYST")
    print("Analyzing new drivers, autoruns, scheduled tasks, and services")
    print("="*80 + "\n")

    # Use provided DataFrame or load via extract_alert_events
    if alerts_df is not None:
        tool_state.NEW_DF = alerts_df
    elif tool_state.NEW_DF is None:
        from data_layer.extract_alert_events import main as extract_main
        print("Loading alerts from alerts/ directory...")
        tool_state.NEW_DF = extract_main()

    if tool_state.NEW_DF is None or len(tool_state.NEW_DF) == 0:
        print("ERROR: No alert events available")
        return None

    print(f"Loaded {len(tool_state.NEW_DF):,} alert events")

    # Show summary
    if 'event' in tool_state.NEW_DF.columns:
        event_counts = tool_state.NEW_DF['event'].dropna().value_counts()
        if len(event_counts) > 0:
            print(f"\nEvent type breakdown:")
            for event_type, count in event_counts.items():
                print(f"  {event_type}: {count:,}")

    print(f"\nDate range: {tool_state.NEW_DF['timestamp'].min()} to {tool_state.NEW_DF['timestamp'].max()}")
    print(f"Hostnames: {', '.join(tool_state.NEW_DF['hostname'].dropna().unique())}")

    # Initialize Claude with tools
    llm_with_tools = get_llm(tools=NEW_TOOLS)
    print(f"\nUsing model: {os.getenv('CLAUDE_MODEL', 'claude-sonnet-4-5-20250929')}")

    # Build event stream tools message
    event_stream_msg = ""
    if tool_state.EVENTS_DF is not None:
        event_stream_msg = f"""

You also have access to the event stream ({len(tool_state.EVENTS_DF):,} events) via the delegate_event_search tool.
Use delegate_event_search to investigate process activity, network connections, or build process trees.
The tool requires alert_timestamp and hostname parameters which automatically scope the search to ±30 minutes of the alert."""

    # Load prompt from file and build system message with event count
    base_prompt = load_new_analyst_prompt()
    known_benign = load_known_benign()
    system_msg = SystemMessage(content=f"""{base_prompt}

## Current Dataset

You have access to {len(tool_state.NEW_DF):,} behavioral anomaly events from Windows systems.
{event_stream_msg}

Use your tools to analyze these events for potential security concerns, persistence mechanisms, or suspicious activity.
Be thorough but concise in your analysis.{known_benign}""")

    # Interactive Q&A mode
    print("\n" + "="*80)
    print("INTERACTIVE MODE - Ask questions about behavioral anomalies")
    print(f"Tools enabled: Can query {len(tool_state.NEW_DF):,} anomaly detection events")
    print("Type 'exit' or 'quit' to finish")
    print("="*80 + "\n")

    while True:
        try:
            # Get user input
            user_input = input("\nYour question: ").strip()

            # Check for exit commands
            if user_input.lower() in ['exit', 'quit', 'q', 'x', '']:
                print("\nExiting interactive mode...")
                break

            # Memory report command
            if user_input.lower() in ('memory', 'mem', 'm'):
                from memory_tracker import get_tracker
                print("\n" + get_tracker().get_report() + "\n")
                continue

            # Fresh conversation per question to prevent unbounded token growth
            human_msg = HumanMessage(content=user_input)
            conversation = [system_msg, human_msg]

            print("\nClaude's response:")
            print("-" * 80)

            # Get response (may include tool calls) — streams to screen
            response = stream_response(llm_with_tools, conversation)

            # Handle tool calls if present (cap at 10 rounds)
            tool_rounds = 0
            while response.tool_calls and tool_rounds < 10:
                tool_rounds += 1
                print(f"\n🔧 Using {len(response.tool_calls)} tool(s)...")

                # Add AI message with tool calls to history
                conversation.append(response)

                # Process each tool call
                for tool_call in response.tool_calls:
                    tool_name = tool_call['name']
                    tool_input = tool_call['args']

                    print(f"  Tool: {tool_name}")

                    # Execute the tool
                    tool_result = process_new_tool_call(tool_name, tool_input)

                    # Add tool result to conversation
                    tool_msg = ToolMessage(
                        content=tool_result,
                        tool_call_id=tool_call['id']
                    )
                    conversation.append(tool_msg)

                # Get next response from Claude with tool results
                response = stream_response(llm_with_tools, conversation)

            # stream_response already printed the response
            print("-" * 80)

        except KeyboardInterrupt:
            print("\n\nInteractive mode interrupted by user.")
            break
        except EOFError:
            print("\n\nEnd of input detected.")
            break
        except Exception as e:
            print(f"\n\nError during interactive mode: {e}")
            import traceback
            traceback.print_exc()

    print("\nSession completed.")
    return tool_state.NEW_DF


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nBehavioral anomaly analyst interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
