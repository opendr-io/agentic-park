"""
Run Claude-based event stream search.
Queries the full system event stream (process creation, network connections, etc.).
Used directly by the router for user queries, and by other agents via delegation.
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from tools import EVENT_SEARCH_TOOLS, process_event_search_tool_call
import tools.state as tool_state
from llm_utils import get_llm, stream_response

# Load environment variables from .env file
load_dotenv()

# Module-level reference for memory tracking (set during interactive mode)
_active_conversation = None


def load_prompt(name):
    """Load a prompt template from the prompts/ directory."""
    prompt_file = Path('prompts') / name
    if not prompt_file.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
    with open(prompt_file, 'r', encoding='utf-8') as f:
        return f.read()


def answer_question(question, events_df=None, silent=False, prior_messages=None):
    """
    Answer a question about the event stream.

    Args:
        question: User's question or delegated query
        events_df: Optional events DataFrame
        silent: If True, suppress print output
        prior_messages: Optional list of prior conversation messages for context

    Returns:
        Response text
    """
    if events_df is not None:
        tool_state.EVENTS_DF = events_df

    if tool_state.EVENTS_DF is None:
        return "ERROR: Event stream data not loaded"

    # Load prompt from file and build system message with event count
    base_prompt = load_prompt('event_search.txt')
    system_msg = SystemMessage(content=f"""{base_prompt}

## Current Dataset

You have access to {len(tool_state.EVENTS_DF):,} system events (process creation, network connections, etc.).

Use your tools to search and analyze these events.""")

    human_msg = HumanMessage(content=question)

    # Initialize LLM with tools
    llm_with_tools = get_llm(tools=EVENT_SEARCH_TOOLS)

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
            print(f"\n  Using {len(response.tool_calls)} tool(s)...")

        conversation.append(response)

        for tool_call in response.tool_calls:
            tool_name = tool_call['name']
            tool_input = tool_call['args']

            if not silent:
                print(f"    {tool_name}({', '.join(f'{k}={v}' for k, v in tool_input.items())})")

            # Execute tool
            tool_result = process_event_search_tool_call(tool_name, tool_input)

            tool_msg = ToolMessage(
                content=tool_result,
                tool_call_id=tool_call['id']
            )
            conversation.append(tool_msg)

        # Get next response
        response = stream_response(llm_with_tools, conversation, silent=silent)

    return response.content


def main():
    """Run interactive event stream search."""
    print("\n" + "="*80)
    print("EVENT STREAM SEARCH")
    print("Search process and network events from the system event stream")
    print("="*80 + "\n")

    # Load events DataFrame from exports
    if tool_state.EVENTS_DF is None:
        from data_layer.event_stream import EventStream
        log_dir = Path('.')
        stream = EventStream(log_dir)
        stream.load()
        if not stream.events_df.empty:
            tool_state.EVENTS_DF = stream.events_df

    if tool_state.EVENTS_DF is None or len(tool_state.EVENTS_DF) == 0:
        print("ERROR: No event stream data available")
        return None

    print(f"Loaded {len(tool_state.EVENTS_DF):,} events")

    # Show summary
    if 'category' in tool_state.EVENTS_DF.columns:
        cat_counts = tool_state.EVENTS_DF['category'].dropna().value_counts()
        if len(cat_counts) > 0:
            print(f"\nEvent categories:")
            for cat, count in cat_counts.items():
                print(f"  {cat}: {count:,}")

    # Initialize Claude with tools
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not found in environment variables")
        return None

    model = os.getenv('CLAUDE_MODEL', 'claude-sonnet-4-5-20250929')
    print(f"\nUsing model: {model}")

    llm_with_tools = get_llm(tools=EVENT_SEARCH_TOOLS)

    # Load prompt from file and build system message with event count
    base_prompt = load_prompt('event_search.txt')
    system_msg = SystemMessage(content=f"""{base_prompt}

## Current Dataset

You have access to {len(tool_state.EVENTS_DF):,} system events.

Use your tools to search and analyze these events.""")

    # Initialize conversation history
    global _active_conversation
    conversation_history = [system_msg]
    _active_conversation = conversation_history

    # Interactive Q&A mode
    print("\n" + "="*80)
    print("INTERACTIVE MODE - Search the event stream")
    print(f"Tools enabled: Can query {len(tool_state.EVENTS_DF):,} events")
    print("Type 'exit' or 'quit' to finish")
    print("="*80 + "\n")

    while True:
        try:
            user_input = input("\nYour question: ").strip()

            if user_input.lower() in ['exit', 'quit', 'q', 'x', '']:
                print("\nExiting interactive mode...")
                break

            # Memory report command
            if user_input.lower() in ('memory', 'mem', 'm'):
                from memory_tracker import get_tracker
                print("\n" + get_tracker().get_report() + "\n")
                continue

            human_msg = HumanMessage(content=user_input)
            conversation_history.append(human_msg)

            print("\nEvent Search response:")
            print("-" * 80)

            response = stream_response(llm_with_tools, conversation_history)

            tool_rounds = 0
            while response.tool_calls and tool_rounds < 10:
                tool_rounds += 1
                print(f"\n  Using {len(response.tool_calls)} tool(s)...")

                conversation_history.append(response)

                for tool_call in response.tool_calls:
                    tool_name = tool_call['name']
                    tool_input = tool_call['args']

                    print(f"    {tool_name}({', '.join(f'{k}={v}' for k, v in tool_input.items())})")

                    tool_result = process_event_search_tool_call(tool_name, tool_input)

                    tool_msg = ToolMessage(
                        content=tool_result,
                        tool_call_id=tool_call['id']
                    )
                    conversation_history.append(tool_msg)

                response = stream_response(llm_with_tools, conversation_history)

            # stream_response already printed the response
            print("-" * 80)

            conversation_history.append(response)

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
    return tool_state.EVENTS_DF


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nEvent stream search interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
