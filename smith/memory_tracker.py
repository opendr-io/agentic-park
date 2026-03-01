"""
Memory and token usage reporting for all agent conversations.

Central registry that agents register their conversation stores with.
On demand, iterates over all registered stores and reports message
counts and estimated token usage.

Token estimation uses chars/4 as a simple approximation.
"""

from datetime import datetime


# Chars-per-token approximation (conservative for English text)
CHARS_PER_TOKEN = 4


def estimate_tokens(text):
    """Estimate token count from text using chars/4 approximation."""
    if not text:
        return 0
    return len(str(text)) // CHARS_PER_TOKEN


def estimate_message_tokens(message):
    """Estimate tokens for a single LangChain message."""
    content = getattr(message, 'content', '')
    # Add small overhead for role prefix (human/ai/system/tool)
    return estimate_tokens(content) + 4


class ConversationInfo:
    """Wraps a reference to a conversation store with a callable accessor."""

    def __init__(self, name, accessor):
        self.name = name
        self.accessor = accessor

    def get_conversations(self):
        """
        Returns dict of {scope_key: message_list}.
        If accessor returns a flat list, wraps it as {"main": list}.
        """
        result = self.accessor()
        if result is None:
            return {}
        if isinstance(result, list):
            return {"main": result}
        return result


class MemoryTracker:
    """
    Central registry for all agent conversation memory.
    Agents register themselves; status_agent queries on demand.
    """

    def __init__(self):
        self._registered = []

    def register(self, name, accessor):
        """
        Register a conversation store.

        Args:
            name: Human-readable name for the agent/store
            accessor: Callable returning dict {scope: [messages]} or [messages]
        """
        self._registered.append(ConversationInfo(name, accessor))

    def get_report(self):
        """Generate a memory usage report across all registered conversations."""
        lines = []
        lines.append("=" * 60)
        lines.append("MEMORY USAGE REPORT")
        lines.append("=" * 60)

        grand_total_messages = 0
        grand_total_tokens = 0
        agent_reports = []

        for info in self._registered:
            try:
                conversations = info.get_conversations()
            except Exception as e:
                agent_reports.append((info.name, 0, 0, [], str(e)))
                continue

            if not conversations:
                agent_reports.append((info.name, 0, 0, [], None))
                continue

            agent_messages = 0
            agent_tokens = 0
            scope_details = []

            for scope_key, messages in conversations.items():
                msg_count = len(messages)
                token_count = sum(estimate_message_tokens(m) for m in messages)
                agent_messages += msg_count
                agent_tokens += token_count
                scope_details.append((scope_key, msg_count, token_count))

            agent_reports.append((info.name, agent_messages, agent_tokens, scope_details, None))
            grand_total_messages += agent_messages
            grand_total_tokens += agent_tokens

        # Format output
        lines.append(f"\n  Total: {grand_total_messages} messages, ~{grand_total_tokens:,} tokens")
        lines.append(f"  Registered agents: {len(self._registered)}")

        for name, msg_count, token_count, scopes, error in agent_reports:
            lines.append(f"\n  {name}")
            lines.append("  " + "-" * (len(name) + 2))

            if error:
                lines.append(f"    ERROR: {error}")
                continue

            if msg_count == 0:
                lines.append("    (no active conversations)")
                continue

            lines.append(f"    {len(scopes)} conversation(s), {msg_count} messages, ~{token_count:,} tokens")

            # Show individual scopes if more than 1, or if scope is not "main"
            if len(scopes) > 1 or (len(scopes) == 1 and scopes[0][0] != "main"):
                scopes_sorted = sorted(scopes, key=lambda x: x[2], reverse=True)
                for scope_key, s_msgs, s_tokens in scopes_sorted[:10]:
                    display_key = scope_key[:40] + "..." if len(scope_key) > 40 else scope_key
                    lines.append(f"      {display_key}: {s_msgs} msgs, ~{s_tokens:,} tok")
                if len(scopes_sorted) > 10:
                    lines.append(f"      ... and {len(scopes_sorted) - 10} more")

        lines.append(f"\n  Report generated: {datetime.now().strftime('%H:%M:%S')}")
        lines.append("=" * 60)
        return "\n".join(lines)


# Module-level singleton
_tracker = None


def get_tracker():
    """Get or create the global MemoryTracker singleton."""
    global _tracker
    if _tracker is None:
        _tracker = MemoryTracker()
    return _tracker
