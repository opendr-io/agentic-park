"""
Per-alert conversation memory using LangChain InMemoryChatMessageHistory.

Each alert gets its own conversation history keyed by alert_hash.
When the history exceeds a threshold, older messages are summarized
using a cheap LLM (Haiku) to prevent context window overflow.

Usage:
    from alert_memory import AlertMemoryManager

    mgr = AlertMemoryManager(alerts_df)
    alert_id = mgr.detect_alert_id("tell me about alert a3f8b2c1")  # -> full hash
    prior = mgr.load_context_messages(alert_id)                      # -> [messages...]
    # ... pass prior to analyst, get answer ...
    mgr.save_exchange(alert_id, question, answer)
"""

import re
import pandas as pd
from langchain_core.chat_history import InMemoryChatMessageHistory
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage


# Phrases that indicate a follow-up question about the same alert
FOLLOWUP_PHRASES = [
    'tell me more', 'more detail', 'explain', 'elaborate',
    'what about', 'also', 'that alert', 'this alert', 'same alert',
    'the parent', 'the process', 'the command', 'that process',
    'is this', 'is that', 'false positive', 'true positive',
    'how about', 'and what', 'the network', 'the connection',
    'why', 'how did', 'what happened', 'related',
]


class AlertMemoryManager:
    """
    Manages per-alert conversation memory with automatic summarization.

    Each alert (by alert_hash) gets its own InMemoryChatMessageHistory.
    When history exceeds max_messages, older messages are summarized
    into a compact string and replaced with a single SystemMessage.
    """

    def __init__(self, alerts_df, max_messages=10):
        """
        Args:
            alerts_df: Reference to the alerts DataFrame (for seeding from analysis)
            max_messages: Max messages per alert before summarization triggers
        """
        self.alerts_df = alerts_df
        self.max_messages = max_messages

        self._memories = {}      # {alert_hash: InMemoryChatMessageHistory}
        self._summaries = {}     # {alert_hash: str}
        self._seeded = set()     # Track which alert_hashes have been seeded
        self._last_alert_id = None  # Full alert_hash of most recently referenced alert

        self._summary_llm = None

    def _get_summary_llm(self):
        """Lazy-load a cheap LLM for summarization (from config or default haiku)."""
        if self._summary_llm is None:
            from llm_utils import get_llm, _load_config
            try:
                config = _load_config()
                summary_model = config.get('LLM', 'summary_model', fallback='haiku')
                self._summary_llm = get_llm(
                    model=summary_model,
                    max_tokens=500,
                )
            except Exception:
                return None
        return self._summary_llm

    def _resolve_hash_prefix(self, prefix):
        """
        Resolve a hash prefix to a full alert_hash.

        Args:
            prefix: First N characters of an alert_hash (min 4)

        Returns:
            Full alert_hash string, or None if not found/ambiguous
        """
        if self.alerts_df is None or 'alert_hash' not in self.alerts_df.columns:
            return None

        prefix_lower = prefix.lower().strip()
        matches = self.alerts_df[
            self.alerts_df['alert_hash'].str.lower().str.startswith(prefix_lower)
        ]

        if len(matches) == 1:
            return matches.iloc[0]['alert_hash']
        return None

    def detect_alert_id(self, question):
        """
        Detect which alert a question refers to by hash prefix.

        Checks for explicit patterns like "alert a3f8b2c1", "#a3f8".
        Falls back to follow-up phrase detection using _last_alert_id.

        Returns:
            Full alert_hash string, or None
        """
        if self.alerts_df is None:
            return None

        # Explicit reference: "alert a3f8b2c1", "#a3f8", "alert [a3f8b2c1]"
        match = re.search(
            r'(?:alert|row|#)\s*\[?([0-9a-fA-F]{4,})\]?',
            question, re.IGNORECASE
        )
        if match:
            prefix = match.group(1)
            resolved = self._resolve_hash_prefix(prefix)
            if resolved:
                return resolved

        # Follow-up detection
        if self._last_alert_id is not None:
            question_lower = question.lower()
            if any(phrase in question_lower for phrase in FOLLOWUP_PHRASES):
                return self._last_alert_id

        return None

    def _get_or_create_memory(self, alert_id):
        """Get or create the message history for an alert, seeding if needed."""
        if alert_id not in self._memories:
            self._memories[alert_id] = InMemoryChatMessageHistory()

        # Seed from existing analysis on first access
        if alert_id not in self._seeded:
            self._seeded.add(alert_id)
            self._seed_from_analysis(alert_id)

        return self._memories[alert_id]

    def _seed_from_analysis(self, alert_id):
        """Seed memory with existing analysis from the DataFrame."""
        if self.alerts_df is None or 'alert_hash' not in self.alerts_df.columns:
            return

        mask = self.alerts_df['alert_hash'] == alert_id
        if not mask.any():
            return

        row = self.alerts_df[mask].iloc[0]
        analysis = row.get('analysis')
        if pd.isna(analysis) or not str(analysis).strip():
            return

        analysis_val = str(analysis).strip()
        if analysis_val == 'file':
            from data_layer.alert_tracker import load_analysis_text
            analysis_text = load_analysis_text(alert_id)
            if not analysis_text:
                return
        else:
            analysis_text = analysis_val
        # Truncate very long analyses to avoid blowing the token budget on seed
        if len(analysis_text) > 3000:
            analysis_text = analysis_text[:3000] + '\n[... truncated]'

        memory = self._memories[alert_id]
        memory.add_message(HumanMessage(content="What is the initial analysis of this alert?"))
        memory.add_message(AIMessage(content=analysis_text))

    def load_context_messages(self, alert_id):
        """
        Load conversation context for an alert.

        Returns a list of messages to prepend to the conversation:
        - Summary of older messages (if any) as SystemMessage
        - Recent messages from buffer

        Args:
            alert_id: Full alert_hash string

        Returns:
            list[BaseMessage] — may be empty if no prior context
        """
        if alert_id is None:
            return []

        memory = self._get_or_create_memory(alert_id)
        messages = list(memory.messages)

        result = []

        # Prepend summary if we have one
        if alert_id in self._summaries:
            result.append(SystemMessage(
                content=f"Summary of prior conversation about this alert:\n{self._summaries[alert_id]}"
            ))

        result.extend(messages)
        return result

    def save_exchange(self, alert_id, question, answer):
        """
        Save a Q&A exchange to the alert's memory.

        Only the final question and answer are saved — intermediate tool calls
        are NOT stored, keeping the memory compact.

        Args:
            alert_id: Full alert_hash string
            question: The user's question
            answer: The analyst's final response
        """
        if alert_id is None:
            return

        memory = self._get_or_create_memory(alert_id)
        memory.add_message(HumanMessage(content=question))
        memory.add_message(AIMessage(content=answer))

        self._last_alert_id = alert_id
        self._summarize_if_needed(alert_id)

    def get_all_conversations(self):
        """Return all active conversations as {alert_hash_prefix: [messages]}.

        Used by MemoryTracker for reporting. Includes summary as a
        SystemMessage prepended to the message list if one exists.
        """
        result = {}
        for alert_id, memory in self._memories.items():
            messages = list(memory.messages)
            if alert_id in self._summaries:
                summary_msg = SystemMessage(
                    content=f"Summary of prior conversation:\n{self._summaries[alert_id]}"
                )
                messages = [summary_msg] + messages
            result[alert_id[:8]] = messages
        return result

    def _summarize_if_needed(self, alert_id):
        """Summarize older messages if the buffer exceeds max_messages."""
        memory = self._memories.get(alert_id)
        if memory is None:
            return

        messages = list(memory.messages)
        if len(messages) <= self.max_messages:
            return

        # Keep the last 2 messages (most recent Q/A pair), summarize the rest
        keep_count = 2
        to_summarize = messages[:-keep_count]
        to_keep = messages[-keep_count:]

        # Build summarization input
        existing_summary = self._summaries.get(alert_id, '')
        conversation_text = []
        for msg in to_summarize:
            role = 'Analyst' if isinstance(msg, AIMessage) else 'User'
            conversation_text.append(f"{role}: {msg.content[:500]}")

        summary_input = ""
        if existing_summary:
            summary_input += f"Previous summary:\n{existing_summary}\n\n"
        summary_input += "New conversation to incorporate:\n" + "\n".join(conversation_text)

        # Try LLM summarization
        llm = self._get_summary_llm()
        if llm:
            try:
                response = llm.invoke([
                    SystemMessage(content=(
                        "Condense this security alert conversation into a brief summary (3-5 sentences). "
                        "Preserve: key findings, IOCs, severity assessments, and conclusions. "
                        "If a previous summary exists, merge it with the new information. "
                        "Provide ONLY the summary, no preamble."
                    )),
                    HumanMessage(content=summary_input),
                ])
                self._summaries[alert_id] = response.content
            except Exception:
                # Fallback: simple truncation
                self._summaries[alert_id] = self._truncate_summary(
                    existing_summary, to_summarize
                )
        else:
            # No LLM available: simple truncation
            self._summaries[alert_id] = self._truncate_summary(
                existing_summary, to_summarize
            )

        # Replace memory with just the recent messages
        memory.clear()
        for msg in to_keep:
            memory.add_message(msg)

    def _truncate_summary(self, existing_summary, messages):
        """Fallback summarization: keep key lines from messages."""
        parts = []
        if existing_summary:
            parts.append(existing_summary)
        for msg in messages:
            role = 'Analyst' if isinstance(msg, AIMessage) else 'User'
            # Keep first 200 chars of each message
            parts.append(f"{role}: {msg.content[:200]}")
        # Cap total summary at 2000 chars
        result = '\n'.join(parts)
        if len(result) > 2000:
            result = result[:2000] + '\n[... truncated]'
        return result

    def clear_memory(self, alert_id):
        """Clear all memory for a specific alert."""
        self._memories.pop(alert_id, None)
        self._summaries.pop(alert_id, None)
        self._seeded.discard(alert_id)
