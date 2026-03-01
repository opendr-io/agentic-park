"""Tests for MemoryTracker: registration, token estimation, reporting."""

import pytest
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

from memory_tracker import (
    MemoryTracker, estimate_tokens, estimate_message_tokens,
    ConversationInfo, get_tracker,
)


class TestEstimateTokens:

    def test_empty_string(self):
        assert estimate_tokens("") == 0

    def test_none(self):
        assert estimate_tokens(None) == 0

    def test_short_string(self):
        # 5 chars // 4 = 1
        assert estimate_tokens("hello") == 1

    def test_longer_string(self):
        text = "a" * 400
        assert estimate_tokens(text) == 100

    def test_non_string(self):
        assert estimate_tokens(12345) == 1  # "12345" is 5 chars


class TestEstimateMessageTokens:

    def test_human_message(self):
        msg = HumanMessage(content="What is this alert?")
        tokens = estimate_message_tokens(msg)
        assert tokens == len("What is this alert?") // 4 + 4

    def test_ai_message(self):
        msg = AIMessage(content="This appears to be benign.")
        tokens = estimate_message_tokens(msg)
        assert tokens > 0

    def test_system_message(self):
        msg = SystemMessage(content="You are a security analyst.")
        tokens = estimate_message_tokens(msg)
        assert tokens > 0

    def test_empty_content(self):
        msg = HumanMessage(content="")
        tokens = estimate_message_tokens(msg)
        assert tokens == 4  # just the overhead


class TestConversationInfo:

    def test_dict_accessor(self):
        info = ConversationInfo("test", lambda: {"scope1": [HumanMessage(content="hi")]})
        convos = info.get_conversations()
        assert "scope1" in convos
        assert len(convos["scope1"]) == 1

    def test_list_accessor(self):
        info = ConversationInfo("test", lambda: [HumanMessage(content="hi")])
        convos = info.get_conversations()
        assert "main" in convos
        assert len(convos["main"]) == 1

    def test_none_accessor(self):
        info = ConversationInfo("test", lambda: None)
        assert info.get_conversations() == {}

    def test_empty_dict_accessor(self):
        info = ConversationInfo("test", lambda: {})
        assert info.get_conversations() == {}

    def test_empty_list_accessor(self):
        info = ConversationInfo("test", lambda: [])
        convos = info.get_conversations()
        assert convos == {"main": []}


class TestMemoryTracker:

    def test_register_and_report(self):
        tracker = MemoryTracker()
        messages = [HumanMessage(content="Q"), AIMessage(content="A")]
        tracker.register("Test Agent", lambda: {"conv1": messages})
        report = tracker.get_report()
        assert "Test Agent" in report
        assert "2 messages" in report

    def test_empty_tracker(self):
        tracker = MemoryTracker()
        report = tracker.get_report()
        assert "MEMORY USAGE REPORT" in report
        assert "Total: 0 messages" in report

    def test_no_active_conversations(self):
        tracker = MemoryTracker()
        tracker.register("Empty Agent", lambda: None)
        report = tracker.get_report()
        assert "Empty Agent" in report
        assert "no active conversations" in report

    def test_multiple_agents(self):
        tracker = MemoryTracker()
        tracker.register("Agent A", lambda: {"c1": [HumanMessage(content="x")]})
        tracker.register("Agent B", lambda: None)
        report = tracker.get_report()
        assert "Agent A" in report
        assert "Agent B" in report
        assert "Registered agents: 2" in report

    def test_error_in_accessor(self):
        tracker = MemoryTracker()
        tracker.register("Broken", lambda: 1 / 0)
        report = tracker.get_report()
        assert "ERROR" in report
        assert "Broken" in report

    def test_multiple_scopes(self):
        tracker = MemoryTracker()
        tracker.register("Multi", lambda: {
            "scope_a": [HumanMessage(content="a")],
            "scope_b": [HumanMessage(content="b"), AIMessage(content="c")],
        })
        report = tracker.get_report()
        assert "2 conversation(s)" in report
        assert "scope_a" in report
        assert "scope_b" in report

    def test_single_main_scope_not_shown(self):
        """When there's a single 'main' scope, don't show scope details."""
        tracker = MemoryTracker()
        tracker.register("Simple", lambda: [HumanMessage(content="hello")])
        report = tracker.get_report()
        assert "Simple" in report
        assert "1 conversation(s)" in report
        assert "main" not in report  # "main" scope key should be hidden

    def test_long_scope_key_truncated(self):
        tracker = MemoryTracker()
        long_key = "a" * 50
        tracker.register("Long", lambda: {long_key: [HumanMessage(content="x")]})
        report = tracker.get_report()
        assert "..." in report

    def test_token_totals(self):
        tracker = MemoryTracker()
        msg1 = HumanMessage(content="a" * 100)  # ~25 tokens + 4 overhead
        msg2 = AIMessage(content="b" * 200)  # ~50 tokens + 4 overhead
        tracker.register("Counted", lambda: {"c1": [msg1, msg2]})
        report = tracker.get_report()
        # Total should be (25+4) + (50+4) = 83 tokens
        assert "83" in report

    def test_report_has_timestamp(self):
        tracker = MemoryTracker()
        report = tracker.get_report()
        assert "Report generated:" in report

    def test_many_scopes_shows_top_10(self):
        tracker = MemoryTracker()
        scopes = {f"scope_{i}": [HumanMessage(content="x")] for i in range(15)}
        tracker.register("Many", lambda: scopes)
        report = tracker.get_report()
        assert "... and 5 more" in report


class TestSingleton:

    def test_get_tracker_returns_same_instance(self):
        import memory_tracker
        memory_tracker._tracker = None
        t1 = get_tracker()
        t2 = get_tracker()
        assert t1 is t2
        # Clean up
        memory_tracker._tracker = None
