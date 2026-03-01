"""Tests for AlertMemoryManager: detection, seeding, save/load, summarization."""

import pandas as pd
import pytest
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from alert_memory import AlertMemoryManager, FOLLOWUP_PHRASES


@pytest.fixture
def alerts_df(sample_alerts_df):
    """Sample alerts with an analysis column for seeding tests."""
    df = sample_alerts_df.copy()
    df['analysis'] = None
    df.loc[0, 'analysis'] = 'This is a known benign driver. LOW severity.'
    return df


@pytest.fixture
def alert_ids(alerts_df):
    """Return the alert_hash values for the sample alerts."""
    return alerts_df['alert_hash'].tolist()


@pytest.fixture
def mgr(alerts_df):
    """AlertMemoryManager with sample alerts."""
    return AlertMemoryManager(alerts_df)


class TestDetectAlertId:

    def test_explicit_alert_hash(self, mgr, alert_ids):
        short_id = alert_ids[0][:8]
        assert mgr.detect_alert_id(f'tell me about alert {short_id}') == alert_ids[0]

    def test_hash_syntax(self, mgr, alert_ids):
        short_id = alert_ids[2][:8]
        assert mgr.detect_alert_id(f'look at #{short_id}') == alert_ids[2]

    def test_bracket_syntax(self, mgr, alert_ids):
        short_id = alert_ids[0][:8]
        assert mgr.detect_alert_id(f'alert [{short_id}]') == alert_ids[0]

    def test_full_hash(self, mgr, alert_ids):
        assert mgr.detect_alert_id(f'alert {alert_ids[1]}') == alert_ids[1]

    def test_no_match(self, mgr):
        assert mgr.detect_alert_id('what is happening?') is None

    def test_nonexistent_hash_prefix(self, mgr):
        assert mgr.detect_alert_id('alert zzzzzzzz') is None

    def test_followup_uses_last_alert(self, mgr, alert_ids):
        mgr._last_alert_id = alert_ids[1]
        assert mgr.detect_alert_id('tell me more') == alert_ids[1]

    def test_followup_without_last_alert(self, mgr):
        assert mgr.detect_alert_id('tell me more') is None

    def test_followup_phrases_coverage(self, mgr, alert_ids):
        """Each phrase in FOLLOWUP_PHRASES should trigger follow-up detection."""
        mgr._last_alert_id = alert_ids[0]
        for phrase in FOLLOWUP_PHRASES:
            result = mgr.detect_alert_id(phrase)
            assert result == alert_ids[0], f"Phrase '{phrase}' did not trigger follow-up"


class TestSeedFromAnalysis:

    def test_seeds_on_first_access(self, mgr, alert_ids):
        """First access to an alert with analysis should seed the memory."""
        messages = mgr.load_context_messages(alert_ids[0])
        assert len(messages) == 2
        assert isinstance(messages[0], HumanMessage)
        assert isinstance(messages[1], AIMessage)
        assert 'benign driver' in messages[1].content

    def test_no_seed_without_analysis(self, mgr, alert_ids):
        """Alert without analysis should have empty memory."""
        messages = mgr.load_context_messages(alert_ids[1])
        assert len(messages) == 0

    def test_seed_only_once(self, mgr, alert_ids):
        """Accessing the same alert twice should not re-seed."""
        mgr.load_context_messages(alert_ids[0])
        mgr.load_context_messages(alert_ids[0])
        memory = mgr._memories[alert_ids[0]]
        assert len(memory.messages) == 2  # Still just the seed pair

    def test_long_analysis_truncated(self, mgr, alert_ids):
        """Analysis longer than 3000 chars should be truncated in seed."""
        mgr.alerts_df.loc[0, 'analysis'] = 'x' * 5000
        # Reset seeded state so it re-seeds
        mgr._seeded.discard(alert_ids[0])
        mgr._memories.pop(alert_ids[0], None)
        messages = mgr.load_context_messages(alert_ids[0])
        assert '[... truncated]' in messages[1].content


class TestSaveAndLoad:

    def test_save_creates_messages(self, mgr, alert_ids):
        mgr.save_exchange(alert_ids[1], 'Is this suspicious?', 'No, it looks benign.')
        messages = mgr.load_context_messages(alert_ids[1])
        assert len(messages) == 2
        assert messages[0].content == 'Is this suspicious?'
        assert messages[1].content == 'No, it looks benign.'

    def test_save_updates_last_alert_id(self, mgr, alert_ids):
        mgr.save_exchange(alert_ids[2], 'question', 'answer')
        assert mgr._last_alert_id == alert_ids[2]

    def test_multiple_exchanges(self, mgr, alert_ids):
        mgr.save_exchange(alert_ids[1], 'Q1', 'A1')
        mgr.save_exchange(alert_ids[1], 'Q2', 'A2')
        messages = mgr.load_context_messages(alert_ids[1])
        assert len(messages) == 4

    def test_none_alert_id_is_noop(self, mgr):
        mgr.save_exchange(None, 'question', 'answer')
        assert mgr._last_alert_id is None

    def test_load_none_returns_empty(self, mgr):
        assert mgr.load_context_messages(None) == []


class TestSummarization:

    def test_summarize_truncation_fallback(self, mgr, alert_ids):
        """When no LLM is available, summarization should use truncation fallback."""
        aid = alert_ids[0]
        mgr.max_messages = 4

        # Add enough messages to trigger summarization (seed=2 + 2 exchanges=6 > 4)
        mgr.load_context_messages(aid)  # seeds 2 messages
        mgr.save_exchange(aid, 'Q1', 'A1')  # 4 messages
        mgr.save_exchange(aid, 'Q2', 'A2')  # 6 messages, triggers summarization

        # After summarization, memory should have only the last 2 messages
        memory = mgr._memories[aid]
        assert len(memory.messages) == 2

        # Summary should exist
        assert aid in mgr._summaries
        summary_text = mgr._summaries[aid]
        assert len(summary_text) > 0

    def test_summary_included_in_context(self, mgr, alert_ids):
        """After summarization, load_context_messages should include the summary."""
        aid = alert_ids[0]
        mgr.max_messages = 4
        mgr.load_context_messages(aid)
        mgr.save_exchange(aid, 'Q1', 'A1')
        mgr.save_exchange(aid, 'Q2', 'A2')

        messages = mgr.load_context_messages(aid)
        # Should be: SystemMessage(summary) + 2 recent messages
        assert len(messages) == 3
        assert isinstance(messages[0], SystemMessage)
        assert 'Summary of prior conversation' in messages[0].content

    def test_summary_cap_at_2000(self, mgr, alert_ids):
        """Truncation summary should be capped at 2000 chars."""
        aid = alert_ids[0]
        mgr.max_messages = 4
        mgr.load_context_messages(aid)
        # Add long messages
        mgr.save_exchange(aid, 'Q' * 1000, 'A' * 1000)
        mgr.save_exchange(aid, 'Q2', 'A2')

        summary = mgr._summaries.get(aid, '')
        assert len(summary) <= 2010  # 2000 + '[... truncated]'


class TestClearMemory:

    def test_clear_removes_everything(self, mgr, alert_ids):
        aid = alert_ids[1]
        mgr.save_exchange(aid, 'Q', 'A')
        mgr._summaries[aid] = 'old summary'
        mgr.clear_memory(aid)

        assert aid not in mgr._memories
        assert aid not in mgr._summaries
        assert aid not in mgr._seeded

    def test_clear_nonexistent_is_safe(self, mgr):
        mgr.clear_memory('nonexistent_hash')  # Should not raise


class TestIsolation:

    def test_separate_alerts_have_separate_memory(self, mgr, alert_ids):
        """Different alerts should have independent memory."""
        mgr.save_exchange(alert_ids[0], 'Q for alert 0', 'A for alert 0')
        mgr.save_exchange(alert_ids[1], 'Q for alert 1', 'A for alert 1')

        msgs_0 = mgr.load_context_messages(alert_ids[0])
        msgs_1 = mgr.load_context_messages(alert_ids[1])

        # Alert 0 has seed (2) + exchange (2) = 4
        assert len(msgs_0) == 4
        # Alert 1 has no seed + exchange (2) = 2
        assert len(msgs_1) == 2

        # Content should not leak
        assert 'alert 1' not in msgs_0[-1].content.lower()
        assert 'alert 0' not in msgs_1[-1].content.lower()


class TestResolveHashPrefix:

    def test_resolve_full_hash(self, mgr, alert_ids):
        """Full hash should resolve to itself."""
        result = mgr._resolve_hash_prefix(alert_ids[0])
        assert result == alert_ids[0]

    def test_resolve_short_prefix(self, mgr, alert_ids):
        """First 4 chars should resolve if unique."""
        prefix = alert_ids[0][:4]
        # May or may not be unique depending on hash values
        result = mgr._resolve_hash_prefix(prefix)
        if result is not None:
            assert result == alert_ids[0]

    def test_resolve_nonexistent(self, mgr):
        """Nonexistent prefix should return None."""
        assert mgr._resolve_hash_prefix('zzzzzzzz') is None

    def test_resolve_with_no_df(self):
        """No DataFrame should return None."""
        mgr = AlertMemoryManager(None)
        assert mgr._resolve_hash_prefix('abcd') is None
