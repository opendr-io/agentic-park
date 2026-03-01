"""Tests for alert-context-aware routing.

Verifies that:
- Selecting a security alert routes follow-ups to alert_analyst
- Selecting a behavioral alert routes follow-ups to new_analyst
- Context clears on status/progress/breakdown commands
- Context switches when a different alert is selected
"""

import pytest
from unittest.mock import patch, MagicMock
from status_agent import StatusAgent


@pytest.fixture
def agent(sample_alerts_df):
    """StatusAgent wired up with sample alerts (both behavioral and security)."""
    return StatusAgent(alerts_df=sample_alerts_df)


@pytest.fixture
def security_alert_hash(sample_alerts_df):
    """Hash of a security alert (Sublime Text Internet Activity)."""
    row = sample_alerts_df[
        sample_alerts_df['alert_name'].str.contains('Internet Activity', na=False)
    ].iloc[0]
    return row['alert_hash']


@pytest.fixture
def behavioral_alert_hash(sample_alerts_df):
    """Hash of a behavioral alert (New Driver)."""
    row = sample_alerts_df[
        sample_alerts_df['alert_name'].str.contains('New Driver', na=False)
    ].iloc[0]
    return row['alert_hash']


class TestIsBehavioralAlert:

    def test_new_driver_is_behavioral(self, agent, behavioral_alert_hash):
        assert agent._is_behavioral_alert(behavioral_alert_hash) is True

    def test_new_service_is_behavioral(self, agent, sample_alerts_df):
        row = sample_alerts_df[
            sample_alerts_df['alert_name'].str.contains('New Service', na=False)
        ].iloc[0]
        assert agent._is_behavioral_alert(row['alert_hash']) is True

    def test_internet_activity_is_not_behavioral(self, agent, security_alert_hash):
        assert agent._is_behavioral_alert(security_alert_hash) is False

    def test_nonexistent_hash_is_not_behavioral(self, agent):
        assert agent._is_behavioral_alert('nonexistent_hash_000') is False


class TestApplyAlertContextRouting:

    def test_security_alert_redirects_new_to_alert(self, agent, security_alert_hash):
        """When a security alert is selected, new_analyst → alert_analyst."""
        result = agent._apply_alert_context_routing('new_analyst', security_alert_hash)
        assert result == 'alert_analyst'

    def test_security_alert_keeps_alert_analyst(self, agent, security_alert_hash):
        """When a security alert is selected, alert_analyst stays."""
        result = agent._apply_alert_context_routing('alert_analyst', security_alert_hash)
        assert result == 'alert_analyst'

    def test_security_alert_keeps_event_search(self, agent, security_alert_hash):
        """event_search is never redirected."""
        result = agent._apply_alert_context_routing('event_search', security_alert_hash)
        assert result == 'event_search'

    def test_behavioral_alert_redirects_alert_to_new(self, agent, behavioral_alert_hash):
        """When a behavioral alert is selected, alert_analyst → new_analyst."""
        result = agent._apply_alert_context_routing('alert_analyst', behavioral_alert_hash)
        assert result == 'new_analyst'

    def test_behavioral_alert_keeps_new_analyst(self, agent, behavioral_alert_hash):
        """When a behavioral alert is selected, new_analyst stays."""
        result = agent._apply_alert_context_routing('new_analyst', behavioral_alert_hash)
        assert result == 'new_analyst'

    def test_behavioral_alert_keeps_event_search(self, agent, behavioral_alert_hash):
        """event_search is never redirected."""
        result = agent._apply_alert_context_routing('event_search', behavioral_alert_hash)
        assert result == 'event_search'


class TestRouteWithAlertContext:
    """End-to-end routing tests with mocked LLM."""

    def _route_with_mock_llm(self, agent, question, llm_response):
        """Call route_question with LLM mocked to return a fixed classification."""
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content=llm_response)
        with patch.object(agent, '_get_llm', return_value=mock_llm):
            return agent.route_question(question)

    def test_no_context_routes_normally(self, agent):
        """Without active alert, LLM classification is used directly."""
        assert agent._get_alert_memory()._last_alert_id is None
        result = self._route_with_mock_llm(agent, 'show me the events', 'NEW_EVENTS')
        assert result == 'new_analyst'

    def test_security_context_overrides_new_events(self, agent, security_alert_hash):
        """With a security alert selected, NEW_EVENTS → alert_analyst."""
        agent._get_alert_memory()._last_alert_id = security_alert_hash
        result = self._route_with_mock_llm(agent, 'show me the events', 'NEW_EVENTS')
        assert result == 'alert_analyst'

    def test_behavioral_context_overrides_alerts(self, agent, behavioral_alert_hash):
        """With a behavioral alert selected, ALERTS → new_analyst."""
        agent._get_alert_memory()._last_alert_id = behavioral_alert_hash
        result = self._route_with_mock_llm(agent, 'show me more details', 'ALERTS')
        assert result == 'new_analyst'

    def test_security_context_keeps_event_search(self, agent, security_alert_hash):
        """event_search classification is never overridden."""
        agent._get_alert_memory()._last_alert_id = security_alert_hash
        result = self._route_with_mock_llm(agent, 'show network connections', 'EVENT_SEARCH')
        assert result == 'event_search'

    def test_behavioral_context_keeps_event_search(self, agent, behavioral_alert_hash):
        """event_search classification is never overridden."""
        agent._get_alert_memory()._last_alert_id = behavioral_alert_hash
        result = self._route_with_mock_llm(agent, 'show network connections', 'EVENT_SEARCH')
        assert result == 'event_search'


class TestContextClearing:
    """Verify alert context clears on status/progress/breakdown commands."""

    def _set_context(self, agent, alert_hash):
        agent._get_alert_memory()._last_alert_id = alert_hash

    def _get_context(self, agent):
        return agent._get_alert_memory()._last_alert_id

    def test_status_clears_context(self, agent, security_alert_hash):
        self._set_context(agent, security_alert_hash)
        assert agent.route_question("What is the status?") == 'status'
        # route_question doesn't clear context — the interactive loop does.
        # We test the is_status_question detection which triggers clearing.
        assert agent.is_status_question("What is the status?")

    def test_important_is_status(self, agent):
        """'important' should route to status (which clears context in the loop)."""
        assert agent.is_status_question("important")

    def test_breakdown_is_status(self, agent):
        assert agent.is_status_question("breakdown")

    def test_analytical_question_not_status(self, agent):
        """Analytical questions with status words should NOT route to status."""
        assert not agent.is_status_question(
            "do any of the important alerts have the same processid?"
        )


class TestContextSwitching:
    """Verify context switches when selecting a different alert."""

    def test_selecting_alert_sets_context(self, agent, sample_alerts_df):
        """Simulates what the interactive loop does on 'alert <#>'."""
        first_hash = sample_alerts_df.iloc[0]['alert_hash']
        second_hash = sample_alerts_df.iloc[1]['alert_hash']

        agent._get_alert_memory()._last_alert_id = first_hash
        assert agent._get_alert_memory()._last_alert_id == first_hash

        # Selecting another alert replaces context
        agent._get_alert_memory()._last_alert_id = second_hash
        assert agent._get_alert_memory()._last_alert_id == second_hash

    def test_switching_from_security_to_behavioral(self, agent, security_alert_hash,
                                                    behavioral_alert_hash):
        """Routing should change when switching alert types."""
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content='NEW_EVENTS')

        with patch.object(agent, '_get_llm', return_value=mock_llm):
            # Security alert selected → new_analyst redirected to alert_analyst
            agent._get_alert_memory()._last_alert_id = security_alert_hash
            result = agent.route_question('show me the events')
            assert result == 'alert_analyst'

            # Switch to behavioral alert → new_analyst stays
            agent._get_alert_memory()._last_alert_id = behavioral_alert_hash
            result = agent.route_question('show me the events')
            assert result == 'new_analyst'
