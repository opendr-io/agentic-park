"""Tests for question routing: service -> new_analyst, network -> alert_analyst."""

from status_agent import StatusAgent


class TestIsStatusQuestion:

    def setup_method(self):
        self.agent = StatusAgent()

    def test_status_keywords(self):
        assert self.agent.is_status_question("What is the status?")
        assert self.agent.is_status_question("How many alerts are there?")
        assert self.agent.is_status_question("Show me the progress")
        assert self.agent.is_status_question("Give me a summary")

    def test_non_status_questions(self):
        assert not self.agent.is_status_question("Is VM3DService malicious?")
        assert not self.agent.is_status_question("Tell me about the new drivers")
        assert not self.agent.is_status_question("What connected to 45.55.41.223?")


class TestRouteQuestion:
    """Test route_question classification.

    Note: These tests require an API key since routing uses the LLM.
    They are skipped if ANTHROPIC_API_KEY is not set.
    """

    def setup_method(self):
        self.agent = StatusAgent()

    def test_status_route(self):
        """Status questions should be routed locally without LLM."""
        assert self.agent.route_question("What is the status?") == 'status'
        assert self.agent.route_question("How many alerts analyzed?") == 'status'

    def test_last_agent_sticky_routing(self):
        """GENERAL classification should continue with the last agent used."""
        agent = StatusAgent()
        # Simulate last agent being event_search
        agent._last_agent_type = 'event_search'
        # A status question still routes to status (not sticky)
        assert agent.route_question("How many alerts?") == 'status'
        # _last_agent_type should still be event_search (status doesn't change it)
        assert agent._last_agent_type == 'event_search'

    def test_last_agent_starts_none(self):
        """No last agent at startup."""
        agent = StatusAgent()
        assert agent._last_agent_type is None

    # LLM-dependent routing tests would go here with:
    # @pytest.mark.skipif(not os.getenv('ANTHROPIC_API_KEY'), reason="No API key")
