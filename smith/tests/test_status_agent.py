"""Tests for status_agent.py — resolve_alert_input, close_alert, get_alert_by_id."""

import os
import sys
import pytest
import pandas as pd
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from status_agent import StatusAgent


def _make_agent(tmp_path, rows=None):
    """Create a StatusAgent with a minimal alerts CSV and DataFrame."""
    if rows is None:
        rows = [
            {'alert_hash': 'aaa111aaa111aaa1', 'alert_name': 'Test Alert A', 'hostname': 'HOST-1',
             'timestamp': '2026-01-01', 'alert_status': 'open', 'read': None},
            {'alert_hash': 'bbb222bbb222bbb2', 'alert_name': 'Test Alert B', 'hostname': 'HOST-2',
             'timestamp': '2026-01-02', 'alert_status': 'open', 'read': None},
            {'alert_hash': 'ccc333ccc333ccc3', 'alert_name': 'Closed Alert', 'hostname': 'HOST-1',
             'timestamp': '2026-01-03', 'alert_status': 'closed', 'read': None},
        ]
    df = pd.DataFrame(rows)
    csv = tmp_path / 'alerts.csv'
    df.to_csv(csv, index=False)
    agent = StatusAgent(alerts_csv_path=str(csv), alerts_df=df)
    return agent


# ── _resolve_alert_input ────────────────────────────────────────────

class TestResolveAlertInput:
    def test_resolve_by_hash_prefix(self, tmp_path):
        agent = _make_agent(tmp_path)
        alert_hash, idx = agent._resolve_alert_input('aaa111aa')
        assert alert_hash == 'aaa111aaa111aaa1'

    def test_resolve_by_menu_number(self, tmp_path):
        agent = _make_agent(tmp_path)
        # Populate menu: 1 → first hash, 2 → second hash
        agent._alert_menu = {1: 'aaa111aaa111aaa1', 2: 'bbb222bbb222bbb2'}
        alert_hash, idx = agent._resolve_alert_input('1')
        assert alert_hash == 'aaa111aaa111aaa1'

    def test_menu_number_not_in_menu(self, tmp_path):
        agent = _make_agent(tmp_path)
        agent._alert_menu = {1: 'aaa111aaa111aaa1'}
        # Number 99 isn't in the menu, falls through to hash prefix lookup
        with pytest.raises(ValueError, match="No alert found"):
            agent._resolve_alert_input('99')

    def test_invalid_hash_prefix(self, tmp_path):
        agent = _make_agent(tmp_path)
        with pytest.raises(ValueError, match="No alert found"):
            agent._resolve_alert_input('zzz999')

    def test_ambiguous_prefix(self, tmp_path):
        rows = [
            {'alert_hash': 'abc123def', 'alert_name': 'A', 'hostname': 'H',
             'timestamp': '2026-01-01', 'alert_status': 'open', 'read': None},
            {'alert_hash': 'abc123ghi', 'alert_name': 'B', 'hostname': 'H',
             'timestamp': '2026-01-02', 'alert_status': 'open', 'read': None},
        ]
        agent = _make_agent(tmp_path, rows)
        with pytest.raises(ValueError, match="Ambiguous"):
            agent._resolve_alert_input('abc123')


# ── close_alert ─────────────────────────────────────────────────────

class TestCloseAlert:
    def test_close_by_hash_prefix(self, tmp_path):
        agent = _make_agent(tmp_path)
        result = agent.close_alert('aaa111aa')
        assert 'Closed' in result
        assert 'Test Alert A' in result

    def test_close_by_menu_number(self, tmp_path):
        agent = _make_agent(tmp_path)
        agent._alert_menu = {1: 'aaa111aaa111aaa1'}
        result = agent.close_alert('1')
        assert 'Closed' in result

    def test_close_updates_dataframe(self, tmp_path):
        agent = _make_agent(tmp_path)
        agent.close_alert('aaa111aa')
        row = agent.alerts_df[agent.alerts_df['alert_hash'] == 'aaa111aaa111aaa1'].iloc[0]
        assert row['alert_status'] == 'closed'

    def test_close_missing_alert(self, tmp_path):
        agent = _make_agent(tmp_path)
        result = agent.close_alert('zzz999')
        assert 'No alert found' in result


# ── get_alert_by_id ─────────────────────────────────────────────────

class TestGetAlertById:
    def test_get_by_hash_prefix(self, tmp_path):
        agent = _make_agent(tmp_path)
        result = agent.get_alert_by_id('aaa111aa')
        assert 'Test Alert A' in result
        assert 'HOST-1' in result

    def test_get_by_menu_number(self, tmp_path):
        agent = _make_agent(tmp_path)
        agent._alert_menu = {1: 'aaa111aaa111aaa1'}
        result = agent.get_alert_by_id('1')
        assert 'Test Alert A' in result

    def test_get_missing_alert(self, tmp_path):
        agent = _make_agent(tmp_path)
        result = agent.get_alert_by_id('zzz999')
        assert 'No alert found' in result
