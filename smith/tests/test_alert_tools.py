"""Tests for alert query tools: query_alerts, search_alerts, get_alert_summary."""

import os
import sys
import json
import pytest
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools import state
from tools.query_alerts import query_alerts
from tools.search_alerts import search_alerts
from tools.get_alert_summary import get_alert_summary


@pytest.fixture(autouse=True)
def setup_alerts_df(sample_alerts_df):
    """Set ALERTS_DF for all tests, clean up after."""
    old = state.ALERTS_DF
    # Add columns query_alerts expects
    df = sample_alerts_df.copy()
    if 'first_seen' not in df.columns:
        df['first_seen'] = df.get('timestamp', pd.Timestamp.now())
    if 'last_seen' not in df.columns:
        df['last_seen'] = df.get('timestamp', pd.Timestamp.now())
    state.ALERTS_DF = df
    yield
    state.ALERTS_DF = old


# ── query_alerts ────────────────────────────────────────────────────

class TestQueryAlerts:
    def test_returns_all_alerts(self):
        result = json.loads(query_alerts())
        assert result['count'] > 0
        assert 'alerts' in result

    def test_filter_by_alert_name(self):
        result = json.loads(query_alerts(alert_name='New Driver'))
        for alert in result['alerts']:
            assert 'driver' in alert['alert_name'].lower() or 'Driver' in alert['alert_name']

    def test_filter_by_hostname(self):
        result = json.loads(query_alerts(hostname='DESKTOP-TEST'))
        for alert in result['alerts']:
            assert alert['hostname'] == 'DESKTOP-TEST'

    def test_no_match(self):
        result = json.loads(query_alerts(alert_name='ZZZZNONEXISTENT'))
        assert result['count'] == 0

    def test_limit(self):
        result = json.loads(query_alerts(limit=1))
        assert result['count'] <= 1

    def test_not_loaded(self):
        state.ALERTS_DF = None
        result = json.loads(query_alerts())
        assert 'error' in result


# ── search_alerts ───────────────────────────────────────────────────

class TestSearchAlerts:
    def test_search_finds_match(self):
        result = json.loads(search_alerts('sublime_text'))
        assert result['count'] > 0

    def test_search_case_insensitive(self):
        result = json.loads(search_alerts('SUBLIME_TEXT'))
        assert result['count'] > 0

    def test_search_no_match(self):
        result = json.loads(search_alerts('zzzznonexistent'))
        assert result['count'] == 0

    def test_search_limit(self):
        result = json.loads(search_alerts('DESKTOP', limit=1))
        assert result['count'] <= 1

    def test_not_loaded(self):
        state.ALERTS_DF = None
        result = json.loads(search_alerts('test'))
        assert 'error' in result


# ── get_alert_summary ───────────────────────────────────────────────

class TestGetAlertSummary:
    def test_returns_summary(self):
        result = json.loads(get_alert_summary())
        assert 'total_alerts' in result
        assert result['total_alerts'] > 0
        assert 'alert_types' in result
        assert 'hostnames' in result

    def test_not_loaded(self):
        state.ALERTS_DF = None
        result = json.loads(get_alert_summary())
        assert 'error' in result
