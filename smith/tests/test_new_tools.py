"""Smoketests for recently added tools: find_alert_correlations, check_known_fps, check_fp_journal."""

import json
import sys
import tempfile
import pytest
import pandas as pd
import tools.state as state
from tools.find_alert_correlations import find_alert_correlations
from tools.check_known_fps import check_known_fps
from tools.check_fp_journal import check_fp_journal
from tools.query_alerts import query_alerts
from tools.search_alerts import search_alerts
from tools.get_alert_summary import get_alert_summary
from tools import process_alert_tool_call, process_new_tool_call, process_event_search_tool_call


@pytest.fixture(autouse=True)
def set_alerts_state(sample_alerts_df):
    """Set the global ALERTS_DF state for tool queries.
    Also adds first_seen/last_seen columns that query_alerts expects."""
    df = sample_alerts_df.copy()
    if 'first_seen' not in df.columns:
        df['first_seen'] = df['timestamp']
    if 'last_seen' not in df.columns:
        df['last_seen'] = df['timestamp']
    old = state.ALERTS_DF
    state.ALERTS_DF = df
    yield
    state.ALERTS_DF = old


# --- find_alert_correlations ---

class TestFindAlertCorrelations:

    def test_finds_shared_hostname(self):
        """All sample alerts share the same hostname — should find a correlation."""
        result = json.loads(find_alert_correlations(fields=['hostname']))
        # All alerts are on DESKTOP-TEST, so there should be a group
        assert 'correlations' in result
        assert result['correlations_found'] >= 1
        hostnames = [c['shared_value'] for c in result['correlations']]
        assert 'DESKTOP-TEST' in hostnames

    def test_no_correlations_on_unique_field(self, sample_alerts_df):
        """alert_hash is unique per row — no correlations expected."""
        result = json.loads(find_alert_correlations(fields=['alert_hash']))
        assert result.get('correlations_found', 0) == 0 or 'message' in result

    def test_auto_fields(self):
        """Omitting fields= should auto-check common fields."""
        result = json.loads(find_alert_correlations())
        # Should at least return without error
        assert 'error' not in result

    def test_filter_by_alert_name(self):
        result = json.loads(find_alert_correlations(alert_name='New'))
        assert 'error' not in result

    def test_min_group_size(self):
        """Setting min_group_size higher than total alerts should find nothing."""
        result = json.loads(find_alert_correlations(min_group_size=100))
        assert result.get('correlations_found', 0) == 0 or 'message' in result

    def test_no_data(self):
        """With no alerts loaded, should return an error message."""
        old = state.ALERTS_DF
        state.ALERTS_DF = None
        try:
            result = json.loads(find_alert_correlations())
            assert 'error' in result
        finally:
            state.ALERTS_DF = old

    def test_fewer_than_2_alerts(self):
        """With only 1 alert, nothing to correlate."""
        old = state.ALERTS_DF
        state.ALERTS_DF = state.ALERTS_DF.iloc[:1].copy()
        try:
            result = json.loads(find_alert_correlations())
            assert result.get('count', 0) == 0 or 'message' in result
        finally:
            state.ALERTS_DF = old


# --- check_known_fps ---

class TestCheckKnownFps:

    def test_no_args_returns_error(self):
        result = json.loads(check_known_fps())
        assert 'error' in result

    def test_unknown_process_not_found(self):
        result = json.loads(check_known_fps(process='totally_unknown_binary_12345.exe'))
        assert 'NOT in the known false positive' in result['message']

    def test_with_process_and_commandline(self):
        """Should run without error even if no match."""
        result = json.loads(check_known_fps(process='test.exe', commandline='test.exe --flag'))
        assert 'message' in result

    def test_with_fp_data(self, tmp_path, monkeypatch):
        """Create a temp system_fps.csv and verify matching works."""
        import hashlib
        # Build a hash matching process=test.exe, command=test.exe --run
        hash_dict = {'process': 'test.exe', 'command': 'test.exe --run'}
        hash_json = json.dumps(hash_dict, sort_keys=True)
        fp_hash = hashlib.sha256(hash_json.encode()).hexdigest()

        csv_path = tmp_path / 'system_fps.csv'
        pd.DataFrame([{
            'process': 'test.exe',
            'command': 'test.exe --run',
            'fp_hash': fp_hash,
        }]).to_csv(csv_path, index=False)

        monkeypatch.setattr(sys.modules['tools.check_known_fps'], 'SYSTEM_FPS_PATH', csv_path)

        result = json.loads(check_known_fps(process='test.exe', commandline='test.exe --run'))
        assert len(result['hash_matches']) == 1
        assert 'exact_hash_match' in result['hash_matches'][0]['type']

    def test_process_name_match(self, tmp_path, monkeypatch):
        """Process name matching (broader than hash)."""
        csv_path = tmp_path / 'system_fps.csv'
        pd.DataFrame([{
            'process': 'chrome.exe',
            'command': 'chrome.exe --some-flag',
            'fp_hash': 'abc123',
        }]).to_csv(csv_path, index=False)

        monkeypatch.setattr(sys.modules['tools.check_known_fps'], 'SYSTEM_FPS_PATH', csv_path)

        result = json.loads(check_known_fps(process='chrome.exe'))
        assert len(result['process_matches']) == 1

    def test_known_benign_txt_match(self, tmp_path, monkeypatch):
        """Matching against known_benign.txt patterns."""
        txt_path = tmp_path / 'known_benign.txt'
        txt_path.write_text('# Comment line\nchrome.exe - Google Chrome browser\n', encoding='utf-8')

        monkeypatch.setattr(sys.modules['tools.check_known_fps'], 'KNOWN_BENIGN_PATH', txt_path)
        monkeypatch.setattr(sys.modules['tools.check_known_fps'], 'SYSTEM_FPS_PATH', tmp_path / 'nonexistent.csv')

        result = json.loads(check_known_fps(process='chrome.exe'))
        assert len(result['known_benign_patterns']) == 1
        assert 'Google Chrome' in result['known_benign_patterns'][0]


# --- check_fp_journal ---

class TestCheckFpJournal:

    def test_no_journal_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys.modules['tools.check_fp_journal'], 'FP_JOURNAL_PATH', tmp_path / 'nonexistent.csv')
        result = json.loads(check_fp_journal(alert_name='anything'))
        assert 'No false positive journal' in result['message']

    def test_empty_journal(self, monkeypatch, tmp_path):
        csv_path = tmp_path / 'false_positives.csv'
        pd.DataFrame(columns=['alert_name', 'hostname', 'reason', 'analyzed_by', 'timestamp']).to_csv(csv_path, index=False)

        monkeypatch.setattr(sys.modules['tools.check_fp_journal'], 'FP_JOURNAL_PATH', csv_path)
        result = json.loads(check_fp_journal(alert_name='test'))
        assert 'empty' in result['message'].lower()

    def test_matches_alert_name(self, monkeypatch, tmp_path):
        csv_path = tmp_path / 'false_positives.csv'
        pd.DataFrame([{
            'alert_name': 'Suspicious PowerShell',
            'hostname': 'SERVER-01',
            'reason': 'Known admin script',
            'analyzed_by': 'analyst1',
            'timestamp': '2026-01-15',
        }]).to_csv(csv_path, index=False)

        monkeypatch.setattr(sys.modules['tools.check_fp_journal'], 'FP_JOURNAL_PATH', csv_path)

        result = json.loads(check_fp_journal(alert_name='PowerShell'))
        assert len(result['matches']) == 1
        assert result['matches'][0]['hostname'] == 'SERVER-01'

    def test_no_match(self, monkeypatch, tmp_path):
        csv_path = tmp_path / 'false_positives.csv'
        pd.DataFrame([{
            'alert_name': 'Some Alert',
            'hostname': 'HOST',
            'reason': 'reason',
            'analyzed_by': 'a',
            'timestamp': 't',
        }]).to_csv(csv_path, index=False)

        monkeypatch.setattr(sys.modules['tools.check_fp_journal'], 'FP_JOURNAL_PATH', csv_path)
        result = json.loads(check_fp_journal(alert_name='nonexistent'))
        assert len(result['matches']) == 0

    def test_process_search(self, monkeypatch, tmp_path):
        csv_path = tmp_path / 'false_positives.csv'
        pd.DataFrame([{
            'alert_name': 'New Service',
            'hostname': 'HOST',
            'reason': 'svchost.exe is normal Windows process',
            'analyzed_by': 'a',
            'timestamp': 't',
        }]).to_csv(csv_path, index=False)

        monkeypatch.setattr(sys.modules['tools.check_fp_journal'], 'FP_JOURNAL_PATH', csv_path)

        # Search by process name should match in reason column
        result = json.loads(check_fp_journal(alert_name='nonexistent', process='svchost.exe'))
        assert len(result['matches']) == 1


# --- Dispatch tables ---

class TestDispatchTables:
    """Verify dispatch tables route to the correct functions."""

    def test_alert_dispatch_query_alerts(self):
        result = json.loads(process_alert_tool_call('query_alerts', {}))
        assert 'count' in result

    def test_alert_dispatch_get_summary(self):
        result = json.loads(process_alert_tool_call('get_alert_summary', {}))
        assert 'total' in result or 'error' not in result

    def test_alert_dispatch_search_alerts(self):
        result = json.loads(process_alert_tool_call('search_alerts', {'search_term': 'driver'}))
        assert 'count' in result

    def test_alert_dispatch_correlations(self):
        result = json.loads(process_alert_tool_call('find_alert_correlations', {}))
        assert 'error' not in result

    def test_alert_dispatch_check_known_fps(self):
        result = json.loads(process_alert_tool_call('check_known_fps', {'process': 'test.exe'}))
        assert 'message' in result

    def test_alert_dispatch_check_fp_journal(self):
        result = json.loads(process_alert_tool_call('check_fp_journal', {'alert_name': 'test'}))
        assert 'message' in result or 'matches' in result

    def test_alert_dispatch_unknown_tool(self):
        result = json.loads(process_alert_tool_call('nonexistent_tool', {}))
        assert 'error' in result

    def test_new_dispatch_check_known_fps(self):
        """check_known_fps should also be accessible from the new analyst dispatch."""
        result = json.loads(process_new_tool_call('check_known_fps', {'process': 'test.exe'}))
        assert 'message' in result

    def test_new_dispatch_check_fp_journal(self):
        result = json.loads(process_new_tool_call('check_fp_journal', {'alert_name': 'test'}))
        assert 'message' in result or 'matches' in result

    def test_event_dispatch_unknown_tool(self):
        result = json.loads(process_event_search_tool_call('nonexistent_tool', {}))
        assert 'error' in result


# --- query_alerts with optional fields ---

class TestQueryAlertsOptionalFields:
    """Verify query_alerts returns optional fields when present."""

    def test_returns_processid_when_present(self):
        result = json.loads(query_alerts())
        # The Sublime Text alert has processid=12168
        network_alerts = [a for a in result['alerts'] if 'processid' in a]
        assert len(network_alerts) >= 1

    def test_returns_network_fields_when_present(self):
        result = json.loads(query_alerts())
        # The Sublime Text alert has source/destination IP
        network_alerts = [a for a in result['alerts'] if 'destination_ip' in a]
        assert len(network_alerts) >= 1
        alert = network_alerts[0]
        assert alert['destination_ip'] == '45.55.41.223'
        assert alert['destination_port'] == 443

    def test_omits_fields_when_nan(self):
        result = json.loads(query_alerts())
        # The New Driver alert shouldn't have network fields
        driver_alerts = [a for a in result['alerts'] if 'New Driver' in a.get('alert_name', '')]
        assert len(driver_alerts) >= 1
        assert 'destination_ip' not in driver_alerts[0]
