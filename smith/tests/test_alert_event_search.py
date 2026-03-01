"""System tests: verify event search tools can find events for each alert.

For every alert in the test fixture, the tools should be able to find
corresponding process and/or network events by PID, process name, and
process tree.  This validates the full alert → event lookup path without
requiring an API key (no LLM calls).
"""

import json
import pandas as pd
import pytest
import tools.state as state


# ---------------------------------------------------------------------------
# Fixtures — realistic alert + event data
# ---------------------------------------------------------------------------

@pytest.fixture
def alerts_df():
    """Alerts that mirror real alert_dd.csv structure."""
    return pd.DataFrame([
        {
            'alert_name': 'Python Shelled Out',
            'hostname': 'DESKTOP1',
            'username': 'DESKTOP1\\admin',
            'processid': 17004,
            'process': 'python.exe',
            'parentprocessid': 5672,
            'parentimage': 'cmd.exe',
            'commandline': 'python.exe sshell.py',
            'destinationip': '34.41.118.55',
            'destinationport': 8080,
            'sourceip': '192.168.1.10',
            'sourceport': 51234,
            'first_seen': '2026-01-13 06:28:00',
            'last_seen': '2026-01-13 06:35:00',
            'alert_status': 'open',
            'category': 'process_creation',
        },
        {
            'alert_name': 'Suspicious Network Connection',
            'hostname': 'DESKTOP1',
            'username': 'DESKTOP1\\admin',
            'processid': 17004,
            'process': 'python.exe',
            'parentprocessid': 5672,
            'parentimage': 'cmd.exe',
            'commandline': 'python.exe sshell.py',
            'destinationip': '34.41.118.55',
            'destinationport': 8080,
            'sourceip': '192.168.1.10',
            'sourceport': 51234,
            'first_seen': '2026-01-13 06:29:00',
            'last_seen': '2026-01-13 06:35:00',
            'alert_status': 'open',
            'category': 'network_connection',
        },
        {
            'alert_name': 'PowerShell Execution',
            'hostname': 'SERVER2',
            'username': 'SERVER2\\svc_account',
            'processid': 8800,
            'process': 'powershell.exe',
            'parentprocessid': 4400,
            'parentimage': 'services.exe',
            'commandline': 'powershell.exe -enc SQBFAFgA',
            'first_seen': '2026-01-13 07:10:00',
            'last_seen': '2026-01-13 07:10:00',
            'alert_status': 'open',
            'category': 'process_creation',
        },
    ])


@pytest.fixture
def events_df():
    """Events that should match the alerts above — process + network."""
    return pd.DataFrame([
        # --- DESKTOP1 chain: cmd.exe → python.exe + network ---
        {
            'timestamp': '2026-01-13 06:27:30',
            'hostname': 'DESKTOP1',
            'username': 'DESKTOP1\\admin',
            'category': 'process_creation',
            'processid': 5672,
            'process': 'cmd.exe',
            'parentprocessid': 1000,
            'parentimage': 'explorer.exe',
            'commandline': 'cmd.exe /c python sshell.py',
        },
        {
            'timestamp': '2026-01-13 06:28:00',
            'hostname': 'DESKTOP1',
            'username': 'DESKTOP1\\admin',
            'category': 'process_creation',
            'processid': 17004,
            'process': 'python.exe',
            'parentprocessid': 5672,
            'parentimage': 'cmd.exe',
            'commandline': 'python.exe sshell.py',
        },
        {
            'timestamp': '2026-01-13 06:28:10',
            'hostname': 'DESKTOP1',
            'username': 'DESKTOP1\\admin',
            'category': 'network_connection',
            'processid': 17004,
            'process': 'python.exe',
            'sourceip': '192.168.1.10',
            'sourceport': 51234,
            'destinationip': '34.41.118.55',
            'destinationport': 8080,
            'status': 'ESTABLISHED',
        },
        {
            'timestamp': '2026-01-13 06:30:00',
            'hostname': 'DESKTOP1',
            'username': 'DESKTOP1\\admin',
            'category': 'network_connection',
            'processid': 17004,
            'process': 'python.exe',
            'sourceip': '192.168.1.10',
            'sourceport': 51235,
            'destinationip': '34.41.118.55',
            'destinationport': 8080,
            'status': 'ESTABLISHED',
        },
        # --- DESKTOP1: explorer.exe (root of the tree) ---
        {
            'timestamp': '2026-01-13 06:00:00',
            'hostname': 'DESKTOP1',
            'username': 'DESKTOP1\\admin',
            'category': 'process_creation',
            'processid': 1000,
            'process': 'explorer.exe',
            'parentprocessid': 4,
            'parentimage': 'System',
            'commandline': 'C:\\Windows\\explorer.exe',
        },
        # --- SERVER2 chain: services.exe → powershell.exe + network ---
        {
            'timestamp': '2026-01-13 07:09:50',
            'hostname': 'SERVER2',
            'username': 'SERVER2\\svc_account',
            'category': 'process_creation',
            'processid': 4400,
            'process': 'services.exe',
            'parentprocessid': 600,
            'parentimage': 'wininit.exe',
            'commandline': 'C:\\Windows\\system32\\services.exe',
        },
        {
            'timestamp': '2026-01-13 07:10:00',
            'hostname': 'SERVER2',
            'username': 'SERVER2\\svc_account',
            'category': 'process_creation',
            'processid': 8800,
            'process': 'powershell.exe',
            'parentprocessid': 4400,
            'parentimage': 'services.exe',
            'commandline': 'powershell.exe -enc SQBFAFgA',
        },
        {
            'timestamp': '2026-01-13 07:10:05',
            'hostname': 'SERVER2',
            'username': 'SERVER2\\svc_account',
            'category': 'network_connection',
            'processid': 8800,
            'process': 'powershell.exe',
            'sourceip': '10.0.0.5',
            'sourceport': 49152,
            'destinationip': '104.20.0.1',
            'destinationport': 443,
            'status': 'ESTABLISHED',
        },
    ])


@pytest.fixture(autouse=True)
def set_state(alerts_df, events_df):
    """Inject fixture data into global state."""
    old_alerts = state.ALERTS_DF
    old_events = state.EVENTS_DF
    state.ALERTS_DF = alerts_df
    state.EVENTS_DF = events_df
    yield
    state.ALERTS_DF = old_alerts
    state.EVENTS_DF = old_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call(tool_name, tool_input):
    """Shorthand for dispatch + JSON parse."""
    from tools import process_event_search_tool_call
    return json.loads(process_event_search_tool_call(tool_name, tool_input))


def _events_have_categories(events, *categories):
    """Return True if events list contains at least one event in each given category."""
    found = {e['category'] for e in events}
    return all(c in found for c in categories)


# ---------------------------------------------------------------------------
# Tests: For each alert, event tools return process AND network events
# ---------------------------------------------------------------------------

class TestAlertEventLookupByPid:
    """query_events_by_pid should return both process and network events for alert PIDs."""

    def test_python_alert_pid_returns_process_and_network(self, alerts_df):
        """PID 17004 (python.exe) has process_creation + 2 network_connection events."""
        alert = alerts_df[alerts_df['alert_name'] == 'Python Shelled Out'].iloc[0]
        result = _call('query_events_by_pid', {
            'pid': int(alert['processid']),
            'hostname': alert['hostname'],
            'start_time': '2026-01-13 06:18:00',
            'end_time': '2026-01-13 06:38:00',
        })
        assert result['count'] == 3
        assert _events_have_categories(result['events'],
                                       'process_creation', 'network_connection')

    def test_python_alert_pid_network_has_dest_ip(self, alerts_df):
        """Network events should include destination IP matching the alert."""
        alert = alerts_df[alerts_df['alert_name'] == 'Python Shelled Out'].iloc[0]
        result = _call('query_events_by_pid', {
            'pid': int(alert['processid']),
            'hostname': alert['hostname'],
        })
        net_events = [e for e in result['events'] if 'network' in e]
        assert len(net_events) == 2
        for ne in net_events:
            assert ne['network']['dest_ip'] == '34.41.118.55'
            assert ne['network']['dest_port'] == 8080

    def test_powershell_alert_pid_returns_process_and_network(self, alerts_df):
        """PID 8800 (powershell.exe) has process_creation + 1 network_connection event."""
        alert = alerts_df[alerts_df['alert_name'] == 'PowerShell Execution'].iloc[0]
        result = _call('query_events_by_pid', {
            'pid': int(alert['processid']),
            'hostname': alert['hostname'],
            'start_time': '2026-01-13 07:00:00',
            'end_time': '2026-01-13 07:20:00',
        })
        assert result['count'] == 2
        assert _events_have_categories(result['events'],
                                       'process_creation', 'network_connection')

    def test_parent_pid_returns_events(self, alerts_df):
        """The parent PID from the alert should also have events."""
        alert = alerts_df[alerts_df['alert_name'] == 'Python Shelled Out'].iloc[0]
        result = _call('query_events_by_pid', {
            'pid': int(alert['parentprocessid']),
            'hostname': alert['hostname'],
        })
        assert result['count'] >= 1
        assert result['events'][0]['process'] == 'cmd.exe'


class TestAlertEventLookupByProcessName:
    """query_events_by_process_name should return all event types for a process."""

    def test_python_by_name_returns_process_and_network(self, alerts_df):
        """Searching 'python' should find process_creation + network events."""
        alert = alerts_df[alerts_df['alert_name'] == 'Python Shelled Out'].iloc[0]
        result = _call('query_events_by_process_name', {
            'process_name': alert['process'].replace('.exe', ''),
            'hostname': alert['hostname'],
            'start_time': '2026-01-13 06:18:00',
            'end_time': '2026-01-13 06:38:00',
        })
        assert result['count'] == 3
        categories = {e['category'] for e in result['events']}
        assert 'process_creation' in categories
        assert 'network_connection' in categories

    def test_powershell_by_name_returns_process_and_network(self, alerts_df):
        """Searching 'powershell' should find both event types on SERVER2."""
        alert = alerts_df[alerts_df['alert_name'] == 'PowerShell Execution'].iloc[0]
        result = _call('query_events_by_process_name', {
            'process_name': 'powershell',
            'hostname': alert['hostname'],
            'start_time': '2026-01-13 07:00:00',
            'end_time': '2026-01-13 07:20:00',
        })
        assert result['count'] == 2
        categories = {e['category'] for e in result['events']}
        assert 'process_creation' in categories
        assert 'network_connection' in categories

    def test_partial_name_match(self):
        """Partial process name should still match."""
        result = _call('query_events_by_process_name', {'process_name': 'cmd'})
        assert result['count'] >= 1
        assert 'cmd.exe' in result['events'][0]['process']


class TestAlertEventLookupByProcessTree:
    """build_process_tree should trace the parent chain for alert PIDs."""

    def test_python_process_tree(self, alerts_df):
        """PID 17004 → parent 5672 (cmd.exe) → parent 1000 (explorer.exe)."""
        alert = alerts_df[alerts_df['alert_name'] == 'Python Shelled Out'].iloc[0]
        result = _call('build_process_tree', {
            'pid': int(alert['processid']),
            'hostname': alert['hostname'],
            'reference_timestamp': str(alert['first_seen']),
        })
        assert result['depth'] >= 3
        pids_in_tree = [n['pid'] for n in result['tree']]
        # python (17004) and its parent cmd (5672) must be in the tree
        assert 17004 in pids_in_tree
        assert 5672 in pids_in_tree
        assert 1000 in pids_in_tree
        # Tree should be root-first
        assert result['tree'][-1]['pid'] == 17004

    def test_powershell_process_tree(self, alerts_df):
        """PID 8800 → parent 4400 (services.exe)."""
        alert = alerts_df[alerts_df['alert_name'] == 'PowerShell Execution'].iloc[0]
        result = _call('build_process_tree', {
            'pid': int(alert['processid']),
            'hostname': alert['hostname'],
            'reference_timestamp': str(alert['first_seen']),
        })
        assert result['depth'] >= 2
        pids = [n['pid'] for n in result['tree']]
        assert 8800 in pids
        assert 4400 in pids

    def test_tree_shows_parent_image(self, alerts_df):
        """Each tree node should report the parent image."""
        alert = alerts_df[alerts_df['alert_name'] == 'Python Shelled Out'].iloc[0]
        result = _call('build_process_tree', {
            'pid': int(alert['processid']),
            'hostname': alert['hostname'],
            'reference_timestamp': str(alert['first_seen']),
        })
        python_node = [n for n in result['tree'] if n['pid'] == 17004][0]
        assert python_node['parent_image'] == 'cmd.exe'


class TestAlertEventLookupByNetwork:
    """query_network_events should find connections matching alert network data."""

    def test_network_by_dest_ip(self, alerts_df):
        """Search by destination IP from the alert."""
        alert = alerts_df[alerts_df['alert_name'] == 'Python Shelled Out'].iloc[0]
        result = _call('query_network_events', {
            'ip_address': alert['destinationip'],
        })
        assert result['count'] >= 1
        for ev in result['events']:
            assert ev['dest_ip'] == '34.41.118.55'

    def test_network_by_dest_port(self, alerts_df):
        """Search by destination port from the alert."""
        alert = alerts_df[alerts_df['alert_name'] == 'Suspicious Network Connection'].iloc[0]
        result = _call('query_network_events', {
            'port': int(alert['destinationport']),
        })
        assert result['count'] >= 1

    def test_network_with_time_window(self, alerts_df):
        """Network events scoped to alert time window."""
        alert = alerts_df[alerts_df['alert_name'] == 'PowerShell Execution'].iloc[0]
        result = _call('query_network_events', {
            'start_time': '2026-01-13 07:00:00',
            'end_time': '2026-01-13 07:20:00',
        })
        assert result['count'] >= 1
        assert result['events'][0]['process'] == 'powershell.exe'


class TestEveryAlertHasEvents:
    """Iterate every alert and confirm events can be found by PID."""

    def test_all_alerts_have_pid_events(self, alerts_df):
        """Every alert with a processid should have at least one matching event."""
        for _, alert in alerts_df.iterrows():
            pid = alert.get('processid')
            if pd.isna(pid):
                continue
            result = _call('query_events_by_pid', {
                'pid': int(pid),
                'hostname': alert['hostname'],
            })
            assert result['count'] > 0, (
                f"No events found for alert '{alert['alert_name']}' "
                f"PID {pid} on {alert['hostname']}"
            )

    def test_all_alerts_have_process_name_events(self, alerts_df):
        """Every alert with a process name should have at least one matching event."""
        for _, alert in alerts_df.iterrows():
            proc = alert.get('process')
            if pd.isna(proc) or proc == 'N/A':
                continue
            result = _call('query_events_by_process_name', {
                'process_name': proc,
                'hostname': alert['hostname'],
            })
            assert result['count'] > 0, (
                f"No events found for alert '{alert['alert_name']}' "
                f"process '{proc}' on {alert['hostname']}"
            )

    def test_all_alerts_with_network_have_network_events(self, alerts_df):
        """Alerts with destination IPs should have matching network events."""
        for _, alert in alerts_df.iterrows():
            dest_ip = alert.get('destinationip')
            if pd.isna(dest_ip) or str(dest_ip) in ('', 'N/A'):
                continue
            result = _call('query_network_events', {
                'ip_address': dest_ip,
            })
            assert result['count'] > 0, (
                f"No network events found for alert '{alert['alert_name']}' "
                f"destination IP {dest_ip}"
            )
