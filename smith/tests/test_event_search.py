"""Tests for event search agent tools, dispatch, and EventStream dedup fix."""

import json
import pandas as pd
import pytest
import tools.state as state


@pytest.fixture
def sample_events_df():
    """Create a sample events DataFrame for testing."""
    return pd.DataFrame([
        {
            'timestamp': '2026-01-13 06:28:50',
            'hostname': 'DESKTOP-TEST',
            'username': 'DESKTOP-TEST\\user',
            'category': 'process_creation',
            'processid': 12168,
            'process': 'sublime_text.exe',
            'parentprocessid': 1000,
            'parentimage': 'explorer.exe',
            'commandline': '"C:\\Program Files\\Sublime Text\\sublime_text.exe"',
        },
        {
            'timestamp': '2026-01-13 06:28:55',
            'hostname': 'DESKTOP-TEST',
            'username': 'DESKTOP-TEST\\user',
            'category': 'network_connection',
            'processid': 12168,
            'process': 'sublime_text.exe',
            'sourceip': '192.168.1.48',
            'sourceport': 61497,
            'destinationip': '45.55.41.223',
            'destinationport': 443,
            'status': 'ESTABLISHED',
        },
        {
            'timestamp': '2026-01-13 06:30:00',
            'hostname': 'DESKTOP-TEST',
            'username': 'DESKTOP-TEST\\user',
            'category': 'process_creation',
            'processid': 17004,
            'process': 'python.exe',
            'parentprocessid': 12168,
            'parentimage': 'sublime_text.exe',
            'commandline': 'python.exe script.py',
        },
    ])


@pytest.fixture(autouse=True)
def set_events_state(sample_events_df):
    """Set the global EVENTS_DF state for tool queries."""
    old = state.EVENTS_DF
    state.EVENTS_DF = sample_events_df
    yield
    state.EVENTS_DF = old


class TestEventSearchToolDispatch:
    """Test that event search tool dispatch works correctly."""

    def test_query_events_by_pid(self):
        from tools import process_event_search_tool_call
        result = json.loads(process_event_search_tool_call(
            'query_events_by_pid', {'pid': 12168}
        ))
        # 2 own events (process_creation + network_connection)
        # + 1 child process (python.exe spawned by PID 12168)
        assert result['count'] == 3

    def test_query_events_by_pid_no_match(self):
        from tools import process_event_search_tool_call
        result = json.loads(process_event_search_tool_call(
            'query_events_by_pid', {'pid': 99999}
        ))
        assert result['count'] == 0

    def test_query_events_by_process_name(self):
        from tools import process_event_search_tool_call
        result = json.loads(process_event_search_tool_call(
            'query_events_by_process_name', {'process_name': 'python'}
        ))
        assert result['count'] == 1

    def test_query_network_events(self):
        from tools import process_event_search_tool_call
        result = json.loads(process_event_search_tool_call(
            'query_network_events', {'ip_address': '45.55.41.223'}
        ))
        assert result['count'] == 1

    def test_unknown_tool(self):
        from tools import process_event_search_tool_call
        result = json.loads(process_event_search_tool_call(
            'nonexistent_tool', {}
        ))
        assert 'error' in result


class TestToolListSeparation:
    """Verify event tools are separated from alert tools."""

    def test_event_tools_not_in_alert_tools(self):
        from tools import ALERT_TOOLS, EVENT_SEARCH_TOOLS
        alert_names = {t['name'] for t in ALERT_TOOLS}
        event_names = {t['name'] for t in EVENT_SEARCH_TOOLS}
        overlap = alert_names & event_names
        assert len(overlap) == 0, f"Overlap found: {overlap}"

    def test_delegation_tool_in_alert_tools(self):
        from tools import ALERT_TOOLS
        names = {t['name'] for t in ALERT_TOOLS}
        assert 'delegate_event_search' in names

    def test_event_search_tools_complete(self):
        from tools import EVENT_SEARCH_TOOLS
        names = {t['name'] for t in EVENT_SEARCH_TOOLS}
        expected = {
            'query_events_by_pid',
            'query_events_by_process_name',
            'build_process_tree',
            'lookup_ip_info',
            'query_network_events',
        }
        assert names == expected

    def test_alert_tools_no_event_tools(self):
        from tools import ALERT_TOOLS
        names = {t['name'] for t in ALERT_TOOLS}
        event_tool_names = {
            'query_events_by_pid', 'query_events_by_process_name',
            'build_process_tree', 'query_network_events',
        }
        assert names & event_tool_names == set()


class TestBuildProcessTree:
    """Test process tree construction."""

    def test_builds_tree_for_child(self):
        from tools.build_process_tree import build_process_tree
        result = json.loads(build_process_tree(pid=17004))
        # python.exe (17004) → parent sublime_text.exe (12168) → parent explorer.exe (1000, stub)
        assert result['depth'] >= 2
        pids = [n['pid'] for n in result['tree']]
        assert 17004 in pids
        assert 12168 in pids

    def test_tree_includes_stub_for_missing_parent(self):
        """When the root parent has no own events, it should still appear as a stub."""
        from tools.build_process_tree import build_process_tree
        result = json.loads(build_process_tree(pid=12168))
        # sublime_text.exe (12168) has parentprocessid=1000 (explorer.exe)
        # PID 1000 has no events → should be added as a stub node
        tree = result['tree']
        root = tree[0]
        assert root['pid'] == 1000
        assert 'note' in root  # Stub indicator
        assert 'explorer.exe' in root['process']

    def test_tree_no_match(self):
        from tools.build_process_tree import build_process_tree
        result = json.loads(build_process_tree(pid=99999))
        assert result['tree'] == []

    def test_tree_hostname_filter(self):
        from tools.build_process_tree import build_process_tree
        result = json.loads(build_process_tree(pid=12168, hostname='WRONG-HOST'))
        assert result['tree'] == []


class TestQueryEventsByPid:
    """Test PID query including child process discovery."""

    def test_own_events(self):
        from tools.query_events_by_pid import query_events_by_pid
        result = json.loads(query_events_by_pid(pid=17004))
        # python.exe has 1 own event (process_creation)
        # No children spawned by PID 17004
        assert result['count'] == 1

    def test_includes_child_processes(self):
        from tools.query_events_by_pid import query_events_by_pid
        result = json.loads(query_events_by_pid(pid=12168))
        # 2 own events + 1 child (python.exe spawned by PID 12168)
        assert result['count'] == 3
        processes = [e['process'] for e in result['events']]
        assert 'sublime_text.exe' in processes
        assert 'python.exe' in processes

    def test_parent_with_no_own_events(self):
        from tools.query_events_by_pid import query_events_by_pid
        result = json.loads(query_events_by_pid(pid=1000))
        # PID 1000 (explorer.exe) has no own events, but sublime_text.exe lists it as parent
        assert result['count'] == 1
        assert result['events'][0]['process'] == 'sublime_text.exe'

    def test_hostname_filter(self):
        from tools.query_events_by_pid import query_events_by_pid
        result = json.loads(query_events_by_pid(pid=12168, hostname='WRONG-HOST'))
        assert result['count'] == 0

    def test_no_match(self):
        from tools.query_events_by_pid import query_events_by_pid
        result = json.loads(query_events_by_pid(pid=99999))
        assert result['count'] == 0


class TestQueryNetworkEvents:
    """Test network event queries."""

    def test_by_dest_ip(self):
        from tools.query_network_events import query_network_events
        result = json.loads(query_network_events(ip_address='45.55.41.223'))
        assert result['count'] == 1
        assert result['events'][0]['dest_ip'] == '45.55.41.223'

    def test_by_source_ip(self):
        from tools.query_network_events import query_network_events
        result = json.loads(query_network_events(ip_address='192.168.1.48'))
        assert result['count'] == 1

    def test_no_match(self):
        from tools.query_network_events import query_network_events
        result = json.loads(query_network_events(ip_address='10.0.0.1'))
        assert result['count'] == 0


class TestQueryEventsByProcessName:

    def test_exact_process(self):
        from tools.query_events_by_process_name import query_events_by_process_name
        result = json.loads(query_events_by_process_name(process_name='python'))
        assert result['count'] == 1
        assert result['events'][0]['process'] == 'python.exe'

    def test_partial_match(self):
        from tools.query_events_by_process_name import query_events_by_process_name
        result = json.loads(query_events_by_process_name(process_name='sublime'))
        assert result['count'] >= 1

    def test_no_match(self):
        from tools.query_events_by_process_name import query_events_by_process_name
        result = json.loads(query_events_by_process_name(process_name='nonexistent'))
        assert result['count'] == 0


class TestEventStreamDedup:
    """Test that the EventStream dedup fix correctly distinguishes events."""

    def test_different_pids_different_hashes(self):
        """Two events with same process+commandline but different PIDs must have different hashes."""
        from data_layer.event_stream import EventStream
        es = EventStream('.')

        event1 = {
            'process': 'cmd.exe', 'commandline': 'whoami',
            'processid': '100', 'timestamp': '2026-01-01 00:00:00',
            'hostname': 'HOST1',
        }
        event2 = {
            'process': 'cmd.exe', 'commandline': 'whoami',
            'processid': '200', 'timestamp': '2026-01-01 00:01:00',
            'hostname': 'HOST1',
        }

        hash1 = es.generate_event_hash(event1)
        hash2 = es.generate_event_hash(event2)
        assert hash1 != hash2, "Events with different PIDs should have different hashes"

    def test_identical_events_same_hash(self):
        """Truly identical events should produce the same hash."""
        from data_layer.event_stream import EventStream
        es = EventStream('.')

        event = {
            'process': 'cmd.exe', 'commandline': 'whoami',
            'processid': '100', 'timestamp': '2026-01-01 00:00:00',
            'hostname': 'HOST1',
        }
        assert es.generate_event_hash(event) == es.generate_event_hash(event)

    def test_different_timestamps_different_hashes(self):
        """Same process but different timestamps must have different hashes."""
        from data_layer.event_stream import EventStream
        es = EventStream('.')

        event1 = {
            'process': 'cmd.exe', 'commandline': 'whoami',
            'processid': '100', 'timestamp': '2026-01-01 00:00:00',
        }
        event2 = {
            'process': 'cmd.exe', 'commandline': 'whoami',
            'processid': '100', 'timestamp': '2026-01-01 00:05:00',
        }

        hash1 = es.generate_event_hash(event1)
        hash2 = es.generate_event_hash(event2)
        assert hash1 != hash2, "Events with different timestamps should have different hashes"

    def test_empty_values_ignored(self):
        """None/empty/N/A values should be excluded from hash."""
        from data_layer.event_stream import EventStream
        es = EventStream('.')

        event1 = {
            'process': 'cmd.exe', 'timestamp': '2026-01-01 00:00:00',
        }
        event2 = {
            'process': 'cmd.exe', 'timestamp': '2026-01-01 00:00:00',
            'sourceip': None, 'destinationip': 'N/A',
        }
        assert es.generate_event_hash(event1) == es.generate_event_hash(event2)
