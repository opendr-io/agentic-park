"""Tests for alert parsing: separators, field extraction, driver/service fields."""

import tempfile
import pytest
from pathlib import Path
from data_layer.extract_alert_events import parse_opendr_alerts_with_events, parse_opendr_event


class TestParseAlertLog:
    """Test parse_opendr_alerts_with_events against sample data."""

    def test_total_event_count(self, parsed_events):
        assert len(parsed_events) == 4  # 1 driver + 2 services + 1 network

    def test_alert_types(self, parsed_events):
        names = [e['alert_name'] for e in parsed_events]
        assert names.count('\u26a0\ufe0f New Driver') == 1
        assert names.count('\u26a0\ufe0f New Service') == 2
        assert names.count('\U0001f6a8 Sublime Text Internet Activity') == 1

    def test_separator_not_in_alert_names(self, parsed_events):
        for e in parsed_events:
            assert '=====' not in e['alert_name']

    def test_descriptions_populated(self, parsed_events):
        for e in parsed_events:
            assert e.get('alert_description'), f"Missing description for {e['alert_name']}"

    def test_leading_separator_stripped(self, tmp_path):
        """File starting with ==== separator should not produce an empty alert."""
        content = "==================================================\n"
        content += "\u26a0\ufe0f Test Alert\nDescription\nMatching log entries:\n\n"
        content += "timestamp: 2026-01-01 00:00:00 | hostname: TEST | event: test\n"
        content += "==================================================\n"

        f = tmp_path / "test.log"
        f.write_text(content, encoding='utf-8')
        events = parse_opendr_alerts_with_events(str(f))
        assert len(events) == 1
        assert events[0]['alert_name'] == '\u26a0\ufe0f Test Alert'

    def test_trailing_summary_line_ignored(self, parsed_events):
        """The '4 alerts were generated...' summary line should not create events."""
        for e in parsed_events:
            assert 'alerts were generated' not in e.get('alert_name', '')

    def test_empty_lines_between_sections_handled(self, parsed_events):
        """Multiple empty lines between sections should not break parsing."""
        assert len(parsed_events) == 4


class TestParseDriverFields:
    """Test that driver-specific fields are extracted correctly."""

    def test_driver_fields_present(self, parsed_events):
        drivers = [e for e in parsed_events if 'new driver' in e.get('event', '')]
        assert len(drivers) == 1
        d = drivers[0]
        assert d['desc'] == 'Generic Non-PnP Monitor'
        assert d['signer'] == 'Microsoft Windows'
        assert d['device_id'] == 'DISPLAY\\DEFAULT_MONITOR\\4&427137E&0&UID0'
        assert d['driver_version'] == '10.0.19041.5794'
        assert d['is_signed'] == 'True'
        assert d['pdo'] == '\\Device\\0000008c'
        assert d['ec2_instance_id'] == 'No instance ID'

    def test_friendly_name_none_converted(self, parsed_events):
        drivers = [e for e in parsed_events if 'new driver' in e.get('event', '')]
        assert drivers[0]['friendly_name'] is None


class TestParseServiceFields:
    """Test that service-specific fields are extracted correctly."""

    def test_service_count(self, parsed_events):
        services = [e for e in parsed_events if 'new service' in e.get('event', '')]
        assert len(services) == 2

    def test_service_fields(self, parsed_events):
        services = [e for e in parsed_events if 'new service' in e.get('event', '')]
        vm3d = [s for s in services if s['servicename'] == 'VM3DService'][0]

        assert vm3d['displayname'] == 'VMware SVGA Helper Service'
        assert vm3d['status'] == 'running'
        assert vm3d['start'] == 'automatic'
        assert vm3d['executable'] == 'C:\\WINDOWS\\system32\\vm3dservice.exe'
        assert vm3d['pid'] == '76644'

    def test_service_quotes_stripped(self, parsed_events):
        """Quoted values like 'VM3DService' should have quotes removed."""
        services = [e for e in parsed_events if 'new service' in e.get('event', '')]
        for s in services:
            assert not s['servicename'].startswith("'")
            assert not s['displayname'].startswith("'")

    def test_service_pid_none(self, parsed_events):
        """pid: None should be converted to Python None."""
        services = [e for e in parsed_events if 'new service' in e.get('event', '')]
        vmvss = [s for s in services if s['servicename'] == 'vmvss'][0]
        assert vmvss['pid'] is None


class TestParseNetworkFields:
    """Test that network-specific fields are extracted correctly."""

    def test_network_fields(self, parsed_events):
        net = [e for e in parsed_events if e.get('category') == 'network_connection']
        assert len(net) == 1
        n = net[0]
        assert n['process'] == 'sublime_text.exe'
        assert n['sourceip'] == '192.168.1.48'
        assert n['sourceport'] == '61497'
        assert n['destinationip'] == '45.55.41.223'
        assert n['destinationport'] == '443'
        assert n['status'] == 'ESTABLISHED'


class TestAlertFieldTypes:
    """Verify each alert type produces ONLY its expected fields.

    This is the ground truth: network alerts must NOT have parent fields,
    shell-out alerts must NOT have network fields, etc.
    """

    # The raw alert file content — two alert types, 6 events total
    ALERT_LOG = """\
==================================================
\U0001f6a8 Python Shelled Out
Python.exe (Python) started the cmd.exe shell.
Matching log entries:

timestamp: 2026-02-13 11:41:08 | hostname: DESKTOP-IAGNT81 | username: DESKTOP-IAGNT81\\flynn | processid: 5672 | process: cmd.exe | parentprocessid: 17004 | parentimage: python.exe | image: C:\\Windows\\System32\\cmd.exe /c
timestamp: 2026-02-13 11:41:24 | hostname: DESKTOP-IAGNT81 | username: DESKTOP-IAGNT81\\flynn | processid: 16272 | process: cmd.exe | parentprocessid: 17004 | parentimage: python.exe | image: C:\\Windows\\System32\\cmd.exe /c ipconfig
==================================================

==================================================
\U0001f6a8 Python Internet Activity
Python made an unusual outbound connection.
Matching log entries:

timestamp: 2026-02-13 11:39:22 | hostname: DESKTOP-IAGNT81 | username: DESKTOP-IAGNT81\\flynn | category: network_connection | process: python.exe | processid: 16788 | sourceip: 192.168.1.48 | sourceport: 61458 | destinationip: 34.41.118.55 | destinationport: 8080 | status: SYN_SENT | sid: S-1-5-80-TEST
==================================================
"""

    # Fields that ONLY belong to process/shell-out alerts
    PROCESS_ONLY_FIELDS = {'parentimage', 'parentprocessid', 'image'}

    # Fields that ONLY belong to network alerts
    NETWORK_ONLY_FIELDS = {'sourceip', 'sourceport', 'destinationip', 'destinationport', 'category'}

    @pytest.fixture
    def parsed(self, tmp_path):
        f = tmp_path / "mixed_alerts.log"
        f.write_text(self.ALERT_LOG, encoding='utf-8')
        return parse_opendr_alerts_with_events(str(f))

    def test_event_count(self, parsed):
        """2 shelled out + 1 network = 3 events."""
        assert len(parsed) == 3

    def test_shelled_out_has_parent_fields(self, parsed):
        """Shelled Out events must have parentimage and parentprocessid."""
        shell_events = [e for e in parsed if 'Shelled Out' in e['alert_name']]
        for ev in shell_events:
            assert 'parentimage' in ev, f"Missing parentimage in Shelled Out event"
            assert 'parentprocessid' in ev, f"Missing parentprocessid in Shelled Out event"
            assert ev['parentimage'] == 'python.exe'
            assert ev['parentprocessid'] == '17004'

    def test_shelled_out_no_network_fields(self, parsed):
        """Shelled Out events must NOT have network fields."""
        shell_events = [e for e in parsed if 'Shelled Out' in e['alert_name']]
        for ev in shell_events:
            for field in self.NETWORK_ONLY_FIELDS:
                assert field not in ev, f"Shelled Out event should not have '{field}'"

    def test_network_has_network_fields(self, parsed):
        """Internet Activity events must have network fields."""
        net_events = [e for e in parsed if 'Internet Activity' in e['alert_name']]
        assert len(net_events) == 1
        ev = net_events[0]
        assert ev['sourceip'] == '192.168.1.48'
        assert ev['destinationip'] == '34.41.118.55'
        assert ev['destinationport'] == '8080'
        assert ev['category'] == 'network_connection'

    def test_network_no_parent_fields(self, parsed):
        """Internet Activity events must NOT have parent process fields."""
        net_events = [e for e in parsed if 'Internet Activity' in e['alert_name']]
        for ev in net_events:
            for field in self.PROCESS_ONLY_FIELDS:
                assert field not in ev, f"Network event should not have '{field}'"

    def test_expected_shelled_out_values(self, parsed):
        """Verify exact field values for a Shelled Out event."""
        shell_events = [e for e in parsed if 'Shelled Out' in e['alert_name']]
        first = shell_events[0]
        assert first['timestamp'] == '2026-02-13 11:41:08'
        assert first['hostname'] == 'DESKTOP-IAGNT81'
        assert first['username'] == 'DESKTOP-IAGNT81\\flynn'
        assert first['process'] == 'cmd.exe'
        assert first['processid'] == '5672'

    def test_expected_network_values(self, parsed):
        """Verify exact field values for an Internet Activity event."""
        net = [e for e in parsed if 'Internet Activity' in e['alert_name']][0]
        assert net['timestamp'] == '2026-02-13 11:39:22'
        assert net['hostname'] == 'DESKTOP-IAGNT81'
        assert net['process'] == 'python.exe'
        assert net['processid'] == '16788'
        assert net['sourceport'] == '61458'
        assert net['status'] == 'SYN_SENT'

    def test_dataframe_nan_for_missing_fields(self, parsed):
        """When built into a DataFrame, missing fields become NaN — not fabricated values."""
        import pandas as pd

        df = pd.DataFrame(parsed)

        # Network rows should have NaN for parent fields
        net_mask = df['alert_name'].str.contains('Internet Activity')
        for field in self.PROCESS_ONLY_FIELDS:
            if field in df.columns:
                assert df.loc[net_mask, field].isna().all(), \
                    f"Network alert has non-NaN '{field}' in DataFrame"

        # Shell-out rows should have NaN for network fields
        shell_mask = df['alert_name'].str.contains('Shelled Out')
        for field in self.NETWORK_ONLY_FIELDS:
            if field in df.columns:
                assert df.loc[shell_mask, field].isna().all(), \
                    f"Shelled Out alert has non-NaN '{field}' in DataFrame"


class TestParseSingleEvent:
    """Test parse_opendr_event for edge cases."""

    def test_colon_in_value(self):
        line = "timestamp: 2026-01-01 12:00:00 | hostname: TEST"
        event = parse_opendr_event(line)
        assert event['timestamp'] == '2026-01-01 12:00:00'

    def test_empty_line(self):
        assert parse_opendr_event("") is None

    def test_no_pipe(self):
        assert parse_opendr_event("just some text") is None
