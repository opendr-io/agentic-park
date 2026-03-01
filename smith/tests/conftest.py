"""Shared test fixtures for the Jackson test suite."""

import os
import sys
import tempfile
import pytest
import pandas as pd

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# --- Sample alert log content ---

SAMPLE_ALERT_LOG = """\
==================================================
\u26a0\ufe0f New Driver
A new driver was created recently. Check logs
Matching log entries:

timestamp: 2026-01-02 12:09:09 | hostname: DESKTOP-TEST | event: new driver found | desc: Generic Non-PnP Monitor | signer: Microsoft Windows | device_id: DISPLAY\\DEFAULT_MONITOR\\4&427137E&0&UID0 | driver_version: 10.0.19041.5794 | friendly_name: None | is_signed: True | pdo: \\Device\\0000008c | ec2_instance_id: No instance ID | sid: S-1-5-80-TEST

==================================================
\u26a0\ufe0f New Service
A new service was created recently.
Matching log entries:

timestamp: 2026-01-12 11:18:46 | hostname: DESKTOP-TEST | username: LocalSystem | event: new service | pid: 76644 | servicename: 'VM3DService' | displayname: 'VMware SVGA Helper Service' | status: running | start: automatic | executable: C:\\WINDOWS\\system32\\vm3dservice.exe | sid: S-1-5-80-TEST
timestamp: 2026-01-12 11:18:46 | hostname: DESKTOP-TEST | username: LocalSystem | event: new service | pid: None | servicename: 'vmvss' | displayname: 'VMware Snapshot Provider' | status: stopped | start: manual | executable: C:\\WINDOWS\\system32\\dllhost.exe /Processid:{TEST} | sid: S-1-5-80-TEST
==================================================


==================================================
\U0001f6a8 Sublime Text Internet Activity
sublime_text.exe created an outbound connection.
Matching log entries:

timestamp: 2026-01-13 06:28:50 | hostname: DESKTOP-TEST | username: DESKTOP-TEST\\user | category: network_connection | process: sublime_text.exe | processid: 12168 | sourceip: 192.168.1.48 | sourceport: 61497 | destinationip: 45.55.41.223 | destinationport: 443 | status: ESTABLISHED | sid: S-1-5-80-TEST
==================================================

4 alerts were generated during the time period.
"""


@pytest.fixture
def alert_log_file(tmp_path):
    """Create a temporary alert log file with sample data."""
    f = tmp_path / "test_alerts.log"
    f.write_text(SAMPLE_ALERT_LOG, encoding='utf-8')
    return str(f)


@pytest.fixture
def parsed_events(alert_log_file):
    """Parse the sample alert log and return list of event dicts."""
    from data_layer.extract_alert_events import parse_opendr_alerts_with_events
    return parse_opendr_alerts_with_events(alert_log_file)


@pytest.fixture
def sample_alerts_df(parsed_events):
    """Create a DataFrame from parsed events with hashes."""
    from data_layer.extract_alert_events import generate_event_hash
    df = pd.DataFrame(parsed_events)
    df['alert_status'] = 'open'
    df['read'] = None
    for col in ['pid', 'processid', 'parentprocessid', 'sourceport', 'destinationport']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['alert_hash'] = df.apply(lambda row: generate_event_hash(row.to_dict()), axis=1)
    return df


@pytest.fixture
def sample_new_df(sample_alerts_df):
    """A DataFrame suitable for use as NEW_DF (new analyst tools)."""
    return sample_alerts_df.copy()


@pytest.fixture
def csv_path(tmp_path, sample_alerts_df):
    """Save sample alerts to a temp CSV and return path."""
    p = tmp_path / "alert_events.csv"
    sample_alerts_df.to_csv(p, index=False)
    return str(p)
