"""Tests for periodic alert file re-scanning and in-place DataFrame update."""

import pandas as pd
import pytest
from data_layer.extract_alert_events import (
    parse_alert_folder, merge_alerts, generate_event_hash
)


# Minimal alert log for rescan tests (distinct from conftest's INITIAL_ALERT_LOG)
INITIAL_ALERT_LOG = """\
==================================================
\u26a0\ufe0f New Service
A new service was created recently.
Matching log entries:

timestamp: 2026-01-12 11:18:46 | hostname: DESKTOP-TEST | username: LocalSystem | event: new service | pid: 76644 | servicename: 'VM3DService' | displayname: 'VMware SVGA Helper Service' | status: running | start: automatic | executable: C:\\WINDOWS\\system32\\vm3dservice.exe | sid: S-1-5-80-TEST
==================================================
"""

# A different alert that doesn't exist in INITIAL_ALERT_LOG
NEW_ALERT_LOG = """\
==================================================
\u26a0\ufe0f New Autorun
A new autorun entry was detected
Matching log entries:

timestamp: 2026-02-01 09:00:00 | hostname: SERVER-01 | username: SYSTEM | event: new autorun | process: malware.exe | commandline: C:\\temp\\malware.exe --persist | pid: 99999 | sid: S-1-5-18
==================================================
"""


class TestParseAlertFolder:

    def test_returns_dataframe_with_hashes(self, tmp_path):
        alerts_dir = tmp_path / "alerts"
        alerts_dir.mkdir()
        (alerts_dir / "test.log").write_text(INITIAL_ALERT_LOG, encoding='utf-8')

        df = parse_alert_folder(str(alerts_dir))
        assert df is not None
        assert 'alert_hash' in df.columns
        assert len(df) == 1

    def test_returns_none_for_empty_folder(self, tmp_path):
        alerts_dir = tmp_path / "alerts"
        alerts_dir.mkdir()
        assert parse_alert_folder(str(alerts_dir)) is None

    def test_returns_none_for_missing_folder(self, tmp_path):
        assert parse_alert_folder(str(tmp_path / "nonexistent")) is None

    def test_tracking_columns_initialized(self, tmp_path):
        alerts_dir = tmp_path / "alerts"
        alerts_dir.mkdir()
        (alerts_dir / "test.log").write_text(INITIAL_ALERT_LOG, encoding='utf-8')

        df = parse_alert_folder(str(alerts_dir))
        assert (df['alert_status'] == 'open').all()
        assert df['read'].isna().all()

    def test_reads_both_log_and_txt(self, tmp_path):
        """Both .log and .txt files should be parsed."""
        alerts_dir = tmp_path / "alerts"
        alerts_dir.mkdir()
        (alerts_dir / "first.log").write_text(INITIAL_ALERT_LOG, encoding='utf-8')
        (alerts_dir / "second.txt").write_text(NEW_ALERT_LOG, encoding='utf-8')

        df = parse_alert_folder(str(alerts_dir))
        assert len(df) == 2  # 1 from INITIAL + 1 from NEW


class TestRescanDetectsNewFiles:

    def test_new_file_adds_new_alerts(self, tmp_path):
        """Dropping a new file after initial parse produces new rows on merge."""
        alerts_dir = tmp_path / "alerts"
        alerts_dir.mkdir()

        # Initial scan
        (alerts_dir / "initial.log").write_text(INITIAL_ALERT_LOG, encoding='utf-8')
        initial_df = parse_alert_folder(str(alerts_dir))
        initial_count = len(initial_df)

        # Drop a new file
        (alerts_dir / "new_alerts.log").write_text(NEW_ALERT_LOG, encoding='utf-8')

        # Re-scan and merge
        fresh_df = parse_alert_folder(str(alerts_dir))
        merged = merge_alerts(initial_df, fresh_df)

        assert len(merged) == initial_count + 1
        # The new alert should be present
        assert 'new autorun' in merged['event'].values

    def test_rescan_same_files_no_duplicates(self, tmp_path):
        """Re-scanning with no new files should not add duplicates."""
        alerts_dir = tmp_path / "alerts"
        alerts_dir.mkdir()
        (alerts_dir / "test.log").write_text(INITIAL_ALERT_LOG, encoding='utf-8')

        df1 = parse_alert_folder(str(alerts_dir))
        df2 = parse_alert_folder(str(alerts_dir))
        merged = merge_alerts(df1, df2)

        assert len(merged) == len(df1)

    def test_preserves_tracking_state_on_rescan(self, tmp_path):
        """Existing analysis/severity should survive a rescan merge."""
        alerts_dir = tmp_path / "alerts"
        alerts_dir.mkdir()
        (alerts_dir / "test.log").write_text(INITIAL_ALERT_LOG, encoding='utf-8')

        existing = parse_alert_folder(str(alerts_dir))
        existing.loc[existing.index[0], 'severity'] = 'LOW'
        existing.loc[existing.index[0], 'analysis'] = 'Benign driver'
        existing.loc[existing.index[0], 'read'] = 'read|2026-01-15'

        # Drop a new file and rescan
        (alerts_dir / "new.log").write_text(NEW_ALERT_LOG, encoding='utf-8')
        fresh = parse_alert_folder(str(alerts_dir))
        merged = merge_alerts(existing, fresh)

        # Original tracking preserved
        first_row = merged.iloc[0]
        assert first_row['severity'] == 'LOW'
        assert first_row['analysis'] == 'Benign driver'
        assert first_row['read'] == 'read|2026-01-15'

        # New alert added
        assert len(merged) == len(existing) + 1


class TestInPlaceDataFrameUpdate:

    def test_shared_reference_sees_new_rows(self, sample_alerts_df):
        """Both holders of a DataFrame reference see in-place appended rows."""
        shared_df = sample_alerts_df
        ref_a = shared_df  # simulates BackgroundAlertProcessor
        ref_b = shared_df  # simulates StatusAgent

        initial_len = len(shared_df)

        # Simulate the in-place append pattern from _rescan_alert_folder
        new_row = {
            'timestamp': pd.Timestamp('2026-02-01'),
            'hostname': 'NEW-HOST',
            'event': 'new autorun',
            'alert_name': 'New Autorun',
            'alert_status': 'open',
            'read': None,
        }
        new_row['alert_hash'] = generate_event_hash(new_row)

        start_idx = shared_df.index.max() + 1
        shared_df.loc[start_idx] = new_row

        # Both references must see the new row
        assert len(ref_a) == initial_len + 1
        assert len(ref_b) == initial_len + 1
        assert ref_a is ref_b

    def test_new_row_is_queryable(self, sample_alerts_df):
        """After in-place append, the new row can be found by alert_hash."""
        new_row = {
            'timestamp': pd.Timestamp('2026-02-01'),
            'hostname': 'NEW-HOST',
            'event': 'new autorun',
            'alert_name': 'New Autorun',
            'alert_status': 'open',
            'read': None,
        }
        new_hash = generate_event_hash(new_row)
        new_row['alert_hash'] = new_hash

        start_idx = sample_alerts_df.index.max() + 1
        sample_alerts_df.loc[start_idx] = new_row

        matches = sample_alerts_df[sample_alerts_df['alert_hash'] == new_hash]
        assert len(matches) == 1
        assert matches.iloc[0]['hostname'] == 'NEW-HOST'
