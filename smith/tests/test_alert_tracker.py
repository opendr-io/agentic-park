"""Tests for alert_tracker.py — state transitions, analysis saving, FP journal."""

import os
import sys
import pytest
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from data_layer.alert_tracker import (
    AlertTracker, save_analysis_text, load_analysis_text,
    _extract_fp_reason, _log_false_positive, backfill_fp_journal,
)


# --- Helpers ---

def _make_csv(tmp_path, rows=None):
    """Create a minimal alerts CSV and return (path, DataFrame)."""
    if rows is None:
        rows = [
            {'alert_hash': 'aaa111', 'alert_name': 'Test Alert', 'hostname': 'HOST-1',
             'timestamp': '2026-01-01 00:00:00', 'read': None, 'alert_status': 'open'},
            {'alert_hash': 'bbb222', 'alert_name': 'Another Alert', 'hostname': 'HOST-2',
             'timestamp': '2026-01-02 00:00:00', 'read': None, 'alert_status': 'open'},
        ]
    df = pd.DataFrame(rows)
    p = tmp_path / 'alerts.csv'
    df.to_csv(p, index=False)
    return str(p), df


# ── State transitions ──────────────────────────────────────────────

class TestMarkProcessing:
    def test_marks_processing(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.mark_processing('aaa111') is True
        val = t.df.loc[t.df['alert_hash'] == 'aaa111', 'read'].iloc[0]
        assert val.startswith('processing|')

    def test_persists_to_csv(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_processing('aaa111')
        # Reload from disk
        t2 = AlertTracker(csv)
        val = t2.df.loc[t2.df['alert_hash'] == 'aaa111', 'read'].iloc[0]
        assert val.startswith('processing|')

    def test_returns_false_for_missing_hash(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.mark_processing('zzz999') is False


class TestMarkRead:
    def test_marks_read(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_processing('aaa111')
        assert t.mark_read('aaa111') is True
        val = t.df.loc[t.df['alert_hash'] == 'aaa111', 'read'].iloc[0]
        assert val.startswith('read|')

    def test_returns_false_for_missing_hash(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.mark_read('zzz999') is False


class TestMarkUnread:
    def test_resets_to_none(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_processing('aaa111')
        assert t.mark_unread('aaa111') is True
        val = t.df.loc[t.df['alert_hash'] == 'aaa111', 'read'].iloc[0]
        assert pd.isna(val)

    def test_returns_false_for_missing_hash(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.mark_unread('zzz999') is False


class TestMarkClosed:
    def test_closes_alert(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.mark_closed('aaa111') is True
        val = t.df.loc[t.df['alert_hash'] == 'aaa111', 'alert_status'].iloc[0]
        assert val == 'closed'

    def test_persists_to_csv(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_closed('aaa111')
        t2 = AlertTracker(csv)
        val = t2.df.loc[t2.df['alert_hash'] == 'aaa111', 'alert_status'].iloc[0]
        assert val == 'closed'

    def test_closed_excluded_from_unread(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_closed('aaa111')
        unread = t.get_unread_alerts()
        assert 'aaa111' not in unread['alert_hash'].values

    def test_returns_false_for_missing_hash(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.mark_closed('zzz999') is False


class TestMarkOpen:
    def test_reopens_alert(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_closed('aaa111')
        assert t.mark_open('aaa111') is True
        val = t.df.loc[t.df['alert_hash'] == 'aaa111', 'alert_status'].iloc[0]
        assert val == 'open'


# ── Get helpers ─────────────────────────────────────────────────────

class TestGetUnreadAlerts:
    def test_returns_all_unread(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        unread = t.get_unread_alerts()
        assert len(unread) == 2

    def test_excludes_processing(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_processing('aaa111')
        unread = t.get_unread_alerts()
        assert len(unread) == 1
        assert unread.iloc[0]['alert_hash'] == 'bbb222'

    def test_limit(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        unread = t.get_unread_alerts(limit=1)
        assert len(unread) == 1


class TestGetStats:
    def test_initial_stats(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        stats = t.get_stats()
        assert stats['total'] == 2
        assert stats['unread'] == 2
        assert stats['processing'] == 0
        assert stats['read'] == 0
        assert stats['closed'] == 0

    def test_stats_after_transitions(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_processing('aaa111')
        t.mark_read('bbb222')
        stats = t.get_stats()
        assert stats['unread'] == 0
        assert stats['processing'] == 1
        assert stats['read'] == 1

    def test_stats_with_closed(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_closed('aaa111')
        stats = t.get_stats()
        assert stats['closed'] == 1


# ── Recover stuck alerts ────────────────────────────────────────────

class TestRecoverStuckAlerts:
    def test_recovers_old_processing(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        # Manually set processing with an old timestamp
        old_time = (datetime.now() - timedelta(minutes=60)).isoformat()
        t.df.loc[t.df['alert_hash'] == 'aaa111', 'read'] = f"processing|{old_time}"
        recovered = t.recover_stuck_alerts(timeout_minutes=30)
        assert recovered == 1
        val = t.df.loc[t.df['alert_hash'] == 'aaa111', 'read'].iloc[0]
        assert pd.isna(val)

    def test_does_not_recover_recent(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_processing('aaa111')
        recovered = t.recover_stuck_alerts(timeout_minutes=30)
        assert recovered == 0

    def test_does_not_touch_read(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.mark_read('aaa111')
        recovered = t.recover_stuck_alerts(timeout_minutes=0)
        assert recovered == 0
        val = t.df.loc[t.df['alert_hash'] == 'aaa111', 'read'].iloc[0]
        assert val.startswith('read|')


# ── Analysis saving ─────────────────────────────────────────────────

class TestSaveLoadAnalysisText:
    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        save_analysis_text('hash123', 'This is the analysis.')
        result = load_analysis_text('hash123')
        assert result == 'This is the analysis.'

    def test_load_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        assert load_analysis_text('nonexistent') is None


class TestSaveAnalysis:
    def test_saves_severity_and_file_flag(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', tmp_path / 'fp.csv')
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        result = t.save_analysis('aaa111', 'HIGH', 'Detailed analysis text', 'alert_analyst')
        assert result is True
        row = t.df[t.df['alert_hash'] == 'aaa111'].iloc[0]
        assert row['severity'] == 'HIGH'
        assert row['analysis'] == 'file'
        assert row['analyzed_by'] == 'alert_analyst'
        assert pd.notna(row['analyzed_at'])

    def test_writes_analysis_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', tmp_path / 'fp.csv')
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.save_analysis('aaa111', 'LOW', 'The analysis content')
        text = load_analysis_text('aaa111')
        assert text == 'The analysis content'

    def test_returns_false_for_missing_hash(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', tmp_path / 'fp.csv')
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.save_analysis('zzz999', 'LOW', 'text') is False

    def test_triggers_fp_journal_for_false_positive(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        fp_path = tmp_path / 'fp.csv'
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', fp_path)
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.save_analysis('aaa111', 'LOW', 'This is a FALSE POSITIVE. Benign activity.', 'alert_analyst')
        assert fp_path.exists()
        fp_df = pd.read_csv(fp_path)
        assert len(fp_df) == 1
        assert fp_df.iloc[0]['alert_hash'] == 'aaa111'

    def test_no_fp_journal_for_true_positive(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        fp_path = tmp_path / 'fp.csv'
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', fp_path)
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.save_analysis('aaa111', 'HIGH', 'This is malicious. Investigate immediately.')
        assert not fp_path.exists()


class TestGetAnalysis:
    def test_returns_analysis(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', tmp_path / 'fp.csv')
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        t.save_analysis('aaa111', 'MEDIUM', 'Full analysis text here', 'new_analyst')
        result = t.get_analysis('aaa111')
        assert result['severity'] == 'MEDIUM'
        assert result['analysis'] == 'Full analysis text here'
        assert result['analyzed_by'] == 'new_analyst'

    def test_returns_none_for_missing(self, tmp_path):
        csv, _ = _make_csv(tmp_path)
        t = AlertTracker(csv)
        assert t.get_analysis('zzz999') is None


# ── FP reason extraction ────────────────────────────────────────────

class TestExtractFpReason:
    def test_finds_sentence_with_false_positive(self):
        text = "This alert is benign. It is a false positive caused by auto-update. No action needed."
        reason = _extract_fp_reason(text)
        assert 'false positive' in reason.lower()

    def test_strips_markdown(self):
        text = "## **Assessment: FALSE POSITIVE** — normal telemetry behavior."
        reason = _extract_fp_reason(text)
        assert not reason.startswith('#')
        assert not reason.startswith('*')

    def test_truncates_long_reason(self):
        text = "This is a false positive " + "x" * 300 + "."
        reason = _extract_fp_reason(text)
        assert len(reason) <= 200
        assert reason.endswith('...')

    def test_fallback_when_no_sentence(self):
        # Text contains "false positive" but as part of one big blob
        text = "false positive"
        reason = _extract_fp_reason(text)
        assert 'false positive' in reason.lower()

    def test_default_when_not_found(self):
        text = "This is completely normal."
        reason = _extract_fp_reason(text)
        assert reason == 'Classified as false positive'


# ── _log_false_positive ─────────────────────────────────────────────

class TestLogFalsePositive:
    def test_logs_when_fp_found(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', fp_path)
        df = pd.DataFrame([{
            'alert_hash': 'abc123', 'alert_name': 'New Service', 'hostname': 'HOST-1'
        }])
        _log_false_positive('abc123', 'This is a false positive.', df, 'alert_analyst')
        assert fp_path.exists()
        result = pd.read_csv(fp_path)
        assert len(result) == 1
        assert result.iloc[0]['alert_name'] == 'New Service'
        assert result.iloc[0]['hostname'] == 'HOST-1'
        assert result.iloc[0]['analyzed_by'] == 'alert_analyst'

    def test_skips_when_no_fp(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', fp_path)
        df = pd.DataFrame([{'alert_hash': 'abc123', 'alert_name': 'Test', 'hostname': 'H'}])
        _log_false_positive('abc123', 'Definitely malicious.', df)
        assert not fp_path.exists()

    def test_appends_to_existing(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', fp_path)
        df = pd.DataFrame([
            {'alert_hash': 'abc', 'alert_name': 'A', 'hostname': 'H1'},
            {'alert_hash': 'def', 'alert_name': 'B', 'hostname': 'H2'},
        ])
        _log_false_positive('abc', 'This is a false positive.', df)
        _log_false_positive('def', 'Also a false positive here.', df)
        result = pd.read_csv(fp_path)
        assert len(result) == 2


# ── backfill_fp_journal ──────────────────────────────────────────────

class TestBackfillFpJournal:
    def test_backfills_from_analysis_files(self, tmp_path, monkeypatch):
        analyses_dir = tmp_path / 'analyses'
        analyses_dir.mkdir()
        fp_path = tmp_path / 'fp.csv'
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', analyses_dir)
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', fp_path)

        # Create analysis files
        (analyses_dir / 'hash_fp.txt').write_text('This is a false positive.', encoding='utf-8')
        (analyses_dir / 'hash_tp.txt').write_text('This is malicious.', encoding='utf-8')

        # Create CSV with matching hashes
        csv = tmp_path / 'alerts.csv'
        pd.DataFrame([
            {'alert_hash': 'hash_fp', 'alert_name': 'FP Alert', 'hostname': 'H1', 'analyzed_by': 'alert_analyst'},
            {'alert_hash': 'hash_tp', 'alert_name': 'TP Alert', 'hostname': 'H2', 'analyzed_by': 'alert_analyst'},
        ]).to_csv(csv, index=False)

        count = backfill_fp_journal(str(csv))
        assert count == 1
        result = pd.read_csv(fp_path)
        assert len(result) == 1
        assert result.iloc[0]['alert_hash'] == 'hash_fp'

    def test_skips_existing_hashes(self, tmp_path, monkeypatch):
        analyses_dir = tmp_path / 'analyses'
        analyses_dir.mkdir()
        fp_path = tmp_path / 'fp.csv'
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', analyses_dir)
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', fp_path)

        (analyses_dir / 'hash_fp.txt').write_text('This is a false positive.', encoding='utf-8')
        csv = tmp_path / 'alerts.csv'
        pd.DataFrame([
            {'alert_hash': 'hash_fp', 'alert_name': 'FP Alert', 'hostname': 'H1'},
        ]).to_csv(csv, index=False)

        # First run
        backfill_fp_journal(str(csv))
        # Second run — should skip
        count = backfill_fp_journal(str(csv))
        assert count == 0
        result = pd.read_csv(fp_path)
        assert len(result) == 1  # Still just 1

    def test_returns_zero_when_no_csv(self, tmp_path, monkeypatch):
        monkeypatch.setattr('data_layer.alert_tracker.ANALYSES_DIR', tmp_path / 'analyses')
        monkeypatch.setattr('data_layer.alert_tracker.FP_JOURNAL_PATH', tmp_path / 'fp.csv')
        count = backfill_fp_journal(str(tmp_path / 'nonexistent.csv'))
        assert count == 0
