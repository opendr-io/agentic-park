"""Tests for tools/check_fp_journal.py."""

import os
import sys
import json
import pytest
import pandas as pd
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the function — this also causes the module to load
from tools.check_fp_journal import check_fp_journal

# Get the actual module (not the function) for monkeypatching
import importlib
_fp_mod = importlib.import_module('tools.check_fp_journal')


class TestCheckFpJournal:
    def test_no_journal_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', tmp_path / 'nope.csv')
        result = json.loads(check_fp_journal('Test Alert'))
        assert result['matches'] == []
        assert 'No false positive journal' in result['message']

    def test_empty_journal(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        pd.DataFrame(columns=['timestamp', 'alert_hash', 'alert_name', 'hostname', 'analyzed_by', 'reason']).to_csv(fp_path, index=False)
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', fp_path)
        result = json.loads(check_fp_journal('Test Alert'))
        assert result['matches'] == []
        assert 'empty' in result['message']

    def test_finds_match_by_alert_name(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        pd.DataFrame([{
            'timestamp': '2026-01-01', 'alert_hash': 'abc123',
            'alert_name': 'New Service', 'hostname': 'HOST-1',
            'analyzed_by': 'alert_analyst', 'reason': 'VMware service is benign'
        }]).to_csv(fp_path, index=False)
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', fp_path)
        result = json.loads(check_fp_journal('New Service'))
        assert len(result['matches']) == 1
        assert result['matches'][0]['alert_name'] == 'New Service'

    def test_case_insensitive_match(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        pd.DataFrame([{
            'timestamp': '2026-01-01', 'alert_hash': 'abc',
            'alert_name': 'New Driver', 'hostname': 'H',
            'analyzed_by': '', 'reason': 'Generic monitor driver'
        }]).to_csv(fp_path, index=False)
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', fp_path)
        result = json.loads(check_fp_journal('new driver'))
        assert len(result['matches']) == 1

    def test_substring_match(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        pd.DataFrame([{
            'timestamp': '2026-01-01', 'alert_hash': 'abc',
            'alert_name': 'Sublime Text Internet Activity', 'hostname': 'H',
            'analyzed_by': '', 'reason': 'Auto-update'
        }]).to_csv(fp_path, index=False)
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', fp_path)
        result = json.loads(check_fp_journal('Internet Activity'))
        assert len(result['matches']) == 1

    def test_no_match(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        pd.DataFrame([{
            'timestamp': '2026-01-01', 'alert_hash': 'abc',
            'alert_name': 'New Service', 'hostname': 'H',
            'analyzed_by': '', 'reason': 'VMware'
        }]).to_csv(fp_path, index=False)
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', fp_path)
        result = json.loads(check_fp_journal('Shelled Out'))
        assert result['matches'] == []

    def test_process_search(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        pd.DataFrame([{
            'timestamp': '2026-01-01', 'alert_hash': 'abc',
            'alert_name': 'Internet Activity', 'hostname': 'H',
            'analyzed_by': '', 'reason': 'sublime_text.exe connecting to sublimetext.com'
        }]).to_csv(fp_path, index=False)
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', fp_path)
        # Alert name doesn't match but process does
        result = json.loads(check_fp_journal('Some Other Alert', process='sublime_text'))
        assert len(result['matches']) == 1

    def test_multiple_matches(self, tmp_path, monkeypatch):
        fp_path = tmp_path / 'fp.csv'
        pd.DataFrame([
            {'timestamp': '2026-01-01', 'alert_hash': 'a', 'alert_name': 'New Service',
             'hostname': 'H1', 'analyzed_by': '', 'reason': 'VMware'},
            {'timestamp': '2026-01-02', 'alert_hash': 'b', 'alert_name': 'New Service',
             'hostname': 'H2', 'analyzed_by': '', 'reason': 'Another service'},
        ]).to_csv(fp_path, index=False)
        monkeypatch.setattr(_fp_mod, 'FP_JOURNAL_PATH', fp_path)
        result = json.loads(check_fp_journal('New Service'))
        assert len(result['matches']) == 2
        assert '2 prior' in result['message']
