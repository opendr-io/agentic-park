"""
Tests for the alert filter — deterministic prompt injection scanner.

All tests are fast (no API calls, no LLM). Alert test data lives in the
tests/data/ folder as openDR-format log files:

    tests/data/clean/       — alerts that must pass through (0 findings)
    tests/data/injection/   — alerts that must be intercepted (1+ findings)

Injection files use the naming convention:
    {expected_rule}--{description}.log

To test with a different data set, drop .log files into the appropriate folder.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from alert_filter import scan_alerts, scan_alert_row
from data_layer.extract_alert_events import parse_opendr_alerts_with_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ALERTS_DIR = Path(__file__).parent / 'data'
CLEAN_DIR = ALERTS_DIR / 'clean'
INJECTION_DIR = ALERTS_DIR / 'injection'


def _discover_files(directory):
    """Discover .log files in a directory, sorted for stable test order."""
    if not directory.exists():
        return []
    return sorted(directory.glob('*.log'))


def _parse_alert_file(filepath):
    """Parse an openDR alert log file and return list of event dicts."""
    return parse_opendr_alerts_with_events(str(filepath))


def _parse_all_events(directory):
    """Parse all .log files in a directory and return flat list of events."""
    events = []
    for f in _discover_files(directory):
        events.extend(_parse_alert_file(f))
    return events


def _make_df(events):
    """Build a DataFrame from a list of event dicts with hashes."""
    from data_layer.extract_alert_events import generate_event_hash
    df = pd.DataFrame(events)
    if len(df) == 0:
        return df
    df['alert_status'] = 'open'
    df['read'] = None
    for col in ['pid', 'processid', 'parentprocessid', 'sourceport', 'destinationport']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['alert_hash'] = df.apply(lambda row: generate_event_hash(row.to_dict()), axis=1)
    return df


# ---------------------------------------------------------------------------
# Discover test files at import time for parametrize
# ---------------------------------------------------------------------------

CLEAN_FILES = _discover_files(CLEAN_DIR)
INJECTION_FILES = _discover_files(INJECTION_DIR)


# ---------------------------------------------------------------------------
# Detection tests — clean alerts pass through
# ---------------------------------------------------------------------------

class TestCleanAlertsPass:
    """Every alert in tests/alerts/clean/ must produce zero findings."""

    @pytest.mark.parametrize(
        'alert_file', CLEAN_FILES, ids=[f.stem for f in CLEAN_FILES]
    )
    def test_no_findings(self, alert_file):
        events = _parse_alert_file(alert_file)
        assert len(events) > 0, f'{alert_file.name}: no events parsed'
        for event in events:
            findings = scan_alert_row(event)
            assert findings == [], (
                f'{alert_file.name}: unexpected findings: {findings}'
            )


# ---------------------------------------------------------------------------
# Detection tests — injection alerts are caught
# ---------------------------------------------------------------------------

class TestInjectionDetection:
    """Every alert in tests/alerts/injection/ must produce at least one finding."""

    @pytest.mark.parametrize(
        'alert_file', INJECTION_FILES, ids=[f.stem for f in INJECTION_FILES]
    )
    def test_has_findings(self, alert_file):
        events = _parse_alert_file(alert_file)
        assert len(events) > 0, f'{alert_file.name}: no events parsed'
        for event in events:
            findings = scan_alert_row(event)
            assert len(findings) > 0, (
                f'{alert_file.name}: no findings — injection was not detected'
            )

    @pytest.mark.parametrize(
        'alert_file', INJECTION_FILES, ids=[f.stem for f in INJECTION_FILES]
    )
    def test_expected_rule(self, alert_file):
        """The expected rule (from the filename prefix) must be among the findings."""
        expected_rule = alert_file.stem.split('--')[0]
        if expected_rule == 'multiple':
            return  # multiple-rule files don't target a single rule

        events = _parse_alert_file(alert_file)
        for event in events:
            findings = scan_alert_row(event)
            rules = {f['rule'] for f in findings}
            assert expected_rule in rules, (
                f'{alert_file.name}: expected rule "{expected_rule}" '
                f'not found. Got: {rules}'
            )


# ---------------------------------------------------------------------------
# Edge case tests — boundary conditions for individual rules
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Programmatic edge cases that test rule boundaries."""

    def test_short_base64_passes(self):
        """Base64-like strings under 40 chars should not trigger."""
        event = {
            'executable': r'C:\Windows\system32\svchost.exe -k netsvcs',
            'servicename': 'TestSvc',
        }
        findings = scan_alert_row(event)
        encoding_findings = [f for f in findings if f['rule'] == 'obfuscated_encoding']
        assert encoding_findings == []

    def test_normal_length_passes(self):
        """Service names under 500 chars should not trigger length check."""
        event = {'servicename': 'A' * 499}
        findings = scan_alert_row(event)
        length_findings = [
            f for f in findings
            if f['rule'] == 'structural_anomaly'
            and 'length' in f.get('matched', '').lower()
        ]
        assert length_findings == []

    def test_normal_desc_passes(self):
        """Normal driver descriptions should not trigger LLM directive."""
        event = {'desc': 'Intel(R) Management Engine Interface'}
        findings = scan_alert_row(event)
        llm_findings = [f for f in findings if f['rule'] == 'llm_directive']
        assert llm_findings == []

    def test_short_prose_below_threshold(self):
        """Very short values (under 6 words) skip prose analysis."""
        event = {'commandline': 'This is a test'}
        findings = scan_alert_row(event)
        prose_findings = [f for f in findings if f['rule'] == 'prose_content']
        assert prose_findings == []

    def test_normal_emojis_pass(self):
        """Alert names with emojis (U+26A0, U+1F6A8) are normal — not invisible Unicode."""
        event = {
            'alert_name': '\u26a0\ufe0f New Service',
            'servicename': 'TestService',
            'displayname': 'Test',
        }
        findings = scan_alert_row(event)
        assert findings == []


# ---------------------------------------------------------------------------
# Integration tests — scan_alerts on DataFrames built from files
# ---------------------------------------------------------------------------

class TestScanAlerts:
    """Integration tests for the full scan_alerts pipeline."""

    @pytest.fixture(autouse=True)
    def _reset_interceptions(self):
        """Reset INTERCEPTIONS_DF before each test so tests don't bleed."""
        import tools.state as tool_state
        tool_state.INTERCEPTIONS_DF = None
        yield
        tool_state.INTERCEPTIONS_DF = None

    def test_scan_removes_bad_from_df(self):
        """Intercepted alerts must be removed from the returned DataFrame."""
        clean_events = _parse_all_events(CLEAN_DIR)[:1]
        inject_events = _parse_all_events(INJECTION_DIR)[:1]
        df = _make_df(clean_events + inject_events)

        with tempfile.TemporaryDirectory() as tmp:
            clean_df, intercepted = scan_alerts(
                df, log_dir=tmp, export_dir=os.path.join(tmp, 'intercepted'))

        assert len(clean_df) == 1
        assert len(intercepted) == 1

    def test_scan_preserves_clean(self):
        """Clean alerts must remain unchanged."""
        clean_events = _parse_all_events(CLEAN_DIR)
        df = _make_df(clean_events)

        with tempfile.TemporaryDirectory() as tmp:
            clean_df, intercepted = scan_alerts(
                df, log_dir=tmp, export_dir=os.path.join(tmp, 'intercepted'))

        assert len(clean_df) == len(clean_events)
        assert intercepted == []

    def test_mixed_batch(self):
        """All clean + all injection = clean count returned, injection count intercepted."""
        clean_events = _parse_all_events(CLEAN_DIR)
        inject_events = _parse_all_events(INJECTION_DIR)
        df = _make_df(clean_events + inject_events)

        with tempfile.TemporaryDirectory() as tmp:
            clean_df, intercepted = scan_alerts(
                df, log_dir=tmp, export_dir=os.path.join(tmp, 'intercepted'))

        assert len(clean_df) == len(clean_events)
        assert len(intercepted) == len(inject_events)

    def test_log_file_written(self):
        """Interception log must be written when alerts are intercepted."""
        inject_events = _parse_all_events(INJECTION_DIR)[:1]
        df = _make_df(inject_events)

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = os.path.join(tmp, 'logging')
            scan_alerts(df, log_dir=log_dir,
                       export_dir=os.path.join(tmp, 'intercepted'))
            log_file = os.path.join(log_dir, 'alert_filter.log')
            assert os.path.exists(log_file)
            content = open(log_file, encoding='utf-8').read()
            assert 'INTERCEPTED' in content

    def test_log_file_created_when_clean(self):
        """Log file must exist even when no alerts are intercepted."""
        clean_events = _parse_all_events(CLEAN_DIR)[:2]
        df = _make_df(clean_events)

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = os.path.join(tmp, 'logging')
            scan_alerts(df, log_dir=log_dir,
                       export_dir=os.path.join(tmp, 'intercepted'))
            log_file = os.path.join(log_dir, 'alert_filter.log')
            assert os.path.exists(log_file)
            content = open(log_file, encoding='utf-8').read()
            assert 'SCAN' in content
            assert '0 intercepted' in content

    def test_json_export(self):
        """Full alert must be saved as JSON."""
        inject_events = _parse_all_events(INJECTION_DIR)[:1]
        df = _make_df(inject_events)

        with tempfile.TemporaryDirectory() as tmp:
            export_dir = os.path.join(tmp, 'intercepted')
            scan_alerts(df, log_dir=tmp, export_dir=export_dir)
            json_files = list(Path(export_dir).glob('*.json'))
            assert len(json_files) == 1
            data = json.loads(json_files[0].read_text(encoding='utf-8'))
            assert data['action'] == 'intercepted'
            assert len(data['findings']) > 0

    def test_empty_df(self):
        """Empty DataFrame should return empty, no errors."""
        df = pd.DataFrame()
        clean_df, intercepted = scan_alerts(df)
        assert len(clean_df) == 0
        assert intercepted == []

    def test_none_df(self):
        """None DataFrame should return None, no errors."""
        clean_df, intercepted = scan_alerts(None)
        assert clean_df is None
        assert intercepted == []

    def test_report_structure(self):
        """Interception report must have the expected fields."""
        inject_events = _parse_all_events(INJECTION_DIR)[:1]
        df = _make_df(inject_events)

        with tempfile.TemporaryDirectory() as tmp:
            _, intercepted = scan_alerts(
                df, log_dir=tmp, export_dir=os.path.join(tmp, 'intercepted'))

        report = intercepted[0]
        assert 'timestamp' in report
        assert 'alert_hash' in report
        assert 'alert_name' in report
        assert 'hostname' in report
        assert 'findings' in report
        assert 'action' in report
        assert report['action'] == 'intercepted'
        assert 'full_alert' in report

    def test_finding_structure(self):
        """Each finding must have rule, field, matched, value_preview."""
        inject_events = _parse_all_events(INJECTION_DIR)[:1]
        df = _make_df(inject_events)

        with tempfile.TemporaryDirectory() as tmp:
            _, intercepted = scan_alerts(
                df, log_dir=tmp, export_dir=os.path.join(tmp, 'intercepted'))

        finding = intercepted[0]['findings'][0]
        assert 'rule' in finding
        assert 'field' in finding
        assert 'matched' in finding
        assert 'value_preview' in finding

    def test_write_report(self):
        """Run all test data through the filter and write results to logging/."""
        clean_events = _parse_all_events(CLEAN_DIR)
        inject_events = _parse_all_events(INJECTION_DIR)
        df = _make_df(clean_events + inject_events)

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = os.path.join(tmp, 'logging')
            export_dir = os.path.join(tmp, 'intercepted')
            source = f'{CLEAN_DIR}, {INJECTION_DIR}'
            clean_df, intercepted = scan_alerts(
                df, log_dir=log_dir, export_dir=export_dir, source=source
            )

        assert len(clean_df) == len(clean_events)
        assert len(intercepted) == len(inject_events)


def _run_on_alerts(folder):
    """Run the filter on a folder of real alerts (no expected outcomes)."""
    folder = Path(folder)
    events = []
    for f in sorted(list(folder.glob('*.log')) + list(folder.glob('*.txt'))):
        parsed = parse_opendr_alerts_with_events(str(f))
        print(f'Parsed {f.name}: {len(parsed)} events')
        events.extend(parsed)

    if not events:
        print(f'No events found in {folder}')
        return

    df = _make_df(events)
    log_dir = str(Path(__file__).parent / '..' / 'logging')
    export_dir = str(ALERTS_DIR / 'interceptions')

    clean_df, intercepted = scan_alerts(
        df, log_dir=log_dir, export_dir=export_dir, source=str(folder)
    )

    print(f'\nResults: {len(df)} alerts scanned, '
          f'{len(intercepted)} intercepted, {len(clean_df)} clean')
    if intercepted:
        for report in intercepted:
            print(f'\n  INTERCEPTED: {report["alert_name"]} '
                  f'from {report["hostname"]}')
            for finding in report['findings']:
                print(f'    Rule: {finding["rule"]} | '
                      f'Field: {finding["field"]} | '
                      f'Matched: {finding["matched"]}')
    else:
        print('No injection indicators detected.')
    print(f'\nLog written to: {os.path.join(log_dir, "alert_filter.log")}')


def _run_on_test_data():
    """Run the filter on the test data folders with accuracy report."""
    clean_events = _parse_all_events(CLEAN_DIR)
    inject_events = _parse_all_events(INJECTION_DIR)
    all_events = clean_events + inject_events
    df = _make_df(all_events)

    log_dir = str(Path(__file__).parent / '..' / 'logging')
    export_dir = str(ALERTS_DIR / 'interceptions')
    source = f'{CLEAN_DIR}, {INJECTION_DIR}'

    clean_df, intercepted = scan_alerts(
        df, log_dir=log_dir, export_dir=export_dir, source=source
    )

    # Build per-alert accuracy results
    intercepted_hashes = {r['alert_hash'] for r in intercepted}
    clean_hashes = set(df['alert_hash']) - intercepted_hashes

    # Check clean alerts — should all pass (true negatives)
    clean_event_hashes = set(_make_df(clean_events)['alert_hash'])
    true_negatives = clean_event_hashes - intercepted_hashes
    false_positives = clean_event_hashes & intercepted_hashes

    # Check injection alerts — should all be caught (true positives)
    inject_event_hashes = set(_make_df(inject_events)['alert_hash'])
    true_positives = inject_event_hashes & intercepted_hashes
    false_negatives = inject_event_hashes - intercepted_hashes

    total = len(all_events)
    correct = len(true_positives) + len(true_negatives)
    accuracy = correct / total * 100 if total else 0

    # Console output
    print(f'Alert Filter Accuracy Report')
    print(f'  Clean folder:     {CLEAN_DIR}')
    print(f'  Injection folder: {INJECTION_DIR}')
    print(f'  Total alerts:     {total}')
    print(f'  True positives:   {len(true_positives)} '
          f'(injection correctly intercepted)')
    print(f'  True negatives:   {len(true_negatives)} '
          f'(clean correctly passed)')
    print(f'  False positives:  {len(false_positives)} '
          f'(clean incorrectly intercepted)')
    print(f'  False negatives:  {len(false_negatives)} '
          f'(injection incorrectly passed)')
    print(f'  Accuracy:         {accuracy:.1f}%')

    if false_positives:
        print(f'\n  False positives:')
        for h in false_positives:
            row = df[df['alert_hash'] == h].iloc[0]
            print(f'    {row.get("alert_name", "?")} — {h[:16]}...')

    if false_negatives:
        print(f'\n  False negatives:')
        for h in false_negatives:
            row = df[df['alert_hash'] == h].iloc[0]
            print(f'    {row.get("alert_name", "?")} — {h[:16]}...')

    if accuracy == 100:
        print(f'\n  PASS — all detections correct')
    else:
        print(f'\n  FAIL — {total - correct} errors')

    # Write accuracy report to log file
    log_path = Path(log_dir) / 'alert_filter.log'
    timestamp = __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f'[{timestamp}] [alert_filter] [ACCURACY]\n')
        f.write(f'  Clean folder:     {CLEAN_DIR}\n')
        f.write(f'  Injection folder: {INJECTION_DIR}\n')
        f.write(f'  Total: {total} | '
                f'TP: {len(true_positives)} | '
                f'TN: {len(true_negatives)} | '
                f'FP: {len(false_positives)} | '
                f'FN: {len(false_negatives)} | '
                f'Accuracy: {accuracy:.1f}%\n')
        if false_positives:
            for h in false_positives:
                row = df[df['alert_hash'] == h].iloc[0]
                f.write(f'  FP: {row.get("alert_name", "?")} — {h[:16]}...\n')
        if false_negatives:
            for h in false_negatives:
                row = df[df['alert_hash'] == h].iloc[0]
                f.write(f'  FN: {row.get("alert_name", "?")} — {h[:16]}...\n')

    print(f'\nLog written to: {log_path}')


if __name__ == '__main__':
    import io
    # Restore original stdout — the logger wraps it during import
    sys.stdout = io.TextIOWrapper(
        sys.__stdout__.buffer, encoding='utf-8', errors='replace'
    )

    usage = (
        'Usage: python tests/test_alert_filter.py <mode>\n'
        '  alerts   — scan real alerts in alerts/ folder\n'
        '  data     — scan test data with accuracy report\n'
        '  <path>   — scan a specific folder'
    )

    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)

    mode = sys.argv[1]
    if mode == 'data':
        _run_on_test_data()
    elif mode == 'alerts':
        alerts_dir = Path(__file__).parent / '..' / 'alerts'
        _run_on_alerts(alerts_dir)
    else:
        _run_on_alerts(mode)
