"""Tests for hash stability: CSV round-trips, tracking column exclusion, normalization."""

import pandas as pd
from data_layer.extract_alert_events import (
    generate_event_hash, _normalize_value, TRACKING_COLUMNS
)


class TestNormalizeValue:
    """Test _normalize_value for type consistency."""

    def test_int_and_float_same(self):
        assert _normalize_value(51696) == _normalize_value(51696.0)

    def test_string_float_same_as_int(self):
        assert _normalize_value('51696.0') == _normalize_value(51696)

    def test_string_int_same(self):
        assert _normalize_value('51696') == _normalize_value(51696)

    def test_true_float_preserved(self):
        assert _normalize_value(3.14) == '3.14'

    def test_nan_returns_none(self):
        assert _normalize_value(float('nan')) is None

    def test_none_returns_none(self):
        assert _normalize_value(None) is None

    def test_datetime_to_isoformat(self):
        ts = pd.Timestamp('2026-01-12 11:18:46')
        result = _normalize_value(ts)
        assert '2026-01-12' in result
        assert '11:18:46' in result

    def test_string_passthrough(self):
        assert _normalize_value('hello') == 'hello'


class TestHashStability:
    """Test that hashes are stable across CSV round-trips."""

    def test_hash_excludes_tracking_columns(self):
        """Changing tracking columns should not change the hash."""
        base = {'hostname': 'TEST', 'event': 'test', 'timestamp': '2026-01-01'}
        h1 = generate_event_hash(base)

        with_tracking = {**base, 'read': 'read|2026-01-01', 'severity': 'LOW',
                         'analysis': 'Looks fine', 'alert_status': 'open'}
        h2 = generate_event_hash(with_tracking)
        assert h1 == h2

    def test_hash_excludes_alert_hash(self):
        """The alert_hash field itself should not affect the hash."""
        base = {'hostname': 'TEST', 'event': 'test'}
        h1 = generate_event_hash(base)
        h2 = generate_event_hash({**base, 'alert_hash': 'abc123'})
        assert h1 == h2

    def test_hash_includes_data_columns(self):
        """Changing data columns should change the hash."""
        base = {'hostname': 'TEST', 'event': 'test'}
        h1 = generate_event_hash(base)
        h2 = generate_event_hash({**base, 'status': 'running'})
        assert h1 != h2

    def test_hash_stable_across_csv_roundtrip(self, sample_alerts_df, tmp_path):
        """Hash should be the same before and after CSV save/load."""
        csv_path = tmp_path / "test.csv"
        sample_alerts_df.to_csv(csv_path, index=False)
        reloaded = pd.read_csv(csv_path)
        reloaded['timestamp'] = pd.to_datetime(reloaded['timestamp'], errors='coerce')

        for idx in range(len(sample_alerts_df)):
            orig_hash = sample_alerts_df.iloc[idx]['alert_hash']
            reload_row = reloaded.iloc[idx].to_dict()
            reload_hash = generate_event_hash(reload_row)
            assert orig_hash == reload_hash, (
                f"Row {idx} hash mismatch after CSV round-trip: "
                f"{orig_hash[:12]} vs {reload_hash[:12]}"
            )

    def test_hash_ignores_nan_vs_missing(self):
        """A dict without a key and a dict with key=NaN should hash the same."""
        h1 = generate_event_hash({'hostname': 'TEST', 'event': 'test'})
        h2 = generate_event_hash({'hostname': 'TEST', 'event': 'test', 'extra': float('nan')})
        assert h1 == h2

    def test_hash_ignores_empty_string(self):
        h1 = generate_event_hash({'hostname': 'TEST', 'event': 'test'})
        h2 = generate_event_hash({'hostname': 'TEST', 'event': 'test', 'extra': ''})
        assert h1 == h2

    def test_hash_deterministic(self):
        data = {'hostname': 'TEST', 'event': 'test', 'pid': '123'}
        assert generate_event_hash(data) == generate_event_hash(data)

    def test_all_tracking_columns_excluded(self):
        """Verify the set matches expectations."""
        expected = {'alert_status', 'read', 'severity', 'analysis',
                    'analyzed_by', 'analyzed_at', 'alert_hash'}
        assert TRACKING_COLUMNS == expected
