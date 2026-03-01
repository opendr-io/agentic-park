"""Tests for deduplication and merge: identity dedup, data repair, tracking preservation."""

import pandas as pd
from data_layer.extract_alert_events import (
    generate_event_hash, merge_alerts, load_existing_alerts, TRACKING_COLUMNS
)


class TestIdentityDedup:
    """Test that load_existing_alerts deduplicates by identity columns."""

    def test_dedup_removes_incomplete_duplicates(self, sample_alerts_df, tmp_path):
        """When a row exists with and without 'status', keep the one with status."""
        df = sample_alerts_df.copy()

        # Create a duplicate of the first service row but without status
        services = df[df['event'].str.contains('new service', case=False, na=False)]
        assert len(services) == 2

        incomplete = services.iloc[0:1].copy()
        incomplete['status'] = None
        incomplete['alert_hash'] = incomplete.apply(
            lambda row: generate_event_hash(row.to_dict()), axis=1
        )

        # Append incomplete duplicate
        df = pd.concat([df, incomplete], ignore_index=True)
        assert len(df) == 5  # 4 original + 1 incomplete dupe

        # Save and reload through load_existing_alerts
        csv_path = tmp_path / "test.csv"
        df.to_csv(csv_path, index=False)
        result = load_existing_alerts(str(csv_path))

        # Should be back to 4 (incomplete dupe removed)
        assert len(result) == 4
        # The kept service row should have status populated
        svc = result[result['event'].str.contains('new service', case=False, na=False)]
        for _, row in svc.iterrows():
            assert pd.notna(row.get('status')), f"Service {row['servicename']} lost status"

    def test_dedup_preserves_tracking_data(self, sample_alerts_df, tmp_path):
        """When deduplicating, prefer the row with analysis/severity."""
        df = sample_alerts_df.copy()

        # Add analysis to first row
        df.loc[0, 'severity'] = 'LOW'
        df.loc[0, 'analysis'] = 'Looks benign'
        df.loc[0, 'read'] = 'read|2026-01-01'

        # Create a duplicate of row 0 with more complete data but no tracking
        better_data = df.iloc[0:1].copy()
        better_data['severity'] = None
        better_data['analysis'] = None
        better_data['read'] = None
        better_data['extra_field'] = 'bonus'
        better_data['alert_hash'] = better_data.apply(
            lambda row: generate_event_hash(row.to_dict()), axis=1
        )
        df = pd.concat([df, better_data], ignore_index=True)

        csv_path = tmp_path / "test.csv"
        df.to_csv(csv_path, index=False)
        result = load_existing_alerts(str(csv_path))

        # The kept row should have the tracking data (analysis is worth more)
        kept = result.iloc[0]
        assert kept['analysis'] == 'Looks benign'
        assert kept['severity'] == 'LOW'


class TestMergeAlerts:
    """Test merge_alerts: data repair, dedup, new event detection."""

    def test_no_duplicates_on_identical_data(self, sample_alerts_df):
        """Merging identical data should not add duplicates."""
        fresh = sample_alerts_df.copy()
        existing = sample_alerts_df.copy()
        result = merge_alerts(existing, fresh)
        assert len(result) == len(sample_alerts_df)

    def test_truly_new_events_added(self, sample_alerts_df):
        """A genuinely new event should be added."""
        existing = sample_alerts_df.copy()
        fresh = sample_alerts_df.copy()

        # Add a new event to fresh
        new_event = {
            'timestamp': pd.Timestamp('2026-02-01'),
            'hostname': 'NEW-HOST',
            'event': 'new service',
            'servicename': 'NewService',
            'alert_name': 'New Alert',
            'alert_status': 'open',
        }
        new_event['alert_hash'] = generate_event_hash(new_event)
        new_row = pd.DataFrame([new_event])
        fresh = pd.concat([fresh, new_row], ignore_index=True)

        result = merge_alerts(existing, fresh)
        assert len(result) == len(sample_alerts_df) + 1

    def test_data_repair_fills_missing_status(self, sample_alerts_df):
        """If existing row is missing 'status' but fresh has it, fill it in."""
        existing = sample_alerts_df.copy()
        # Remove status from existing
        existing['status'] = None
        # Regenerate hashes (they'll differ now)
        existing['alert_hash'] = existing.apply(
            lambda row: generate_event_hash(row.to_dict()), axis=1
        )

        fresh = sample_alerts_df.copy()
        result = merge_alerts(existing, fresh)

        # Should NOT add duplicates
        assert len(result) == len(sample_alerts_df)
        # Should have repaired the status
        services = result[result['event'].str.contains('new service', case=False, na=False)]
        for _, row in services.iterrows():
            if row['servicename'] == 'VM3DService':
                assert row['status'] == 'running'

    def test_merge_preserves_tracking(self, sample_alerts_df):
        """Merge should preserve read/analysis/severity from existing rows."""
        existing = sample_alerts_df.copy()
        existing.loc[0, 'read'] = 'read|2026-01-15'
        existing.loc[0, 'severity'] = 'MEDIUM'
        existing.loc[0, 'analysis'] = 'Benign activity'

        fresh = sample_alerts_df.copy()
        result = merge_alerts(existing, fresh)

        assert result.loc[0, 'read'] == 'read|2026-01-15'
        assert result.loc[0, 'severity'] == 'MEDIUM'
        assert result.loc[0, 'analysis'] == 'Benign activity'

    def test_merge_none_existing(self, sample_alerts_df):
        """If existing is None, return fresh as-is."""
        result = merge_alerts(None, sample_alerts_df)
        assert len(result) == len(sample_alerts_df)


class TestFullPipelineStability:
    """Test that the full extract pipeline produces stable results."""

    def test_idempotent_extract(self, sample_alerts_df, tmp_path):
        """Running load → merge → save twice should produce identical results."""
        csv_path = tmp_path / "test.csv"
        sample_alerts_df.to_csv(csv_path, index=False)

        # Run 1
        existing1 = load_existing_alerts(str(csv_path))
        fresh1 = sample_alerts_df.copy()
        result1 = merge_alerts(existing1, fresh1)
        result1.to_csv(csv_path, index=False)
        count1 = len(result1)

        # Run 2
        existing2 = load_existing_alerts(str(csv_path))
        fresh2 = sample_alerts_df.copy()
        result2 = merge_alerts(existing2, fresh2)
        count2 = len(result2)

        assert count1 == count2 == len(sample_alerts_df)
