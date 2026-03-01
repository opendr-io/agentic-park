"""Tests for analyst tools: query_new_services, query_new_drivers."""

import json
import pandas as pd
import pytest
import tools.state as state
from tools.query_new_services import query_new_services
from tools.query_new_drivers import query_new_drivers


@pytest.fixture(autouse=True)
def set_state(sample_new_df):
    """Set the global NEW_DF state for tool queries."""
    old = state.NEW_DF
    state.NEW_DF = sample_new_df
    yield
    state.NEW_DF = old


class TestQueryNewServices:

    def test_returns_services(self):
        result = json.loads(query_new_services())
        assert result['count'] == 2
        names = [e['servicename'] for e in result['events']]
        assert 'VM3DService' in names
        assert 'vmvss' in names

    def test_filter_by_servicename(self):
        result = json.loads(query_new_services(servicename='VM3D'))
        assert result['count'] == 1
        assert result['events'][0]['servicename'] == 'VM3DService'

    def test_filter_by_status(self):
        result = json.loads(query_new_services(status='running'))
        assert result['count'] == 1
        assert result['events'][0]['servicename'] == 'VM3DService'

    def test_filter_by_hostname(self):
        result = json.loads(query_new_services(hostname='DESKTOP-TEST'))
        assert result['count'] == 2

    def test_no_match(self):
        result = json.loads(query_new_services(servicename='nonexistent'))
        assert result['count'] == 0

    def test_service_fields_present(self):
        result = json.loads(query_new_services())
        event = result['events'][0]
        for field in ['timestamp', 'hostname', 'event', 'servicename',
                      'displayname', 'start', 'executable', 'sid']:
            assert field in event

    def test_limit(self):
        result = json.loads(query_new_services(limit=1))
        assert result['count'] == 1
        assert result['total_matching'] == 2

    def test_no_data(self):
        state.NEW_DF = None
        result = json.loads(query_new_services())
        assert 'error' in result


class TestQueryNewDrivers:

    def test_returns_drivers(self):
        result = json.loads(query_new_drivers())
        assert result['count'] == 1

    def test_driver_fields_present(self):
        result = json.loads(query_new_drivers())
        event = result['events'][0]
        for field in ['timestamp', 'hostname', 'event', 'desc', 'signer',
                      'device_id', 'driver_version', 'is_signed', 'pdo', 'sid']:
            assert field in event

    def test_filter_by_signer(self):
        result = json.loads(query_new_drivers(signer='Microsoft'))
        assert result['count'] == 1

    def test_filter_by_desc(self):
        result = json.loads(query_new_drivers(desc='Non-PnP'))
        assert result['count'] == 1

    def test_filter_no_match(self):
        result = json.loads(query_new_drivers(signer='Unknown Vendor'))
        assert result['count'] == 0

    def test_no_data(self):
        state.NEW_DF = None
        result = json.loads(query_new_drivers())
        assert 'error' in result


class TestAlertTrackerDedup:
    """Test that AlertTracker deduplicates on load."""

    def test_tracker_dedup(self, sample_alerts_df, tmp_path):
        """AlertTracker should deduplicate rows with different data completeness."""
        from data_layer.alert_tracker import AlertTracker
        from data_layer.extract_alert_events import generate_event_hash

        df = sample_alerts_df.copy()
        # Create incomplete duplicate
        incomplete = df.iloc[0:1].copy()
        incomplete['status'] = None
        incomplete['alert_hash'] = incomplete.apply(
            lambda row: generate_event_hash(row.to_dict()), axis=1
        )
        df = pd.concat([df, incomplete], ignore_index=True)

        csv_path = tmp_path / "test.csv"
        df.to_csv(csv_path, index=False)

        tracker = AlertTracker(str(csv_path))
        assert len(tracker.df) == len(sample_alerts_df)
