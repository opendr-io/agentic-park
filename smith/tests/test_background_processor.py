"""Tests for background_processor.py — parse_severity, route_alert."""

import os
import sys
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from data_layer.background_processor import COMPILED_RULES


# parse_severity is a method on BackgroundProcessor, but we can test the regex directly
def parse_severity(response):
    """Extracted severity parser (same regex as BackgroundProcessor.parse_severity)."""
    match = re.search(r'SEVERITY:\s*(LOW|MEDIUM|HIGH|CRITICAL)', response, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return 'UNKNOWN'


def route_alert(alert_name):
    """Extracted router (same logic as BackgroundProcessor.route_alert)."""
    for pattern in COMPILED_RULES.get('new_analyst', []):
        if pattern.search(alert_name):
            return 'new_analyst'
    for pattern in COMPILED_RULES.get('alert_analyst', []):
        if pattern.search(alert_name):
            return 'alert_analyst'
    return 'alert_analyst'


class TestParseSeverity:
    def test_low(self):
        assert parse_severity('Analysis complete. SEVERITY: LOW') == 'LOW'

    def test_high(self):
        assert parse_severity('SEVERITY: HIGH\nDetails follow.') == 'HIGH'

    def test_critical(self):
        assert parse_severity('This is bad. SEVERITY: CRITICAL') == 'CRITICAL'

    def test_medium(self):
        assert parse_severity('SEVERITY: MEDIUM') == 'MEDIUM'

    def test_case_insensitive(self):
        assert parse_severity('severity: low') == 'LOW'

    def test_unknown_when_missing(self):
        assert parse_severity('No severity rating here.') == 'UNKNOWN'

    def test_unknown_for_empty(self):
        assert parse_severity('') == 'UNKNOWN'

    def test_extra_whitespace(self):
        assert parse_severity('SEVERITY:   HIGH') == 'HIGH'

    def test_embedded_in_markdown(self):
        assert parse_severity('**SEVERITY: CRITICAL**') == 'CRITICAL'


class TestRouteAlert:
    # New analyst routes
    def test_new_service(self):
        assert route_alert('New Service Installed') == 'new_analyst'

    def test_new_driver(self):
        assert route_alert('New Driver Detected') == 'new_analyst'

    def test_new_autorun(self):
        assert route_alert('New Autorun Entry') == 'new_analyst'

    def test_new_scheduled_task(self):
        assert route_alert('New Scheduled Task Created') == 'new_analyst'

    def test_persistence(self):
        assert route_alert('Persistence Mechanism') == 'new_analyst'

    # Alert analyst routes
    def test_internet_activity(self):
        assert route_alert('Sublime Text Internet Activity') == 'alert_analyst'

    def test_network(self):
        assert route_alert('Suspicious Network Connection') == 'alert_analyst'

    def test_shell(self):
        assert route_alert('Python Shelled Out') == 'alert_analyst'

    def test_powershell(self):
        assert route_alert('PowerShell Execution') == 'alert_analyst'

    def test_malware(self):
        assert route_alert('Possible Malware Activity') == 'alert_analyst'

    # Default
    def test_unknown_defaults_to_alert_analyst(self):
        assert route_alert('Something Completely Unrelated') == 'alert_analyst'

    # Case insensitive
    def test_case_insensitive(self):
        assert route_alert('NEW SERVICE created') == 'new_analyst'
