"""
Background Alert Processor
Runs alert analysis in a background thread, sending high-severity
alerts to the main agent via message queue.
"""
import os
import re
import json
import time
import threading
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# Import routing rules from router (avoid duplication)
ROUTING_RULES = {
    'new_analyst': [
        r'new\s+service',
        r'new\s+driver',
        r'new\s+autorun',
        r'new\s+scheduled\s+task',
        r'persistence',
        r'startup',
        r'registry\s+run',
    ],
    'alert_analyst': [
        r'internet\s+activity',
        r'network',
        r'connection',
        r'shell',
        r'powershell',
        r'cmd\.exe',
        r'suspicious',
        r'malware',
        r'exploit',
        r'injection',
        r'lateral',
        r'credential',
        r'exfil',
    ]
}

COMPILED_RULES = {
    agent: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for agent, patterns in ROUTING_RULES.items()
}

# Priority patterns
PRIORITY_PATTERNS = {
    'CRITICAL': [
        r'critical', r'ransomware', r'c2\b', r'command\s*and\s*control',
        r'beacon', r'cobalt', r'mimikatz', r'credential\s*dump',
        r'lateral\s*movement', r'privilege\s*escalation', r'rootkit',
    ],
    'HIGH': [
        r'malware', r'exploit', r'injection',
        r'reverse\s*shell', r'backdoor', r'exfil', r'data\s*theft',
        r'suspicious.*powershell', r'encoded\s*command', r'obfuscated',
        r'shelled\s*out',
    ],
    'MEDIUM': [
        r'internet\s+activity', r'new\s+service', r'new\s+driver', r'new\s+autorun',
        r'persistence', r'scheduled\s+task', r'unusual', r'anomal',
        r'suspicious',
    ],
}

COMPILED_PRIORITY = {
    priority: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for priority, patterns in PRIORITY_PATTERNS.items()
}

PRIORITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}


class BackgroundAlertProcessor:
    """
    Processes alerts in the background, sending notifications to main agent.
    """

    def __init__(self, message_queue, alerts_df=None, new_df=None, events_df=None):
        """
        Initialize the background processor.

        Args:
            message_queue: Queue to send messages to main agent
            alerts_df: DataFrame with security alerts
            new_df: DataFrame with behavioral anomaly events
            events_df: DataFrame with full event stream
        """
        self.message_queue = message_queue
        self.alerts_df = alerts_df
        self.new_df = new_df
        self.events_df = events_df

        self.thread = None
        self.running = False
        self._fatal_error = threading.Event()
        self.stats = {
            'processed': 0,
            'errors': 0,
            'high_severity': 0,
            'high_severity_alerts': [],
        }

        # Set up logging
        self.log_file = Path('logging/background_processor.log')
        self.log_file.parent.mkdir(exist_ok=True)

        # Import modules lazily
        self._alert_analyst = None
        self._new_analyst = None
        self._tracker = None

        self._log("Background processor initialized")

    def _log(self, message, level='INFO'):
        """Write timestamped log entry."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"

        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')

    def _get_tracker(self):
        """Lazy load alert tracker."""
        if self._tracker is None:
            from data_layer.alert_tracker import AlertTracker
            try:
                self._tracker = AlertTracker('exports/alert_events.csv')
            except FileNotFoundError:
                self._log("Alert events file not found", 'WARNING')
                return None
        return self._tracker

    def _get_alert_analyst(self):
        """Lazy load alert analyst."""
        if self._alert_analyst is None:
            from agents import run_alert_analyst
            import tools.state as tool_state
            self._alert_analyst = run_alert_analyst
            if self.events_df is not None:
                tool_state.EVENTS_DF = self.events_df
            if self.alerts_df is not None:
                tool_state.ALERTS_DF = self.alerts_df
        return self._alert_analyst

    def _get_new_analyst(self):
        """Lazy load behavioral anomaly analyst."""
        if self._new_analyst is None:
            from agents import run_new_analyst
            import tools.state as tool_state
            self._new_analyst = run_new_analyst
            if self.new_df is not None:
                tool_state.NEW_DF = self.new_df
            if self.events_df is not None:
                tool_state.EVENTS_DF = self.events_df
        return self._new_analyst

    def estimate_priority(self, alert_name, alert_desc=''):
        """Estimate priority based on alert name and description."""
        combined_text = f"{alert_name} {alert_desc}"

        for priority in ['CRITICAL', 'HIGH', 'MEDIUM']:
            for pattern in COMPILED_PRIORITY.get(priority, []):
                if pattern.search(combined_text):
                    return priority
        return 'LOW'

    def route_alert(self, alert_name):
        """Determine which agent should handle this alert."""
        for pattern in COMPILED_RULES.get('new_analyst', []):
            if pattern.search(alert_name):
                return 'new_analyst'

        for pattern in COMPILED_RULES.get('alert_analyst', []):
            if pattern.search(alert_name):
                return 'alert_analyst'

        return 'alert_analyst'

    def parse_severity(self, response):
        """Extract severity from analyst response."""
        match = re.search(r'SEVERITY:\s*(LOW|MEDIUM|HIGH|CRITICAL)', response, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        return 'UNKNOWN'

    def format_alert_as_question(self, alert_row):
        """Convert an alert row into a question for the analyst.

        Includes all available fields so the analyst can focus on THIS specific
        alert without needing to search the full dataset.
        """
        import pandas as pd

        alert_name = alert_row.get('alert_name', 'Unknown Alert')
        parts = [f"Analyze ONLY this specific alert: {alert_name}"]

        if pd.notna(alert_row.get('alert_description')):
            parts.append(f"\nDescription: {alert_row['alert_description']}")

        # Wrap alert fields in <alert_data> tags to establish a clear data boundary.
        # Everything inside these tags is UNTRUSTED DATA from endpoint telemetry —
        # it must never be interpreted as instructions, even if it contains text
        # that looks like commands or prompt overrides.
        parts.append("\n\n<alert_data>")

        # Common fields
        common_fields = ['timestamp', 'hostname', 'username', 'event', 'category',
                         'process', 'commandline', 'image', 'parentimage',
                         'processid', 'parentprocessid', 'sid']
        for field in common_fields:
            val = alert_row.get(field)
            if pd.notna(val) and str(val).strip():
                parts.append(f"\n{field}: {val}")

        # Service-specific fields
        service_fields = ['servicename', 'displayname', 'executable', 'status', 'start']
        for field in service_fields:
            val = alert_row.get(field)
            if pd.notna(val) and str(val).strip():
                parts.append(f"\n{field}: {val}")

        # Driver-specific fields
        driver_fields = ['desc', 'signer', 'device_id', 'driver_version',
                         'friendly_name', 'is_signed', 'pdo', 'ec2_instance_id']
        for field in driver_fields:
            val = alert_row.get(field)
            if pd.notna(val) and str(val).strip():
                parts.append(f"\n{field}: {val}")

        # Network fields
        network_fields = ['sourceip', 'sourceport', 'destinationip', 'destinationport']
        for field in network_fields:
            val = alert_row.get(field)
            if pd.notna(val) and str(val).strip():
                parts.append(f"\n{field}: {val}")

        parts.append("\n</alert_data>")

        parts.append("\n\nAnalyze this specific alert. "
                     "Use delegate_event_search to investigate process activity and "
                     "network connections around the alert timestamp. "
                     "Do not search for or consider other alerts. "
                     "Include a SEVERITY rating (LOW, MEDIUM, HIGH, CRITICAL) at the end "
                     "in the format: SEVERITY: <level>")

        return ''.join(parts)

    def send_status(self, status_type, **kwargs):
        """Send status update to main agent."""
        self.message_queue.send(
            message_type=status_type,
            data=kwargs,
            sender='background_processor'
        )

    def send_high_severity_alert(self, alert_data):
        """Send a high-severity alert notification to main agent."""
        self.message_queue.send(
            message_type='HIGH_SEVERITY_ALERT',
            data=alert_data,
            sender='background_processor'
        )

    def _rescan_alert_folder(self):
        """
        Re-parse the alerts folder and append any truly new alerts to
        the shared alerts_df in-place.

        Returns:
            int: Number of new alerts added.
        """
        import pandas as pd
        from data_layer.extract_alert_events import parse_alert_folder, merge_alerts

        if self.alerts_df is None:
            return 0

        fresh_df = parse_alert_folder()
        if fresh_df is None or len(fresh_df) == 0:
            return 0

        # Use merge_alerts to identify truly new rows
        merged_df = merge_alerts(self.alerts_df, fresh_df)

        # Find rows whose alert_hash is not in the current DataFrame
        # or already intercepted by the filter
        existing_hashes = set(self.alerts_df['alert_hash'].tolist())
        import tools.state as tool_state
        if tool_state.INTERCEPTIONS_DF is not None and len(tool_state.INTERCEPTIONS_DF) > 0:
            existing_hashes |= set(tool_state.INTERCEPTIONS_DF['alert_hash'].tolist())
        new_rows = merged_df[~merged_df['alert_hash'].isin(existing_hashes)]

        if len(new_rows) == 0:
            return 0

        # Scan new alerts for prompt injection before adding to shared DataFrame
        from alert_filter import scan_alerts
        new_rows, intercepted = scan_alerts(new_rows)
        for report in intercepted:
            self._log(
                f"INTERCEPTED new alert {report['alert_hash'][:16]}... "
                f"({report['alert_name']}) during rescan",
                'WARNING'
            )

        if len(new_rows) == 0:
            return 0

        # Append new rows in-place to preserve the shared reference
        # (StatusAgent and BackgroundProcessor hold the same object)
        import tools.state as tool_state
        with tool_state.DF_LOCK:
            start_idx = self.alerts_df.index.max() + 1 if len(self.alerts_df) > 0 else 0
            new_rows = new_rows.reset_index(drop=True)
            new_rows.index = range(start_idx, start_idx + len(new_rows))
            for idx in new_rows.index:
                self.alerts_df.loc[idx] = new_rows.loc[idx]
            self.alerts_df.to_csv('exports/alert_events.csv', index=False)
        self._log(f"Saved {len(self.alerts_df)} alerts to exports/alert_events.csv")

        # Reload tracker so it sees new rows
        if self._tracker is not None:
            self._tracker.reload()

        # Notify status agent
        self.send_status('NEW_ALERTS_INGESTED',
                         new_count=len(new_rows),
                         total=len(self.alerts_df))

        return len(new_rows)

    def _process_queue(self, queue_df, agent_type, tracker, stats, total):
        """Process a queue of alerts with the specified agent type.

        Runs in its own thread. Uses per-thread `stats` dict to avoid races.
        The tracker and alerts_df mutations are protected by their own locks.
        """
        import tools.state as tool_state

        for idx, alert_row in queue_df.iterrows():
            if not self.running or self._fatal_error.is_set():
                break

            alert_hash = alert_row['alert_hash']
            alert_name = alert_row.get('alert_name', 'Unknown')

            try:
                tracker.mark_processing(alert_hash)
                self._log(f"[{agent_type}] Processing: {alert_name[:50]}...")

                question = self.format_alert_as_question(alert_row)

                if agent_type == 'alert_analyst':
                    analyst = self._get_alert_analyst()
                    response = analyst.answer_question(
                        question,
                        events_df=self.events_df,
                        alerts_df=self.alerts_df,
                        silent=True
                    )
                else:
                    analyst = self._get_new_analyst()
                    response = analyst.answer_question(question, self.new_df, silent=True)

                severity = self.parse_severity(response)
                self._log(f"[{agent_type}] Alert {alert_hash[:16]}... severity: {severity}")

                tracker.save_analysis(alert_hash, severity, response, agent_type)

                if self.alerts_df is not None:
                    with tool_state.DF_LOCK:
                        mask = self.alerts_df['alert_hash'] == alert_hash
                        if mask.any():
                            self.alerts_df.loc[mask, 'analysis'] = 'file'
                            self.alerts_df.loc[mask, 'severity'] = severity
                            self.alerts_df.loc[mask, 'analyzed_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                if severity in ('HIGH', 'CRITICAL'):
                    stats['high_severity'] += 1
                    stats['high_severity_alerts'].append({
                        'alert_name': alert_name,
                        'hostname': alert_row.get('hostname', '?'),
                        'severity': severity,
                    })
                    self.send_high_severity_alert({
                        'alert_hash': alert_hash,
                        'alert_name': alert_name,
                        'severity': severity,
                        'hostname': alert_row.get('hostname'),
                        'timestamp': str(alert_row.get('timestamp')),
                        'summary': response[:500] + '...' if len(response) > 500 else response
                    })

                tracker.mark_read(alert_hash)
                stats['processed'] += 1

                self.send_status('PROCESSING_STATUS',
                                 alert_processing='running',
                                 alerts_total=total,
                                 alerts_processed=stats['processed'],
                                 high_severity_count=stats['high_severity'])

            except Exception as e:
                error_str = str(e).lower()
                self._log(f"[{agent_type}] Error processing {alert_hash[:16]}...: {e}", 'ERROR')
                tracker.mark_unread(alert_hash)
                stats['errors'] += 1

                is_fatal = any(kw in error_str for kw in [
                    'credit', 'billing', 'insufficient', 'quota',
                    'authentication', 'invalid api key', 'unauthorized',
                ])
                if is_fatal:
                    self._fatal_error.set()
                    self._log(f"[{agent_type}] Fatal API error — stopping: {e}", 'ERROR')
                    self.send_status('API_ERROR',
                                     error=str(e),
                                     alerts_processed=stats['processed'],
                                     alerts_remaining=len(queue_df) - stats['processed'])
                    break

            # Sleep between alerts to stay within token rate limits
            remaining_in_queue = len(queue_df) - stats['processed']
            if self.running and remaining_in_queue > 0:
                self._log(f"[{agent_type}] Sleeping 30s before next alert (rate limiting)")
                for _ in range(30):
                    if not self.running:
                        break
                    time.sleep(1)

    def process_alerts(self):
        """Process all unread alerts.

        Partitions alerts by agent type (alert_analyst vs new_analyst) and
        processes both queues in parallel threads for faster throughput.
        """
        import pandas as pd
        from data_layer.alert_tracker import load_analysis_text

        tracker = self._get_tracker()
        if tracker is None:
            self._log("No tracker available, skipping alert processing", 'WARNING')
            return

        # Recover stuck alerts
        recovered = tracker.recover_stuck_alerts(timeout_minutes=30)
        if recovered > 0:
            self._log(f"Recovered {recovered} stuck alerts")

        # Get unread alerts
        unread = tracker.get_unread_alerts()

        if len(unread) == 0:
            self._log("No unread alerts to process")
            self.send_status('PROCESSING_COMPLETE', processed=0, high_severity=0)
            return

        # Reconcile: if analysis file exists on disk but CSV not updated, fix it
        # (e.g. API crash wrote the file but didn't update the CSV row)
        # Update tracker DataFrame directly — do NOT call save_analysis() which
        # would overwrite the existing analysis file.
        reconciled = 0
        for idx, row in unread.iterrows():
            h = row['alert_hash']
            if pd.isna(row.get('analysis')) and load_analysis_text(h) is not None:
                self._log(f"Reconciling orphaned analysis for {str(h)[:8]}")
                with tracker._lock:
                    mask = tracker.df['alert_hash'] == h
                    if mask.any():
                        tracker.df.loc[mask, 'analysis'] = 'file'
                        tracker.df.loc[mask, 'read'] = f"read|{datetime.now().isoformat()}"
                        tracker._save()
                # Also update the shared in-memory DataFrame
                if self.alerts_df is not None:
                    import tools.state as tool_state
                    with tool_state.DF_LOCK:
                        amask = self.alerts_df['alert_hash'] == h
                        if amask.any():
                            self.alerts_df.loc[amask, 'analysis'] = 'file'
                reconciled += 1
        if reconciled > 0:
            self._log(f"Reconciled {reconciled} orphaned analysis files")
            # Refresh unread list after reconciliation
            unread = tracker.get_unread_alerts()
            if len(unread) == 0:
                self._log("All alerts reconciled, nothing left to process")
                self.send_status('PROCESSING_COMPLETE', processed=0, high_severity=0)
                return

        # Scan for prompt injection before sending to agents
        from alert_filter import scan_alerts
        unread, intercepted = scan_alerts(unread)
        for report in intercepted:
            self._log(
                f"INTERCEPTED alert {report['alert_hash'][:16]}... "
                f"({report['alert_name']}) — "
                f"{len(report['findings'])} injection indicator(s)",
                'WARNING'
            )
            tracker.mark_read(report['alert_hash'])
            import tools.state as tool_state
            with tool_state.DF_LOCK:
                drop_idx = self.alerts_df[
                    self.alerts_df['alert_hash'] == report['alert_hash']
                ].index
                self.alerts_df.drop(drop_idx, inplace=True)

        if len(unread) == 0:
            self._log("All unread alerts were intercepted by sanitizer")
            self.send_status('PROCESSING_COMPLETE', processed=0, high_severity=0)
            return

        # Add priority and sort
        unread = unread.copy()
        unread['_priority'] = unread.apply(
            lambda r: self.estimate_priority(
                str(r.get('alert_name', '')),
                str(r.get('alert_description', ''))
            ), axis=1
        )
        unread['_priority_order'] = unread['_priority'].map(PRIORITY_ORDER)
        unread = unread.sort_values(
            by=['_priority_order', 'timestamp'],
            ascending=[False, True]
        )

        total = len(unread)

        # Partition by agent type
        unread['_agent_type'] = unread['alert_name'].apply(
            lambda name: self.route_alert(str(name)))
        _temp_cols = ['_agent_type', '_priority', '_priority_order']
        alert_batch = unread[unread['_agent_type'] == 'alert_analyst'].drop(columns=_temp_cols)
        new_batch = unread[unread['_agent_type'] == 'new_analyst'].drop(columns=_temp_cols)

        self._log(f"Processing {len(unread)} alerts: "
                  f"{len(alert_batch)} for alert_analyst, "
                  f"{len(new_batch)} for new_analyst")

        # Send initial status
        self.send_status('PROCESSING_STATUS',
                         alert_processing='running',
                         alerts_total=total,
                         alerts_processed=0)

        # Per-thread stats to avoid races
        alert_stats = {'processed': 0, 'errors': 0, 'high_severity': 0, 'high_severity_alerts': []}
        new_stats = {'processed': 0, 'errors': 0, 'high_severity': 0, 'high_severity_alerts': []}

        threads = []
        if len(alert_batch) > 0:
            t = threading.Thread(
                target=self._process_queue,
                args=(alert_batch, 'alert_analyst', tracker, alert_stats, total),
                name='alert-analyst-worker',
                daemon=True)
            threads.append(t)
        if len(new_batch) > 0:
            t = threading.Thread(
                target=self._process_queue,
                args=(new_batch, 'new_analyst', tracker, new_stats, total),
                name='new-analyst-worker',
                daemon=True)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Merge per-thread stats
        self.stats['processed'] = alert_stats['processed'] + new_stats['processed']
        self.stats['errors'] = alert_stats['errors'] + new_stats['errors']
        self.stats['high_severity'] = alert_stats['high_severity'] + new_stats['high_severity']
        self.stats['high_severity_alerts'] = (alert_stats['high_severity_alerts'] +
                                               new_stats['high_severity_alerts'])

        # Send completion status
        self.send_status('PROCESSING_COMPLETE',
                         alerts_processed=self.stats['processed'],
                         errors=self.stats['errors'],
                         high_severity_count=self.stats['high_severity'],
                         high_severity_alerts=self.stats['high_severity_alerts'])

        self._log(f"Background processing complete: {self.stats}")

    def _run(self):
        """Thread target: process alerts, then loop checking for new files."""
        RESCAN_INTERVAL = 120  # seconds between folder re-scans

        self.running = True
        try:
            while self.running:
                new_count = self._rescan_alert_folder()
                if new_count > 0:
                    self._log(f"Ingested {new_count} new alert(s) from file re-scan")

                self.process_alerts()

                # Sleep in 1s increments for clean shutdown
                for _ in range(RESCAN_INTERVAL):
                    if not self.running:
                        break
                    time.sleep(1)
        except Exception as e:
            self._log(f"Background processor error: {e}", 'ERROR')
        finally:
            self.running = False

    def start(self):
        """Start background processing in a new thread."""
        if self.thread and self.thread.is_alive():
            self._log("Background processor already running", 'WARNING')
            return

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self._log("Background processor started")

    def stop(self):
        """Stop background processing."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self._log("Background processor stopped")

    def is_running(self) -> bool:
        """Check if background processing is running."""
        return self.thread and self.thread.is_alive()
