"""
Alert Tracker - Two-phase read status tracking for alerts DataFrame.

States:
- None/NaN: Unread, ready to be processed
- "processing|{timestamp}": Currently being processed by an agent
- "read|{timestamp}": Successfully processed

Usage:
    from data_layer.alert_tracker import AlertTracker

    tracker = AlertTracker('exports/alert_events.csv')

    # Get unread alerts
    unread = tracker.get_unread_alerts()

    # Mark as processing before starting
    tracker.mark_processing(alert_hash)

    # After successful processing
    tracker.mark_read(alert_hash)

    # If processing failed, reset to unread
    tracker.mark_unread(alert_hash)

    # Recover stuck alerts (e.g., after crash)
    tracker.recover_stuck_alerts(timeout_minutes=30)
"""

import threading

import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
from logger import get_logger

logger = get_logger('alert_tracker')

ANALYSES_DIR = Path('exports/analyses')


def _short_hash(alert_hash):
    """Return first 8 chars of a hash for human-readable filenames."""
    return str(alert_hash)[:8]


def save_analysis_text(alert_hash, text):
    """Write analysis text to a per-alert file (named by short hash)."""
    ANALYSES_DIR.mkdir(parents=True, exist_ok=True)
    filepath = ANALYSES_DIR / f"{_short_hash(alert_hash)}.txt"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(text)


def load_analysis_text(alert_hash):
    """Read analysis text from a per-alert file. Returns None if not found."""
    short = _short_hash(alert_hash)
    filepath = ANALYSES_DIR / f"{short}.txt"
    if not filepath.exists():
        # Fall back to full-hash filename (legacy files)
        filepath = ANALYSES_DIR / f"{alert_hash}.txt"
        if not filepath.exists():
            return None
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()


FP_JOURNAL_PATH = Path('exports/false_positives.csv')
FP_COLUMNS = ['timestamp', 'alert_hash', 'alert_name', 'hostname', 'analyzed_by', 'reason']


def _extract_fp_reason(text):
    """Extract the sentence containing 'false positive' from analysis text."""
    import re
    # Split on sentence boundaries (period/newline followed by space or end)
    sentences = re.split(r'(?<=[.!?\n])\s+', text)
    for sentence in sentences:
        if 'false positive' in sentence.lower():
            # Clean up markdown/whitespace, truncate if very long
            reason = sentence.strip().strip('*#- ')
            if len(reason) > 200:
                reason = reason[:197] + '...'
            return reason
    return 'Classified as false positive'


def _log_false_positive(alert_hash, analysis_text, df, agent=None):
    """Append to FP journal if analysis contains a false positive classification.

    Args:
        alert_hash: The alert's hash
        analysis_text: Full analysis text from the analyst
        df: The alerts DataFrame (to look up alert_name/hostname)
        agent: Which agent made the classification
    """
    if 'false positive' not in analysis_text.lower():
        return

    # Look up alert metadata
    alert_name = 'Unknown'
    hostname = 'Unknown'
    mask = df['alert_hash'] == alert_hash
    if mask.any():
        row = df.loc[mask].iloc[0]
        alert_name = row.get('alert_name', 'Unknown')
        hostname = row.get('hostname', 'Unknown')

    reason = _extract_fp_reason(analysis_text)

    # Append to CSV (create with header if needed)
    FP_JOURNAL_PATH.parent.mkdir(parents=True, exist_ok=True)
    write_header = not FP_JOURNAL_PATH.exists()

    row_data = pd.DataFrame([{
        'timestamp': datetime.now().isoformat(),
        'alert_hash': alert_hash,
        'alert_name': alert_name,
        'hostname': hostname,
        'analyzed_by': agent or '',
        'reason': reason,
    }])
    row_data.to_csv(FP_JOURNAL_PATH, mode='a', header=write_header, index=False)
    logger.info(f"FP journal: logged {alert_hash[:16]} ({alert_name})")


def backfill_fp_journal(csv_path='exports/alert_events.csv'):
    """Scan existing analysis files and populate FP journal for any containing 'false positive'.

    Safe to run multiple times — skips hashes already in the journal.
    """
    # Load existing journal hashes to avoid duplicates
    existing_hashes = set()
    if FP_JOURNAL_PATH.exists():
        existing = pd.read_csv(FP_JOURNAL_PATH)
        existing_hashes = set(existing['alert_hash'].tolist())

    # Load alert metadata
    csv_file = Path(csv_path)
    if not csv_file.exists():
        logger.warning(f"Cannot backfill: {csv_path} not found")
        return 0

    df = pd.read_csv(csv_file)

    count = 0
    for filepath in ANALYSES_DIR.glob('*.txt'):
        short = filepath.stem
        # Resolve short hash to full hash from the DataFrame
        full_hash = _resolve_full_hash(df, short)
        if full_hash is None:
            continue
        if full_hash in existing_hashes:
            continue

        text = filepath.read_text(encoding='utf-8')
        if 'false positive' not in text.lower():
            continue

        _log_false_positive(full_hash, text, df,
                            agent=_lookup_agent(df, full_hash))
        count += 1

    logger.info(f"FP journal backfill: added {count} entries")
    return count


def _resolve_full_hash(df, short_hash):
    """Resolve a short hash prefix to a full alert_hash from the DataFrame."""
    if 'alert_hash' not in df.columns:
        return None
    mask = df['alert_hash'].str.startswith(short_hash, na=False)
    if mask.any():
        return str(df.loc[mask].iloc[0]['alert_hash'])
    return None


def _lookup_agent(df, alert_hash):
    """Look up analyzed_by for a hash from the DataFrame."""
    if 'analyzed_by' not in df.columns:
        return ''
    mask = df['alert_hash'] == alert_hash
    if mask.any():
        return str(df.loc[mask].iloc[0].get('analyzed_by', ''))
    return ''


class AlertTracker:
    """
    Manages two-phase read status tracking for alerts.

    Persists changes to CSV after each status update to ensure
    crash recovery is possible.
    """

    def __init__(self, csv_path: str):
        """
        Initialize the tracker with path to alerts CSV.

        Args:
            csv_path: Path to the alert_events.csv file
        """
        self.csv_path = Path(csv_path)
        self.df = None
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        """Load the alerts DataFrame from CSV."""
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Alerts file not found: {self.csv_path}")

        self.df = pd.read_csv(self.csv_path)

        # Convert timestamp to datetime
        if 'timestamp' in self.df.columns:
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], errors='coerce')

        # Migrate old tracking values from 'status' column to 'alert_status'.
        # The 'status' column may contain BOTH tracking values (open/closed)
        # AND event data (ESTABLISHED, running, stopped). We only move tracking
        # values to 'alert_status' and preserve event data in 'status'.
        TRACKING_VALUES = {'open', 'closed', 'processing', 'read', 'unread'}
        if 'status' in self.df.columns:
            if 'alert_status' not in self.df.columns:
                self.df['alert_status'] = None
                is_tracking = self.df['status'].astype(str).str.strip().str.lower().isin(TRACKING_VALUES)
                self.df.loc[is_tracking, 'alert_status'] = self.df.loc[is_tracking, 'status']
                self.df.loc[is_tracking, 'status'] = None
            else:
                needs_fill = self.df['alert_status'].isna() | (self.df['alert_status'] == '')
                is_tracking = self.df['status'].astype(str).str.strip().str.lower().isin(TRACKING_VALUES)
                fill_mask = needs_fill & is_tracking
                self.df.loc[fill_mask, 'alert_status'] = self.df.loc[fill_mask, 'status']
                self.df.loc[is_tracking, 'status'] = None

        # Identity-based dedup: catches duplicate events where one copy has
        # more data than the other (e.g., one missing 'status' due to old code).
        # Keeps the row with the most non-null data + tracking info.
        IDENTITY_COLS = [
            'timestamp', 'alert_name', 'hostname', 'event',
            'servicename', 'pdo', 'process', 'processid', 'pid',
            'sourceip', 'sourceport', 'destinationip', 'destinationport',
        ]
        id_cols = [c for c in IDENTITY_COLS if c in self.df.columns]
        before = len(self.df)

        def _row_quality(row):
            score = 0
            _tracking = {'alert_status', 'read', 'severity', 'analysis',
                         'analyzed_by', 'analyzed_at', 'alert_hash'}
            if pd.notna(row.get('analysis')) and str(row.get('analysis', '')).strip():
                score += 100
            if pd.notna(row.get('severity')) and str(row.get('severity', '')).strip():
                score += 50
            if pd.notna(row.get('read')) and str(row.get('read', '')).strip():
                score += 25
            for col in row.index:
                if col in _tracking or col.startswith('_'):
                    continue
                if pd.notna(row[col]) and str(row[col]).strip():
                    score += 1
            return score

        self.df['_quality'] = self.df.apply(_row_quality, axis=1)
        self.df = self.df.sort_values('_quality', ascending=False)
        self.df = self.df.drop_duplicates(subset=id_cols, keep='first')
        self.df = self.df.drop(columns=['_quality'])
        if len(self.df) < before:
            logger.info(f"  Dedup: {before} -> {len(self.df)} rows")

        # Ensure 'read' column exists and is object type (for mixed None/string values)
        if 'read' not in self.df.columns:
            self.df['read'] = None
        self.df['read'] = self.df['read'].astype(object)

        logger.info(f"Loaded {len(self.df)} alerts from {self.csv_path}")

    def _save(self):
        """Save the DataFrame back to CSV."""
        self.df.to_csv(self.csv_path, index=False)

    def reload(self):
        """Reload the DataFrame from disk (useful if file was modified externally)."""
        with self._lock:
            self._load()

    def get_unread_alerts(self, limit: int = None) -> pd.DataFrame:
        """
        Get alerts that have not been read (read is None/NaN) and are not closed.

        Args:
            limit: Maximum number of alerts to return (None for all)

        Returns:
            DataFrame of unread, open alerts
        """
        mask = self.df['read'].isna()

        # Exclude closed alerts
        if 'alert_status' in self.df.columns:
            mask = mask & (self.df['alert_status'] != 'closed')

        unread = self.df[mask]

        if limit:
            unread = unread.head(limit)

        return unread.copy()

    def get_processing_alerts(self) -> pd.DataFrame:
        """
        Get alerts currently in 'processing' state.

        Returns:
            DataFrame of alerts being processed
        """
        mask = self.df['read'].fillna('').str.startswith('processing|')
        return self.df[mask].copy()

    def get_read_alerts(self) -> pd.DataFrame:
        """
        Get alerts that have been successfully read.

        Returns:
            DataFrame of read alerts
        """
        mask = self.df['read'].fillna('').str.startswith('read|')
        return self.df[mask].copy()

    def mark_processing(self, alert_hash: str) -> bool:
        """
        Mark an alert as 'processing' (phase 1).

        Args:
            alert_hash: The alert_hash of the alert to mark

        Returns:
            True if successful, False if alert not found
        """
        with self._lock:
            mask = self.df['alert_hash'] == alert_hash

            if not mask.any():
                logger.warning(f"Alert not found: {alert_hash}")
                return False

            timestamp = datetime.now().isoformat()
            self.df.loc[mask, 'read'] = f"processing|{timestamp}"
            self._save()

            return True

    def mark_processing_batch(self, alert_hashes: list) -> int:
        """
        Mark multiple alerts as 'processing' (phase 1).

        Args:
            alert_hashes: List of alert_hash values to mark

        Returns:
            Number of alerts marked
        """
        with self._lock:
            mask = self.df['alert_hash'].isin(alert_hashes)
            count = mask.sum()

            if count > 0:
                timestamp = datetime.now().isoformat()
                self.df.loc[mask, 'read'] = f"processing|{timestamp}"
                self._save()

            return count

    def mark_read(self, alert_hash: str) -> bool:
        """
        Mark an alert as 'read' (phase 2 - successful processing).

        Args:
            alert_hash: The alert_hash of the alert to mark

        Returns:
            True if successful, False if alert not found
        """
        with self._lock:
            mask = self.df['alert_hash'] == alert_hash

            if not mask.any():
                logger.warning(f"Alert not found: {alert_hash}")
                return False

            timestamp = datetime.now().isoformat()
            self.df.loc[mask, 'read'] = f"read|{timestamp}"
            self._save()

            return True

    def mark_read_batch(self, alert_hashes: list) -> int:
        """
        Mark multiple alerts as 'read' (phase 2).

        Args:
            alert_hashes: List of alert_hash values to mark

        Returns:
            Number of alerts marked
        """
        with self._lock:
            mask = self.df['alert_hash'].isin(alert_hashes)
            count = mask.sum()

            if count > 0:
                timestamp = datetime.now().isoformat()
                self.df.loc[mask, 'read'] = f"read|{timestamp}"
                self._save()

            return count

    def mark_unread(self, alert_hash: str) -> bool:
        """
        Reset an alert to unread (e.g., if processing failed).

        Args:
            alert_hash: The alert_hash of the alert to reset

        Returns:
            True if successful, False if alert not found
        """
        with self._lock:
            mask = self.df['alert_hash'] == alert_hash

            if not mask.any():
                logger.warning(f"Alert not found: {alert_hash}")
                return False

            self.df.loc[mask, 'read'] = None
            self._save()

            return True

    def mark_closed(self, alert_hash: str) -> bool:
        """
        Close an alert so it won't be analyzed or shown again.

        Args:
            alert_hash: The alert_hash of the alert to close

        Returns:
            True if successful, False if alert not found
        """
        with self._lock:
            mask = self.df['alert_hash'] == alert_hash

            if not mask.any():
                logger.warning(f"Alert not found: {alert_hash}")
                return False

            if 'alert_status' not in self.df.columns:
                self.df['alert_status'] = 'open'

            self.df.loc[mask, 'alert_status'] = 'closed'
            self._save()
            logger.info(f"Closed alert: {alert_hash}")
            return True

    def mark_open(self, alert_hash: str) -> bool:
        """
        Reopen a closed alert.

        Args:
            alert_hash: The alert_hash of the alert to reopen

        Returns:
            True if successful, False if alert not found
        """
        with self._lock:
            mask = self.df['alert_hash'] == alert_hash

            if not mask.any():
                logger.warning(f"Alert not found: {alert_hash}")
                return False

            if 'alert_status' not in self.df.columns:
                self.df['alert_status'] = 'open'

            self.df.loc[mask, 'alert_status'] = 'open'
            self._save()
            logger.info(f"Reopened alert: {alert_hash}")
            return True

    def recover_stuck_alerts(self, timeout_minutes: int = 30) -> int:
        """
        Reset alerts stuck in 'processing' state back to unread.

        This handles crash recovery - if an agent crashed while processing,
        alerts may be left in 'processing' state indefinitely.

        Args:
            timeout_minutes: Consider alerts stuck if processing started
                           more than this many minutes ago

        Returns:
            Number of alerts recovered
        """
        with self._lock:
            cutoff = datetime.now() - timedelta(minutes=timeout_minutes)

            read_col = self.df['read'].fillna('')
            processing_mask = read_col.str.startswith('processing|')
            if not processing_mask.any():
                return 0

            # Extract timestamps from "processing|{timestamp}" values
            ts_strings = read_col[processing_mask].str.split('|', n=1).str[1]
            timestamps = pd.to_datetime(ts_strings, errors='coerce')

            # Build mask of stuck alerts (processing started before cutoff)
            stuck_within = timestamps < cutoff
            stuck_mask = processing_mask.copy()
            stuck_mask[processing_mask] = stuck_within.fillna(False)

            recovered = int(stuck_mask.sum())
            if recovered > 0:
                for alert_hash in self.df.loc[stuck_mask, 'alert_hash']:
                    logger.info(f"Recovered stuck alert: {alert_hash}")
                self.df.loc[stuck_mask, 'read'] = None
                self._save()
                logger.info(f"Recovered {recovered} stuck alerts")

            return recovered

    def get_stats(self) -> dict:
        """
        Get statistics about alert read status.

        Returns:
            Dictionary with counts for each status
        """
        total = len(self.df)
        unread = self.df['read'].isna().sum()
        processing = self.df['read'].fillna('').str.startswith('processing|').sum()
        read = self.df['read'].fillna('').str.startswith('read|').sum()
        closed = 0
        if 'alert_status' in self.df.columns:
            closed = (self.df['alert_status'] == 'closed').sum()

        return {
            'total': total,
            'unread': unread,
            'processing': processing,
            'read': read,
            'closed': closed
        }

    def print_stats(self):
        """Print a summary of alert status."""
        stats = self.get_stats()
        logger.info(f"Alert Status: {stats['unread']} unread, {stats['processing']} processing, {stats['read']} read (total: {stats['total']})")

    def save_analysis(self, alert_hash: str, severity: str, analysis: str, agent: str = None) -> bool:
        """
        Save analysis results for an alert.

        Args:
            alert_hash: The alert_hash of the alert
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN)
            analysis: Full analysis text from the analyst
            agent: Which agent performed the analysis (alert_analyst, new_analyst)

        Returns:
            True if successful, False if alert not found
        """
        # Write analysis file outside lock (independent per hash, no contention)
        save_analysis_text(alert_hash, analysis)

        with self._lock:
            mask = self.df['alert_hash'] == alert_hash

            if not mask.any():
                logger.warning(f"Alert not found for analysis save: {alert_hash}")
                return False

            # Ensure columns exist
            if 'severity' not in self.df.columns:
                self.df['severity'] = None
            if 'analysis' not in self.df.columns:
                self.df['analysis'] = None
            if 'analyzed_by' not in self.df.columns:
                self.df['analyzed_by'] = None
            if 'analyzed_at' not in self.df.columns:
                self.df['analyzed_at'] = None

            # Log to FP journal if classified as false positive
            _log_false_positive(alert_hash, analysis, self.df, agent)

            # Store 'file' flag in DataFrame (not the full text)
            self.df.loc[mask, 'severity'] = severity
            self.df.loc[mask, 'analysis'] = 'file'
            if agent:
                self.df.loc[mask, 'analyzed_by'] = agent
            self.df.loc[mask, 'analyzed_at'] = datetime.now().isoformat()

            self._save()
            return True

    def get_analysis(self, alert_hash: str) -> dict:
        """
        Get analysis results for an alert.

        Args:
            alert_hash: The alert_hash of the alert

        Returns:
            Dictionary with severity, analysis, analyzed_by, analyzed_at or None
        """
        mask = self.df['alert_hash'] == alert_hash

        if not mask.any():
            return None

        row = self.df[mask].iloc[0]
        analysis = row.get('analysis')
        if analysis == 'file':
            analysis = load_analysis_text(alert_hash)
        return {
            'severity': row.get('severity'),
            'analysis': analysis,
            'analyzed_by': row.get('analyzed_by'),
            'analyzed_at': row.get('analyzed_at')
        }


# Convenience functions for simple usage without instantiating the class

_default_path = 'exports/alert_events.csv'

def get_unread_alerts(csv_path: str = _default_path, limit: int = None) -> pd.DataFrame:
    """Get unread alerts from the CSV file."""
    tracker = AlertTracker(csv_path)
    return tracker.get_unread_alerts(limit)

def mark_processing(alert_hash: str, csv_path: str = _default_path) -> bool:
    """Mark a single alert as processing."""
    tracker = AlertTracker(csv_path)
    return tracker.mark_processing(alert_hash)

def mark_read(alert_hash: str, csv_path: str = _default_path) -> bool:
    """Mark a single alert as read."""
    tracker = AlertTracker(csv_path)
    return tracker.mark_read(alert_hash)

def recover_stuck(timeout_minutes: int = 30, csv_path: str = _default_path) -> int:
    """Recover alerts stuck in processing state."""
    tracker = AlertTracker(csv_path)
    return tracker.recover_stuck_alerts(timeout_minutes)
