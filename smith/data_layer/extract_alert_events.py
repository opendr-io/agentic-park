"""
Extract Alert Events - Parse OpenDR alerts and create structured event data
Creates a DataFrame where each row is an event with its associated alert metadata.
"""

import pandas as pd
import re
import hashlib
import json
from pathlib import Path
from logger import get_logger

# Initialize logger
logger = get_logger('extract_alert_events')



# Tracking/metadata columns that should NOT be included in the event hash.
# The hash should only reflect the immutable event data so that re-parsing
# the same alert file always produces the same hash regardless of tracking state.
TRACKING_COLUMNS = {
    'alert_status', 'read', 'severity', 'analysis',
    'analyzed_by', 'analyzed_at', 'alert_hash',
}


def _normalize_value(value):
    """Normalize a value for consistent hashing across CSV round-trips.

    Ensures that '51696', 51696, and 51696.0 all produce the same hash input.
    """
    if pd.isna(value):
        return None
    if hasattr(value, 'isoformat'):  # datetime/Timestamp
        return value.isoformat()
    # Normalize numeric values: 51696.0 -> '51696', 3.14 -> '3.14'
    if isinstance(value, float):
        if value == int(value):
            return str(int(value))
        return str(value)
    # String that looks like a float from CSV (e.g. '51696.0')
    if isinstance(value, str):
        try:
            f = float(value)
            if f == int(f):
                return str(int(f))
        except (ValueError, OverflowError):
            pass
    return str(value) if not isinstance(value, str) else value


def generate_event_hash(event_dict):
    """
    Generate a unique hash for an event based on its data fields only.
    Excludes mutable tracking/metadata columns so that the hash is stable
    across re-parses regardless of read/analysis state.
    Normalizes values so that CSV round-tripping (type changes) doesn't
    affect the hash.

    Args:
        event_dict: Dictionary containing all event fields

    Returns:
        SHA256 hash of the event
    """
    serializable_dict = {}
    for key, value in event_dict.items():
        if key in TRACKING_COLUMNS:
            continue
        normalized = _normalize_value(value)
        # Skip None/empty values so that missing columns in fresh parse
        # match NaN columns in CSV-loaded data
        if normalized is None or normalized == '':
            continue
        serializable_dict[key] = normalized

    event_json = json.dumps(serializable_dict, sort_keys=True)
    return hashlib.sha256(event_json.encode()).hexdigest()


def parse_opendr_alerts_with_events(alert_file):
    """
    Parse OpenDR alerts and extract individual matching events.

    OpenDR format:
    - First line: alert name (with emoji like ⚠️ or 🚨)
    - Second line: description (can be multi-line)
    - "Matching log entries:" precedes the events
    - "==" separator between alerts
    - Events are pipe-delimited key: value pairs

    Returns:
        list: List of event dictionaries, each containing alert metadata + full event info
    """
    if not Path(alert_file).exists():
        raise FileNotFoundError(f"Alert file not found: {alert_file}")

    all_events = []

    with open(alert_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Strip leading/trailing separator lines before splitting
    content = re.sub(r'^=+\n', '', content)
    content = re.sub(r'\n=+$', '', content)

    # Split by separator lines
    alert_sections = re.split(r'\n=+\n', content)

    for section in alert_sections:
        lines = section.strip().split('\n')
        if len(lines) < 3:  # Need at least name, description, and one event
            continue

        # First line is alert name (may have emoji)
        alert_name = lines[0].strip()
        if not alert_name:
            continue

        # Find "Matching log entries:" line
        matching_idx = None
        for i, line in enumerate(lines):
            if line.strip() == 'Matching log entries:':
                matching_idx = i
                break

        if matching_idx is None:
            continue

        # Everything between line 1 and "Matching log entries:" is description
        description = '\n'.join(lines[1:matching_idx]).strip()

        # Parse events after "Matching log entries:"
        for line in lines[matching_idx + 1:]:
            line = line.strip()
            if not line:
                continue

            # Check if this is an event line (contains pipe and timestamp pattern)
            if '|' in line and 'timestamp:' in line.lower():
                event = parse_opendr_event(line)
                if event:
                    # Add alert metadata to event
                    event['alert_name'] = alert_name
                    event['alert_description'] = description

                    all_events.append(event)

    return all_events


def parse_opendr_event(line):
    """
    Parse a single OpenDR event line to extract all fields.

    Format example:
      timestamp: 2026-01-12 11:18:46 | hostname: DESKTOP-IAGNT81 | username: LocalSystem |
      event: new service | pid: 76644 | servicename: 'VM3DService' | ...

    Returns:
        dict: Event details with all available fields
    """
    event = {}

    # Split by pipe delimiter
    parts = [p.strip() for p in line.split('|')]

    for part in parts:
        # Must have colon for key-value pairs
        if ':' not in part:
            continue

        # Split key-value pairs (only on first colon to handle values with colons)
        key, value = part.split(':', 1)
        key = key.strip().lower()
        value = value.strip()

        # Remove quotes from values if present
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        elif value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        # Convert 'None' string to None
        if value == 'None':
            value = None

        # Store the field
        event[key] = value

    return event if event else None


def load_dump_data(dump_path):
    """
    Load full event data from dump file.

    Args:
        dump_path: Path to opendr_dump.csv or .parquet

    Returns:
        DataFrame with full event data
    """
    parquet_file = Path(dump_path).parent / 'opendr_dump.parquet'

    # Try parquet first if it exists
    if parquet_file.exists():
        try:
            logger.info(f"  Reading dump from parquet: {parquet_file}")
            events_df = pd.read_parquet(parquet_file)
            logger.info(f"  Loaded {len(events_df):,} events from dump")
            return events_df
        except ImportError:
            logger.warning("  Parquet support not available, falling back to CSV")

    # Fall back to CSV
    csv_file = Path(dump_path)
    if not csv_file.exists():
        logger.error(f"  Dump file not found: {csv_file}")
        return None

    logger.info(f"  Reading dump from CSV: {csv_file}")
    events_df = pd.read_csv(csv_file)
    logger.info(f"  Loaded {len(events_df):,} events from dump")
    return events_df


def load_existing_alerts(output_file):
    """
    Load existing alerts DataFrame from CSV if it exists.

    Args:
        output_file: Path to the alerts CSV file

    Returns:
        DataFrame with existing alerts, or None if file doesn't exist
    """
    if not Path(output_file).exists():
        return None

    try:
        existing_df = pd.read_csv(output_file)
        # Convert timestamp back to datetime
        if 'timestamp' in existing_df.columns:
            existing_df['timestamp'] = pd.to_datetime(existing_df['timestamp'], errors='coerce')

        # Migrate old tracking values from 'status' column to 'alert_status'.
        # The 'status' column is overloaded: it may contain tracking values
        # (open/closed) from the old code AND event data (ESTABLISHED, running,
        # stopped). We only move tracking values to 'alert_status' and preserve
        # the event data in 'status'.
        TRACKING_VALUES = {'open', 'closed', 'processing', 'read', 'unread'}
        if 'status' in existing_df.columns:
            if 'alert_status' not in existing_df.columns:
                # No alert_status yet — create it from tracking values in status
                existing_df['alert_status'] = None
                is_tracking = existing_df['status'].astype(str).str.strip().str.lower().isin(TRACKING_VALUES)
                existing_df.loc[is_tracking, 'alert_status'] = existing_df.loc[is_tracking, 'status']
                # Clear tracking values from status column (they're not event data)
                existing_df.loc[is_tracking, 'status'] = None
                logger.info("  Migrated tracking values from 'status' to 'alert_status'")
            else:
                # Both columns exist — fill empty alert_status from tracking values in status
                needs_fill = existing_df['alert_status'].isna() | (existing_df['alert_status'] == '')
                is_tracking = existing_df['status'].astype(str).str.strip().str.lower().isin(TRACKING_VALUES)
                fill_mask = needs_fill & is_tracking
                existing_df.loc[fill_mask, 'alert_status'] = existing_df.loc[fill_mask, 'status']
                # Clear tracking values from status (keep event data like ESTABLISHED, running)
                existing_df.loc[is_tracking, 'status'] = None
                logger.info("  Merged tracking values into 'alert_status', preserved event status data")

        # Regenerate hashes to ensure consistency (old hashes may have included
        # tracking columns like 'status' that are now excluded from the hash).
        old_hashes = existing_df['alert_hash'].tolist() if 'alert_hash' in existing_df.columns else []
        existing_df['alert_hash'] = existing_df.apply(
            lambda row: generate_event_hash(row.to_dict()), axis=1
        )
        # Rename analysis files to follow any hash changes
        if old_hashes:
            new_hashes = existing_df['alert_hash'].tolist()
            from data_layer.alert_tracker import ANALYSES_DIR, _short_hash
            for old_h, new_h in zip(old_hashes, new_hashes):
                if old_h != new_h:
                    old_path = ANALYSES_DIR / f"{_short_hash(old_h)}.txt"
                    new_path = ANALYSES_DIR / f"{_short_hash(new_h)}.txt"
                    if old_path.exists() and not new_path.exists():
                        old_path.rename(new_path)
                        logger.info(f"  Renamed analysis {_short_hash(old_h)} -> {_short_hash(new_h)}")

        # Deduplicate in two passes, keeping the best row each time.
        def row_quality(row):
            """Score: tracking data (high value) + data completeness (tiebreak)."""
            score = 0
            if pd.notna(row.get('analysis')) and str(row.get('analysis', '')).strip():
                score += 100
            if pd.notna(row.get('severity')) and str(row.get('severity', '')).strip():
                score += 50
            if pd.notna(row.get('read')) and str(row.get('read', '')).strip():
                score += 25
            # Data completeness: count non-null, non-tracking columns
            for col in row.index:
                if col in TRACKING_COLUMNS or col.startswith('_'):
                    continue
                if pd.notna(row[col]) and str(row[col]).strip():
                    score += 1
            return score

        before_dedup = len(existing_df)

        # Pass 1: exact hash dedup
        if existing_df['alert_hash'].duplicated().any():
            existing_df['_quality'] = existing_df.apply(row_quality, axis=1)
            existing_df = existing_df.sort_values('_quality', ascending=False)
            existing_df = existing_df.drop_duplicates(subset='alert_hash', keep='first')
            existing_df = existing_df.drop(columns=['_quality'])
            logger.info(f"  Hash dedup: {before_dedup} -> {len(existing_df)} rows")

        # Pass 2: identity dedup — catches rows that represent the same event
        # but have different data completeness (e.g., one missing 'status' field
        # due to old migration code stripping it). These produce different hashes
        # but are the same underlying event.
        IDENTITY_COLS = [
            'timestamp', 'alert_name', 'hostname', 'event',
            'servicename', 'pdo', 'process', 'processid', 'pid',
            'sourceip', 'sourceport', 'destinationip', 'destinationport',
        ]
        id_cols = [c for c in IDENTITY_COLS if c in existing_df.columns]
        before_id_dedup = len(existing_df)
        existing_df['_quality'] = existing_df.apply(row_quality, axis=1)
        existing_df = existing_df.sort_values('_quality', ascending=False)
        existing_df = existing_df.drop_duplicates(subset=id_cols, keep='first')
        existing_df = existing_df.drop(columns=['_quality'])
        if len(existing_df) < before_id_dedup:
            logger.info(f"  Identity dedup: {before_id_dedup} -> {len(existing_df)} rows")
            # Regenerate hashes for the kept rows (they may have gained data)
            existing_df['alert_hash'] = existing_df.apply(
                lambda row: generate_event_hash(row.to_dict()), axis=1
            )

        if len(existing_df) < before_dedup:
            logger.info(f"  Total dedup: {before_dedup} -> {len(existing_df)} rows")

        logger.info(f"  Loaded {len(existing_df):,} existing alerts from {output_file}")
        return existing_df
    except Exception as e:
        logger.warning(f"  Could not load existing alerts: {e}")
        return None


def merge_alerts(existing_df, new_df):
    """
    Merge new alerts with existing alerts.
    Uses identity columns to match events, not just hash.
    For matching events: fills missing data from fresh parse while preserving tracking.
    For non-matching events: adds as new.

    Args:
        existing_df: DataFrame with existing alerts (may be None)
        new_df: DataFrame with newly extracted alerts

    Returns:
        Merged DataFrame with no duplicate events
    """
    if existing_df is None or len(existing_df) == 0:
        return new_df

    IDENTITY_COLS = [
        'timestamp', 'alert_name', 'hostname', 'event',
        'servicename', 'pdo', 'process', 'processid', 'pid',
        'sourceip', 'sourceport', 'destinationip', 'destinationport',
    ]
    id_cols = [c for c in IDENTITY_COLS if c in existing_df.columns]

    # Build identity key for existing rows
    def _identity_key(row):
        parts = []
        for col in id_cols:
            val = row.get(col)
            parts.append(str(_normalize_value(val)) if pd.notna(val) else '')
        return '|'.join(parts)

    existing_df['_identity'] = existing_df.apply(_identity_key, axis=1)
    new_df = new_df.copy()
    new_df['_identity'] = new_df.apply(_identity_key, axis=1)

    existing_identities = set(existing_df['_identity'].tolist())
    existing_hashes = set(existing_df['alert_hash'].dropna().tolist())

    # Split new_df: identity matches (for data repair) vs truly new
    identity_matches = new_df[new_df['_identity'].isin(existing_identities)]
    truly_new = new_df[
        ~new_df['_identity'].isin(existing_identities) &
        ~new_df['alert_hash'].isin(existing_hashes)
    ]

    # Data repair: fill missing values in existing rows from fresh parse
    repaired = 0
    data_cols = [c for c in new_df.columns if c not in TRACKING_COLUMNS and c != '_identity']
    for _, fresh_row in identity_matches.iterrows():
        identity = fresh_row['_identity']
        mask = existing_df['_identity'] == identity
        for col in data_cols:
            fresh_val = fresh_row.get(col)
            if pd.notna(fresh_val) and str(fresh_val).strip():
                existing_vals = existing_df.loc[mask, col]
                needs_fill = existing_vals.isna() | (existing_vals.astype(str).str.strip() == '')
                if needs_fill.any():
                    existing_df.loc[mask & needs_fill, col] = fresh_val
                    repaired += 1

    if repaired > 0:
        logger.info(f"  Repaired {repaired} missing field(s) in existing rows from fresh parse")
        # Regenerate hashes after data repair — rename analysis files to match
        old_hashes = existing_df['alert_hash'].tolist()
        existing_df['alert_hash'] = existing_df.apply(
            lambda row: generate_event_hash(row.to_dict()), axis=1
        )
        new_hashes = existing_df['alert_hash'].tolist()
        from data_layer.alert_tracker import ANALYSES_DIR, _short_hash
        for old_h, new_h in zip(old_hashes, new_hashes):
            if old_h != new_h:
                old_path = ANALYSES_DIR / f"{_short_hash(old_h)}.txt"
                new_path = ANALYSES_DIR / f"{_short_hash(new_h)}.txt"
                if old_path.exists() and not new_path.exists():
                    old_path.rename(new_path)
                    logger.info(f"  Renamed analysis {_short_hash(old_h)} -> {_short_hash(new_h)}")

    # Count preserved tracking state
    tracking_cols = ['read', 'alert_status', 'severity', 'analysis', 'analyzed_by', 'analyzed_at']
    for col in tracking_cols:
        if col in existing_df.columns:
            non_null = existing_df[col].notna().sum()
            if non_null > 0:
                logger.info(f"  Preserving {non_null:,} existing '{col}' values")

    # Drop temp column
    existing_df = existing_df.drop(columns=['_identity'])

    if len(truly_new) == 0:
        logger.info("  No new alerts to add")
        return existing_df

    logger.info(f"  Found {len(truly_new):,} new alerts to add")
    truly_new = truly_new.drop(columns=['_identity'])

    # Append truly new alerts
    merged_df = pd.concat([existing_df, truly_new], ignore_index=True)

    # Sort by timestamp
    if 'timestamp' in merged_df.columns:
        merged_df = merged_df.sort_values('timestamp')

    return merged_df


COLUMN_ORDER = [
    'timestamp',
    'alert_status',
    'read',
    'alert_name',
    'alert_description',
    'hostname',
    'username',
    'event',
    'category',
    'pid',
    'processid',
    'process',
    'parentprocessid',
    'parentimage',
    'image',
    'commandline',
    'servicename',
    'displayname',
    'executable',
    'status',
    'start',
    'desc',
    'signer',
    'device_id',
    'driver_version',
    'friendly_name',
    'is_signed',
    'pdo',
    'ec2_instance_id',
    'sourceip',
    'sourceport',
    'destinationip',
    'destinationport',
    'sid',
    'alert_hash',
    'severity',
    'analysis',
    'analyzed_by',
    'analyzed_at'
]


def _reorder_columns(df):
    """Reorder DataFrame columns to the standard order."""
    cols = [c for c in COLUMN_ORDER if c in df.columns]
    remaining = [c for c in df.columns if c not in cols]
    return df[cols + remaining]


def parse_alert_folder(alerts_folder='alerts'):
    """
    Scan alerts folder, parse all .log/.txt files, return prepared DataFrame.
    Does NOT load/merge/save CSV — caller handles that.

    Returns:
        pd.DataFrame with parsed alerts ready for merge, or None if no events found.
    """
    alerts_path = Path(alerts_folder)
    if not alerts_path.exists() or not alerts_path.is_dir():
        return None

    alert_files = list(alerts_path.glob('*.log')) + list(alerts_path.glob('*.txt'))
    if not alert_files:
        return None

    all_alert_matches = []
    for alert_file in alert_files:
        try:
            events = parse_opendr_alerts_with_events(str(alert_file))
            all_alert_matches.extend(events)
        except Exception as e:
            logger.error(f"Error parsing {alert_file.name}: {e}")
            continue

    if len(all_alert_matches) == 0:
        return None

    alerts_df = pd.DataFrame(all_alert_matches)
    alerts_df['alert_status'] = 'open'
    if 'read' not in alerts_df.columns:
        alerts_df['read'] = None
    for col in ['pid', 'processid', 'parentprocessid', 'sourceport', 'destinationport']:
        if col in alerts_df.columns:
            alerts_df[col] = pd.to_numeric(alerts_df[col], errors='coerce').astype('Int64')
    if 'timestamp' in alerts_df.columns:
        alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'], errors='coerce')
    alerts_df['alert_hash'] = alerts_df.apply(lambda row: generate_event_hash(row.to_dict()), axis=1)

    alerts_df = _reorder_columns(alerts_df)

    if 'timestamp' in alerts_df.columns:
        alerts_df = alerts_df.sort_values('timestamp')

    return alerts_df


def main():
    # Configuration
    alerts_folder = 'alerts'

    # Create exports folder if it doesn't exist
    export_dir = Path('exports')
    export_dir.mkdir(exist_ok=True)

    output_file = export_dir / 'alert_events.csv'

    logger.header("EXTRACTING OPENDR ALERT EVENTS")

    existing_alerts_df = load_existing_alerts(output_file)

    alerts_df = parse_alert_folder(alerts_folder)
    if alerts_df is None:
        logger.warning("No alert events found.")
        return None

    logger.info(f"Parsed {len(alerts_df)} alert events from {alerts_folder}")

    # Merge with existing alerts (preserves read/status/analysis tracking)
    if existing_alerts_df is not None:
        alerts_df = merge_alerts(existing_alerts_df, alerts_df)

        if 'read' not in alerts_df.columns:
            alerts_df['read'] = None

        alerts_df = _reorder_columns(alerts_df)

    # Display statistics
    logger.subheader("STATISTICS")
    logger.info(f"Total events: {len(alerts_df):,}")

    if 'alert_name' in alerts_df.columns:
        logger.info(f"Unique alerts: {alerts_df['alert_name'].nunique()}")

    if 'hostname' in alerts_df.columns:
        unique_hosts = alerts_df['hostname'].dropna().nunique()
        logger.info(f"Unique hosts: {unique_hosts}")

    if 'process' in alerts_df.columns:
        unique_processes = alerts_df['process'].dropna().nunique()
        logger.info(f"Unique processes: {unique_processes}")

    if 'event' in alerts_df.columns:
        unique_event_types = alerts_df['event'].dropna().nunique()
        logger.info(f"Unique event types: {unique_event_types}")

    # Check field population
    logger.info("\nField population:")
    for field in ['process', 'commandline', 'sourceip', 'destinationip', 'servicename', 'parentimage']:
        if field in alerts_df.columns:
            count = alerts_df[field].notna().sum()
            pct = (count / len(alerts_df) * 100) if len(alerts_df) > 0 else 0
            logger.info(f"  {field}: {count:,} ({pct:.1f}%)")

    # Top alerts
    if 'alert_name' in alerts_df.columns:
        logger.info("\nAlerts by event count:")
        for alert, count in alerts_df['alert_name'].value_counts().items():
            logger.info(f"  {count:4d} - {alert}")

    # Save to CSV
    alerts_df.to_csv(output_file, index=False)
    logger.separator()
    logger.success(f"✓ Alert events saved to: {output_file}")
    logger.separator()

    # Display sample
    logger.info("\nSample events (first 5):")
    logger.separator('-')
    for idx, row in alerts_df.head(5).iterrows():
        logger.info(f"\n{row['alert_name']}")

        if 'timestamp' in alerts_df.columns and pd.notna(row['timestamp']):
            logger.info(f"  Time: {row['timestamp']}")

        if 'hostname' in alerts_df.columns and pd.notna(row['hostname']):
            logger.info(f"  Host: {row['hostname']}")

        if 'username' in alerts_df.columns and pd.notna(row['username']):
            logger.info(f"  User: {row['username']}")

        if 'event' in alerts_df.columns and pd.notna(row['event']):
            logger.info(f"  Event: {row['event']}")

        if 'category' in alerts_df.columns and pd.notna(row['category']):
            logger.info(f"  Category: {row['category']}")

        # PID and Process
        if 'pid' in alerts_df.columns and pd.notna(row['pid']):
            logger.info(f"  PID: {row['pid']}")

        if 'processid' in alerts_df.columns and pd.notna(row['processid']):
            logger.info(f"  Process ID: {row['processid']}")

        if 'process' in alerts_df.columns and pd.notna(row['process']):
            logger.info(f"  Process: {row['process']}")

        if 'parentprocessid' in alerts_df.columns and pd.notna(row['parentprocessid']):
            logger.info(f"  Parent PID: {row['parentprocessid']}")

        if 'parentimage' in alerts_df.columns and pd.notna(row['parentimage']):
            logger.info(f"  Parent Image: {row['parentimage']}")

        if 'commandline' in alerts_df.columns and pd.notna(row['commandline']):
            cmd = str(row['commandline'])[:100]
            logger.info(f"  Command: {cmd}{'...' if len(str(row['commandline'])) > 100 else ''}")

        # Network fields
        if 'sourceip' in alerts_df.columns and pd.notna(row['sourceip']):
            src = f"{row['sourceip']}:{row.get('sourceport', 'N/A')}"
            dst = f"{row.get('destinationip', 'N/A')}:{row.get('destinationport', 'N/A')}"
            logger.info(f"  Network: {src} -> {dst}")

        # Service fields
        if 'servicename' in alerts_df.columns and pd.notna(row['servicename']):
            logger.info(f"  Service: {row['servicename']}")
            if 'displayname' in alerts_df.columns and pd.notna(row['displayname']):
                logger.info(f"  Display Name: {row['displayname']}")

    # Return the DataFrame for orchestrator
    return alerts_df


if __name__ == "__main__":
    main()
