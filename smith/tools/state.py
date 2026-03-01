"""Shared DataFrame references used by tool functions."""

import threading
import pandas as pd

EVENTS_DF = None
RECENT_EVENTS_DF = None
ALERTS_DF = None
NEW_DF = None
INTERCEPTIONS_DF = None

# Lock for thread-safe DataFrame mutations (background processor + main thread)
DF_LOCK = threading.Lock()

# Cache for get_all_events() — invalidated when RECENT_EVENTS_DF is swapped
_cached_combined = None
_cached_recent_id = None


def get_all_events():
    """Combine EVENTS_DF and RECENT_EVENTS_DF, deduplicate, sort by timestamp.

    Results are cached and reused until RECENT_EVENTS_DF is swapped by the
    EventRefresher (every ~60s). EVENTS_DF is immutable after startup.

    Returns combined DataFrame or None if no events loaded.
    """
    global _cached_combined, _cached_recent_id

    with DF_LOCK:
        if EVENTS_DF is None and RECENT_EVENTS_DF is None:
            return None
        if RECENT_EVENTS_DF is None or RECENT_EVENTS_DF.empty:
            return EVENTS_DF
        if EVENTS_DF is None or EVENTS_DF.empty:
            return RECENT_EVENTS_DF

        # Cache hit: same RECENT_EVENTS_DF object as last time
        recent_id = id(RECENT_EVENTS_DF)
        if _cached_combined is not None and _cached_recent_id == recent_id:
            return _cached_combined

        # Cache miss: snapshot references, then release lock for heavy work
        events_snap = EVENTS_DF
        recent_snap = RECENT_EVENTS_DF

    combined = pd.concat([events_snap, recent_snap], ignore_index=True)
    metadata_cols = {'source_file', 'line_number', 'raw_line'}
    dedup_cols = [c for c in combined.columns if c not in metadata_cols]
    combined = combined.drop_duplicates(subset=dedup_cols, keep='first')
    if 'timestamp' in combined.columns:
        combined['timestamp'] = pd.to_datetime(combined['timestamp'], errors='coerce')
        combined = combined.sort_values('timestamp').reset_index(drop=True)

    _cached_combined = combined
    _cached_recent_id = recent_id
    return combined
