"""
Deduplicate Alerts
Creates alerts_dd by deduplicating alerts_df on all fields except timestamp.
Keeps both first_seen and last_seen timestamps for each unique alert.
Assumes alerts_df already exists in memory.
"""

import pandas as pd
from pathlib import Path


def main(alerts_df=None):
    """Deduplicate alerts and track first/last seen timestamps.

    Args:
        alerts_df: Existing alerts DataFrame (required)

    Returns:
        alerts_dd: Deduplicated DataFrame with first_seen and last_seen columns
    """

    # Check if alerts_df was provided
    if alerts_df is None:
        print("\nERROR: alerts_df must be provided as a parameter")
        print("This DataFrame should be created by extract_alert_events.py")
        return None

    print(f"Using provided alerts_df with {len(alerts_df):,} alerts")

    # Make a copy
    alerts_dd = alerts_df.copy()

    # Check if timestamp column exists
    if 'timestamp' not in alerts_dd.columns:
        print("\nERROR: alerts_df does not have 'timestamp' column")
        return None

    print(f"\nDeduplicating alerts...")

    # Get all columns except timestamp for grouping
    group_cols = [col for col in alerts_dd.columns if col not in ['timestamp', 'pid','match_count','alert_hash']]

    print(f"  Grouping by {len(group_cols)} fields (excluding uniques)")

    # Group by all non-timestamp fields and aggregate timestamps
    initial_count = len(alerts_dd)

    # Group and aggregate
    # We need to aggregate timestamp (for first_seen and last_seen)
    agg_dict = {
        'timestamp': ['min', 'max']
    }

    # Group by all non-timestamp fields
    alerts_dd = alerts_dd.groupby(group_cols, as_index=False, dropna=False).agg(agg_dict)

    # Flatten column names and rename timestamp aggregations
    alerts_dd.columns = group_cols + ['first_seen', 'last_seen']

    final_count = len(alerts_dd)
    duplicates_removed = initial_count - final_count

    print(f"\nDeduplication complete:")
    print(f"  Initial alerts: {initial_count:,}")
    print(f"  After deduplication: {final_count:,}")
    print(f"  Duplicates removed: {duplicates_removed:,}")

    if duplicates_removed > 0:
        reduction_pct = (duplicates_removed / initial_count) * 100
        print(f"  Reduction: {reduction_pct:.1f}%")

    # Calculate time spans for deduplicated alerts
    alerts_dd['time_span'] = pd.to_datetime(alerts_dd['last_seen'], errors='coerce') - pd.to_datetime(alerts_dd['first_seen'], errors='coerce')

    # Count how many alerts have time spans (repeated alerts)
    repeated_alerts = (alerts_dd['first_seen'] != alerts_dd['last_seen']).sum()
    if repeated_alerts > 0:
        print(f"\n  Repeated alerts: {repeated_alerts:,} ({(repeated_alerts/final_count)*100:.1f}%)")
        print(f"  Single occurrence: {final_count - repeated_alerts:,} ({((final_count - repeated_alerts)/final_count)*100:.1f}%)")

    # Show summary
    print("\nSummary:")
    print(f"  Total unique alerts: {len(alerts_dd):,}")
    print(f"  Alerts with timestamp column: first_seen, last_seen")

    # Sample of repeated alerts
    if repeated_alerts > 0:
        print("\nSample repeated alerts (top 5 by occurrence span):")
        sample = alerts_dd[alerts_dd['first_seen'] != alerts_dd['last_seen']].nlargest(5, 'time_span')
        for idx, row in sample.iterrows():
            alert_name = row.get('alert_name', 'Unknown')
            print(f"  {alert_name}")
            print(f"    First seen: {row['first_seen']}")
            print(f"    Last seen:  {row['last_seen']}")
            print(f"    Span: {row['time_span']}")

    # Save to CSV using temp file approach to avoid append issues
    import tempfile
    import shutil

    output_file = Path('exports/alerts_dd.csv')

    print(f"  Writing {len(alerts_dd):,} rows to CSV...")

    # Write to temp file first
    with tempfile.NamedTemporaryFile(mode='w', delete=False, newline='', encoding='utf-8', suffix='.csv') as tmp:
        tmp_path = tmp.name
        alerts_dd.to_csv(tmp, index=False)

    # Verify temp file by reading it back as CSV (handles multiline fields correctly)
    try:
        verify_df = pd.read_csv(tmp_path)
        written_rows = len(verify_df)
        print(f"  Temp file verified: {written_rows:,} data rows")

        if written_rows != len(alerts_dd):
            print(f"  ERROR: Row count mismatch in temp file! Expected {len(alerts_dd):,}, got {written_rows:,}")
            Path(tmp_path).unlink()
            return None
    except Exception as e:
        print(f"  ERROR: Could not verify temp file: {e}")
        Path(tmp_path).unlink()
        return None

    # Move temp file to final location (this will replace the old file atomically)
    shutil.move(tmp_path, output_file)

    # Final verification by reading back as CSV
    try:
        final_df = pd.read_csv(output_file)
        final_rows = len(final_df)
        print(f"  Final file verified: {final_rows:,} data rows")

        if final_rows != len(alerts_dd):
            print(f"  ERROR: Final file has wrong count! Expected {len(alerts_dd):,}, got {final_rows:,}")
    except Exception as e:
        print(f"  WARNING: Could not verify final file: {e}")

    print(f"\nDeduplicated alerts saved to: {output_file}")

    # Return deduplicated DataFrame
    return alerts_dd


if __name__ == "__main__":
    main()
