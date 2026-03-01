"""
Match False Positives
Simple script to match alert hashes against known FP hashes
Assumes alerts_df already exists in memory
"""

import pandas as pd
from pathlib import Path

def main(alerts_df=None):
    """Match alerts against known FP hashes.

    Args:
        alerts_df: Existing alerts DataFrame (optional, will load from CSV if not provided)

    Returns:
        Updated alerts_df with systemfp column
    """

    # Check if alerts_df was provided
    if alerts_df is None:
        print("\nERROR: alerts_df must be provided as a parameter")
        print("This DataFrame should be created by extract_alert_events.py")
        return None

    print(f"Using provided alerts_df with {len(alerts_df):,} alerts")

    # File paths
    fps_file = Path('fp-data/system_fps.csv')

    print(f"\nReading FP hashes from {fps_file}...")
    system_fps = pd.read_csv(fps_file)
    print(f"  Loaded {len(system_fps):,} FP hashes")

    # Get set of FP hashes for fast lookup
    fp_hash_set = set(system_fps['fp_hash'].dropna())
    print(f"  Created lookup set with {len(fp_hash_set):,} unique hashes")

    # Check if alerts_df has alert_hash column
    if 'alert_hash' not in alerts_df.columns:
        print("\nERROR: alerts_df does not have 'alert_hash' column")
        return

    # Initialize or update systemfp column
    if 'systemfp' not in alerts_df.columns:
        print("\nCreating 'systemfp' column...")
        alerts_df['systemfp'] = 'false'
    else:
        print("\nUpdating existing 'systemfp' column...")

    # Match hashes
    print("\nMatching alert hashes against FP hashes...")
    matches = 0
    for idx, row in alerts_df.iterrows():
        alert_hash = row.get('alert_hash')
        if pd.notna(alert_hash) and alert_hash in fp_hash_set:
            alerts_df.at[idx, 'systemfp'] = 'true'
            matches += 1
        else:
            alerts_df.at[idx, 'systemfp'] = 'false'

    print(f"  Found {matches:,} matches out of {len(alerts_df):,} alerts")
    print(f"  Match rate: {(matches / len(alerts_df) * 100):.1f}%")

    # Show summary
    print("\nSummary:")
    print(f"  Total alerts: {len(alerts_df):,}")
    print(f"  System FPs (true): {(alerts_df['systemfp'] == 'true').sum():,}")
    print(f"  Non-FPs (false): {(alerts_df['systemfp'] == 'false').sum():,}")

    # Return updated DataFrame
    return alerts_df


if __name__ == "__main__":
    main()
