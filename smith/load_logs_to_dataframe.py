"""
Load logs from /tmp folder into a pandas DataFrame
"""

import sys
import pandas as pd
from pathlib import Path
import re
import configparser

def parse_log_line(line: str, known_fields: set = None) -> dict:
    """Parse a pipe-separated log line into a dictionary of fields.

    Expected format: timestamp: ... | hostname: ... | username: ... | category: ... | ...

    The challenge is that commandline fields can contain pipes (|) as part of bash commands.
    We solve this by only recognizing fields that match known log field names.

    Args:
        line: The log line to parse
        known_fields: Set of known field names to recognize (loaded from config)
    """
    fields = {}

    # Use provided known fields or fall back to default set
    if known_fields is None:
        known_fields = {
            'timestamp', 'hostname', 'username', 'category', 'processid', 'process',
            'parentprocessid', 'parentimage', 'image', 'commandline', 'sid',
            'sourceip', 'sourceport', 'destinationip', 'destinationport', 'protocol',
            'event', 'servicename', 'displayname', 'executable', 'desc', 'signer',
            'friendly_name', 'is_signed', 'message', 'pid', 'status', 'start'
        }

    KNOWN_FIELDS = known_fields

    # Split by pipe, but validate each part
    parts = line.split(" | ")

    # Track the current field being built (for handling multi-pipe values)
    current_key = None
    current_value = []

    for part in parts:
        if ": " in part:
            # Check if this looks like a new field
            potential_key = part.split(": ", 1)[0].strip()

            if potential_key in KNOWN_FIELDS:
                # Save previous field if exists
                if current_key:
                    fields[current_key] = " | ".join(current_value)

                # Start new field
                current_key = potential_key
                current_value = [part.split(": ", 1)[1].strip()]
            else:
                # This is part of the previous field's value (e.g., part of commandline)
                if current_key:
                    current_value.append(part)
        else:
            # No colon, so this is a continuation of the current field
            if current_key:
                current_value.append(part)

    # Save the last field
    if current_key:
        fields[current_key] = " | ".join(current_value)

    return fields

def load_logs_to_dataframe(log_dir: Path, log_type: str = None, known_fields: set = None, progress_callback=None) -> pd.DataFrame:
    """
    Load all log files from a directory into a pandas DataFrame.

    Args:
        log_dir: Path to the directory containing log files
        log_type: Optional filter for specific log type (e.g., 'network', 'process', 'driver')
        known_fields: Set of known field names to recognize (loaded from config)
        progress_callback: Optional callable invoked after each file is read

    Returns:
        DataFrame with all log entries
    """
    all_records = []

    # Get all .log files
    log_files = list(log_dir.glob("*.log"))

    # Filter by type if specified
    if log_type:
        log_files = [f for f in log_files if log_type in f.name]

    print(f"Loading {len(log_files)} log files from {log_dir}")

    for log_file in log_files:
        print(f"  Reading: {log_file.name}")

        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or ' | ' not in line:
                        continue

                    # Parse the log line with known fields
                    fields = parse_log_line(line, known_fields)

                    # Add metadata
                    fields['source_file'] = log_file.name
                    fields['line_number'] = line_num
                    fields['raw_line'] = line

                    all_records.append(fields)

        except Exception as e:
            print(f"  Error reading {log_file.name}: {e}")

        if progress_callback:
            progress_callback()

    # Create DataFrame
    events_df = pd.DataFrame(all_records)

    print(f"\nLoaded {len(events_df)} log entries")
    if len(events_df) > 0:
        print(f"Columns: {', '.join(events_df.columns)}")
        print(f"\nLog types (category): {events_df['category'].value_counts().head(10).to_dict() if 'category' in events_df.columns else 'N/A'}")

    return events_df

def main(progress_callback=None):
    """
    Main function to load, process, and export event logs.
    Returns the combined events_df DataFrame.

    Args:
        progress_callback: Optional callable invoked after each log file is read.
    """
    # Load configuration
    config_file = Path(__file__).parent / "log_loader_config.ini"
    config = configparser.ConfigParser()
    config.read(config_file)

    # Parse configuration
    log_dirs_str = config.get('Paths', 'log_directories', fallback='../tmp')
    log_dirs = [Path(__file__).parent / d.strip() for d in log_dirs_str.split(',') if d.strip()]
    output_dir = Path(__file__).parent / config.get('Paths', 'output_directory', fallback='.')

    log_types_str = config.get('LogTypes', 'log_types', fallback='process, network')
    log_types = [lt.strip() for lt in log_types_str.split(',') if lt.strip() and lt.strip().lower() != 'all']
    if not log_types or log_types_str.strip().lower() == 'all':
        log_types = ['process', 'network', 'service', 'driver', 'user', 'endpoint']

    export_csv = config.getboolean('OutputFormats', 'export_csv', fallback=True)
    export_tsv = config.getboolean('OutputFormats', 'export_tsv', fallback=True)
    export_parquet = config.getboolean('OutputFormats', 'export_parquet', fallback=True)
    csv_quoting = config.getint('OutputFormats', 'csv_quoting', fallback=1)
    parquet_compression = config.get('OutputFormats', 'parquet_compression', fallback='snappy')

    field_order_str = config.get('FieldOrdering', 'field_order', fallback='')
    desired_order = [f.strip() for f in field_order_str.split(',') if f.strip()]

    # Load known fields from config - REQUIRED, no fallback
    if not config.has_section('KnownFields') or not config.has_option('KnownFields', 'known_fields'):
        raise ValueError(
            "[KnownFields] section with 'known_fields' option is required in log_loader_config.ini"
        )

    known_fields_str = config.get('KnownFields', 'known_fields')
    known_fields = set(f.strip() for f in known_fields_str.split(',') if f.strip())

    if not known_fields:
        raise ValueError("'known_fields' option in [KnownFields] section cannot be empty")

    print(f"Loaded {len(known_fields)} known fields from config: {', '.join(sorted(known_fields))}")

    deduplicate = config.getboolean('Processing', 'deduplicate', fallback=True)
    sort_order = config.get('Processing', 'sort_by_timestamp', fallback='descending').lower()
    show_statistics = config.getboolean('Processing', 'show_statistics', fallback=True)

    # Create output directory if needed
    output_dir.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print(f"Loading logs from {len(log_dirs)} director{'y' if len(log_dirs) == 1 else 'ies'}:")
    for log_dir in log_dirs:
        print(f"  - {log_dir}")
    print(f"Log types: {', '.join(log_types)}")
    print("="*70)

    # Load logs by type from all directories
    dataframes = []
    for log_dir in log_dirs:
        if not log_dir.exists():
            print(f"\nWarning: Directory not found: {log_dir}")
            continue

        for log_type in log_types:
            print(f"\nLoading {log_type} logs from {log_dir}...")
            df = load_logs_to_dataframe(log_dir, log_type=log_type, known_fields=known_fields, progress_callback=progress_callback)
            if len(df) > 0:
                dataframes.append(df)

    if not dataframes:
        print("\nNo logs found!")
        return pd.DataFrame()

    # Combine all dataframes
    print("\nCombining dataframes...")
    events_df = pd.concat(dataframes, ignore_index=True)
    print(f"Total combined records: {len(events_df)}")

    # Deduplicate if enabled
    if deduplicate:
        print("\nDeduplicating records...")
        before_dedup = len(events_df)
        events_df = events_df.drop_duplicates(subset=events_df.columns.tolist(), keep='first')
        after_dedup = len(events_df)
        duplicates_removed = before_dedup - after_dedup
        print(f"Removed {duplicates_removed} duplicate records ({before_dedup} -> {after_dedup})")

    # Convert data types
    print("\nConverting data types...")

    # Convert timestamp to datetime
    events_df['timestamp'] = pd.to_datetime(events_df['timestamp'], errors='coerce')

    # Convert integer fields
    int_fields = ['processid', 'parentprocessid', 'sourceport', 'destinationport']
    for field in int_fields:
        if field in events_df.columns:
            events_df[field] = pd.to_numeric(events_df[field], errors='coerce').astype('Int64')

    print("Data types converted")

    # Sort by timestamp if enabled
    if sort_order in ['ascending', 'descending']:
        print(f"\nSorting by timestamp ({sort_order})...")
        events_df = events_df.sort_values('timestamp', ascending=(sort_order == 'ascending')).reset_index(drop=True)
        print(f"Sorted {len(events_df)} records by timestamp")

    # Reorder columns if specified
    if desired_order:
        print("\nReordering columns...")
        # Only include columns that exist in the dataframe
        column_order = [col for col in desired_order if col in events_df.columns]
        events_df = events_df[column_order]
        print(f"Reordered to: {', '.join(column_order)}")

    # Show DataFrame info if statistics enabled
    if show_statistics:
        print("\n" + "="*70)
        print("DataFrame Info:")
        print("="*70)
        print(events_df.info())

        print("\n" + "="*70)
        print("Sample records:")
        print("="*70)
        print(events_df.head())

    # Export to configured formats
    print("\n" + "="*70)
    print("Exporting data:")
    print("="*70)

    if export_csv:
        output_file = output_dir / "logs_dataframe.csv"
        events_df.to_csv(output_file, index=False, encoding='utf-8', quoting=csv_quoting)
        print(f"CSV saved to: {output_file}")

    if export_tsv:
        output_tsv = output_dir / "logs_dataframe.tsv"
        events_df.to_csv(output_tsv, index=False, encoding='utf-8', sep='\t')
        print(f"TSV saved to: {output_tsv}")

    if export_parquet:
        output_parquet = output_dir / "logs_dataframe.parquet"
        events_df.to_parquet(output_parquet, index=False, engine='pyarrow', compression=parquet_compression)
        print(f"Parquet saved to: {output_parquet}")

    # Show statistics if enabled
    if show_statistics:
        # Show breakdown by log type
        if 'category' in events_df.columns:
            print("\n" + "="*70)
            print("Breakdown by category:")
            print("="*70)
            print(events_df['category'].value_counts())

        # Show breakdown by process for network connections
        network_dfs = [df for df in dataframes if 'sourceip' in df.columns]
        if network_dfs:
            df_network = pd.concat(network_dfs, ignore_index=True)
            if 'process' in df_network.columns:
                print("\n" + "="*70)
                print("Network connections by process:")
                print("="*70)
                print(df_network['process'].value_counts().head(10))

        # Show process creation statistics
        process_dfs = [df for df in dataframes if 'commandline' in df.columns]
        if process_dfs:
            df_process = pd.concat(process_dfs, ignore_index=True)
            if 'process' in df_process.columns:
                print("\n" + "="*70)
                print("Process creation by process:")
                print("="*70)
                print(df_process['process'].value_counts().head(10))

    # Return the final events_df for use by orchestrator
    return events_df


def _load_known_fields():
    """Load known fields from config file."""
    config_file = Path(__file__).parent / "log_loader_config.ini"
    config = configparser.ConfigParser()
    config.read(config_file)

    if not config.has_section('KnownFields') or not config.has_option('KnownFields', 'known_fields'):
        return None

    known_fields_str = config.get('KnownFields', 'known_fields')
    return set(f.strip() for f in known_fields_str.split(',') if f.strip()) or None


def load_recent_events(known_fields=None):
    """
    Load only today's process/network logs from C:/opendr/tmp.
    Designed to be called repeatedly from a background thread.
    Returns a deduplicated DataFrame of recent events, or empty DataFrame.

    Args:
        known_fields: Set of known field names for parsing. If None, loads from config.
    """
    from datetime import date

    if known_fields is None:
        known_fields = _load_known_fields()

    today_str = date.today().strftime('%Y-%m-%d')
    tmp_dir = Path('C:/opendr/tmp')

    if not tmp_dir.exists():
        return pd.DataFrame()

    all_records = []
    for log_type in ('process', 'network'):
        pattern = f"{log_type}_*_{today_str}_*.log"
        for log_file in tmp_dir.glob(pattern):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or ' | ' not in line:
                            continue
                        fields = parse_log_line(line, known_fields)
                        fields['source_file'] = log_file.name
                        fields['line_number'] = line_num
                        all_records.append(fields)
            except Exception:
                continue

    if not all_records:
        return pd.DataFrame()

    df = pd.DataFrame(all_records)

    # Deduplicate using data fields (exclude file metadata)
    metadata_cols = {'source_file', 'line_number', 'raw_line'}
    dedup_cols = [c for c in df.columns if c not in metadata_cols]
    df = df.drop_duplicates(subset=dedup_cols, keep='first')

    # Convert types to match the main events_df
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    int_fields = ['processid', 'parentprocessid', 'sourceport', 'destinationport']
    for field in int_fields:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors='coerce').astype('Int64')

    if 'timestamp' in df.columns:
        df = df.sort_values('timestamp').reset_index(drop=True)

    return df


if __name__ == "__main__":
    main()
