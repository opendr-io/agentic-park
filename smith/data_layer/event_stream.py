"""
Event Stream Data Layer
Reads process and network events from log files and provides deduplicated DataFrame.
"""

import pandas as pd
from pathlib import Path
import hashlib
import json
from logger import get_logger

# Initialize logger
logger = get_logger('event_stream')
log_dir='.'

class EventStream:
    """Simple event stream that reads and deduplicates log files."""

    def __init__(self, log_dir):
        """
        Initialize the event stream.

        Args:
            log_dir: Directory containing log files
        """
        self.log_dir = Path(log_dir)
        self.events_df = pd.DataFrame()

    # Fields used for identity-based hashing (must include enough to distinguish events)
    HASH_FIELDS = [
        'timestamp', 'hostname', 'username', 'category',
        'processid', 'process', 'parentprocessid', 'parentimage',
        'image', 'commandline', 'sid',
        'sourceip', 'sourceport', 'destinationip', 'destinationport',
        'status', 'protocol'
    ]

    def generate_event_hash(self, event_dict):
        """
        Generate a unique hash for an event based on identity fields.

        Uses timestamp, hostname, process, commandline, processid, and
        network fields to distinguish events.

        Args:
            event_dict: Dictionary containing all event fields

        Returns:
            SHA256 hash of the event
        """
        hash_dict = {}
        for field in self.HASH_FIELDS:
            val = event_dict.get(field, '')
            if val and str(val) not in ('None', 'N/A', ''):
                hash_dict[field] = str(val)
        event_json = json.dumps(hash_dict, sort_keys=True)
        return hashlib.sha256(event_json.encode()).hexdigest()

    def parse_log_line(self, line, event_type):
        """
        Parse a pipe-delimited log line into a dictionary.

        Args:
            line: The log line to parse
            event_type: 'process' or 'network'

        Returns:
            Dictionary with event fields, or None if parsing failed
        """
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        # Whitelist of valid field names for process and network events
        valid_fields = {
            'timestamp', 'hostname', 'username', 'category', 'processid',
            'process', 'parentprocessid', 'parentimage', 'image', 'commandline',
            'sid', 'sourceip', 'sourceport', 'destinationip', 'destinationport',
            'status', 'protocol', 'bytes', 'packets'
        }

        # Split by pipe delimiter
        parts = [p.strip() for p in line.split('|')]
        event = {'event_type': event_type}

        # Parse key-value pairs
        for part in parts:
            if ':' not in part:
                continue

            key, value = part.split(':', 1)
            key = key.strip().lower()
            value = value.strip()

            # Only accept whitelisted field names
            if key not in valid_fields:
                continue

            # Skip empty values
            if value and value not in ['None', 'N/A', '']:
                event[key] = value

        # Must have at least timestamp
        if 'timestamp' not in event:
            return None

        return event

    def load(self):
        """
        Load all events from log files and deduplicate.
        Stores result in self.events_df
        """
        logger.info("Loading events from log directory...")
        logger.info(f"  Directory: {self.log_dir}")

        events = []

        # Read process logs
        process_files = list(self.log_dir.glob('process_*.log'))
        logger.info(f"  Found {len(process_files)} process log file(s)")

        for log_file in process_files:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    event = self.parse_log_line(line, 'process')
                    if event:
                        event['event_hash'] = self.generate_event_hash(event)
                        events.append(event)

        # Read network logs
        network_files = list(self.log_dir.glob('network_*.log'))
        logger.info(f"  Found {len(network_files)} network log file(s)")

        for log_file in network_files:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    event = self.parse_log_line(line, 'network')
                    if event:
                        event['event_hash'] = self.generate_event_hash(event)
                        events.append(event)

        # Convert to DataFrame
        if events:
            self.events_df = pd.DataFrame(events)
            initial_count = len(self.events_df)

            # Deduplicate by event_hash
            self.events_df = self.events_df.drop_duplicates(subset=['event_hash'], keep='first')
            dedup_count = len(self.events_df)

            logger.info(f"  Total events read: {initial_count:,}")
            logger.info(f"  After deduplication: {dedup_count:,}")
            if initial_count > dedup_count:
                logger.info(f"  Duplicates removed: {initial_count - dedup_count:,}")

            # Sort by timestamp
            if 'timestamp' in self.events_df.columns:
                self.events_df = self.events_df.sort_values('timestamp').reset_index(drop=True)

        else:
            logger.warning("  No events found!")
            self.events_df = pd.DataFrame()

        return self.events_df

    def get_events(self, event_type=None, processid=None):
        """
        Get events with optional filtering.

        Args:
            event_type: Optional filter for 'process' or 'network'
            processid: Optional filter by process ID

        Returns:
            Filtered DataFrame
        """
        result_df = self.events_df.copy()

        if event_type:
            result_df = result_df[result_df['event_type'] == event_type]

        if processid:
            processid_str = str(processid)
            if 'processid' in result_df.columns:
                result_df = result_df[result_df['processid'].astype(str) == processid_str]

        return result_df

    def save_to_csv(self, output_file='exports/event_stream.csv'):
        """
        Save current event stream to CSV file.

        Args:
            output_file: Path to output CSV file
        """
        if not self.events_df.empty:
            self.events_df.to_csv(output_file, index=False)
            logger.info(f"Saved {len(self.events_df):,} events to {output_file}")
        else:
            logger.warning("No events to save")


def main():
    """Test the event stream."""
    logger.header("EVENT STREAM TEST")

    # Create and load event stream
    stream = EventStream(log_dir)
    stream.load()

    # Show statistics
    logger.info("\nStream Statistics:")
    logger.info(f"  Total events: {len(stream.events_df):,}")

    if not stream.events_df.empty:
        process_count = len(stream.events_df[stream.events_df['event_type'] == 'process'])
        network_count = len(stream.events_df[stream.events_df['event_type'] == 'network'])
        logger.info(f"  Process events: {process_count:,}")
        logger.info(f"  Network events: {network_count:,}")

        if 'processid' in stream.events_df.columns:
            unique_pids = stream.events_df['processid'].nunique()
            logger.info(f"  Unique PIDs: {unique_pids:,}")

    # Save to CSV
    stream.save_to_csv('event_stream_test.csv')

    logger.separator()
    logger.success("Test complete!")
    logger.separator()

    return 0


if __name__ == "__main__":
    exit(main())
