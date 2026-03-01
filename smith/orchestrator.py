"""
Main Orchestrator
Runs the complete alert analysis pipeline silently in the background.
Only the Status Agent interacts with the user.

Pipeline:
1. Data loading (logs, alerts) - runs silently
2. Background alert processing - runs silently in background thread
3. Status Agent - runs in foreground for user interaction
"""

import os
import sys
import io
import importlib
import threading
import pandas as pd
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class SilentLogger:
    """Simple file-based logger that doesn't print to console."""

    def __init__(self, log_file='logging/orchestrator.log'):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(exist_ok=True)

    def _write(self, level, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")

    def info(self, message):
        self._write('INFO', message)

    def error(self, message):
        self._write('ERROR', message)

    def warning(self, message):
        self._write('WARNING', message)


# Initialize silent logger
logger = SilentLogger()


class EventRefresher:
    """Background thread that periodically ingests today's events from C:/opendr/tmp.

    Reads today's process/network logs every `interval` seconds and stores
    them in tool_state.RECENT_EVENTS_DF. The tools combine this with
    EVENTS_DF via state.get_all_events().
    """

    def __init__(self, interval=60):
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None
        self._known_fields = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name='EventRefresher')
        self._thread.start()
        logger.info(f"EventRefresher started (interval={self.interval}s)")

    def stop(self):
        self._stop.set()

    def _run(self):
        import load_logs_to_dataframe
        import tools.state as tool_state

        # Load known_fields once
        self._known_fields = load_logs_to_dataframe._load_known_fields()

        while not self._stop.wait(self.interval):
            try:
                recent = load_logs_to_dataframe.load_recent_events(self._known_fields)
                if recent.empty:
                    continue

                with tool_state.DF_LOCK:
                    prev = tool_state.RECENT_EVENTS_DF
                    prev_count = len(prev) if prev is not None else 0
                    tool_state.RECENT_EVENTS_DF = recent

                new_count = len(recent) - prev_count
                if new_count > 0:
                    logger.info(
                        f"EventRefresher: {len(recent):,} recent events "
                        f"(+{new_count} new)"
                    )
            except Exception as e:
                logger.error(f"EventRefresher error: {e}")


def run_module_silent(module_name, **kwargs):
    """
    Import and run a module's main() function silently (no stdout/stderr).

    Args:
        module_name: Name of the module to import
        **kwargs: Arguments to pass to the module's main()

    Returns:
        Tuple of (success: bool, result: any)
    """
    logger.info(f"Running module: {module_name}")

    try:
        # Capture stdout/stderr to suppress print statements
        captured_out = io.StringIO()
        captured_err = io.StringIO()

        with redirect_stdout(captured_out), redirect_stderr(captured_err):
            # Import the module
            module = importlib.import_module(module_name)

            # Call its main() function with provided kwargs
            result = module.main(**kwargs)

        # Log captured output to file (not console)
        output = captured_out.getvalue()
        if output:
            logger.info(f"Module {module_name} output: {len(output)} chars")

        logger.info(f"Module {module_name} completed successfully")
        return True, result

    except SystemExit as e:
        logger.error(f"Module {module_name} called sys.exit({e.code})")
        return False, None
    except Exception as e:
        logger.error(f"Module {module_name} failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False, None


def main():
    """Main orchestrator execution."""

    logger.info("=" * 80)
    logger.info("Agent Pack starting")
    logger.info("=" * 80)

    start_time = datetime.now()

    # Show minimal startup message
    print("\nLoading threat hunting agent pack")

    # =========================================================================
    # PHASE 1: DATA LOADING (silent)
    # =========================================================================
    logger.info("PHASE 1: DATA LOADING")

    # Step 1: Load logs to create events_df
    # Check for cached data — parquet (fast) or CSV (slower but still faster than re-parse)
    parquet_path = Path('exports/logs_dataframe.parquet')
    csv_path = Path('exports/logs_dataframe.csv')
    skip_parse = False
    cache_path = None

    # Try parquet first (fast), then CSV
    for path, fmt in [(parquet_path, 'parquet'), (csv_path, 'csv')]:
        if not path.exists():
            continue
        try:
            if fmt == 'parquet':
                row_count = len(pd.read_parquet(path, columns=[]))
            else:
                # Count rows without loading entire file
                with open(path, 'r', encoding='utf-8') as f:
                    row_count = sum(1 for _ in f) - 1  # subtract header
        except Exception:
            row_count = 0
        if row_count > 0:
            mod_time = datetime.fromtimestamp(path.stat().st_mtime)
            age = datetime.now() - mod_time
            age_str = f"{age.seconds // 3600}h ago" if age.days == 0 else f"{age.days}d ago"
            print(f"\nCached event data found ({row_count:,} rows, {fmt}, updated {age_str})")
            response = input("Skip event re-parsing? [Y/n]: ").strip().lower()
            skip_parse = response != 'n'
            cache_path = (path, fmt)
            break

    if skip_parse and cache_path:
        path, fmt = cache_path
        if fmt == 'parquet':
            events_df = pd.read_parquet(path)
        else:
            events_df = pd.read_csv(path)
        success = True
        logger.info(f"Loaded events from {fmt} cache: {len(events_df):,} rows")
        print("Loading all openDR event data... cached!", flush=True)
    else:
        print("Loading all openDR event data", end="", flush=True)
        real_stdout = sys.stdout
        def _dot():
            real_stdout.write(".")
            real_stdout.flush()

        try:
            import load_logs_to_dataframe
            captured_out = io.StringIO()
            captured_err = io.StringIO()
            with redirect_stdout(captured_out), redirect_stderr(captured_err):
                events_df = load_logs_to_dataframe.main(progress_callback=_dot)
            success = events_df is not None
        except Exception as e:
            logger.error(f"load_logs_to_dataframe failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            success = False
            events_df = None

    if not success or events_df is None:
        print("\nError loading event logs. Check logging/orchestrator.log")
        return 1

    logger.info(f"events_df created: {len(events_df):,} rows")

    # Step 2: Extract alert events from alerts folder
    success, alerts_df = run_module_silent('data_layer.extract_alert_events')
    print(".", end="", flush=True)

    if not success or alerts_df is None:
        print("\nError extracting alerts. Check logging/orchestrator.log")
        return 1

    logger.info(f"alerts_df created: {len(alerts_df):,} rows")

    # Step 3: Match FP hashes
    success, fp_result = run_module_silent('data_layer.match_fps', alerts_df=alerts_df)
    print(".", end="", flush=True)

    if not success or fp_result is None:
        logger.warning("FP matching failed, continuing with unfiltered alerts")
    else:
        alerts_df = fp_result

    # Step 4: Run alert filter before dedup (so alerts_dd.csv is clean)
    from alert_filter import scan_alerts
    pre_filter_count = len(alerts_df)
    alerts_df, intercepted = scan_alerts(alerts_df, source='startup scan')
    if intercepted:
        logger.warning(f"Alert filter intercepted {len(intercepted)} alerts at startup")
    # Save filtered CSV if any rows were dropped (new interceptions OR previously intercepted)
    if len(alerts_df) < pre_filter_count:
        alerts_df.to_csv('exports/alert_events.csv', index=False)
        logger.info(f"Saved filtered alerts to exports/alert_events.csv ({len(alerts_df)} rows, {pre_filter_count - len(alerts_df)} removed)")
    print(".", end="", flush=True)

    # Step 5: Deduplicate alerts (now operating on filtered data)
    success, alerts_dd = run_module_silent('data_layer.deduplicate_alerts', alerts_df=alerts_df)
    print(".", end="", flush=True)

    if not success:
        logger.warning("Deduplication failed, using original alerts")
        alerts_dd = alerts_df

    # alerts_df is used by both analysts — no separate loading needed
    new_df = alerts_df
    logger.info(f"Using alerts_df ({len(alerts_df):,} events) for both alert and new analysts")

    print(" done!")
    logger.info("PHASE 1 COMPLETE - Data loaded successfully")

    # =========================================================================
    # PHASE 2: START BACKGROUND PROCESSING & STATUS AGENT
    # =========================================================================
    logger.info("PHASE 2: STARTING AGENTS")

    # Import the background processor and status agent
    from data_layer.background_processor import BackgroundAlertProcessor
    from status_agent import StatusAgent, MAIN_QUEUE

    # Create background processor
    background = BackgroundAlertProcessor(
        message_queue=MAIN_QUEUE,
        alerts_df=alerts_df,
        new_df=new_df,
        events_df=events_df
    )

    # Create status agent (main user interface)
    status_agent = StatusAgent(
        message_queue=MAIN_QUEUE,
        alerts_df=alerts_df,
        new_df=new_df,
        events_df=events_df
    )

    # Start background processor
    logger.info("Starting background alert processor")
    background.start()

    # Start event refresher (ingests today's new events every 60s)
    refresher = EventRefresher(interval=60)
    refresher.start()

    # Show summary and start interactive mode
    print(f"\nData loaded:")
    print(f"  - {len(alerts_df):,} alerts")
    print(f"  - {len(events_df):,} event log entries")
    print(f"\nBackground processing started.")

    try:
        # Run the status agent (blocks until user exits)
        status_agent.run()
    except KeyboardInterrupt:
        logger.info("Status agent interrupted by user")
    finally:
        # Stop background services
        logger.info("Stopping background processor")
        background.stop()
        refresher.stop()

    # =========================================================================
    # CLEANUP
    # =========================================================================
    logger.info("Agent Jackson session ended")

    end_time = datetime.now()
    duration = end_time - start_time
    logger.info(f"Duration: {duration}")

    print("\nSession ended.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
