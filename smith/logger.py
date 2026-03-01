"""
Unified Logger for AI Agent Team
All scripts write to the same log file with timestamps.
Captures both logger calls and print statements.
"""

import sys
from datetime import datetime
from pathlib import Path


class UnifiedLogger:
    """Logger that writes to both console and a unified log file."""

    def __init__(self, log_file='analysis_log.txt', script_name=None):
        """
        Initialize the logger.

        Args:
            log_file: Path to the unified log file
            script_name: Name of the script using this logger
        """
        # Create logging folder if it doesn't exist
        log_dir = Path('logging')
        log_dir.mkdir(exist_ok=True)

        # Ensure log file is in the logging folder
        self.log_file = log_dir / log_file
        self.script_name = script_name or 'UNKNOWN'
        self.original_stdout = None
        self.capturing = False

    def _get_timestamp(self):
        """Get current timestamp string."""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _format_message(self, message, level='INFO'):
        """Format message with timestamp and script name."""
        timestamp = self._get_timestamp()
        return f"[{timestamp}] [{self.script_name}] [{level}] {message}"

    def _write_to_log(self, formatted_message):
        """Write formatted message to log file."""
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(formatted_message + '\n')

    def _write_to_console(self, message):
        """Write message to console (original stdout)."""
        # Handle Unicode characters that may not be supported by the console
        try:
            if self.original_stdout:
                self.original_stdout.write(message + '\n')
                self.original_stdout.flush()
            else:
                # Not capturing, use regular print
                print(message)
        except UnicodeEncodeError:
            # Fallback: replace problematic characters with ASCII equivalents
            safe_message = message.encode('ascii', 'replace').decode('ascii')
            if self.original_stdout:
                self.original_stdout.write(safe_message + '\n')
                self.original_stdout.flush()
            else:
                print(safe_message)

    def log(self, message, level='INFO', console=True):
        """
        Write message to log file and optionally console.

        Args:
            message: Message to log
            level: Log level (INFO, ERROR, WARNING, SUCCESS)
            console: Whether to also print to console
        """
        formatted = self._format_message(message, level)
        self._write_to_log(formatted)

        if console:
            self._write_to_console(message)

    def info(self, message, console=True):
        """Log info message."""
        self.log(message, 'INFO', console)

    def error(self, message, console=True):
        """Log error message."""
        self.log(message, 'ERROR', console)

    def warning(self, message, console=True):
        """Log warning message."""
        self.log(message, 'WARNING', console)

    def success(self, message, console=True):
        """Log success message."""
        self.log(message, 'SUCCESS', console)

    def separator(self, char='=', length=100, console=True):
        """Log a separator line."""
        message = char * length
        self.log(message, 'INFO', console)

    def header(self, title, console=True):
        """Log a section header."""
        self.separator('=', console=console)
        self.info(title, console=console)
        self.separator('=', console=console)

    def subheader(self, title, console=True):
        """Log a subsection header."""
        self.separator('-', console=console)
        self.info(title, console=console)
        self.separator('-', console=console)

    def start_capture(self):
        """Start capturing stdout to log file."""
        if not self.capturing:
            self.original_stdout = sys.stdout
            sys.stdout = TeeOutput(self, self.original_stdout)
            self.capturing = True

    def stop_capture(self):
        """Stop capturing stdout."""
        if self.capturing and self.original_stdout:
            sys.stdout = self.original_stdout
            self.original_stdout = None
            self.capturing = False


class TeeOutput:
    """Captures stdout and writes to both console and log file."""

    def __init__(self, logger, terminal):
        self.logger = logger
        self.terminal = terminal
        self.buffer = []

    def write(self, message):
        """Write to both terminal and log file."""
        # Write to terminal immediately
        self.terminal.write(message)
        self.terminal.flush()

        # Buffer the message for logging
        if message and message != '\n':
            self.buffer.append(message)

            # If message ends with newline, flush to log
            if message.endswith('\n'):
                full_message = ''.join(self.buffer).rstrip('\n')
                if full_message.strip():  # Only log non-empty messages
                    formatted = self.logger._format_message(full_message, 'PRINT')
                    self.logger._write_to_log(formatted)
                self.buffer = []

    def flush(self):
        """Flush any buffered content and the terminal."""
        if self.buffer:
            full_message = ''.join(self.buffer).rstrip('\n')
            if full_message.strip():
                formatted = self.logger._format_message(full_message, 'PRINT')
                self.logger._write_to_log(formatted)
            self.buffer = []

        self.terminal.flush()


def get_logger(script_name, log_file='analysis_log.txt', capture_stdout=True):
    """
    Get a logger instance for a script.

    Args:
        script_name: Name of the script
        log_file: Path to log file
        capture_stdout: Whether to capture all stdout (print statements)

    Returns:
        UnifiedLogger instance
    """
    logger = UnifiedLogger(log_file, script_name)

    if capture_stdout:
        logger.start_capture()

    return logger
