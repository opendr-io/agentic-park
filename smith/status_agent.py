"""
Status Agent - Main User Interface for Agent Smith
Provides status reports and routes security questions to specialist agents.

This is the ONLY agent that interacts with the user in the terminal.
All other agents run silently in the background.
"""
import os
import sys
import json
import queue
import threading
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()


# Shared message queue for inter-agent communication
class MessageQueue:
    """Thread-safe message queue for agent communication."""

    def __init__(self):
        self._queue = queue.Queue()
        self._on_send = None  # optional callback fired on every send()

    def set_on_send(self, callback):
        """Register a callback(msg_type, data) fired immediately on send()."""
        self._on_send = callback

    def send(self, message_type, data, sender='unknown'):
        self._queue.put({
            'type': message_type,
            'data': data,
            'sender': sender,
            'timestamp': datetime.now().isoformat()
        })
        # Fire toast callback immediately (runs on sender's thread — safe
        # because toast methods spawn their own daemon threads)
        if self._on_send:
            try:
                self._on_send(message_type, data)
            except Exception:
                pass

    def receive(self, timeout=0.1):
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def has_messages(self):
        return not self._queue.empty()


# Global message queue instance
MAIN_QUEUE = MessageQueue()


class StatusAgent:
    """
    Main user interface agent that:
    1. Monitors alert analysis progress
    2. Provides status reports
    3. Routes security questions to specialist agents
    4. Handles all user interaction
    """

    def __init__(self, message_queue=None, alerts_csv_path='exports/alert_events.csv',
                 alerts_df=None, new_df=None, events_df=None):
        """
        Initialize the status agent.

        Args:
            message_queue: Queue for receiving notifications from background agents
            alerts_csv_path: Path to the alerts CSV file to monitor
            alerts_df: Security alerts DataFrame
            new_df: Behavioral anomaly events DataFrame
            events_df: Full event stream DataFrame
        """
        self.message_queue = message_queue or MAIN_QUEUE
        self.alerts_csv_path = Path(alerts_csv_path)

        # Register immediate toast callback so notifications fire without
        # waiting for the user to press Enter in the main input loop
        self.message_queue.set_on_send(self._on_message_send)

        # Store DataFrames for routing to specialist agents
        self.alerts_df = alerts_df
        self.new_df = new_df
        self.events_df = events_df

        # Current status summary
        self.summary = {
            'last_updated': None,
            'total_alerts': 0,
            'analyzed': 0,
            'unanalyzed': 0,
            'processing': 0,
            'by_severity': defaultdict(int),
            'by_agent': defaultdict(int),
            'by_alert_type': defaultdict(int),
            'important_alerts': [],
            'recent_analyses': [],
            'errors': 0
        }

        # Logging
        self.log_file = Path('logging/status_agent.log')
        self.log_file.parent.mkdir(exist_ok=True)

        # Specialist agents (lazy loaded)
        self._alert_analyst = None
        self._new_analyst = None
        self._event_search = None

        # Last agent used — follow-ups route to same agent
        self._last_agent_type = None

        # Per-alert conversation memory (lazy loaded)
        self._alert_memory = None

        # Display number → alert_hash mapping (rebuilt on every alert listing)
        self._alert_menu = {}

        # LLM for routing (lazy loaded)
        self._llm = None

        # Memory tracker (lazy loaded)
        self._memory_tracker = None

        # Session conversation log for memory tracking
        self._conversation_log = []

        self._log("Status agent initialized")

    def _alerts_snapshot(self):
        """Return alerts_df for read-only use.

        The background processor mutates alerts_df under DF_LOCK from another
        thread. For read-only callers (display, queries), returning the
        reference directly is safe — at worst a reader sees a partially-updated
        row, which is acceptable for display purposes. Callers that need to
        mutate should call .copy() themselves.
        """
        return self.alerts_df

    def _log(self, message, level='INFO'):
        """Write timestamped log entry."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"

        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')

    def _get_llm(self):
        """Lazy load LLM for routing."""
        if self._llm is None:
            from llm_utils import get_llm
            self._llm = get_llm()
        return self._llm

    def _get_memory_tracker(self):
        """Lazy load memory tracker singleton."""
        if self._memory_tracker is None:
            from memory_tracker import get_tracker
            self._memory_tracker = get_tracker()
            self._memory_tracker.register(
                "Session (all agents)",
                lambda: self._conversation_log if self._conversation_log else None
            )
        return self._memory_tracker

    def _get_alert_memory(self):
        """Lazy load per-alert conversation memory manager."""
        if self._alert_memory is None:
            from alert_memory import AlertMemoryManager
            self._alert_memory = AlertMemoryManager(self.alerts_df)
            self._get_memory_tracker().register(
                "Alert Memory (per-alert)",
                self._alert_memory.get_all_conversations
            )
        return self._alert_memory

    def _resolve_menu_number(self, num):
        """
        Resolve a display menu number to a full alert_hash.

        Args:
            num: Display number (1-based) from the most recent alert listing

        Returns:
            Full alert_hash string

        Raises:
            ValueError if number not in current menu
        """
        if num not in self._alert_menu:
            raise ValueError(
                f"No alert #{num} in current listing. "
                f"Use 's' (status) or 'i' (important) to refresh the alert list."
            )
        return self._alert_menu[num]

    def _resolve_alert_input(self, user_arg):
        """
        Resolve user input (number or hash prefix) to a full alert_hash.

        Tries menu number first (if input is a small integer), then hash prefix.

        Args:
            user_arg: The argument after 'alert' or 'close' command

        Returns:
            (alert_hash, row_index) tuple

        Raises:
            ValueError with user-friendly message
        """
        # Try as menu number first
        try:
            num = int(user_arg)
            if num in self._alert_menu:
                full_hash = self._alert_menu[num]
                return self._resolve_alert_id(full_hash[:8])
        except ValueError:
            pass

        # Fall back to hash prefix
        return self._resolve_alert_id(user_arg)

    def _resolve_alert_id(self, id_prefix):
        """
        Resolve a hash prefix to (full_alert_hash, row_index).

        Args:
            id_prefix: First N chars of an alert_hash (min 4 recommended)

        Returns:
            (alert_hash, row_index) tuple

        Raises:
            ValueError with user-friendly message if not found or ambiguous
        """
        df = self._alerts_snapshot()
        if df is None or 'alert_hash' not in df.columns:
            raise ValueError("No alerts data loaded.")

        prefix = id_prefix.lower().strip()
        matches = df[
            df['alert_hash'].str.lower().str.startswith(prefix)
        ]

        if len(matches) == 0:
            raise ValueError(f"No alert found with ID starting with '{id_prefix}'.")
        if len(matches) > 1:
            ids = [h[:8] for h in matches['alert_hash'].tolist()]
            raise ValueError(
                f"Ambiguous ID '{id_prefix}' matches {len(matches)} alerts: "
                f"{', '.join(ids)}. Use more characters."
            )

        idx = matches.index[0]
        return matches.iloc[0]['alert_hash'], idx

    def _get_alert_analyst(self):
        """Lazy load alert analyst module."""
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
        """Lazy load behavioral anomaly analyst module."""
        if self._new_analyst is None:
            from agents import run_new_analyst
            import tools.state as tool_state
            self._new_analyst = run_new_analyst
            if self.new_df is not None:
                tool_state.NEW_DF = self.new_df
            if self.events_df is not None:
                tool_state.EVENTS_DF = self.events_df
        return self._new_analyst

    def _get_event_search(self):
        """Lazy load event search agent module."""
        if self._event_search is None:
            from agents import run_event_search
            import tools.state as tool_state
            self._event_search = run_event_search
            if self.events_df is not None:
                tool_state.EVENTS_DF = self.events_df
        return self._event_search

    def refresh_summary(self):
        """Refresh the summary from in-memory alerts DataFrame."""
        import pandas as pd

        df = self._alerts_snapshot()
        if df is None:
            return False

        try:

            self.summary['total_alerts'] = len(df)
            self.summary['by_severity'] = defaultdict(int)
            self.summary['by_agent'] = defaultdict(int)
            self.summary['by_alert_type'] = defaultdict(int)
            self.summary['important_alerts'] = []
            self.summary['recent_analyses'] = []

            # Count by read status
            if 'read' in df.columns:
                read_col = df['read'].fillna('')
                self.summary['unanalyzed'] = (read_col == '').sum() + df['read'].isna().sum()
                self.summary['processing'] = read_col.str.startswith('processing|').sum()
                self.summary['analyzed'] = read_col.str.startswith('read|').sum()
            else:
                self.summary['unanalyzed'] = len(df)
                self.summary['processing'] = 0
                self.summary['analyzed'] = 0

            # Count by severity
            if 'severity' in df.columns:
                for severity, count in df['severity'].value_counts().items():
                    if pd.notna(severity):
                        self.summary['by_severity'][str(severity)] = int(count)

            # Count by analyzing agent
            if 'analyzed_by' in df.columns:
                for agent, count in df['analyzed_by'].value_counts().items():
                    if pd.notna(agent):
                        self.summary['by_agent'][str(agent)] = int(count)

            # Filter to open alerts only (exclude closed) for type breakdown and important
            open_df = df
            if 'alert_status' in df.columns:
                open_df = df[df['alert_status'] != 'closed']

            # Count by alert type (open only)
            if 'alert_name' in open_df.columns:
                for alert_type, count in open_df['alert_name'].value_counts().items():
                    if pd.notna(alert_type):
                        self.summary['by_alert_type'][str(alert_type)] = int(count)

            # Collect important (HIGH/CRITICAL) open alerts as raw rows
            if 'severity' in open_df.columns:
                important = open_df[open_df['severity'].isin(['HIGH', 'CRITICAL'])]
                for _, row in important.iterrows():
                    self.summary['important_alerts'].append(row)

            self.summary['last_updated'] = datetime.now().isoformat()
            return True

        except Exception as e:
            self._log(f"Error refreshing summary: {e}", 'ERROR')
            return False

    def is_status_question(self, question: str) -> bool:
        """Check if this is a status/progress question (not an analytical one)."""
        status_keywords = [
            'status', 'progress', 'how many', 'count', 'summary',
            'analyzed', 'processed', 'remaining', 'important',
            'critical', 'high severity', 'breakdown', 'report',
            'what have you found', 'any findings', 'results so far',
            # Interception queries stay local — never sent to agents
            'intercept', 'injection', 'filter', 'blocked', 'sanitize',
        ]
        # Analytical phrasing should go to an agent, not the local status handler
        analytical_keywords = [
            'same', 'share', 'common', 'correlat', 'compar', 'between',
            'which', 'why', 'investigate', 'explain', 'related', 'connect',
            'overlap', 'match', 'duplicate', 'similar',
        ]
        question_lower = question.lower()
        if any(kw in question_lower for kw in analytical_keywords):
            return False
        return any(keyword in question_lower for keyword in status_keywords)

    def route_question(self, question: str) -> str:
        """
        Determine which agent should handle this question.

        Returns:
            'status', 'event_search', 'alert_analyst', or 'new_analyst'
        """
        # Status questions handled locally
        if self.is_status_question(question):
            return 'status'

        # Use LLM for routing other questions
        from langchain_core.messages import HumanMessage, SystemMessage

        prompt_file = Path('prompts/routing.txt')
        routing_text = prompt_file.read_text(encoding='utf-8') if prompt_file.exists() else "Classify as ALERTS, NEW_EVENTS, EVENT_SEARCH, or GENERAL. Respond with one word."
        routing_prompt = SystemMessage(content=routing_text)

        try:
            llm = self._get_llm()
            response = llm.invoke([routing_prompt, HumanMessage(content=question)])
            classification = response.content.strip().upper()

            if 'EVENT_SEARCH' in classification or 'EVENT_STREAM' in classification:
                agent_type = 'event_search'
            elif 'NEW' in classification:
                agent_type = 'new_analyst'
            elif 'ALERT' in classification:
                agent_type = 'alert_analyst'
            elif self._last_agent_type:
                # GENERAL or ambiguous — continue with the last agent used
                self._log(f"GENERAL classification, continuing with last agent: {self._last_agent_type}")
                agent_type = self._last_agent_type
            else:
                agent_type = 'alert_analyst'

            # During an active alert conversation, use the alert type to
            # pick the right agent for ambiguous follow-up questions.
            memory = self._get_alert_memory()
            if memory._last_alert_id is not None:
                agent_type = self._apply_alert_context_routing(agent_type, memory._last_alert_id)

            self._last_agent_type = agent_type
            return agent_type

        except Exception as e:
            self._log(f"Routing error: {e}", 'ERROR')
            return self._last_agent_type or 'alert_analyst'

    # Alert names that indicate behavioral anomaly events (from NEW_DF)
    _BEHAVIORAL_ALERT_PATTERNS = [
        'new driver', 'new service', 'new user',
    ]

    def _is_behavioral_alert(self, alert_id):
        """Check if an alert is a behavioral anomaly event (vs a SIGMA security alert)."""
        import pandas as pd
        df = self._alerts_snapshot()
        if df is None or 'alert_hash' not in df.columns:
            return False
        row = df[df['alert_hash'] == alert_id]
        if row.empty:
            return False
        name = str(row.iloc[0].get('alert_name', '')).lower()
        return any(p in name for p in self._BEHAVIORAL_ALERT_PATTERNS)

    def _apply_alert_context_routing(self, agent_type, alert_id):
        """Redirect routing based on the active alert's type.

        When a behavioral alert is selected, keep new_analyst for ambiguous questions.
        When a security alert is selected, redirect new_analyst → alert_analyst.
        """
        is_behavioral = self._is_behavioral_alert(alert_id)

        if is_behavioral:
            # Behavioral alert selected — redirect alert_analyst → new_analyst
            # for ambiguous questions (the new analyst has the right tools)
            if agent_type == 'alert_analyst':
                self._log(f"Behavioral alert context: redirecting alert_analyst → new_analyst")
                return 'new_analyst'
        else:
            # Security alert selected — redirect new_analyst → alert_analyst
            if agent_type == 'new_analyst':
                self._log(f"Security alert context: redirecting new_analyst → alert_analyst")
                return 'alert_analyst'

        return agent_type

    def _extract_alert_context(self, question: str, alert_id: str = None) -> str:
        """
        If the question references an alert (by hash prefix), extract that alert's
        details and pre-fetch surrounding events (±5 min, same PID + hostname) to
        include as context so the LLM doesn't need tool calls for basic event data.

        Args:
            question: User's question
            alert_id: Optional pre-detected full alert_hash (skips regex detection)
        """
        import re
        import pandas as pd

        df = self._alerts_snapshot()
        if df is None:
            return question

        if alert_id is not None:
            mask = df['alert_hash'] == alert_id
            if not mask.any():
                return question
            row = df[mask].iloc[0]
            short_id = alert_id[:8]
        else:
            # Match patterns like "alert a3f8b2c1", "#a3f8", "alert [a3f8b2c1]"
            match = re.search(r'(?:alert|row|#)\s*\[?([0-9a-fA-F]{4,})\]?', question, re.IGNORECASE)
            if not match:
                return question
            try:
                full_hash, row_idx = self._resolve_alert_id(match.group(1))
                row = df.loc[row_idx]
                short_id = full_hash[:8]
            except ValueError:
                return question

        fields = ['alert_name', 'alert_description', 'hostname', 'timestamp',
                  'username', 'process', 'commandline', 'parentimage',
                  'processid', 'parentprocessid', 'pid', 'severity',
                  'sourceip', 'sourceport', 'destinationip', 'destinationport',
                  'servicename', 'image']
        details = []
        for f in fields:
            val = row.get(f)
            if pd.notna(val) and str(val).strip():
                details.append(f"  {f}: {val}")

        context = f"The user is asking about this specific alert (ID {short_id}):\n" + "\n".join(details)

        # Pre-fetch surrounding events from events_df (±5 min, same PID + hostname)
        events_context = ""
        import tools.state as tool_state
        all_events = tool_state.get_all_events()
        if all_events is not None:
            try:
                pid = row.get('processid')
                hostname = row.get('hostname')
                alert_ts = row.get('timestamp')

                if pd.notna(pid) and pd.notna(hostname) and pd.notna(alert_ts):
                    pid = int(pid)
                    ref_time = pd.to_datetime(alert_ts)
                    window_start = ref_time - pd.Timedelta(minutes=5)
                    window_end = ref_time + pd.Timedelta(minutes=5)

                    # Filter: same PID + hostname + ±5 min window
                    mask = (
                        (all_events['processid'] == pid) &
                        (all_events['hostname'].str.upper() == str(hostname).upper())
                    )
                    scoped = all_events[mask].copy()
                    ts = pd.to_datetime(scoped['timestamp'])
                    scoped = scoped[(ts >= window_start) & (ts <= window_end)]
                    scoped = scoped.sort_values('timestamp').head(50)

                    if len(scoped) > 0:
                        event_lines = [f"\nSurrounding system events for PID {pid} on {hostname} (±5 min of {alert_ts}):"]
                        event_lines.append(f"NOTE: These are supplementary events from the system timeline, NOT fields of the alert itself.")
                        event_lines.append(f"({len(scoped)} events)\n")
                        for _, ev in scoped.iterrows():
                            parts = [f"  {ev.get('timestamp', '')} | {ev.get('category', '')}"]
                            if pd.notna(ev.get('process')):
                                parts.append(f"process={ev['process']}")
                            if pd.notna(ev.get('commandline')):
                                cmd = str(ev['commandline'])[:200]
                                parts.append(f"cmd={cmd}")
                            if pd.notna(ev.get('destinationip')):
                                parts.append(f"dst={ev.get('destinationip')}:{ev.get('destinationport', '')}")
                            if pd.notna(ev.get('parentimage')):
                                parts.append(f"parent={ev['parentimage']}")
                            event_lines.append(" | ".join(parts))
                        events_context = "\n".join(event_lines)
            except Exception as e:
                self._log(f"Error pre-fetching events for alert {short_id}: {e}", 'WARNING')

        return f"{context}\n{events_context}\n\nUser question: {question}"

    def _resolve_question_alert(self, question):
        """
        Try to resolve an alert reference in a free-form question.

        Resolution order:
        1. Menu number reference (e.g. "alert 3", "#2")
        2. Hash prefix reference (e.g. "alert a3f8b2c1")
        3. Follow-up phrase detection ("tell me more", "what about...")
        4. Last-viewed alert fallback — if the analyst previously asked
           the user a question (e.g. "did you run this?"), any reply
           automatically continues that alert's conversation.

        Returns:
            Full alert_hash string, or None
        """
        import re

        # Check for menu number reference: "alert 3", "#2", "row 1"
        match = re.search(r'(?:alert|row|#)\s*\[?(\d{1,3})\]?', question, re.IGNORECASE)
        if match:
            try:
                num = int(match.group(1))
                if num in self._alert_menu:
                    return self._alert_menu[num]
            except ValueError:
                pass

        # Check for hash prefix or follow-up phrase
        memory = self._get_alert_memory()
        alert_id = memory.detect_alert_id(question)
        if alert_id:
            return alert_id

        # Fallback: continue the last alert conversation.
        # This handles replies to analyst questions like "Did you run this?"
        # where the user just types "no" or "yes, that was me".
        if memory._last_alert_id is not None:
            return memory._last_alert_id

        return None

    def ask_specialist(self, question: str, agent_type: str) -> str:
        """Send question to specialist agent with per-alert memory context."""
        try:
            if agent_type == 'alert_analyst':
                memory = self._get_alert_memory()
                alert_id = self._resolve_question_alert(question)
                enriched = self._extract_alert_context(question, alert_id=alert_id)
                prior_messages = memory.load_context_messages(alert_id)
                analyst = self._get_alert_analyst()
                answer = analyst.answer_question(
                    enriched,
                    events_df=self.events_df,
                    alerts_df=self.alerts_df,
                    prior_messages=prior_messages
                )
                if alert_id is not None:
                    memory.save_exchange(alert_id, question, answer)
                return answer
            elif agent_type == 'event_search':
                # Resolve alert references so the event search agent knows
                # what "alert 1" or "that IP" means
                alert_id = self._resolve_question_alert(question)
                enriched = self._extract_alert_context(question, alert_id=alert_id)
                analyst = self._get_event_search()
                return analyst.answer_question(enriched, events_df=self.events_df)
            elif agent_type == 'new_analyst':
                analyst = self._get_new_analyst()
                return analyst.answer_question(question, self.new_df)
            else:
                return self.get_status_report(question)

        except Exception as e:
            self._log(f"Agent error: {e}", 'ERROR')
            return f"Error getting response: {e}"

    def _web_search(self, query, max_results=5):
        """Search the web using DuckDuckGo. Returns formatted results string."""
        from ddgs import DDGS

        ddgs = DDGS()
        results = []
        for r in ddgs.text(query, max_results=max_results):
            results.append(f"- {r['title']}: {r['body']} ({r['href']})")
        return '\n'.join(results) if results else 'No results found.'

    def ask_meetup(self, question=None, conversation=None) -> tuple:
        """Ask the meetup agent about the Boston Security Meetup.

        Args:
            question: User question (default: "When is the Boston Security Meetup?")
            conversation: Existing conversation history list to continue

        Returns:
            (response_text, conversation_history) tuple
        """
        import textwrap
        from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

        try:
            prompt_file = Path('prompts/meetup.txt')
            prompt_text = prompt_file.read_text(encoding='utf-8')

            # Build or continue conversation
            if conversation is None:
                # First message — do web search and set up system prompt
                search_results = []
                for query in [
                    'Boston Security Meetup site:meetup.com',
                    'Boston cybersecurity meetup 2026',
                ]:
                    try:
                        search_results.append(f"Query: {query}\n{self._web_search(query)}")
                    except Exception as e:
                        search_results.append(f"Query: {query}\nSearch failed: {e}")

                all_results = '\n\n'.join(search_results)

                system_msg = SystemMessage(content=prompt_text)
                human_content = (
                    f"{question or 'When is the Boston Security Meetup?'}\n\n"
                    f"Here are web search results:\n{all_results}"
                )
                conversation = [system_msg, HumanMessage(content=human_content)]
            else:
                # Follow-up — just append the new question
                conversation.append(HumanMessage(content=question))

            llm = self._get_llm()
            response = llm.invoke(conversation)
            conversation.append(AIMessage(content=response.content))

            # Wrap text for terminal readability
            wrapped = '\n'.join(
                textwrap.fill(line, width=80) if line.strip() else line
                for line in response.content.splitlines()
            )
            return wrapped, conversation

        except Exception as e:
            self._log(f"Meetup agent error: {e}", 'ERROR')
            error_msg = textwrap.fill(
                "I tried to look this up but something broke. This is absolutely Ori's fault. "
                "He was supposed to set up the meetup page and clearly didn't. Classic Ori.",
                width=80
            )
            return error_msg, conversation or []

    def get_status_report(self, query: str = None) -> str:
        """Generate a status report."""
        self.refresh_summary()

        lines = []
        query_lower = (query or '').lower()

        if any(kw in query_lower for kw in ['intercept', 'injection', 'filter', 'blocked', 'sanitize']):
            return self.get_interceptions_report()

        if 'important' in query_lower or 'critical' in query_lower or 'high' in query_lower:
            important = self.summary['important_alerts']
            if not important:
                lines.append("No open HIGH or CRITICAL alerts.")
            else:
                lines.append(f"{len(important)} HIGH/CRITICAL alerts\n")
                self._alert_menu = {}
                for i, row in enumerate(important, 1):
                    alert_hash = str(row.get('alert_hash', ''))
                    self._alert_menu[i] = alert_hash
                    lines.append(self._format_alert_entry(i, row))
                    lines.append("")

        elif 'progress' in query_lower or 'how many' in query_lower or 'count' in query_lower:
            lines.append("=" * 60)
            lines.append("ANALYSIS PROGRESS")
            lines.append("=" * 60)

            total = self.summary['total_alerts']
            analyzed = self.summary['analyzed']
            pct = (analyzed / total * 100) if total > 0 else 0

            lines.append(f"\nTotal Alerts: {total}")
            lines.append(f"Analyzed: {analyzed} ({pct:.1f}%)")
            lines.append(f"In Progress: {self.summary['processing']}")
            lines.append(f"Remaining: {self.summary['unanalyzed']}")

            if self.summary['by_severity']:
                lines.append("\nSeverity Breakdown:")
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    count = self.summary['by_severity'].get(severity, 0)
                    if count > 0:
                        lines.append(f"  {severity}: {count}")

        elif 'type' in query_lower or 'breakdown' in query_lower:
            lines.append("=" * 60)
            lines.append("ALERT TYPE BREAKDOWN (open only)")
            lines.append("=" * 60)

            by_type = self.summary['by_alert_type']
            if not by_type:
                lines.append("\nNo open alert types found.")
            else:
                lines.append(f"\n{len(by_type)} unique alert types:\n")
                sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)
                for alert_type, count in sorted_types[:15]:
                    lines.append(f"  {count:4d} - {alert_type[:60]}")

        else:
            # Show count and list of open alerts with key fields
            import pandas as pd

            df = self._alerts_snapshot()
            if df is None:
                lines.append("No alerts data loaded.")
            else:
                open_df = self._open_alerts(df=df)

                total = len(df)
                closed = total - len(open_df)
                lines.append(f"{len(open_df)} open alerts ({closed} closed, {total} total)\n")

                if len(open_df) > 0:
                    self._alert_menu = {}
                    for i, (_, row) in enumerate(open_df.iterrows(), 1):
                        alert_hash = str(row.get('alert_hash', ''))
                        self._alert_menu[i] = alert_hash
                        lines.append(self._format_alert_entry(i, row))
                        lines.append("")

        return '\n'.join(lines)

    def _format_alert_entry(self, i, row):
        """Format a single alert as field: value lines for terminal display."""
        import pandas as pd

        alert_hash = str(row.get('alert_hash', ''))
        short_id = alert_hash[:8]

        alert_name = row.get('alert_name', 'Unknown')
        lines = [f"ALERT #{i}  {short_id}  {alert_name}"]
        lines.append("=" * 60)

        def val(field):
            v = row.get(field)
            return str(v) if pd.notna(v) and str(v).strip() else None

        # Paired lines: fields combined with tab separator
        pairs = [
            [('hostname', 'Host'), ('username', 'User')],
            [('timestamp', 'Time'), ('process', 'Process'), ('parentimage', 'Parent')],
        ]
        for pair in pairs:
            parts = []
            for field, label in pair:
                v = val(field)
                if v:
                    parts.append(f"{label}: {v}")
            if parts:
                lines.append("  " + "\t".join(parts))

        # Single-line fields
        single_fields = [
            ('commandline', 'Command'),
            ('servicename', 'Service'),
            ('executable', 'Executable'),
        ]
        for field, label in single_fields:
            v = val(field)
            if v:
                lines.append(f"  {label}: {v}")

        # Analysis status line
        severity = val('severity')
        analyzed_by = val('analyzed_by')
        if severity and analyzed_by:
            lines.append(f"  Severity: {severity}  (analyzed by {analyzed_by})")
        elif severity:
            lines.append(f"  Severity: {severity}")
        elif not val('analysis'):
            lines.append(f"  [not yet analyzed]")

        return '\n'.join(lines)

    def _open_alerts(self, df=None):
        """Return only open (non-closed) alerts from alerts_df.

        Args:
            df: Optional pre-snapshot DataFrame. If None, takes a fresh snapshot.
        """
        if df is None:
            df = self._alerts_snapshot()
        if df is None:
            return None
        if 'alert_status' in df.columns:
            return df[df['alert_status'] != 'closed']
        return df

    def get_analysis_progress(self) -> str:
        """Report how many alerts have been analyzed vs. remaining (from in-memory DataFrame)."""
        import pandas as pd

        df = self._alerts_snapshot()
        if df is None:
            return "No alerts data loaded."

        open_df = self._open_alerts(df=df)
        total = len(open_df)
        has_analysis = 'analysis' in open_df.columns

        closed_count = len(df) - total

        if has_analysis:
            analyzed_mask = open_df['analysis'].notna() & (open_df['analysis'] != '')
            analyzed = analyzed_mask.sum()
        else:
            analyzed = 0

        remaining = total - analyzed
        pct = (analyzed / total * 100) if total > 0 else 0

        lines = ["=" * 60, "BACKGROUND ANALYSIS PROGRESS", "=" * 60]
        lines.append(f"\n  Open alerts:   {total:,}")
        lines.append(f"  Analyzed:      {analyzed:,} ({pct:.1f}%)")
        lines.append(f"  Remaining:     {remaining:,}")
        if closed_count > 0:
            lines.append(f"  Closed:        {closed_count:,}")

        import tools.state as tool_state
        idf = tool_state.INTERCEPTIONS_DF
        if idf is not None and len(idf) > 0:
            lines.append(f"  Intercepted:   {len(idf):,} (prompt injection detected)")

        if has_analysis and analyzed > 0:
            analyzed_df = open_df[analyzed_mask]

            # Severity breakdown of analyzed alerts
            if 'severity' in analyzed_df.columns:
                lines.append("\n  Severity breakdown (analyzed):")
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    count = (analyzed_df['severity'] == severity).sum()
                    if count > 0:
                        lines.append(f"    {severity}: {count:,}")

            # List critical/high alerts with numbered menu
            if 'severity' in analyzed_df.columns:
                important = analyzed_df[analyzed_df['severity'].isin(['CRITICAL', 'HIGH'])]
                if len(important) > 0:
                    self._alert_menu = {}
                    lines.append(f"\n  Critical/High alerts (use 'alert <#>' for details):")
                    for i, (_, row) in enumerate(important.iterrows(), 1):
                        sev = row.get('severity', '?')
                        name = str(row.get('alert_name', 'Unknown'))[:50]
                        host = row.get('hostname', '?')
                        alert_hash = str(row.get('alert_hash', ''))
                        self._alert_menu[i] = alert_hash
                        short_id = alert_hash[:8]
                        lines.append(f"    {i}. [{short_id}] {sev}: {name} ({host})")

            # Most recent analysis timestamp
            if 'analyzed_at' in analyzed_df.columns:
                latest = analyzed_df['analyzed_at'].dropna()
                if len(latest) > 0:
                    lines.append(f"\n  Last analyzed: {latest.max()}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def get_interceptions_report(self) -> str:
        """Report intercepted alerts from the INTERCEPTIONS_DF."""
        import tools.state as tool_state
        df = tool_state.INTERCEPTIONS_DF
        if df is None or len(df) == 0:
            return "No alerts have been intercepted by the filter."

        lines = ["=" * 60, "INTERCEPTED ALERTS (prompt injection detected)", "=" * 60]
        lines.append(f"\n  Total intercepted: {len(df):,}")

        # Group by rule
        if 'findings_summary' in df.columns:
            lines.append("\n  Detection rules triggered:")
            rule_counts = {}
            for summary in df['findings_summary']:
                for rule in str(summary).split(', '):
                    rule = rule.strip()
                    if rule:
                        rule_counts[rule] = rule_counts.get(rule, 0) + 1
            for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
                lines.append(f"    {rule}: {count:,}")

        # List each intercepted alert
        lines.append(f"\n  Intercepted alerts:")
        for i, (_, row) in enumerate(df.iterrows(), 1):
            name = str(row.get('alert_name', 'Unknown'))[:50]
            host = row.get('hostname', '?')
            when = row.get('intercepted_at', '?')
            rules = row.get('findings_summary', '?')
            lines.append(f"    {i}. {name} ({host})")
            lines.append(f"       Rules: {rules} | Intercepted: {when}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def get_alert_by_id(self, user_arg: str) -> str:
        """Fetch full alert details and analysis by menu number or hash prefix."""
        import pandas as pd

        try:
            alert_hash, row_idx = self._resolve_alert_input(user_arg)
        except ValueError as e:
            return str(e)

        df = self._alerts_snapshot()
        if df is None or row_idx not in df.index:
            return "Alert data not available."
        row = df.loc[row_idx]
        short_id = alert_hash[:8]

        lines = ["=" * 60]
        lines.append(f"ALERT {short_id}")
        lines.append("=" * 60)
        lines.append(f"\n  ID:        {short_id}")
        lines.append(f"  Alert:     {row.get('alert_name', 'Unknown')}")
        lines.append(f"  Hostname:  {row.get('hostname', 'N/A')}")
        lines.append(f"  Timestamp: {row.get('timestamp', 'N/A')}")

        if pd.notna(row.get('severity')):
            lines.append(f"  Severity:  {row['severity']}")
        if pd.notna(row.get('username')):
            lines.append(f"  Username:  {row['username']}")
        if pd.notna(row.get('process')):
            lines.append(f"  Process:   {row['process']}")
        if pd.notna(row.get('commandline')):
            lines.append(f"  Command:   {row['commandline']}")
        if pd.notna(row.get('parentimage')):
            lines.append(f"  Parent:    {row['parentimage']}")
        if pd.notna(row.get('analyzed_at')):
            lines.append(f"  Analyzed:  {row['analyzed_at']}")

        # Full analysis (loaded from file if stored externally)
        analysis_val = row.get('analysis')
        if pd.notna(analysis_val) and str(analysis_val).strip():
            if str(analysis_val) == 'file':
                from data_layer.alert_tracker import load_analysis_text
                analysis_text = load_analysis_text(alert_hash)
            else:
                analysis_text = str(analysis_val)
            if analysis_text:
                lines.append(f"\n{'─' * 60}")
                lines.append("ANALYSIS:")
                lines.append(f"{'─' * 60}")
                lines.append(analysis_text)
            else:
                lines.append("\n  (Analysis file missing)")
        else:
            lines.append("\n  (Not yet analyzed by background processor)")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def close_alert(self, user_arg: str) -> str:
        """Close an alert by menu number or hash prefix."""
        try:
            alert_hash, row_idx = self._resolve_alert_input(user_arg)
        except ValueError as e:
            return str(e)

        # Update in-memory DataFrame (locked — background thread also writes to alerts_df)
        import tools.state as tool_state
        with tool_state.DF_LOCK:
            row = self.alerts_df.loc[row_idx]
            alert_name = row.get('alert_name', 'Unknown')
            short_id = alert_hash[:8]
            if 'alert_status' not in self.alerts_df.columns:
                self.alerts_df['alert_status'] = 'open'
            self.alerts_df.loc[row_idx, 'alert_status'] = 'closed'

        # Persist to CSV via AlertTracker
        try:
            from data_layer.alert_tracker import AlertTracker
            tracker = AlertTracker(str(self.alerts_csv_path))
            tracker.mark_closed(alert_hash)
        except Exception as e:
            self._log(f"Could not persist close to CSV: {e}", 'WARNING')

        self._log(f"Closed alert {short_id}: {alert_name}")
        return f"Closed: [{short_id}] {alert_name}"

    def _send_error_toast(self, error, remaining):
        """Fire a non-modal tkinter toast for API errors."""
        import threading

        _testing = 'pytest' in sys.modules
        title = 'TEST \u2014 API Error' if _testing else 'Agent Smith \u2014 API Error'
        msg = f'{error}\n\n{remaining} alerts not yet analyzed.'

        def _show():
            try:
                import tkinter as tk
                root = tk.Tk()
                root.overrideredirect(True)
                root.attributes('-topmost', True)
                root.configure(bg='#1a1a2e')
                sw = root.winfo_screenwidth()
                sh = root.winfo_screenheight()
                w, h = 420, 160
                x = sw - w - 20
                y = sh - h - 60
                root.geometry(f'{w}x{h}+{x}+{y}')
                tk.Label(root, text=title, font=('Segoe UI', 11, 'bold'),
                         fg='#ff6b6b', bg='#1a1a2e', anchor='w').pack(
                             fill='x', padx=12, pady=(10, 2))
                tk.Label(root, text=msg, font=('Segoe UI', 9),
                         fg='#eee', bg='#1a1a2e', anchor='nw',
                         justify='left', wraplength=396).pack(
                             fill='both', expand=True, padx=12, pady=(2, 10))
                root.after(12000, root.destroy)
                root.mainloop()
            except Exception as e:
                print(f'[toast] Error notification failed: {e}')

        threading.Thread(target=_show, daemon=True).start()

    def _send_important_toast(self, alerts):
        """Fire a non-modal tkinter toast summarizing important alerts.

        Displays a dark-themed popup in the bottom-right corner that auto-dismisses.
        Runs in a background thread so it doesn't block the main loop.
        """
        import threading

        _testing = 'pytest' in sys.modules
        prefix = 'TEST' if _testing else 'Agent Smith'

        count = len(alerts)
        if count == 1:
            a = alerts[0]
            title = f'{prefix} \u2014 {a["severity"]} Alert'
            msg = f'{a["alert_name"]}\nHost: {a["hostname"]}'
        else:
            title = f'{prefix} \u2014 {count} Important Alerts'
            lines = []
            for a in alerts[:10]:
                lines.append(f'{a["severity"]}: {a["alert_name"]} ({a["hostname"]})')
            if count > 10:
                lines.append(f'...and {count - 10} more')
            msg = '\n'.join(lines)

        def _show():
            try:
                import tkinter as tk
                root = tk.Tk()
                root.overrideredirect(True)
                root.attributes('-topmost', True)
                root.configure(bg='#1a1a2e')
                sw = root.winfo_screenwidth()
                sh = root.winfo_screenheight()
                w, h = 420, 160
                x = sw - w - 20
                y = sh - h - 60
                root.geometry(f'{w}x{h}+{x}+{y}')
                tk.Label(root, text=title, font=('Segoe UI', 11, 'bold'),
                         fg='#e94560', bg='#1a1a2e', anchor='w').pack(
                             fill='x', padx=12, pady=(10, 2))
                tk.Label(root, text=msg, font=('Segoe UI', 9),
                         fg='#eee', bg='#1a1a2e', anchor='nw',
                         justify='left', wraplength=396).pack(
                             fill='both', expand=True, padx=12, pady=(2, 10))
                root.after(8000, root.destroy)
                root.mainloop()
            except Exception as e:
                print(f'[toast] Important alert notification failed: {e}')

        threading.Thread(target=_show, daemon=True).start()

    def _on_message_send(self, msg_type, data):
        """Callback fired immediately when a message is enqueued.

        Fires toasts right away so the user doesn't have to wait until
        the next input prompt to see notifications.
        """
        if msg_type == 'HIGH_SEVERITY_ALERT':
            self._send_important_toast([{
                'alert_name': data.get('alert_name', 'Unknown'),
                'hostname': data.get('hostname', 'Unknown'),
                'severity': data.get('severity', 'HIGH'),
            }])
        elif msg_type == 'API_ERROR':
            self._send_error_toast(
                data.get('error', 'Unknown API error'),
                data.get('alerts_remaining', 0)
            )

    def check_background_messages(self):
        """Check for and display any background agent notifications."""
        while self.message_queue.has_messages():
            msg = self.message_queue.receive(timeout=0)
            if msg:
                msg_type = msg.get('type', '')
                data = msg.get('data', {})

                if msg_type == 'HIGH_SEVERITY_ALERT':
                    print(f"\n** ALERT: {data.get('severity', 'HIGH')} severity alert detected **")
                    print(f"   {data.get('alert_name', 'Unknown')}")
                    print(f"   Host: {data.get('hostname', 'Unknown')}")

                elif msg_type == 'NEW_ALERTS_INGESTED':
                    new_count = data.get('new_count', 0)
                    if new_count > 0:
                        print(f"\n[Background] {new_count} new alert(s) detected from file scan")

                elif msg_type == 'API_ERROR':
                    error = data.get('error', 'Unknown API error')
                    processed = data.get('alerts_processed', 0)
                    remaining = data.get('alerts_remaining', 0)
                    print(f"\n** API ERROR — Background processing stopped **")
                    print(f"   {error}")
                    print(f"   Processed {processed} alerts, {remaining} remaining")

                elif msg_type == 'PROCESSING_COMPLETE':
                    processed = data.get('alerts_processed', 0)
                    high = data.get('high_severity_count', 0)
                    if processed > 0:
                        print(f"\n[Background] Processed {processed} alerts", end="")
                        if high > 0:
                            print(f" ({high} high severity)")
                        else:
                            print()

    def _print_menu(self):
        """Print the command menu."""
        print("\n  [p] progress      - How many alerts analyzed vs. remaining")
        print("  [m] memory        - Memory/token usage across agents")
        print("  [a] alert <#>     - Full details for alert (by list number)")
        print("  [e] events        - All events for the selected alert")
        print("  [c] close <#>     - Close alert (by list number)")
        print("  [s] status        - List open alerts")
        print("  [i] important     - Show high severity alerts")
        print("  [b] breakdown     - Show alert types")
        print("  [f] filter        - Show intercepted alerts")
        print("  [x] exit          - Exit")
        print("  [w] when is the Boston Security Meetup")
        print("  Or ask any security question...\n")

    def run(self):
        """Run the main interactive loop."""
        print("\n" + "=" * 40)
        print("Never send a human to do a machine's job")
        print("""

███████╗███╗   ███╗██╗████████╗██╗  ██╗
██╔════╝████╗ ████║██║╚══██╔══╝██║  ██║
███████╗██╔████╔██║██║   ██║   ███████║
╚════██║██║╚██╔╝██║██║   ██║   ██╔══██║
███████║██║ ╚═╝ ██║██║   ██║   ██║  ██║
╚══════╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝                                                                                                                                

""")
        print("=" * 40)

        self._log("Interactive mode started")

        while True:
            try:
                # Check for background notifications
                self.check_background_messages()

                # Show menu and get input
                self._print_menu()
                user_input = input("Smith> ").strip()

                if not user_input:
                    continue

                cmd = user_input.lower()

                if cmd in ('exit', 'quit', 'x'):
                    print("\nExiting...")
                    self._log("User exited")
                    break

                # Log the question
                self._log(f"User: {user_input}")

                # Handle direct commands (full name or first letter)
                if cmd in ('progress', 'p'):
                    self._get_alert_memory()._last_alert_id = None
                    response = self.get_analysis_progress()
                    print("\n" + response + "\n")
                    self._log(f"Response: progress report")
                    continue

                if cmd in ('filter', 'f'):
                    self._get_alert_memory()._last_alert_id = None
                    response = self.get_interceptions_report()
                    print("\n" + response + "\n")
                    self._log(f"Response: interceptions report")
                    continue

                if cmd in ('memory', 'mem', 'm'):
                    self._get_alert_memory()._last_alert_id = None
                    tracker = self._get_memory_tracker()
                    response = tracker.get_report()
                    print("\n" + response + "\n")
                    self._log(f"Response: memory report")
                    continue

                # alert <#> command
                if cmd.startswith('alert ') or (cmd.startswith('a ') and len(cmd) > 2):
                    try:
                        # Use last token — handles "alert 1", "a 1"
                        user_arg = user_input.split()[-1].strip()
                        response = self.get_alert_by_id(user_arg)
                        print("\n" + response + "\n")
                        self._log(f"Response: alert {user_arg}")
                        # Sync memory so follow-up questions resolve to this alert
                        try:
                            full_hash, _ = self._resolve_alert_input(user_arg)
                            self._get_alert_memory()._last_alert_id = full_hash
                        except ValueError:
                            pass
                        continue
                    except IndexError:
                        print("\nUsage: alert <#>  (e.g. a 1)\n")
                        continue

                # events command — get all events for the currently selected alert
                if cmd in ('events', 'e'):
                    memory = self._get_alert_memory()
                    alert_id = memory._last_alert_id
                    if alert_id is None:
                        print("\nNo alert selected. Use [a <#>] to select an alert first.\n")
                        continue
                    print("\n[Asking Event Search...]")
                    question = "Show me all process and network events for this alert"
                    enriched = self._extract_alert_context(question, alert_id=alert_id)
                    analyst = self._get_event_search()
                    response = analyst.answer_question(enriched, events_df=self.events_df)
                    print("\n" + response + "\n")
                    self._log(f"Response: events for {alert_id[:8]}")
                    from langchain_core.messages import HumanMessage as HMsg, AIMessage as AMsg
                    self._conversation_log.append(HMsg(content=question))
                    self._conversation_log.append(AMsg(content=response))
                    continue

                # close <#> command
                if cmd.startswith('close ') or (cmd.startswith('c ') and len(cmd) > 2):
                    try:
                        # Use last token — handles "close 1", "close alert 1", "c 1"
                        user_arg = user_input.split()[-1].strip()
                        response = self.close_alert(user_arg)
                        print("\n" + response + "\n")
                        continue
                    except IndexError:
                        print("\nUsage: close <#>  (e.g. c 1)\n")
                        continue

                # Boston Security Meetup — enters conversational mode
                if cmd in ('w', 'meetup') or 'boston' in cmd and 'meetup' in cmd:
                    print("\n[Consulting the meetup oracle...]")
                    response, meetup_conv = self.ask_meetup()
                    print("\n" + response + "\n")
                    self._log(f"Response: meetup query")
                    from langchain_core.messages import HumanMessage as HMsg, AIMessage as AMsg
                    self._conversation_log.append(HMsg(content=user_input))
                    self._conversation_log.append(AMsg(content=response))

                    # Stay in meetup conversation until a command is entered
                    menu_commands = {
                        'exit', 'quit', 'x', 'progress', 'p', 'memory', 'mem', 'm',
                        'events', 'e', 'filter', 'f', 's', 'i', 'b', 'w', 'meetup',
                    }
                    menu_prefixes = ('alert ', 'a ', 'close ', 'c ')
                    reprocess_command = False
                    while True:
                        try:
                            followup = input("Meetup> ").strip()
                            if not followup:
                                continue
                            followup_cmd = followup.lower()
                            # Break out on any menu command
                            if followup_cmd in menu_commands or any(followup_cmd.startswith(p) for p in menu_prefixes):
                                user_input = followup
                                reprocess_command = True
                                break
                            self._log(f"User (meetup): {followup}")
                            print("\n[Consulting the meetup oracle...]")
                            response, meetup_conv = self.ask_meetup(followup, meetup_conv)
                            print("\n" + response + "\n")
                            self._log(f"Response: meetup follow-up")
                            self._conversation_log.append(HMsg(content=followup))
                            self._conversation_log.append(AMsg(content=response))
                        except (KeyboardInterrupt, EOFError):
                            print()
                            break
                    if not reprocess_command:
                        continue
                    # Broke out with a menu command — fall through to process it
                    cmd = user_input.lower()

                # Map single-letter shortcuts to full command words
                shortcut_map = {'s': 'status', 'i': 'important', 'b': 'breakdown'}
                if cmd in shortcut_map:
                    user_input = shortcut_map[cmd]

                # Route and answer
                agent_type = self.route_question(user_input)

                if agent_type == 'status':
                    self._get_alert_memory()._last_alert_id = None
                    response = self.get_status_report(user_input)
                else:
                    agent_names = {
                        'alert_analyst': 'Alert Analyst',
                        'event_search': 'Event Search',
                        'new_analyst': 'Behavioral Analyst',
                    }
                    agent_name = agent_names.get(agent_type, agent_type)
                    print(f"\n[Asking {agent_name}...]")
                    response = self.ask_specialist(user_input, agent_type)

                print("\n" + response + "\n")
                self._log(f"Response: {len(response)} chars")

                # Track in session conversation log for memory reporting
                from langchain_core.messages import HumanMessage as HMsg, AIMessage as AMsg
                self._conversation_log.append(HMsg(content=user_input))
                self._conversation_log.append(AMsg(content=response))

            except KeyboardInterrupt:
                print("\n\nInterrupted.")
                self._log("Interrupted by user")
                break
            except EOFError:
                break
            except Exception as e:
                print(f"\nError: {e}")
                self._log(f"Error: {e}", 'ERROR')


def main():
    """Run status agent standalone for testing."""
    agent = StatusAgent()
    agent.run()


if __name__ == "__main__":
    main()
