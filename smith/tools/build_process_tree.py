"""Build process tree by tracing parent-child relationships."""

import json
import pandas as pd
from tools import state


def build_process_tree(pid, hostname=None, reference_timestamp=None):
    """
    Build the complete process tree for a given PID by tracing parent relationships.

    Args:
        pid: Process ID to build tree for
        hostname: Hostname to filter by (strongly recommended - PIDs are reused across hosts)
        reference_timestamp: Alert timestamp to scope results around (±10 minute window).
                           Prevents matching a recycled PID from a different time period.

    Returns:
        JSON string with process tree
    """
    all_events = state.get_all_events()
    if all_events is None:
        return json.dumps({"error": "Event stream not loaded"})

    try:
        # Pre-filter the working dataset by hostname and time window
        working_df = all_events

        if hostname:
            working_df = working_df[working_df['hostname'].str.upper() == hostname.upper()]

        if reference_timestamp:
            ref_time = pd.to_datetime(reference_timestamp)
            window_start = ref_time - pd.Timedelta(minutes=30)
            window_end = ref_time + pd.Timedelta(minutes=30)
            timestamps = pd.to_datetime(working_df['timestamp'])
            working_df = working_df[(timestamps >= window_start) & (timestamps <= window_end)]

        tree = []
        current_pid = int(pid)
        visited_pids = set()

        # Trace up the parent chain
        while current_pid and current_pid not in visited_pids:
            visited_pids.add(current_pid)

            # Find process creation event for this PID
            proc_events = working_df[
                (working_df['processid'] == current_pid) &
                (working_df['category'] == 'process_creation')
            ].sort_values('timestamp')

            # Also check process_existing for persistent processes
            if len(proc_events) == 0:
                proc_events = working_df[
                    (working_df['processid'] == current_pid) &
                    (working_df['category'] == 'process_existing')
                ].sort_values('timestamp')

            if len(proc_events) == 0:
                # No own events found — add a stub node from the child's
                # parentimage/parentprocessid so the tree isn't silently truncated.
                if tree and tree[0].get('parent_pid') == current_pid:
                    child = tree[0]
                    tree.insert(0, {
                        "pid": int(current_pid),
                        "process": child.get('parent_image', 'N/A'),
                        "commandline": "N/A",
                        "timestamp": "N/A",
                        "parent_pid": None,
                        "parent_image": "N/A",
                        "user": "N/A",
                        "hostname": child.get('hostname', 'N/A'),
                        "image": child.get('parent_image', 'N/A'),
                        "note": "No own events found in data — inferred from child process"
                    })
                break

            # Get the first (earliest) event for this PID
            event = proc_events.iloc[0]

            node = {
                "pid": int(current_pid),
                "process": event.get('process', 'N/A'),
                "commandline": event.get('commandline', 'N/A'),
                "timestamp": str(event.get('timestamp', 'N/A')),
                "parent_pid": int(event.get('parentprocessid', 0)) if pd.notna(event.get('parentprocessid')) else None,
                "parent_image": event.get('parentimage', 'N/A'),
                "user": event.get('username', 'N/A'),
                "hostname": event.get('hostname', 'N/A'),
                "image": event.get('image', 'N/A')
            }

            tree.insert(0, node)  # Insert at beginning to build tree from root

            # Move to parent
            current_pid = node['parent_pid']
            if not current_pid:
                break

        if len(tree) == 0:
            msg = f"No process tree found for PID {pid}"
            if hostname:
                msg += f" on {hostname}"
            if reference_timestamp:
                msg += f" within ±30 minutes of {reference_timestamp}"
            return json.dumps({"message": msg, "tree": []})

        # Warn if no hostname was provided and tree spans multiple hosts
        warning = None
        if not hostname and len(tree) > 1:
            hosts = set(n['hostname'] for n in tree if n['hostname'] != 'N/A')
            if len(hosts) > 1:
                warning = f"WARNING: Process tree spans {len(hosts)} different hosts ({', '.join(hosts)}). Use hostname parameter to scope to one host."

        response = {
            "pid": int(pid),
            "depth": len(tree),
            "tree": tree
        }
        if warning:
            response["warning"] = warning

        return json.dumps(response, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


SCHEMA = {
    "name": "build_process_tree",
    "description": "Build the complete process tree for a given PID by tracing parent-child relationships. IMPORTANT: PIDs are reused over time, so you MUST provide the hostname and reference_timestamp (the alert timestamp) to get accurate results. The reference_timestamp creates an automatic ±10 minute window to avoid matching recycled PIDs.",
    "input_schema": {
        "type": "object",
        "properties": {
            "pid": {
                "type": "integer",
                "description": "The process ID to build the tree for"
            },
            "hostname": {
                "type": "string",
                "description": "Hostname to filter by. ALWAYS provide this to avoid PID reuse confusion across hosts."
            },
            "reference_timestamp": {
                "type": "string",
                "description": "The alert timestamp (YYYY-MM-DD HH:MM:SS). Used to create a ±10 minute window so that recycled PIDs from other time periods are excluded."
            }
        },
        "required": ["pid"]
    }
}
