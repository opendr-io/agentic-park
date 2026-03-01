"""Check known false positive databases for matching processes."""

import json
import hashlib
import pandas as pd
from pathlib import Path


SYSTEM_FPS_PATH = Path('fp-data/system_fps.csv')
KNOWN_BENIGN_PATH = Path('fp-data/known_benign.txt')


def check_known_fps(process=None, commandline=None):
    """
    Check if a process or commandline matches the known false positive database.

    Searches two sources:
    1. system_fps.csv — exact hash matches (process + commandline)
    2. known_benign.txt — plain-language known benign patterns

    Args:
        process: Process name to check (e.g. "msedge.exe", "Code.exe")
        commandline: Full command line to check for exact hash match

    Returns:
        JSON string with matching FP entries and known benign patterns
    """
    if not process and not commandline:
        return json.dumps({"error": "Provide at least process or commandline"})

    results = {
        "hash_matches": [],
        "process_matches": [],
        "known_benign_patterns": [],
    }

    # 1. Check system_fps.csv
    if SYSTEM_FPS_PATH.exists():
        try:
            fp_df = pd.read_csv(SYSTEM_FPS_PATH)

            # Exact hash match if both process and commandline provided
            if process and commandline:
                hash_dict = {
                    'process': process,
                    'command': commandline
                }
                hash_json = json.dumps(hash_dict, sort_keys=True)
                fp_hash = hashlib.sha256(hash_json.encode()).hexdigest()

                hash_match = fp_df[fp_df['fp_hash'] == fp_hash]
                if len(hash_match) > 0:
                    results['hash_matches'].append({
                        "type": "exact_hash_match",
                        "process": process,
                        "fp_hash": fp_hash[:16],
                    })

            # Process name match (broader — shows all known FP commands for this process)
            if process:
                proc_lower = process.lower()
                proc_matches = fp_df[fp_df['process'].str.lower() == proc_lower]
                if len(proc_matches) > 0:
                    for _, row in proc_matches.head(10).iterrows():
                        cmd = str(row.get('command', ''))
                        results['process_matches'].append({
                            "process": row.get('process', ''),
                            "command_preview": cmd[:150] + ('...' if len(cmd) > 150 else ''),
                        })

        except Exception as e:
            results['error_reading_fps'] = str(e)

    # 2. Check known_benign.txt
    if KNOWN_BENIGN_PATH.exists():
        try:
            content = KNOWN_BENIGN_PATH.read_text(encoding='utf-8')
            search_terms = []
            if process:
                # Strip .exe for broader matching
                search_terms.append(process.lower())
                if process.lower().endswith('.exe'):
                    search_terms.append(process[:-4].lower())
            if commandline:
                search_terms.append(commandline.lower())

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                line_lower = line.lower()
                if any(term in line_lower for term in search_terms):
                    results['known_benign_patterns'].append(line)

        except Exception:
            pass

    # Build summary message
    total = (len(results['hash_matches']) +
             len(results['process_matches']) +
             len(results['known_benign_patterns']))

    if total == 0:
        search_desc = process or commandline[:80]
        results['message'] = f"'{search_desc}' is NOT in the known false positive database."
    else:
        parts = []
        if results['hash_matches']:
            parts.append("exact command hash match found — this is a known FP")
        if results['process_matches']:
            parts.append(f"{len(results['process_matches'])} known FP entries for this process name")
        if results['known_benign_patterns']:
            parts.append(f"{len(results['known_benign_patterns'])} known benign pattern(s)")
        results['message'] = "Known FP: " + "; ".join(parts)

    return json.dumps(results, indent=2)


SCHEMA = {
    "name": "check_known_fps",
    "description": (
        "Check the pre-built known-benign database to see if a process is recognized safe software "
        "(e.g. Edge, VS Code, Adobe, VMware tools). This is the curated whitelist maintained by the "
        "security team, NOT the runtime FP journal. Use this to quickly check if an alerting process "
        "is expected benign software before doing deeper analysis."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "process": {
                "type": "string",
                "description": "Process name to check (e.g. 'msedge.exe', 'Code.exe')"
            },
            "commandline": {
                "type": "string",
                "description": "Full command line for exact hash matching"
            }
        },
        "required": []
    }
}
