"""Look up IP address information via ipinfo.io."""

import json
import requests


def lookup_ip_info(ip_address):
    """
    Look up information about an IP address using ipinfo.io API.

    Args:
        ip_address: IP address to look up

    Returns:
        JSON string with IP information
    """
    try:
        # Check if it's a private IP
        if ip_address.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                   '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                                   '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                                   '172.30.', '172.31.', '192.168.', '127.')):
            return json.dumps({
                "ip": ip_address,
                "type": "private",
                "message": "Private IP address - no external lookup performed"
            })

        # Query ipinfo.io
        response = requests.get(f'https://ipinfo.io/{ip_address}/json', timeout=5)

        if response.status_code == 200:
            data = response.json()
            return json.dumps({
                "ip": ip_address,
                "hostname": data.get('hostname', 'N/A'),
                "city": data.get('city', 'N/A'),
                "region": data.get('region', 'N/A'),
                "country": data.get('country', 'N/A'),
                "org": data.get('org', 'N/A'),
                "postal": data.get('postal', 'N/A'),
                "timezone": data.get('timezone', 'N/A')
            }, indent=2)
        else:
            return json.dumps({
                "ip": ip_address,
                "error": f"API returned status code {response.status_code}"
            })

    except requests.Timeout:
        return json.dumps({"ip": ip_address, "error": "Lookup timed out"})
    except Exception as e:
        return json.dumps({"ip": ip_address, "error": str(e)})


SCHEMA = {
    "name": "lookup_ip_info",
    "description": "Look up information about an IP address including geolocation, organization, and network details. Use this to understand the origin and ownership of external IPs seen in network events.",
    "input_schema": {
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "The IP address to look up"
            }
        },
        "required": ["ip_address"]
    }
}
