#!/usr/bin/env python3
# Integration for n8n to forward Wazuh DNS alerts

import json
import sys
import os
import requests
import logging
from datetime import datetime

# Setup logging
LOG_FILE = '/var/ossec/logs/integrations.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    filename=LOG_FILE
)

def debug(msg):
    """Log debug messages to the integration log"""
    logging.info(msg)
    if len(sys.argv) > 4 and sys.argv[4] == 'debug':
        print(msg)

def get_json_alert(file_location):
    """Read the JSON alert file"""
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except Exception as e:
        debug(f"Error reading alert file: {e}")
        sys.exit(1)

def main():
    # Validate arguments
    if len(sys.argv) < 4:
        debug("Missing required arguments. Usage: custom-dns-integration.py alert_file_path alert_level hook_url")
        sys.exit(1)
    
    # Wazuh passes: alert_file alert_level rule_group hook_url
    alert_file = sys.argv[1]
    alert_level = sys.argv[2]
    
    # In the integration config, you've specified a group, so Wazuh will pass it as the 3rd argument
    # and the hook_url will be the 4th argument
    if len(sys.argv) >= 5:
        hook_url = sys.argv[4]  # Hook URL is the 4th argument when a group is specified
    elif len(sys.argv) >= 4:
        hook_url = sys.argv[3]  # Hook URL is the 3rd argument when no group is specified
    else:
        debug("Hook URL not provided")
        sys.exit(1)
    
    # Get hook URL from environment variable if not provided
    if not hook_url or hook_url == "sysmon_event_22":  # Handle case where group is passed as 3rd argument
        hook_url = os.environ.get('WAZUH_HOOK_URL', 'http://sbihi.soar.ma:5678/webhook/wazuh-sysmon')
    
    debug(f"Processing alert file: {alert_file}, level: {alert_level}, hook URL: {hook_url}")
    
    # Read and parse alert
    alert_json = get_json_alert(alert_file)
    
    # Check alert level
    try:
        if int(alert_level) > 0:
            rule_level = int(alert_json.get('rule', {}).get('level', 0))
            if rule_level < int(alert_level):
                debug(f"Alert level {rule_level} below minimum {alert_level}, ignoring")
                sys.exit(0)
    except ValueError as e:
        debug(f"Error parsing alert level: {e}. Using default filtering.")
    
    # Check if this is a DNS event
    is_dns_event = False
    event_id = alert_json.get('data', {}).get('win', {}).get('system', {}).get('eventID')
    
    if event_id == "22":
        is_dns_event = True
        debug("DNS event detected (EventID 22)")
    
    # Only send DNS events or events from sysmon_event_22 group
    if not is_dns_event:
        rule_groups = alert_json.get('rule', {}).get('groups', [])
        if 'sysmon_event_22' not in rule_groups:
            debug("Not a DNS event or sysmon_event_22 group, ignoring")
            sys.exit(0)
    
    # Prepare payload with DNS details
    dns_query = alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('queryName', 'unknown')
    dns_result = alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('queryResults', '')
    
    # Enrich the alert with DNS-specific fields to make it easier for n8n
    payload = {
        'alert': alert_json,
        'timestamp': datetime.now().isoformat(),
        'source': 'wazuh-dns-monitor',
        'dns_data': {
            'query': dns_query,
            'results': dns_result,
            'time': alert_json.get('data', {}).get('win', {}).get('eventdata', {}).get('utcTime', '')
        }
    }
    
    # Send to n8n webhook
    try:
        debug(f"Sending DNS event for {dns_query} to n8n webhook: {hook_url}")
        headers = {'Content-Type': 'application/json'}
        response = requests.post(hook_url, headers=headers, json=payload, timeout=10)
        
        if response.status_code >= 200 and response.status_code < 300:
            debug(f"Alert successfully sent to n8n webhook: {response.status_code}")
        else:
            debug(f"Failed to send alert to n8n webhook: {response.status_code} - {response.text}")
            sys.exit(1)
    except Exception as e:
        debug(f"Error sending alert to n8n: {e}")
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()
