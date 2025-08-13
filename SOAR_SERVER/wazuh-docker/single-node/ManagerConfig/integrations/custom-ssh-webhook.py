#!/usr/bin/env python3
# Custom Wazuh integration to forward alerts to n8n
# Based on Wazuh's Shuffle integration

import json
import os
import sys
import time

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7
ERR_CONNECTION = 8

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'
DEBUG_FILE = f'{pwd}/logs/integrations_debug.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3

def debug(msg):
    """Log debug messages if enabled"""
    if debug_enabled:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(DEBUG_FILE, 'a') as f:
            f.write(f"[{timestamp}] {msg}\n")

def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(sys.argv) > 4 else '', args[5] if len(sys.argv) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        send_to_webhook(args)

    except Exception as e:
        debug(f"Error in main function: {str(e)}")
        raise

def send_to_webhook(args):
    """Process the alert and send to webhook"""
    debug('# Running custom-wazuh-webhook script')

    # Get alert file location and webhook URL from args
    alert_file_location = args[ALERT_INDEX]
    webhook_url = args[WEBHOOK_INDEX]
    
    debug(f"# Processing alert from: {alert_file_location}")
    debug(f"# Will send to webhook: {webhook_url}")

    # Load the alert file content
    try:
        with open(alert_file_location) as alert_file:
            alert_data = json.load(alert_file)
            debug(f"# Successfully loaded alert data: {alert_data.get('rule', {}).get('id')}")
    except FileNotFoundError:
        debug(f"# ERROR: Alert file not found: {alert_file_location}")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.JSONDecodeError as e:
        debug(f"# ERROR: Invalid JSON in alert file: {str(e)}")
        sys.exit(ERR_INVALID_JSON)

    # Send to webhook
    headers = {'Content-Type': 'application/json'}
    debug(f"# Sending alert to webhook: {webhook_url}")
    
    try:
        response = requests.post(webhook_url, headers=headers, json=alert_data, timeout=10)
        debug(f"# Response: {response.status_code} - {response.text}")
        
        if response.status_code >= 200 and response.status_code < 300:
            debug("# Successfully sent alert to webhook")
        else:
            debug(f"# Error: Webhook returned non-success status code: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        debug(f"# ERROR: Failed to send to webhook: {str(e)}")
        sys.exit(ERR_CONNECTION)

if __name__ == "__main__":
    main(sys.argv)
