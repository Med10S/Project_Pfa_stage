#!/bin/bash

# Simple ModSecurity XSS log monitor with n8n webhook integration and rich payload
# By Med10S - 2025-08-10

LOG_FILE="/var/log/apache2/modsec_audit.log"
WEBHOOK_URL="${N8N_WEBHOOK_URL:-http://your-n8n-instance:5678/webhook/modsecurity-xss}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}🚀 Simple ModSecurity XSS log monitor with n8n webhook${NC}"
echo -e "${BLUE}📡 Webhook n8n: $WEBHOOK_URL${NC}"

send_xss_alert() {
  local log_entry="$1"

  # Extract fields
  local timestamp=$(echo "$log_entry" | jq -r '.transaction.time_stamp // "unknown"')
  local client_ip=$(echo "$log_entry" | jq -r '.transaction.client_ip // "unknown"')
  local client_port=$(echo "$log_entry" | jq -r '.transaction.client_port // "unknown"')
  local host_ip=$(echo "$log_entry" | jq -r '.transaction.host_ip // "unknown"')
  local host_port=$(echo "$log_entry" | jq -r '.transaction.host_port // "unknown"')
  local unique_id=$(echo "$log_entry" | jq -r '.transaction.unique_id // "unknown"')
  local server_id=$(echo "$log_entry" | jq -r '.transaction.server_id // "unknown"')
  local method=$(echo "$log_entry" | jq -r '.transaction.request.method // "unknown"')
  local http_version=$(echo "$log_entry" | jq -r '.transaction.request.http_version // "unknown"')
  local uri=$(echo "$log_entry" | jq -r '.transaction.request.uri // "unknown"')
  local user_agent=$(echo "$log_entry" | jq -r '.transaction.request.headers."User-Agent" // "unknown"')
  local referer=$(echo "$log_entry" | jq -r '.transaction.request.headers.Referer // "unknown"')
  local http_code=$(echo "$log_entry" | jq -r '.transaction.response.http_code // "unknown"')
  local rule_id=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.ruleId // "unknown"')
  local rule_message=$(echo "$log_entry" | jq -r '.transaction.messages[0].message // "unknown"')
  local match_data=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.data // "unknown"')
  local rule_file=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.file // "unknown"')
  local line_number=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.lineNumber // "unknown"')
  local rule_severity=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.severity // "2"')
  local modsec_version=$(echo "$log_entry" | jq -r '.producer.modsecurity // "unknown"')
  local connector_version=$(echo "$log_entry" | jq -r '.producer.connector // "unknown"')

  # Decode URI payload
  local attack_payload=$(echo "$uri" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null || echo "$uri")
  local severity="HIGH"
  local xss_type="reflected_script_injection"
  local attack_vector="script_tag"

  # Classify attack type based on payload
  if echo "$attack_payload" | grep -Eqi "<script.*?>.*?</script>"; then
    xss_type="reflected_script_injection"
    attack_vector="script_tag"
    severity="CRITICAL"
  elif echo "$attack_payload" | grep -Eqi "javascript:"; then
    xss_type="javascript_protocol_injection"
    attack_vector="javascript_protocol"
    severity="HIGH"
  elif echo "$attack_payload" | grep -Eqi "onerror|onload|onclick|onmouseover|onfocus"; then
    xss_type="event_handler_injection"
    attack_vector="event_handler"
    severity="HIGH"
  elif echo "$attack_payload" | grep -Eqi "<iframe|<embed|<object"; then
    xss_type="iframe_injection"
    attack_vector="iframe_embed"
    severity="HIGH"
  elif echo "$attack_payload" | grep -Eqi "alert|prompt|confirm"; then
    xss_type="javascript_function_injection"
    attack_vector="js_function"
    severity="HIGH"
  fi

  local mitigation_status="unknown"
  if [ "$http_code" = "403" ]; then
    mitigation_status="blocked"
  elif [ "$http_code" = "200" ]; then
    mitigation_status="allowed"
    severity="CRITICAL"
  fi

  # Build payload
  local n8n_payload=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "source": "ModSecurity-WAF",
    "alert_type": "XSS_Detection",
    "severity": "$severity",
    "xss_classification": "$xss_type",
    "attack_vector": "$attack_vector",
    "transaction_details": {
        "unique_id": "$unique_id",
        "server_id": "$server_id",
        "client_ip": "$client_ip",
        "client_port": "$client_port",
        "host_ip": "$host_ip",
        "host_port": "$host_port",
        "http_method": "$method",
        "http_version": "$http_version",
        "uri": "$uri",
        "decoded_uri": "$(echo "$attack_payload" | head -c 500)",
        "user_agent": "$(echo "$user_agent" | head -c 200)",
        "referer": "$referer",
        "response_code": "$http_code"
    },
    "attack_details": {
        "rule_id": "$rule_id",
        "rule_message": "$rule_message",
        "match_data": "$(echo "$match_data" | head -c 300)",
        "rule_file": "$rule_file",
        "line_number": "$line_number",
        "rule_severity": "$rule_severity",
        "payload_length": $(echo "$attack_payload" | wc -c),
        "encoded_payload": "$(echo "$attack_payload" | base64 -w 0)"
    },
    "producer_info": {
        "modsecurity_version": "$modsec_version",
        "connector_version": "$connector_version"
    },
    "geolocation": {
        "ip": "$client_ip",
        "lookup_required": true
    },
    "mitigation": {
        "status": "$mitigation_status",
        "waf_engine": "ModSecurity",
        "action_required": "investigate",
        "blocked": $( [ "$mitigation_status" = "blocked" ] && echo "true" || echo "false" )
    },
    "raw_log": $log_entry,
    "analyst": "Med10S",
    "environment": "SOAR-Lab"
}
EOF
)

  echo -e "${YELLOW}📤 Sending XSS alert to n8n...${NC}"
  local resp=$(curl -X POST -H "Content-Type: application/json" -d "$n8n_payload" "$WEBHOOK_URL" --max-time 8 --silent --write-out "HTTP_CODE:%{http_code}")
  if echo "$resp" | grep -q "HTTP_CODE:200"; then
    echo -e "${GREEN}✅ XSS alert sent to n8n${NC}"
  else
    echo -e "${RED}❌ Error sending to n8n: $resp${NC}"
  fi
}

monitor_logs() {
  echo -e "${GREEN}🔄 Monitoring logs for XSS alerts...${NC}"
  tail -n0 -F "$LOG_FILE" 2>/dev/null | \
    grep --line-buffered "XSS Attack Detected and Blocked" | \
    while read -r entry; do
      # Validate JSON
      if echo "$entry" | jq . >/dev/null 2>&1; then
        send_xss_alert "$entry"
      else
        echo -e "${RED}❌ Invalid JSON log entry skipped${NC}"
      fi
    done
}

monitor_logs