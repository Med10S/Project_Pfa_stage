#!/bin/bash

# Processeur de logs ModSecurity pour Wazuh + n8n
# Par Med10S - 2025-08-09

LOG_FILE="/var/log/apache2/modsec_audit.log"
WEBHOOK_URL="${N8N_WEBHOOK_URL:-http://your-n8n-instance:5678/webhook/modsecurity-xss}"
WAZUH_API="${WAZUH_MANAGER_API:-http://your-wazuh-manager:55000}"
LAST_POSITION_FILE="/tmp/modsec_last_position"

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}🚀 Démarrage du processeur de logs ModSecurity${NC}"
echo -e "${BLUE}📡 Webhook n8n: $WEBHOOK_URL${NC}"
echo -e "${BLUE}🔍 Wazuh API: $WAZUH_API${NC}"

# Fonction pour envoyer vers n8n ET créer un événement Wazuh custom
process_xss_alert() {
    local log_entry="$1"
    local timestamp=$(echo "$log_entry" | jq -r '.transaction.time_stamp // "unknown"' 2>/dev/null)
    
    # Extraction des informations de l'alerte depuis le nouveau format
    local client_ip=$(echo "$log_entry" | jq -r '.transaction.client_ip // "unknown"' 2>/dev/null)
    local client_port=$(echo "$log_entry" | jq -r '.transaction.client_port // "unknown"' 2>/dev/null)
    local host_ip=$(echo "$log_entry" | jq -r '.transaction.host_ip // "unknown"' 2>/dev/null)
    local host_port=$(echo "$log_entry" | jq -r '.transaction.host_port // "unknown"' 2>/dev/null)
    local unique_id=$(echo "$log_entry" | jq -r '.transaction.unique_id // "unknown"' 2>/dev/null)
    local server_id=$(echo "$log_entry" | jq -r '.transaction.server_id // "unknown"' 2>/dev/null)
    local method=$(echo "$log_entry" | jq -r '.transaction.request.method // "unknown"' 2>/dev/null)
    local http_version=$(echo "$log_entry" | jq -r '.transaction.request.http_version // "unknown"' 2>/dev/null)
    local uri=$(echo "$log_entry" | jq -r '.transaction.request.uri // "unknown"' 2>/dev/null)
    local user_agent=$(echo "$log_entry" | jq -r '.transaction.request.headers."User-Agent" // "unknown"' 2>/dev/null)
    local referer=$(echo "$log_entry" | jq -r '.transaction.request.headers.Referer // "unknown"' 2>/dev/null)
    local http_code=$(echo "$log_entry" | jq -r '.transaction.response.http_code // "unknown"' 2>/dev/null)
    local rule_id=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.ruleId // "unknown"' 2>/dev/null)
    local rule_message=$(echo "$log_entry" | jq -r '.transaction.messages[0].message // "unknown"' 2>/dev/null)
    local match_data=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.data // "unknown"' 2>/dev/null)
    local rule_file=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.file // "unknown"' 2>/dev/null)
    local line_number=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.lineNumber // "unknown"' 2>/dev/null)
    local rule_severity=$(echo "$log_entry" | jq -r '.transaction.messages[0].details.severity // "2"' 2>/dev/null)
    local modsec_version=$(echo "$log_entry" | jq -r '.producer.modsecurity // "unknown"' 2>/dev/null)
    local connector_version=$(echo "$log_entry" | jq -r '.producer.connector // "unknown"' 2>/dev/null)
    
    # Extraction du payload XSS depuis l'URI décodée
    local attack_payload=$(echo "$uri" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))" 2>/dev/null || echo "$uri")
    local severity="HIGH"
    
    # Classification du type d'attaque XSS basée sur le payload et les détails
    local xss_type="unknown"
    local attack_vector="unknown"
    
    # Détermination du type d'attaque basée sur le payload décodé
    if echo "$attack_payload" | grep -qi "<script.*>.*</script>"; then
        xss_type="reflected_script_injection"
        attack_vector="script_tag"
        severity="CRITICAL"
    elif echo "$attack_payload" | grep -qi "javascript:"; then
        xss_type="javascript_protocol_injection"
        attack_vector="javascript_protocol"
        severity="HIGH"
    elif echo "$attack_payload" | grep -qi "onerror\|onload\|onclick\|onmouseover\|onfocus"; then
        xss_type="event_handler_injection"
        attack_vector="event_handler"
        severity="HIGH"
    elif echo "$attack_payload" | grep -qi "<iframe\|<embed\|<object"; then
        xss_type="iframe_injection"
        attack_vector="iframe_embed"
        severity="HIGH"
    elif echo "$attack_payload" | grep -qi "alert\|prompt\|confirm"; then
        xss_type="javascript_function_injection"
        attack_vector="js_function"
        severity="HIGH"
    fi
    
    # Ajustement de la sévérité selon le code de réponse HTTP
    if [ "$http_code" = "403" ]; then
        local mitigation_status="blocked"
    elif [ "$http_code" = "200" ]; then
        local mitigation_status="allowed"
        severity="CRITICAL"  # Plus grave si l'attaque a passé
    else
        local mitigation_status="unknown"
    fi
    
    # Payload pour n8n (format enrichi et adapté au nouveau format)
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
        "encoded_payload": $(echo "$attack_payload" | base64 -w 0)
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
        "blocked": $([ "$mitigation_status" = "blocked" ] && echo "true" || echo "false")
    },
    "raw_log": $log_entry,
    "analyst": "Med10S",
    "environment": "SOAR-Lab"
}
EOF
)
    
    # Envoi vers n8n
    echo -e "${YELLOW}📤 Envoi vers n8n...${NC}"
    local n8n_response=$(curl -X POST \
         -H "Content-Type: application/json" \
         -H "X-Source: ModSecurity-WAF" \
         -H "X-Alert-Type: XSS" \
         -H "X-Severity: $severity" \
         -d "$n8n_payload" \
         "$WEBHOOK_URL" \
         --max-time 10 \
         --silent \
         --write-out "HTTP_CODE:%{http_code}")
    
    if echo "$n8n_response" | grep -q "HTTP_CODE:200"; then
        echo -e "${GREEN}✅ Alerte XSS envoyée vers n8n${NC}"
    else
        echo -e "${RED}❌ Erreur envoi n8n: $n8n_response${NC}"
    fi
    
    # Log structuré pour Wazuh (format custom enrichi)
    local wazuh_log=$(cat <<EOF
$(date '+%b %d %H:%M:%S') modsecurity-waf: XSS_ALERT: severity="$severity" client_ip="$client_ip:$client_port" host="$host_ip:$host_port" rule_id="$rule_id" xss_type="$xss_type" attack_vector="$attack_vector" payload_size=$(echo "$attack_payload" | wc -c) http_code="$http_code" mitigation="$mitigation_status" unique_id="$unique_id" user_agent="$(echo "$user_agent" | head -c 100)" analyst="Med10S"
EOF
)
    
    # Écriture dans un fichier de log que Wazuh peut surveiller
    echo "$wazuh_log" >> /var/log/apache2/modsecurity_custom_alerts.log
    
    echo -e "${BLUE}📝 Événement logué pour Wazuh${NC}"
    
    return 0
}

# Fonction de monitoring en temps réel
monitor_logs() {
    if [ ! -f "$LAST_POSITION_FILE" ]; then
        echo "0" > "$LAST_POSITION_FILE"
    fi
    
    while true; do
        if [ -f "$LOG_FILE" ]; then
            local last_pos=$(cat "$LAST_POSITION_FILE")
            local current_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo "0")
            
            if [ "$current_size" -gt "$last_pos" ]; then
                echo -e "${BLUE}📈 Nouveaux logs détectés (taille: $current_size, position: $last_pos)${NC}"
                
                # Lecture ligne par ligne des nouvelles données
                tail -c +$((last_pos + 1)) "$LOG_FILE" | while IFS= read -r line; do
                    if [ -n "$line" ]; then
                        echo -e "${YELLOW}🔍 Analyse de ligne: $(echo "$line" | head -c 100)...${NC}"
                        
                        # Vérification si c'est du JSON valide
                        if echo "$line" | jq . >/dev/null 2>&1; then
                            # Vérification si cette entrée a des messages ModSecurity
                            local messages_count=$(echo "$line" | jq -r '.transaction.messages | length' 2>/dev/null || echo "0")
                            
                            if [ "$messages_count" -gt "0" ]; then
                                echo -e "${GREEN}✅ JSON avec $messages_count message(s) trouvé${NC}"
                                
                                # Extraction des détails pour debugging
                                local rule_id=$(echo "$line" | jq -r '.transaction.messages[0].details.ruleId // "unknown"' 2>/dev/null)
                                local message_text=$(echo "$line" | jq -r '.transaction.messages[0].message // "unknown"' 2>/dev/null)
                                local client_ip=$(echo "$line" | jq -r '.transaction.client_ip // "unknown"' 2>/dev/null)
                                local uri=$(echo "$line" | jq -r '.transaction.request.uri // "unknown"' 2>/dev/null)
                                local http_code=$(echo "$line" | jq -r '.transaction.response.http_code // "unknown"' 2>/dev/null)
                                
                                echo -e "${BLUE}📊 Règle: $rule_id | Message: $message_text${NC}"
                                echo -e "${BLUE}🌐 IP: $client_ip | URI: $(echo "$uri" | head -c 50)... | Code: $http_code${NC}"
                                
                                # Vérification si c'est une alerte XSS
                                local is_xss_alert="no"
                                
                                # Vérification dans le message
                                if echo "$message_text" | grep -qi "xss\|script\|javascript\|injection"; then
                                    is_xss_alert="yes"
                                    echo -e "${RED}🎯 XSS détecté dans le message: $message_text${NC}"
                                fi
                                
                                # Vérification dans les données de règle
                                local rule_data=$(echo "$line" | jq -r '.transaction.messages[0].details.data // ""' 2>/dev/null)
                                if echo "$rule_data" | grep -qi "xss\|script\|alert\|onerror\|onload\|javascript"; then
                                    is_xss_alert="yes"
                                    echo -e "${RED}🎯 XSS détecté dans les données: $rule_data${NC}"
                                fi
                                
                                # Vérification dans l'URI
                                if echo "$uri" | grep -qi "script\|javascript\|alert\|onerror\|onload\|%3C.*%3E"; then
                                    is_xss_alert="yes"
                                    echo -e "${RED}🎯 XSS détecté dans URI: $uri${NC}"
                                fi
                                
                                # Vérification par ID de règle (nos règles custom)
                                if [[ "$rule_id" =~ ^(1001|1002|1003|1004)$ ]]; then
                                    is_xss_alert="yes"
                                    echo -e "${RED}🎯 XSS détecté par rule ID: $rule_id${NC}"
                                fi
                                
                                if [ "$is_xss_alert" = "yes" ]; then
                                    echo -e "${RED}🚨 ALERTE XSS CONFIRMÉE! (Format JSON ModSecurity)${NC}"
                                    process_xss_alert "$line"
                                else
                                    echo -e "${YELLOW}ℹ️ Alerte ModSecurity non-XSS: $message_text${NC}"
                                fi
                            else
                                echo -e "${YELLOW}📋 JSON sans message ModSecurity (requête normale)${NC}"
                            fi
                        else
                            echo -e "${YELLOW}📝 Format de log non-JSON, recherche de patterns...${NC}"
                            # Log format standard - recherche de patterns XSS
                            if echo "$line" | grep -qi "modsecurity.*xss\|blocked.*script\|attack.*javascript"; then
                                echo -e "${RED}🚨 ALERTE XSS (format standard)${NC}"
                                # Conversion en JSON simple pour traitement
                                local simple_json=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "raw_message": "$line",
    "detection_type": "standard_log",
    "transaction": {
        "client_ip": "$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)",
        "request": {
            "uri": "unknown",
            "body": "$(echo "$line" | sed 's/.*\] //')"
        }
    },
    "messages": [{
        "message": "XSS pattern detected in standard log",
        "details": {
            "ruleId": "standard_detection"
        }
    }]
}
EOF
)
                                process_xss_alert "$simple_json"
                            fi
                        fi
                    fi
                done
                
                # Mise à jour de la position
                echo "$current_size" > "$LAST_POSITION_FILE"
                echo -e "${GREEN}📌 Position mise à jour: $current_size${NC}"
            fi
        else
            echo -e "${YELLOW}⏳ En attente du fichier de log ModSecurity...${NC}"
        fi
        
        sleep 3
    done
}

# Démarrage du monitoring
echo -e "${GREEN}🔄 Démarrage du monitoring des logs...${NC}"
monitor_logs