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
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    # Extraction des informations de l'alerte
    local client_ip=$(echo "$log_entry" | jq -r '.transaction.client_ip // "unknown"' 2>/dev/null)
    local rule_id=$(echo "$log_entry" | jq -r '.messages[0].details.ruleId // "unknown"' 2>/dev/null)
    local attack_payload=$(echo "$log_entry" | jq -r '.transaction.request.body // .transaction.request.uri // "unknown"' 2>/dev/null)
    local severity="HIGH"
    
    # Classification du type d'attaque XSS
    local xss_type="unknown"
    if echo "$attack_payload" | grep -qi "script.*>"; then
        xss_type="reflected_script_injection"
        severity="CRITICAL"
    elif echo "$attack_payload" | grep -qi "javascript:"; then
        xss_type="javascript_protocol_injection"
        severity="HIGH"
    elif echo "$attack_payload" | grep -qi "onerror\|onload\|onclick"; then
        xss_type="event_handler_injection"
        severity="HIGH"
    elif echo "$attack_payload" | grep -qi "iframe\|embed"; then
        xss_type="iframe_injection"
        severity="HIGH"
    fi
    
    # Payload pour n8n (format enrichi)
    local n8n_payload=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "source": "ModSecurity-WAF",
    "alert_type": "XSS_Detection",
    "severity": "$severity",
    "xss_classification": "$xss_type",
    "attack_details": {
        "client_ip": "$client_ip",
        "rule_id": "$rule_id",
        "payload": "$(echo "$attack_payload" | head -c 200)",
        "payload_length": $(echo "$attack_payload" | wc -c),
        "encoded_payload": $(echo "$attack_payload" | base64 -w 0)
    },
    "geolocation": {
        "ip": "$client_ip",
        "lookup_required": true
    },
    "mitigation": {
        "blocked": true,
        "waf_engine": "ModSecurity",
        "action_required": "investigate"
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
    
    # Log structuré pour Wazuh (format custom)
    local wazuh_log=$(cat <<EOF
$(date '+%b %d %H:%M:%S') modsecurity-waf: XSS_ALERT: severity="$severity" client_ip="$client_ip" rule_id="$rule_id" xss_type="$xss_type" payload_size=$(echo "$attack_payload" | wc -c) action="blocked" analyst="Med10S"
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
                # Lecture des nouvelles lignes
                tail -c +$((last_pos + 1)) "$LOG_FILE" | while IFS= read -r line; do
                    if [ -n "$line" ]; then
                        # Vérification si c'est du JSON valide
                        if echo "$line" | jq . >/dev/null 2>&1; then
                            # Vérification si c'est une alerte XSS
                            if echo "$line" | jq -r '.messages[]?.msg // ""' 2>/dev/null | grep -qi "xss\|script\|javascript\|onerror\|onload"; then
                                echo -e "${RED}🚨 ALERTE XSS DÉTECTÉE!${NC}"
                                process_xss_alert "$line"
                            fi
                        else
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
        "msg": "XSS pattern detected in standard log",
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