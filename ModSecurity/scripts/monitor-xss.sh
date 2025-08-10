#!/bin/bash

# Script de monitoring XSS pour n8n webhook
# Créé par Med10S - 2025-08-08

LOG_FILE="/var/log/apache2/modsec_audit.log"
WEBHOOK_URL="http://192.168.15.3:5678/webhook/modsecurity-xss"
LAST_POSITION_FILE="/tmp/modsec_last_position"

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Démarrage du moniteur XSS ModSecurity${NC}"
echo -e "${YELLOW}📡 Webhook URL: $WEBHOOK_URL${NC}"

# Fonction pour envoyer l'alerte via webhook
send_webhook() {
    local alert_data="$1"
    
    # Création du payload JSON pour n8n
    webhook_payload=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "source": "ModSecurity-WAF",
    "alert_type": "XSS_Detection",
    "severity": "HIGH",
    "raw_log": $alert_data,
    "waf_engine": "ModSecurity",
    "detection_method": "WAF_Rule",
    "environment": "SOAR-Lab",
    "analyst": "Med10S"
}
EOF
)
    
    # Envoi vers n8n
    curl -X POST \
         -H "Content-Type: application/json" \
         -H "X-Source: ModSecurity-WAF" \
         -H "X-Alert-Type: XSS" \
         -d "$webhook_payload" \
         "$WEBHOOK_URL" \
         --max-time 10 \
         --silent \
         --show-error
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Alerte XSS envoyée vers n8n${NC}"
    else
        echo -e "${RED}❌ Erreur envoi webhook${NC}"
    fi
}

# Fonction pour analyser les logs XSS
analyze_xss_log() {
    local log_line="$1"
    
    # Vérification si c'est une alerte XSS
    if echo "$log_line" | grep -qi "xss\|script\|javascript\|onerror\|onload"; then
        echo -e "${RED}🚨 ALERTE XSS DÉTECTÉE!${NC}"
        
        # Extraction des informations clés
        client_ip=$(echo "$log_line" | jq -r '.transaction.client_ip // "unknown"' 2>/dev/null)
        rule_id=$(echo "$log_line" | jq -r '.messages[0].details.ruleId // "unknown"' 2>/dev/null)
        attack_payload=$(echo "$log_line" | jq -r '.transaction.request.body // .transaction.request.uri // "unknown"' 2>/dev/null)
        
        echo -e "${YELLOW}📍 IP Client: $client_ip${NC}"
        echo -e "${YELLOW}🔍 Règle ID: $rule_id${NC}"
        echo -e "${YELLOW}💉 Payload: ${attack_payload:0:100}...${NC}"
        
        # Envoi du webhook
        send_webhook "$log_line"
        
        return 0
    fi
    return 1
}

# Initialisation de la position dans le fichier
if [ ! -f "$LAST_POSITION_FILE" ]; then
    echo "0" > "$LAST_POSITION_FILE"
fi

# Monitoring en temps réel
while true; do
    if [ -f "$LOG_FILE" ]; then
        last_pos=$(cat "$LAST_POSITION_FILE")
        current_size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null)
        
        if [ "$current_size" -gt "$last_pos" ]; then
            # Lecture des nouvelles lignes
            tail -c +$((last_pos + 1)) "$LOG_FILE" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    # Tentative d'analyse JSON
                    if echo "$line" | jq . >/dev/null 2>&1; then
                        analyze_xss_log "$line"
                    else
                        # Analyse de log standard Apache
                        if echo "$line" | grep -qi "modsecurity.*xss\|blocked.*script"; then
                            echo -e "${RED}🚨 ALERTE XSS (format standard)${NC}"
                            # Création d'un JSON simplifié
                            simple_json=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "raw_message": "$line",
    "detection_type": "standard_log"
}
EOF
)
                            send_webhook "$simple_json"
                        fi
                    fi
                fi
            done
            
            # Mise à jour de la position
            echo "$current_size" > "$LAST_POSITION_FILE"
        fi
    else
        echo -e "${YELLOW}⏳ En attente du fichier de log...${NC}"
    fi
    
    sleep 2
done