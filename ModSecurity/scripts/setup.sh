#!/bin/bash

# Script d'installation SOAR ModSecurity avec support .env
# Par Med10S - 2025-08-09 00:33:04 UTC

set -euo pipefail

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Fonction d'affichage
print_status() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ❌ $1${NC}"
}

# Vérification des prérequis
check_requirements() {
    print_status "Vérification des prérequis..."
    
    # Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker n'est pas installé"
        exit 1
    fi
    
    # Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose n'est pas installé"
        exit 1
    fi
    
    # Fichier .env
    if [ ! -f ".env" ]; then
        print_warning "Fichier .env non trouvé, copie depuis .env.example"
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_warning "Veuillez éditer le fichier .env avant de continuer"
            exit 1
        else
            print_error "Fichier .env.example non trouvé"
            exit 1
        fi
    fi
    
    print_success "Prérequis vérifiés"
}

# Chargement des variables d'environnement
load_env() {
    print_status "Chargement des variables d'environnement..."
    
    if [ -f ".env" ]; then
        set -a
        source .env
        set +a
        print_success "Variables d'environnement chargées"
    else
        print_error "Fichier .env non trouvé"
        exit 1
    fi
}

# Création des répertoires
create_directories() {
    print_status "Création des répertoires..."
    
    mkdir -p {logs,logs/audit,ssl,backup,monitoring}
    mkdir -p {apache-config,modsecurity-config,wazuh-config,scripts}
    mkdir -p {test-payloads,n8n-workflows,documentation}
    mkdir -p database/init
    
    # Permissions
    chmod 755 logs logs/audit
    chmod 700 ssl backup
    chmod +x scripts/*.sh 2>/dev/null || true
    chmod +x scripts/*.py 2>/dev/null || true
    
    print_success "Répertoires créés"
}

# Génération des certificats SSL
generate_ssl() {
    print_status "Génération des certificats SSL..."
    
    if [ "${SSL_GENERATE_SELF_SIGNED:-true}" == "true" ] && [ ! -f "ssl/server.crt" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout ssl/server.key \
            -out ssl/server.crt \
            -subj "/C=${SSL_COUNTRY:-FR}/ST=${SSL_STATE:-Region}/L=${SSL_CITY:-City}/O=${SSL_ORGANIZATION:-SOAR-Lab}/OU=${SSL_ORGANIZATIONAL_UNIT:-Security}/CN=${SERVER_NAME:-modsecurity.local}"
        
        # Génération des paramètres DH
        openssl dhparam -out ssl/dhparam.pem 2048
        
        chmod 600 ssl/server.key ssl/dhparam.pem
        chmod 644 ssl/server.crt
        
        print_success "Certificats SSL générés"
    else
        print_warning "Certificats SSL déjà présents ou génération désactivée"
    fi
}

# Téléchargement des règles OWASP CRS
download_crs_rules() {
    print_status "Téléchargement des règles OWASP CRS..."
    
    if [ ! -d "owasp-crs" ]; then
        git clone https://github.com/coreruleset/coreruleset.git owasp-crs
        cp owasp-crs/rules/*.conf modsecurity-config/
        cp owasp-crs/crs-setup.conf.example modsecurity-config/crs-setup.conf
        print_success "Règles OWASP CRS téléchargées"
    else
        print_warning "Règles OWASP CRS déjà présentes"
    fi
}

# Génération des fichiers de configuration
generate_configs() {
    print_status "Génération des configurations..."
    
    # Substitution des variables d'environnement dans les templates
    for template in apache-config/*.conf wazuh-config/*.conf modsecurity-config/*.conf; do
        if [ -f "$template" ]; then
            envsubst < "$template" > "${template}.tmp" && mv "${template}.tmp" "$template"
        fi
    done
    
    print_success "Configurations générées"
}

# Validation de la configuration
validate_config() {
    print_status "Validation de la configuration..."
    
    # Validation Docker Compose
    if docker-compose config > /dev/null 2>&1; then
        print_success "Configuration Docker Compose valide"
    else
        print_error "Configuration Docker Compose invalide"
        docker-compose config
        exit 1
    fi
    
    # Validation des variables critiques
    local critical_vars=("WAZUH_MANAGER_IP" "N8N_WEBHOOK_URL" "THEHIVE_API_KEY" "CORTEX_API_KEY" "MISP_API_KEY")
    
    for var in "${critical_vars[@]}"; do
        if [ -z "${!var:-}" ] || [[ "${!var:-}" == *"CHANGE"* ]] || [[ "${!var:-}" == *"YOUR"* ]]; then
            print_warning "Variable critique non configurée: $var"
        fi
    done
}

# Création des services
create_services() {
    print_status "Création des services Docker..."
    
    # Build des images personnalisées
    if [ -f "scripts/Dockerfile.log-processor" ]; then
        docker-compose build log-processor
    fi
    
    # Création des volumes
    docker-compose up --no-start
    
    print_success "Services créés"
}

# Test de connectivité
test_connectivity() {
    print_status "Test de connectivité..."
    
    # Test Wazuh Manager
    if curl -s --connect-timeout 5 "${WAZUH_MANAGER_API:-http://localhost:55000}" > /dev/null; then
        print_success "Connexion Wazuh OK"
    else
        print_warning "Impossible de joindre Wazuh Manager à ${WAZUH_MANAGER_IP:-localhost}"
    fi
    
    # Test n8n
    local n8n_host=$(echo "${N8N_WEBHOOK_URL:-}" | sed 's|.*//||' | sed 's|:.*||')
    if [ -n "$n8n_host" ] && ping -c 1 "$n8n_host" > /dev/null 2>&1; then
        print_success "Connexion n8n OK"
    else
        print_warning "Impossible de joindre n8n"
    fi
}

# Fonction principale
main() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════╗
║         SOAR ModSecurity Lab Setup - Med10S           ║
║                   Version 1.0.0                      ║
║               2025-08-09 00:33:04 UTC                ║
╚═══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    check_requirements
    load_env
    create_directories
    generate_ssl
    download_crs_rules
    generate_configs
    validate_config
    create_services
    test_connectivity
    
    print_success "Installation terminée!"
    
    echo -e "${GREEN}"
    cat << EOF
╔═══════════════════════════════════════════════════════╗
║                   SETUP TERMINÉ                      ║
╠═══════════════════════════════════════════════════════╣
║ 🚀 Prochaines étapes:                                ║
║                                                       ║
║ 1. Vérifier .env avec vos configurations             ║
║ 2. Démarrer: docker-compose up -d                    ║
║ 3. Vérifier: docker-compose ps                       ║
║ 4. Tester: ./scripts/test-xss-payloads.sh            ║
║ 5. Logs: docker-compose logs -f                      ║
║                                                       ║
║ 📊 URLs importantes:                                  ║
║ • DVWA: http://localhost:${WEBAPP_PORT:-8080}                       ║
║ • WAF: http://localhost:${HTTP_PORT:-80}                            ║
║ • Monitoring: ./monitoring/healthcheck.sh            ║
║                                                       ║
║ 👨‍💻 Créé par: ${ANALYST_NAME:-Med10S}                               ║
║ 🏷️  Environnement: ${ENVIRONMENT:-development}                      ║
╚═══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Exécution
main "$@"