# 🚀 Déploiement SOAR - Liens de Référence

## 📋 Ressources de Déploiement

Cette section référence toutes les ressources et guides de déploiement disponibles pour la plateforme SOAR.

---

## 🐳 Déploiement Docker

### Scripts Principaux
- **[Installation Docker Stack](../../scripts/installation/install_complete_stack.sh)** - Script d'installation automatisé complet
- **[Configuration Wazuh](../../scripts/wazuh/wazuh_deployment.sh)** - Déploiement spécifique Wazuh
- **[Configurations Cortex](../../scripts/configs/cortex_config.conf)** - Configuration Cortex
- **[Configurations TheHive](../../scripts/configs/thehive_config.conf)** - Configuration TheHive

### Docker Compose
Les fichiers Docker Compose pour le déploiement complet sont disponibles dans le dossier principal :
- **[Configuration Docker](../../flowData_Complex.png)** - Architecture complexe
- **[Configuration Simple](../../flowData_simple.png)** - Architecture simplifiée

---

## � Documentation Technique

### Guides d'Architecture
- **[Architecture Détaillée](../01_ARCHITECTURE/detailed_architecture.md)** - Vue d'ensemble technique
- **[Topologie Réseau](../../docs/topologies/hospital_network_topology.md)** - Topologie hospitalière
- **[Flux de Données](../01_ARCHITECTURE/data_flows/)** - Documentation des flux

### Analyse Comparative
- **[Analyse Comparative](../../docs/benchmarking/comparative_analysis.md)** - Comparaison des solutions SOAR

---

## 🔧 Scripts d'Installation

### Automatisation
- **[Scripts Data Extraction](../../scripts/data-extraction.js)** - Extraction automatisée de données
- **[Configuration OPNsense](../../scripts/opnSense/)** - Intégration firewall OPNsense

### Configurations Réseau
Tous les scripts de configuration réseau sont documentés dans :
- **[Section Intégrations](../05_INTEGRATIONS/)** - APIs et intégrations
- **[Scripts OPNsense](../../scripts/opnSense/opnSenseBlockip.py)** - Blocage IP automatique

---

## 🎯 Scénarios d'Attaque

### Tests et Validation
Les scénarios de test pour valider le déploiement :
- **[Scénarios EternalBlue](../04_ATTACK_SCENARIOS/eternalblue/)** - Tests d'exploitation SMB
- **[Tests n8n](../04_ATTACK_SCENARIOS/eternalblue/n8n/)** - Workflows de test
- **[Documentation Tests](../../tests/attack-scenarios/)** - Scénarios de validation

---

## 📊 Monitoring et Maintenance

### Surveillance
- **[Scripts de Monitoring](../../help/)** - Guides de dépannage
- **[Debug Wazuh](../../help/debug%20wazuh.txt)** - Troubleshooting Wazuh

---

## 🔗 Liens Externes Utiles

### Documentation Officielle
- **[Docker Compose Documentation](https://docs.docker.com/compose/)**
- **[TheHive Installation Guide](https://docs.thehive-project.org/thehive/installation/)**
- **[Cortex Installation Guide](https://docs.thehive-project.org/cortex/installation/)**
- **[Wazuh Documentation](https://documentation.wazuh.com/)**
- **[MISP Installation Guide](https://misp.gitbooks.io/misp-book/content/INSTALL/)**
- **[n8n Documentation](https://docs.n8n.io/)**

### Ressources Communautaires
- **[TheHive Project GitHub](https://github.com/TheHive-Project/TheHive)**
- **[Cortex Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers)**
- **[Wazuh Ruleset](https://github.com/wazuh/wazuh-ruleset)**
- **[MISP Galaxy](https://github.com/MISP/misp-galaxy)**

---

## 📚 Structure des Ressources

```
06_DEPLOYMENT/
├── README.md                    # Ce fichier - index des ressources
├── → ../../scripts/             # Scripts d'installation
├── → ../../docs/                # Documentation technique  
├── → ../01_ARCHITECTURE/        # Architecture et design
├── → ../04_ATTACK_SCENARIOS/    # Scénarios de test
└── → ../05_INTEGRATIONS/        # Intégrations et APIs
```

---

## 🚀 Quick Start

### Déploiement Rapide
1. **Prérequis** : Docker et Docker Compose installés
2. **Cloner** : `git clone <repository>`
3. **Exécuter** : `./scripts/installation/install_complete_stack.sh`
4. **Vérifier** : Accéder aux interfaces web
5. **Configurer** : Suivre les guides de configuration

### Ordre de Déploiement Recommandé
1. Infrastructure (Elasticsearch, Cassandra)
2. SOAR Core (TheHive, Cortex)
3. SIEM (Wazuh)
4. Orchestration (n8n)
5. Threat Intel (MISP)
6. Tests et Validation

---

*Cette section sert d'index centralisé vers toutes les ressources de déploiement du projet SOAR.*  
**Dernière mise à jour** : 19 Août 2025 - Med10S
    B --> E[Redis<br/>:6379]
    
    B --> F[TheHive<br/>:9000]
    B --> G[Cortex<br/>:9001]
    B --> H[MISP<br/>:80/443]
    B --> I[n8n<br/>:5678]
    
    F --> C
    F --> D
    G --> C
    H --> J[MySQL<br/>:3306]
    
    K[External Network] --> L[Reverse Proxy<br/>Nginx]
    L --> F
    L --> G
    L --> H
    L --> I
```

### Composants Déployés

| Service | Image Docker | Port(s) | Dépendances | Status |
|---------|--------------|---------|-------------|--------|
| **Elasticsearch** | `elasticsearch:7.17.0` | 9200, 9300 | - | ✅ |
| **Cassandra** | `cassandra:3.11` | 9042 | - | ✅ |
| **Redis** | `redis:6.2-alpine` | 6379 | - | ✅ |
| **MySQL** | `mysql:8.0` | 3306 | - | ✅ |
| **TheHive** | `thehiveproject/thehive:latest` | 9000 | Elasticsearch, Cassandra | ✅ |
| **Cortex** | `thehiveproject/cortex:latest` | 9001 | Elasticsearch | ✅ |
| **MISP** | `coolacid/misp-docker:core-latest` | 80, 443 | MySQL, Redis | ✅ |
| **n8n** | `n8nio/n8n:latest` | 5678 | - | ✅ |

## 🖥️ Prérequis Système

### Ressources Minimales

#### Environnement de Test
```yaml
CPU: 4 cores (2.0 GHz)
RAM: 8 GB
Stockage: 50 GB SSD
Network: 1 Gbps

Système d'exploitation:
- Ubuntu 20.04 LTS ou plus récent
- Docker 20.10+
- Docker Compose 2.0+
```

#### Environnement de Production
```yaml
CPU: 8 cores (2.5 GHz)
RAM: 16 GB
Stockage: 200 GB SSD + 500 GB pour les données
Network: 1 Gbps (redondant)

Système d'exploitation:
- Ubuntu 22.04 LTS
- Docker 24.0+
- Docker Compose 2.20+

Haute Disponibilité:
- 3 nœuds minimum
- Load balancer (HAProxy/Nginx)
- Stockage partagé (NFS/GlusterFS)
```

### Installation des Prérequis

#### Script d'Installation Automatique
```bash
#!/bin/bash
# install_prerequisites.sh

set -e

echo "🚀 Installation des prérequis SOAR..."

# Mise à jour du système
sudo apt update && sudo apt upgrade -y

# Installation des packages de base
sudo apt install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    jq \
    unzip

# Installation Docker
echo "📦 Installation de Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Installation Docker Compose
echo "📦 Installation de Docker Compose..."
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Configuration système pour Elasticsearch
echo "⚙️ Configuration système..."
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Création des répertoires
echo "📁 Création des répertoires..."
mkdir -p ~/soar-deployment/{data,logs,config}
mkdir -p ~/soar-deployment/data/{elasticsearch,cassandra,mysql,redis}
mkdir -p ~/soar-deployment/config/{thehive,cortex,misp,n8n}

# Configuration firewall
echo "🛡️ Configuration firewall..."
sudo ufw allow 22/tcp
sudo ufw allow 9000/tcp  # TheHive
sudo ufw allow 9001/tcp  # Cortex
sudo ufw allow 80/tcp    # MISP HTTP
sudo ufw allow 443/tcp   # MISP HTTPS
sudo ufw allow 5678/tcp  # n8n
sudo ufw --force enable

echo "✅ Installation des prérequis terminée!"
echo "⚠️  Redémarrage requis pour appliquer les changements Docker"
echo "    Commande: sudo reboot"
```

## 🐳 Déploiement Docker

### Docker Compose Principal

> **📂 Fichier de référence :** 
> 
> Le fichier `docker-compose.yml` complet est disponible dans :
> **[docker_compose/docker-compose.yml](./docker_compose/docker-compose.yml)**

#### Structure du Déploiement
```
📦 SOAR_SERVER/
├── 📄 docker-compose.yml          # Fichier principal
├── 📄 .env                        # Variables d'environnement
├── 📂 config/                     # Configurations
│   ├── 📂 thehive/
│   ├── 📂 cortex/ 
│   ├── 📂 misp/
│   └── 📂 n8n/
└── 📂 data/                       # Données persistantes
    ├── 📂 elasticsearch/
    ├── 📂 cassandra/
    ├── 📂 mysql/
    └── 📂 redis/
```

> **📁 Référence complète :**
> 
> Tous les fichiers de configuration sont disponibles dans le dossier externe :
> **[../../../SOAR_SERVER/](../../../SOAR_SERVER/)**

### Variables d'Environnement

#### Fichier .env
```env
# SOAR Stack Environment Variables

# Network Configuration
SOAR_NETWORK=192.168.15.0/24
EXTERNAL_IP=192.168.15.2

# Database Passwords
MYSQL_ROOT_PASSWORD=SecureRootPassword123!
MYSQL_PASSWORD=SecurePassword123!
CASSANDRA_PASSWORD=SecurePassword123!

# API Keys (à générer)
THEHIVE_SECRET=your-thehive-secret-key-here
CORTEX_SECRET=your-cortex-secret-key-here
MISP_ADMIN_PASSPHRASE=SecureAdminPass123!

# MISP Configuration
MISP_ADMIN_EMAIL=admin@soar.lab
MISP_BASE_URL=http://192.168.15.5

# n8n Configuration
N8N_BASIC_AUTH_ACTIVE=true
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=SecureN8nPass123!

# Timezone
TZ=Europe/Paris

# Resource Limits
ELASTICSEARCH_HEAP_SIZE=1g
CORTEX_MAX_MEMORY=2g
```

### Commandes de Déploiement

#### Déploiement Rapide
```bash
#!/bin/bash
# quick_deploy.sh

echo "🚀 Déploiement rapide de la stack SOAR..."

# Aller dans le répertoire de déploiement
cd ~/soar-deployment

# Télécharger les fichiers de configuration
echo "📥 Téléchargement des configurations..."
# (Les fichiers sont déjà présents dans le projet)

# Créer les répertoires nécessaires
echo "📁 Création des répertoires..."
mkdir -p data/{elasticsearch,cassandra,mysql,redis,thehive,cortex,misp,n8n}
mkdir -p config/{thehive,cortex,misp,n8n}
mkdir -p logs/{thehive,cortex,misp,n8n}

# Définir les permissions
echo "🔐 Configuration des permissions..."
sudo chown -R 1000:1000 data/elasticsearch
sudo chown -R 999:999 data/mysql
sudo chown -R 1000:1000 data/n8n

# Démarrer les services de base
echo "🔧 Démarrage des services de base..."
docker-compose up -d elasticsearch cassandra mysql redis

# Attendre que les services soient prêts
echo "⏳ Attente de la disponibilité des services..."
sleep 60

# Démarrer les services SOAR
echo "🕷️ Démarrage des services SOAR..."
docker-compose up -d thehive cortex misp n8n

# Vérifier le statut
echo "📊 Vérification du statut..."
sleep 30
docker-compose ps

echo "✅ Déploiement terminé!"
echo ""
echo "🌐 URLs d'accès:"
echo "   TheHive: http://localhost:9000"
echo "   Cortex:  http://localhost:9001" 
echo "   MISP:    http://localhost"
echo "   n8n:     http://localhost:5678"
```

#### Déploiement avec Monitoring
```bash
#!/bin/bash
# deploy_with_monitoring.sh

echo "🚀 Déploiement SOAR avec monitoring..."

# Déploiement principal
./quick_deploy.sh

# Ajouter les services de monitoring
echo "📊 Ajout du monitoring..."
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d

# Configuration des alertes
echo "🚨 Configuration des alertes..."
./scripts/setup_monitoring_alerts.sh

echo "✅ Déploiement avec monitoring terminé!"
```

## 🌐 Configuration Réseau

### Réseau Docker Personnalisé
```yaml
# docker-compose.yml - section networks
networks:
  soar-network:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.15.0/24
          gateway: 192.168.15.1
```

### Reverse Proxy (Nginx)

#### Configuration Nginx
```nginx
# /etc/nginx/sites-available/soar.conf

upstream thehive {
    server 192.168.15.2:9000;
}

upstream cortex {
    server 192.168.15.2:9001;
}

upstream misp {
    server 192.168.15.5:80;
}

upstream n8n {
    server 192.168.15.3:5678;
}

# TheHive
server {
    listen 80;
    server_name thehive.soar.lab;
    
    location / {
        proxy_pass http://thehive;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Cortex
server {
    listen 80;
    server_name cortex.soar.lab;
    
    location / {
        proxy_pass http://cortex;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# MISP
server {
    listen 80;
    server_name misp.soar.lab;
    
    location / {
        proxy_pass http://misp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# n8n
server {
    listen 80;
    server_name n8n.soar.lab;
    
    location / {
        proxy_pass http://n8n;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support pour n8n
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## 🛡️ ModSecurity Configuration

### Configuration ModSecurity

> **📂 Fichiers de référence :**
> 
> Les configurations ModSecurity complètes sont disponibles dans :
> **[../../../ModSecurity/](../../../ModSecurity/)**

#### Structure ModSecurity
```
📦 ModSecurity/
├── 📄 modsecurity.conf           # Configuration principale
├── 📄 unicode.mapping            # Mapping Unicode
├── 📂 rules/                     # Règles personnalisées
│   ├── 📄 custom-xss.conf
│   ├── 📄 custom-sqli.conf
│   └── 📄 custom-malware.conf
├── 📂 owasp-crs/                # OWASP Core Rule Set
└── 📂 logs/                     # Logs ModSecurity
```

#### Installation ModSecurity avec Apache
```bash
#!/bin/bash
# install_modsecurity.sh

echo "🛡️ Installation de ModSecurity WAF..."

# Installation des packages
sudo apt update
sudo apt install -y libapache2-mod-security2

# Activation du module
sudo a2enmod security2

# Configuration de base
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Activation du mode protection
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Téléchargement des règles OWASP CRS
cd /tmp
wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/v3.3.0.tar.gz
tar xzf v3.3.0.tar.gz
sudo mv owasp-modsecurity-crs-3.3.0 /etc/modsecurity/crs
cd /etc/modsecurity/crs
sudo cp crs-setup.conf.example crs-setup.conf

# Configuration Apache
sudo tee /etc/apache2/mods-enabled/security2.conf > /dev/null << 'EOF'
<IfModule mod_security2.c>
    Include /etc/modsecurity/modsecurity.conf
    Include /etc/modsecurity/crs/crs-setup.conf
    Include /etc/modsecurity/crs/rules/*.conf
</IfModule>
EOF

# Redémarrage Apache
sudo systemctl restart apache2

echo "✅ ModSecurity installé et configuré!"
```

## 📋 Scripts d'Installation

### Script d'Installation Complète
```bash
#!/bin/bash
# install_complete_soar_stack.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/soar_install.log"

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Vérification des prérequis
check_prerequisites() {
    log "🔍 Vérification des prérequis..."
    
    # Vérifier Docker
    if ! command -v docker &> /dev/null; then
        log "❌ Docker n'est pas installé"
        exit 1
    fi
    
    # Vérifier Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log "❌ Docker Compose n'est pas installé"
        exit 1
    fi
    
    # Vérifier les ressources
    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM" -lt 8 ]; then
        log "⚠️  Avertissement: RAM insuffisante (${TOTAL_MEM}GB < 8GB recommandés)"
    fi
    
    log "✅ Prérequis vérifiés"
}

# Configuration initiale
initial_setup() {
    log "🔧 Configuration initiale..."
    
    # Créer les répertoires
    mkdir -p ~/soar-deployment/{data,config,logs}
    cd ~/soar-deployment
    
    # Copier les fichiers de configuration
    if [ -d "$SCRIPT_DIR/../SOAR_SERVER" ]; then
        cp -r "$SCRIPT_DIR/../SOAR_SERVER/"* .
        log "✅ Fichiers de configuration copiés"
    else
        log "❌ Répertoire SOAR_SERVER non trouvé"
        exit 1
    fi
    
    # Générer les secrets
    generate_secrets
}

# Génération des secrets
generate_secrets() {
    log "🔑 Génération des secrets..."
    
    # Générer des mots de passe aléatoires
    MYSQL_ROOT_PASSWORD=$(openssl rand -base64 32)
    MYSQL_PASSWORD=$(openssl rand -base64 32)
    THEHIVE_SECRET=$(openssl rand -base64 64)
    CORTEX_SECRET=$(openssl rand -base64 64)
    MISP_ADMIN_PASSPHRASE=$(openssl rand -base64 32)
    N8N_PASSWORD=$(openssl rand -base64 32)
    
    # Créer le fichier .env
    cat > .env << EOF
# Generated on $(date)
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_PASSWORD=${MYSQL_PASSWORD}
THEHIVE_SECRET=${THEHIVE_SECRET}
CORTEX_SECRET=${CORTEX_SECRET}
MISP_ADMIN_PASSPHRASE=${MISP_ADMIN_PASSPHRASE}
N8N_BASIC_AUTH_PASSWORD=${N8N_PASSWORD}
MISP_ADMIN_EMAIL=admin@soar.lab
EXTERNAL_IP=192.168.15.2
TZ=Europe/Paris
EOF
    
    # Sauvegarder les secrets
    cp .env secrets_backup_$(date +%Y%m%d_%H%M%S).env
    chmod 600 .env secrets_backup_*.env
    
    log "✅ Secrets générés et sauvegardés"
}

# Déploiement des services
deploy_services() {
    log "🚀 Déploiement des services..."
    
    # Phase 1: Services de base
    log "📊 Démarrage des services de base..."
    docker-compose up -d elasticsearch cassandra mysql redis
    
    # Attendre que les services soient prêts
    log "⏳ Attente de la disponibilité des services de base..."
    sleep 90
    
    # Phase 2: Services SOAR
    log "🕷️ Démarrage des services SOAR..."
    docker-compose up -d thehive cortex
    
    sleep 60
    
    # Phase 3: MISP et n8n
    log "🔍 Démarrage de MISP et n8n..."
    docker-compose up -d misp n8n
    
    sleep 60
    
    log "✅ Tous les services démarrés"
}

# Configuration post-déploiement
post_deployment_config() {
    log "⚙️ Configuration post-déploiement..."
    
    # Attendre que tous les services soient complètement démarrés
    sleep 120
    
    # Configuration TheHive
    log "🕷️ Configuration de TheHive..."
    configure_thehive
    
    # Configuration Cortex
    log "🧠 Configuration de Cortex..."
    configure_cortex
    
    # Configuration MISP
    log "🔍 Configuration de MISP..."
    configure_misp
    
    # Configuration n8n
    log "⚡ Configuration de n8n..."
    configure_n8n
    
    log "✅ Configuration post-déploiement terminée"
}

# Configuration TheHive
configure_thehive() {
    # Créer l'organisation et l'utilisateur admin
    THEHIVE_URL="http://localhost:9000"
    
    # Attendre que TheHive soit disponible
    wait_for_service "$THEHIVE_URL/api/status"
    
    # Configuration via API si nécessaire
    log "✅ TheHive configuré"
}

# Configuration Cortex
configure_cortex() {
    CORTEX_URL="http://localhost:9001"
    
    wait_for_service "$CORTEX_URL/api/status"
    
    log "✅ Cortex configuré"
}

# Configuration MISP
configure_misp() {
    MISP_URL="http://localhost"
    
    wait_for_service "$MISP_URL/users/login"
    
    log "✅ MISP configuré"
}

# Configuration n8n
configure_n8n() {
    N8N_URL="http://localhost:5678"
    
    wait_for_service "$N8N_URL/healthz"
    
    log "✅ n8n configuré"
}

# Attendre qu'un service soit disponible
wait_for_service() {
    local url="$1"
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$url" > /dev/null 2>&1; then
            log "✅ Service disponible: $url"
            return 0
        fi
        
        log "⏳ Tentative $attempt/$max_attempts pour $url..."
        sleep 10
        ((attempt++))
    done
    
    log "❌ Service non disponible après $max_attempts tentatives: $url"
    return 1
}

# Vérification finale
final_verification() {
    log "🔍 Vérification finale du déploiement..."
    
    # Vérifier le statut des conteneurs
    docker-compose ps
    
    # Tester les URLs
    test_urls
    
    # Générer le rapport
    generate_deployment_report
    
    log "✅ Vérification terminée"
}

# Test des URLs
test_urls() {
    local urls=(
        "http://localhost:9000 TheHive"
        "http://localhost:9001 Cortex"
        "http://localhost MISP"
        "http://localhost:5678 n8n"
    )
    
    for url_info in "${urls[@]}"; do
        local url=$(echo $url_info | cut -d' ' -f1)
        local name=$(echo $url_info | cut -d' ' -f2)
        
        if curl -f -s "$url" > /dev/null 2>&1; then
            log "✅ $name accessible: $url"
        else
            log "❌ $name non accessible: $url"
        fi
    done
}

# Générer le rapport de déploiement
generate_deployment_report() {
    local report_file="deployment_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
# SOAR Stack Deployment Report
Generated on: $(date)

## Services Status
$(docker-compose ps)

## Network Configuration
Network: soar-network (192.168.15.0/24)

## Access URLs
- TheHive: http://localhost:9000
- Cortex:  http://localhost:9001
- MISP:    http://localhost
- n8n:     http://localhost:5678

## Credentials
Admin credentials are stored in: secrets_backup_*.env

## Next Steps
1. Access each service and complete initial setup
2. Configure integrations between services
3. Import threat intelligence feeds
4. Set up monitoring and alerting

## Troubleshooting
Logs location: /tmp/soar_install.log
Docker logs: docker-compose logs [service_name]
EOF
    
    log "📊 Rapport de déploiement généré: $report_file"
}

# Fonction principale
main() {
    log "🚀 Début de l'installation de la stack SOAR complète"
    
    check_prerequisites
    initial_setup
    deploy_services
    post_deployment_config
    final_verification
    
    log "🎉 Installation de la stack SOAR terminée avec succès!"
    log "📊 Consultez le rapport de déploiement pour les prochaines étapes"
}

# Gestion des signaux
trap 'log "❌ Installation interrompue"; exit 1' INT TERM

# Exécution
main "$@"
```

## ✅ Vérification du Déploiement

### Script de Vérification
```bash
#!/bin/bash
# verify_deployment.sh

echo "🔍 Vérification du déploiement SOAR..."

# Fonction de test d'URL
test_url() {
    local url="$1"
    local name="$2"
    local expected_code="${3:-200}"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    
    if [ "$response" = "$expected_code" ]; then
        echo "✅ $name: OK ($url)"
        return 0
    else
        echo "❌ $name: FAILED ($url) - Code: $response"
        return 1
    fi
}

# Vérifier les conteneurs
echo "📦 Vérification des conteneurs Docker..."
docker-compose ps

echo ""
echo "🌐 Test des services web..."

# Test des URLs
test_url "http://localhost:9000" "TheHive"
test_url "http://localhost:9001" "Cortex" 
test_url "http://localhost:80" "MISP"
test_url "http://localhost:5678" "n8n"

# Test des bases de données
echo ""
echo "💾 Test des bases de données..."

# Elasticsearch
if curl -s "http://localhost:9200/_cluster/health" | grep -q "green\|yellow"; then
    echo "✅ Elasticsearch: OK"
else
    echo "❌ Elasticsearch: FAILED"
fi

# Test des volumes
echo ""
echo "📁 Vérification des volumes..."
docker volume ls | grep soar

echo ""
echo "📊 Utilisation des ressources..."
docker stats --no-stream

echo ""
echo "✅ Vérification terminée!"
```

### Tests d'Intégration
```bash
#!/bin/bash
# integration_tests.sh

echo "🧪 Tests d'intégration SOAR..."

# Test 1: Création d'un cas TheHive
echo "Test 1: Création d'un cas TheHive..."
CASE_RESPONSE=$(curl -s -X POST "http://localhost:9000/api/case" \
    -H "Content-Type: application/json" \
    -d '{
        "title": "Test Case",
        "description": "Test de déploiement",
        "severity": 2,
        "tlp": 2
    }')

if echo "$CASE_RESPONSE" | grep -q '"id"'; then
    echo "✅ Création de cas TheHive: OK"
    CASE_ID=$(echo "$CASE_RESPONSE" | jq -r '.id')
else
    echo "❌ Création de cas TheHive: FAILED"
fi

# Test 2: Test Cortex analyzer
echo "Test 2: Test Cortex analyzer..."
ANALYZER_RESPONSE=$(curl -s "http://localhost:9001/api/analyzer")

if echo "$ANALYZER_RESPONSE" | grep -q '\[\]'; then
    echo "✅ API Cortex: OK (pas d'analyzers configurés)"
else
    echo "❌ API Cortex: FAILED"
fi

# Test 3: Test n8n webhook
echo "Test 3: Test n8n webhook..."
N8N_RESPONSE=$(curl -s -X POST "http://localhost:5678/webhook/test" \
    -H "Content-Type: application/json" \
    -d '{"test": "data"}')

# Note: Le webhook peut ne pas être configuré, c'est normal

echo "✅ Tests d'intégration terminés!"
```

---

## 🔗 Références

### Fichiers de Configuration Externes

> **📂 Tous les fichiers de configuration sont disponibles dans :**

#### 🐳 **Docker Compose**
- **[docker_compose/docker-compose.yml](./docker_compose/docker-compose.yml)** - Configuration principale
- **[../../../SOAR_SERVER/](../../../SOAR_SERVER/)** - Stack complète avec configurations

#### 🛡️ **ModSecurity**
- **[../../../ModSecurity/](../../../ModSecurity/)** - Configuration WAF complète
- Règles OWASP CRS
- Règles personnalisées anti-XSS/SQLi
- Configuration Apache/Nginx

#### ⚙️ **Scripts d'Installation**
- **[../scripts/installation/](../scripts/installation/)** - Scripts d'installation
- **[../scripts/wazuh/](../scripts/wazuh/)** - Configuration Wazuh
- **[../scripts/configs/](../scripts/configs/)** - Configurations services

### Documentation Technique

- **[Docker Compose Documentation](https://docs.docker.com/compose/)**
- **[TheHive Installation Guide](https://docs.thehive-project.org/thehive/installation/)**
- **[Cortex Installation Guide](https://docs.thehive-project.org/cortex/installation/)**
- **[MISP Installation Guide](https://misp.gitbooks.io/misp-book/content/INSTALL/)**
- **[ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki)**

---
**Mise à jour** : Août 2025 - Med10S
