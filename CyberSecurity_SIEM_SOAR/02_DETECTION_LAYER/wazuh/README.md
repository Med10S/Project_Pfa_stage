# 📊 Configuration Wazuh SIEM  
## Security Information and Event Management

> **Wazuh Open Source SIEM Platform**  
> Collecte, analyse et corrélation d'événements sécurité  

---

## 📋 Table des Matières

- [Vue d'Ensemble](#-vue-densemble)
- [Architecture](#-architecture) 
- [Déploiement Docker](#-déploiement-docker)
- [Configuration](#-configuration)
- [Règles et Décodeurs](#-règles-et-décodeurs)
- [Intégrations](#-intégrations)
- [Alerting](#-alerting)
- [Monitoring](#-monitoring-et-performance)

---

## 🎯 Vue d'Ensemble

Wazuh SIEM centralise la collecte et l'analyse des événements de sécurité de notre infrastructure, fournissant une visibilité complète et une détection avancée des menaces.

### Capabilities Core

| Composant | Description | Status |
|-----------|-------------|--------|
| **Log Collection** | Agents sur 15+ hosts | ✅ Opérationnel |
| **HIDS** | File Integrity Monitoring | ✅ Opérationnel |
| **Vulnerability Assessment** | CVE scanning automatique | ✅ Opérationnel |
| **Compliance** | PCI-DSS, GDPR rules | ✅ Opérationnel |
| **Active Response** | Automated blocking | ✅ Opérationnel |
| **API Integration** | RESTful API access | ✅ Opérationnel |

## 🏗️ Architecture

### Components Distribution

La stack Wazuh est déployée via Docker Compose avec une architecture en 3 tiers :

- **Wazuh Manager** : Collecte et analyse des logs, règles de corrélation
- **Wazuh Indexer** : Stockage et indexation des données (basé sur OpenSearch)  
- **Wazuh Dashboard** : Interface de visualisation et monitoring

### Network Topology

| Service | IP | Ports | Description |
|---------|----|----- |-------------|
| **wazuh.manager** | 192.168.15.2 | 1514/tcp, 1515/tcp, 55000/tcp | Manager principal |
| **wazuh.indexer** | 192.168.15.2 | 9200/tcp, 9300/tcp | Index OpenSearch |
| **wazuh.dashboard** | 192.168.15.2 | 4443/tcp | Interface Web |

> 📁 [**Configuration complète**](../../../SOAR_SERVER/wazuh-docker/single-node/docker-compose.yml)

## 🐳 Déploiement Docker

### Prérequis

1. **Augmenter max_map_count** (Linux/WSL) :
   ```bash
   sudo sysctl -w vm.max_map_count=262144
   ```

2. **Générer les certificats SSL** :
   ```bash
   cd ../../../SOAR_SERVER/wazuh-docker/single-node
   docker-compose -f generate-indexer-certs.yml run --rm generator
   ```

### Démarrage des Services

**Mode foreground** (développement) :
```bash
docker-compose up
```

**Mode background** (production) :
```bash
docker-compose up -d
```

### Vérification du Déploiement

- **Dashboard** : https://localhost:4443 (admin/SecretPassword)
- **API** : https://localhost:55000 (wazuh-wui/MyS3cr37P450r.*-)
- **Manager logs** : `docker logs wazuh.manager`

> 📁 [**Guide complet**](../../../SOAR_SERVER/wazuh-docker/single-node/README.md) 

## ⚙️ Configuration

### Manager Configuration

Le fichier principal `ossec.conf` configure tous les aspects du manager Wazuh :

[**Localisation**](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/ossec.conf) 


#### Composants principaux configurés :

| Section | Description | État |
|---------|-------------|------|
| `<global>` | JSON output, alertes, email | ✅ Configuré |
| `<remote>` | Port 1514/TCP, connexions sécurisées | ✅ Configuré |
| `<integration>` | Webhooks n8n (DNS, SSH) | ✅ Actif |
| `<active-response>` | Isolation réseau automatique | ✅ Actif |
| `<alerts>` | Niveaux d'alertes (3+, email 12+) | ✅ Configuré |




## 📝 Règles et Décodeurs

### Configuration des Règles

Les règles personnalisées sont définies dans le système pour détecter les attaques spécifiques :

[**Localisation**](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/local_rule/local_rules.xml)

#### Structure des règles implémentées :

| Type d'attaque | ID Rules | Niveau | Description |
|----------------|----------|--------|-------------|
| **Base Groups** | 99900-99912 | 0 | Définitions des groupes fondamentaux |
| **SSH Attacks** | 99920-99921 | 5 | Échecs d'authentification SSH |
| **Sysmon Events** | 99900-99902 | 0 | Événements Windows Sysmon |
| **Suricata IDS** | 99910-99912 | 0 | Alertes Suricata/IDS |

#### Groupes de règles configurés :

1. **Windows/Sysmon** : `windows,sysmon`
   - Détection des événements Sysmon
   - Processus suspects et injections
   
2. **Suricata/IDS** : `suricata,ids`
   - Alertes de sécurité réseau
   - Signatures d'attaques
   
3. **SSH/Authentication** : `local,syslog,sshd`
   - Tentatives de connexion échouées
   - Attaques par force brute

### Décodeurs Personnalisés

[**Localisation**](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/local_decoders/modsecurity_decoder.xml)

Les décodeurs analysent et extraient les champs importants des logs :
- **ModSecurity** : Décodage des alertes WAF
- **Sysmon** : Parsing des événements Windows
- **Suricata** : Extraction des métadonnées d'alertes

## 🔗 Intégrations

### Intégrations Actives de Production

[**Configuration**](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/integrations/)

| Integration | Endpoint | Type | Description |
|------------|----------|------|-------------|
| **DNS Integration** | `http://sbihi.soar.ma:5678/webhook/wazuh-sysmon` | Webhook | Événements DNS Sysmon |
| **SSH Integration** | `http://sbihi.soar.ma:5678/webhook/wazuh-ssh` | Webhook | Alertes SSH/Auth |

### Scripts d'Intégration Disponibles

**Localisation**../../../SOAR_SERVER/wazuh-docker/single-node/integration2/`

| Script | Fonction | Usage |
|--------|----------|-------|
| `custom-dns-integration.py` | Traitement DNS | Analyse automatique des requêtes |
| `custom-ssh-webhook.py` | Gestion SSH | Détection d'intrusions |
| `virustotal.py` | VirusTotal API | Enrichissement IoC |
| `shuffle.py` | SOAR Shuffle | Orchestration playbooks |
| `slack.py` | Notifications | Alertes Slack |
| `pagerduty.py` | Incident Management | Escalation automatique |

### Active Response

[**Scripts configurés**](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/active-response/)

#### Actions automatiques activées :

1. **Isolation réseau** : `disable-network.cmd` / `enable-network.cmd`
2. **Blocage IP** : `firewall-drop`, `ip-customblock`
3. **Redémarrage services** : `restart-wazuh`

#### Configuration Active Response :

- **Niveau déclencheur** : 10+
- **Timeout** : 600 secondes (10 min)
- **Scope** : Tous les agents (`location: all`)

### API Wazuh

**Endpoints principaux** :

```bash
# Base URL
API_BASE="https://192.168.15.2:55000"

# Authentication
curl -u wazuh-wui:MyS3cr37P450r.*- -k -X POST "$API_BASE/security/user/authenticate"

# Agents status
curl -k -X GET "$API_BASE/agents" -H "Authorization: Bearer $TOKEN"

# Recent alerts  
curl -k -X GET "$API_BASE/security/events" -H "Authorization: Bearer $TOKEN"
```

## 🚨 Alerting

### Configuration des Alertes

**Niveaux d'alerte configurés** :
- **Niveau 3+** : Alertes générales (logs)
- **Niveau 12+** : Alertes critiques (email)

### Webhooks n8n Actifs

Les intégrations webhook redirigent automatiquement les alertes vers n8n pour orchestration SOAR :

1. **DNS/Sysmon Webhook** : 
   - URL : `http://sbihi.soar.ma:5678/webhook/wazuh-sysmon`
   - Groupe : `sysmon_event_22`
   - Format : JSON

2. **SSH Webhook** :
   - URL : `http://sbihi.soar.ma:5678/webhook/wazuh-ssh` 
   - Rules : `40111,60122,5758,2502,5710,5760,5763,5503`
   - Format : JSON

### Dashboard Wazuh

**Accès** : https://localhost:4443
- **Utilisateur** : admin
- **Mot de passe** : SecretPassword

#### Dashboards personnalisés :
- Vue d'ensemble sécurité SOAR
- Géolocalisation des attaques
- Timeline des incidents
- Statistiques par type d'attaque

## 📊 Monitoring et Performance

### Health Check Automatique

Script de vérification du service :

```bash
# Vérification status des services
docker ps | grep wazuh
docker logs wazuh.manager --tail 50
docker logs wazuh.indexer --tail 50
docker logs wazuh.dashboard --tail 50

# Test connectivité API
curl -k -u wazuh-wui:MyS3cr37P450r.*- \
     "https://localhost:55000/agents?pretty=true"
```

### Métriques de Performance

| Métrique | Valeur | Status |
|----------|--------|--------|
| **Agents connectés** | 15+ | ✅ Normal |
| **Alertes/jour** | ~500 | ✅ Normal |
| **Utilisation disque** | <80% | ✅ Normal |
| **Latence API** | <200ms | ✅ Normal |

### Optimisations Configurées

- **Memory size** : 128MB
- **Queue size** : 131072
- **JSON output** : Activé pour intégrations
- **Réseaux autorisés** : 192.168.15.0/24, 192.168.181.0/24, 192.168.183.0/24

---

## 🔗 Références et Ressources

### Documentation Officielle
- **[Documentation Wazuh](https://documentation.wazuh.com/)**
- **[Rules Reference](https://documentation.wazuh.com/current/user-manual/ruleset/)**
- **[API Reference](https://documentation.wazuh.com/current/user-manual/api/)**

### Fichiers de Configuration du Projet

| Composant | Localisation | Description |
|-----------|--------------|-------------|
| **Docker Compose** | [docker-compose.yml](../../../SOAR_SERVER/wazuh-docker/single-node/docker-compose.yml) | Configuration complète des services |
| **Manager Config** | [ossec.conf](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/ossec.conf) | Configuration principale Wazuh |
| **Custom Rules** | [local_rule](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/local_rule/) | Règles personnalisées |
| **Integrations** | [integrations](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/integrations/) | Scripts d'intégration |
| **Active Response** | [active-response](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/active-response/) | Scripts de réponse automatique |

### Intégrations SOAR
- **[Suricata IDS](../suricata/README.md)** - Détection réseau
- **[ModSecurity WAF](../modsecurity/README.md)** - Protection Web
- **[n8n Workflows](../../01_ARCHITECTURE/data_flows/README.md)** - Orchestration SOAR
- **[TheHive Cases](../../03_SOAR_STACK/thehive/README.md)** - Gestion d'incidents



---
**Dernière mise à jour** : Août 2025 - Configuration Docker SOAR Lab  
**Version Wazuh** : 4.13.0-rc3  
**Contact** : Med10S - SOAR Project Team
