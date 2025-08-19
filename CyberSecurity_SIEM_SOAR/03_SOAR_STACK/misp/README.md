# 🔍 MISP - Threat Intelligence Platform

## Vue d'Ensemble

MISP (Malware Information Sharing Platform) est notre plateforme centrale de threat intelligence, enrichissant les analyses avec des IoCs, des campagnes d'attaques et des données contextuelles.

## Configuration de Production

**Docker Compose** : `../../../../SOAR_SERVER/misp-docker/docker-compose.yml` [here](../../../../SOAR_SERVER/misp-docker/docker-compose.yml)


### Configuration Environment

**Variables** : `../../../../SOAR_SERVER/misp-docker/.env` [here](../../../../SOAR_SERVER/misp-docker/.env)

```bash
# Database Configuration
MYSQL_USER=misp
MYSQL_PASSWORD=example
MYSQL_ROOT_PASSWORD=password
MYSQL_DATABASE=misp

# Redis Configuration
REDIS_PASSWORD=redispassword
REDIS_PORT=6379

# MISP Configuration
MISP_ADMIN_EMAIL=admin@misp.local
MISP_ADMIN_PASSPHRASE=admin
MISP_BASEURL=http://misp.sbihi.soar.ma
MISP_EXTERNAL_BASEURL=http://192.168.15.5
```

### Network Configuration

- **Interface Web** : http://misp.sbihi.soar.ma
- **API Endpoint** : http://misp.sbihi.soar.ma/attributes/restSearch
- **Database** : MariaDB (port 3306)
- **Cache** : Redis (port 6379)
- **Network** : 192.168.15.0/24 (SOAR services)

## Threat Intelligence Feeds

### Configured Feeds

**Localisation** : `../../../../SOAR_SERVER/misp-docker/files/feed-metadata/`

| Feed | URL | Type | Fréquence | Description |
|------|-----|------|-----------|-------------|
| **CIRCL OSINT** | https://www.circl.lu/doc/misp/feed-osint/ | OSINT | Quotidienne | Indicateurs open source |
| **URLhaus Malware** | https://urlhaus.abuse.ch/downloads/misp/ | Malware URLs | Horaire | URLs malveillantes |
| **Feodo Tracker** | https://feodotracker.abuse.ch/downloads/misp/ | Botnet C&C | Horaire | Serveurs de commande |
| **Malware Domain List** | http://www.malwaredomainlist.com/hostslist/mdl.xml | Domaines | Quotidienne | Domaines suspects |
| **Hospital IOCs** | Custom feed | Internal | Real-time | IoCs spécifiques hôpital |


## API Integration

### Cortex Integration

**Configuration pour Cortex analyzers** :

```json
{
  "misp_url": "http://misp.sbihi.soar.ma",
  "misp_key": "MISP_API_KEY_HERE",
  "misp_verifycert": false,
  "misp_tag": "cortex-analysis",
  "misp_tag_positive": "cortex:positive",
  "misp_tag_negative": "cortex:negative"
}
```

