# 🔬 Cortex - Security Analysis Engine

## Vue d'Ensemble

Cortex est notre moteur d'analyse automatisée, exécutant les analyzers de threat intelligence pour enrichir les observables TheHive avec des données contextuelles.

## Configuration de Production

**Docker Compose** : `../../../../SOAR_SERVER/Thehive_code/testing/docker-compose.yml` ([here](../../../../SOAR_SERVER/Thehive_code/testing/docker-compose.yml))


### Network Configuration

- **API Endpoint** : http://cortex.sbihi.soar.ma:9001
- **Job Directory** : `/tmp/cortex-jobs` (Docker volume)
- **Elasticsearch** : Partagé avec TheHive (port 9200)
- **Docker Socket** : Accès pour analyzers containerisés

## Analyzers Déployés

### Threat Intelligence

#### 1. MISP Integration

```javascript
// Configuration MISP Analyzer
{
  "name": "MISP_2_1",
  "url": "http://172.17.0.2", // this should be an ip from the bridge network of the docker 
  "datatypes": ["domain", "ip", "url", "fqdn", "uri_path", "user-agent", "hash"],
  "config": {
    "url": "http://misp.sbihi.soar.ma",
    "key": "MISP_API_KEY_HERE",
    "ssl_verify": false
  }
}
```

**Résultats** :
- Events MISP matching l'observable
- Threat score basé sur attributs malveillants
- Tags et classifications automatiques
- Related indicators extraction

