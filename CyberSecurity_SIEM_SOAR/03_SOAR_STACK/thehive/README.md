# 🕵️ TheHive - Case Management Platform

## Vue d'Ensemble

TheHive est notre plateforme de gestion d'incidents, centralisant la création, le suivi et l'investigation des cas de sécurité dans l'hôpital.

## Configuration de Production

**Docker Compose** : `../../../../SOAR_SERVER/Thehive_code/testing/docker-compose.yml` [here](../../../../SOAR_SERVER/Thehive_code/testing/docker-compose.yml)

### Configuration Réseau

- **URL Frontend** : http://thehive.sbihi.soar.ma
- **API Endpoint** : http://thehive.sbihi.soar.ma:9000/api
- **Backend** : Cassandra (192.168.15.61:9042) + Elasticsearch (9200)
- **Network** : 192.168.15.0/24 (SOAR subnet)

## Intégrations n8n

### API Configuration

**Credentials dans n8n** :
```javascript
{
  "url": "http://thehive.sbihi.soar.ma",
  "api_key": "HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj",
  "organization": "hospital-soc",
  "version": "v1"
}
```

### Automated Case Creation

#### EternalBlue Incidents

**Workflow** : `../../04_ATTACK_SCENARIOS/eternalblue/n8n_workflow.json` [here](../../04_ATTACK_SCENARIOS/eternalblue/n8n_workflow.json)

```javascript
// TheHive Alert Creation
{
  "title": `EternalBlue Attack - ${source_ip} -> ${dest_ip}`,
  "description": "Multi-phase SMB exploitation detected via Suricata IDS",
  "type": "external",
  "source": "Wazuh-Suricata",
  "sourceRef": alert_id,
  "severity": 3, // High
  "tlp": 2, // TLP:AMBER
  "pap": 2, // PAP:AMBER
  "tags": ["eternalblue", "smb", "exploitation", "hospital"],
  "observables": [
    {
      "dataType": "ip",
      "data": source_ip,
      "message": "Attacking IP - GeoLocation enriched",
      "ioc": true,
      "sighted": true
    },
    {
      "dataType": "file",
      "data": pcap_filename,
      "message": "Network capture evidence",
      "attachment": true
    }
  ]
}
```

#### XSS Attack Cases

**Auto-promotion** : Alert → Case après confirmation malveillance

```javascript
// Case Creation pour XSS confirmé
{
  "title": `XSS Attack on ${victim_url}`,
  "description": "Cross-Site Scripting detected by ModSecurity",
  "severity": 2, // Medium
  "template": "xss-investigation-template",
  "tasks": [
    {
      "title": "Analyze XSS Payload",
      "description": "Reverse engineer malicious JavaScript"
    },
    {
      "title": "Impact Assessment", 
      "description": "Check for data exfiltration or session hijacking"
    },
    {
      "title": "Victim Communication",
      "description": "Notify affected departments if patient data involved"
    }
  ]
}
```

## Templates Hospitaliers

### Incident Templates

1. **Patient Data Breach**
   - HIPAA compliance checks
   - Legal notification requirements
   - Medical staff coordination
   - IT forensics procedures

2. **Medical Device Compromise**
   - Patient safety assessment
   - Device isolation procedures
   - Vendor notification
   - Clinical impact analysis

3. **Ransomware Response**
   - Clinical system inventory
   - Backup activation procedures
   - Patient care continuity
   - Recovery timeline estimation

### Observable Types Healthcare

| Type | Description | Criticité |
|------|-------------|-----------|
| **medical-device-ip** | Adresse IP équipement médical | HIGH |
| **patient-workstation** | Poste de travail clinique | HIGH |
| **ehr-system** | Système dossier patient | CRITICAL |
| **pacs-server** | Serveur imagerie médicale | HIGH |
| **lab-system** | Système laboratoire | MEDIUM |

## Cortex Analyzer Integration

### Automated Analysis Pipeline

```javascript
// Observables envoyés automatiquement à Cortex
{
  "observable_id": thehive_observable_id,
  "analyzers": [
    "VirusTotal_GetReport_3_0",
    "MISP_2_1", 
    "AbuseIPDB_1_0",
    "Shodan_Host_1_0",
    "MaxMind_GeoIP_3_0"
  ],
  "auto_extract_artifacts": true,
  "notification_webhook": "http://sbihi.soar.ma:5678/webhook/cortex-results"
}
```

### Response Actions

- **Threat Score > 7** : Auto-escalation vers équipe SOC
- **IoC confirmé** : Blocage automatique OPNsense
- **Medical Device** : Notification immédiate équipe biomédicale

## Métriques Hospitalières

### Dashboard SOC

| Métrique | Valeur | Seuil Critique |
|----------|--------|----------------|
| **Incidents Actifs** | 12 | > 20 |
| **Temps Résolution Moyen** | 4.2h | > 8h |
| **Incidents Patient Data** | 3/mois | > 5/mois |
| **Dispositifs Médicaux Impactés** | 1/semaine | > 2/semaine |

### Compliance Reporting

- **HIPAA Incidents** : Export mensuel automatique
- **RGPD Notifications** : Template 72h notification
- **Audit Trail** : Logs intégrité pour certification

## API Endpoints

### Core Operations

```bash
# Create Alert
POST http://thehive.sbihi.soar.ma:9000/api/alert
Authorization: Bearer Get your Api Key

# Promote Alert to Case  
POST http://thehive.sbihi.soar.ma:9000/api/alert/{alertId}/createCase

# Add Observable
POST http://thehive.sbihi.soar.ma:9000/api/case/{caseId}/artifact

# Search Cases
POST http://thehive.sbihi.soar.ma:9000/api/case/_search
```

### Webhook Notifications

```javascript
// n8n Webhook pour Case Updates
{
  "webhook_url": "http://sbihi.soar.ma:5678/webhook/thehive-update",
  "events": [
    "case-create",
    "case-update", 
    "task-complete",
    "observable-create"
  ]
}
```

## Maintenance

### Database Backup

```bash
# Cassandra backup
docker exec cassandra cqlsh -e "DESCRIBE KEYSPACE thehive;"

# Elasticsearch backup
curl -X PUT "elasticsearch:9200/_snapshot/hospital_soc_backup"
```

### Health Monitoring

```bash
# TheHive status
curl http://thehive.sbihi.soar.ma:9000/api/status

# Database connectivity
curl http://thehive.sbihi.soar.ma:9000/api/health
```

---

**Références** :
- [TheHive Documentation](https://github.com/TheHive-Project/TheHiveDocs)
- [Docker Configuration](../../../../SOAR_SERVER/Thehive_code/testing/)
- [n8n Integration Workflows](../n8n/README.md)
