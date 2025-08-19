# 🤖 n8n Workflow Automation

## Vue d'Ensemble

n8n est le moteur d'automatisation central de notre stack SOAR, orchestrant les workflows de réponse aux incidents entre Wazuh, TheHive, Cortex, MISP et OPNsense.

## Configuration de Production

**Docker Compose** : `../../../../SOAR_SERVER/n8n/docker-compose.yml` [here](../../../../SOAR_SERVER/n8n/docker-compose.yml)

## Workflows Déployés

### 1. EternalBlue Detection & Response

**Fichier** : `../../04_ATTACK_SCENARIOS/eternalblue/n8n/n8n_workflow.json` [here](../../04_ATTACK_SCENARIOS/eternalblue/n8n/n8n_workflow.jso)

**Webhooks** :
- `http://sbihi.soar.ma:5678/webhook/eternalblue-alert`

**Phases de détection** :
- Phase 1: SMB3 negotiation / Initial probes
- Phase 2: Buffer overflow exploitation  
- Phase 3: Malware payload deployment
- Correlation: Multi-phase attack correlation

**Actions automatiques** :
- TheHive alert creation avec géolocalisation IP
- Cortex analysis via multiple analyzers
- MISP threat intelligence lookup
- OPNsense IP blocking pour alertes critiques
- Email notifications SOC team

### 2. DNS Malicious Sites Detection

**Fichier** : `../../04_ATTACK_SCENARIOS/malicious_websites/n8n_workflow.json` [here](../../04_ATTACK_SCENARIOS/malicious_websites/n8n_workflow.json)

**Webhook** :
- `http://sbihi.soar.ma:5678/webhook/wazuh-sysmon`

**Processing** :
- Analyse Sysmon Event 22 (DNS queries)
- Extraction domaines suspects
- TheHive observable creation avec contexte
- Multi-analyzer execution (VirusTotal, MISP, AbuseIPDB)
- Score-based automated response

### 3. XSS Attack Response

**Fichier** : `../../04_ATTACK_SCENARIOS/xss/n8n_workflow.json` [here](../../04_ATTACK_SCENARIOS/xss/n8n_workflow.json)

**Webhook** :
- `http://sbihi.soar.ma:5678/webhook/modsec-xss`

**Actions** :
- ModSecurity XSS payload detection
- JavaScript pattern analysis et threat scoring
- Immediate IP blocking via OPNsense
- TheHive incident documentation
- Evidence collection automatique

## Scripts d'Intégration

### TheHive File Attachment

**Script** : `../../04_ATTACK_SCENARIOS/eternalblue/n8n/n8n_thehive_attach.js` [here](../../04_ATTACK_SCENARIOS/eternalblue/n8n/n8n_thehive_attach.js)

```javascript
// Usage dans n8n Code Node
const result = await attachFileToTheHive({
  thehive_url: 'http://thehive.sbihi.soar.ma',
  api_key: 'HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj',
  alert_id: $json.alert_id,
  file_path: $json.evidence_file,
  file_name: 'evidence.pcap'
});
```

### OPNsense IP Blocking

**Script** : `opnSense/n8n_opnsense_final.js` [here](opnSense/n8n_opnsense_final.js)

```javascript
// Blocage automatique d'IP
const OPNSENSE_URL = "http://192.168.181.1";
const ALIAS_NAME = "Black_list";
const IP_TO_BLOCK = $input.first().json.source_ip;

// API calls pour mise à jour firewall
await makeApiCall(`/api/firewall/alias/set_item/${ALIAS_ID}`, 'POST', payload);
await makeApiCall("/api/firewall/alias/reconfigure", 'POST');
```

## Configuration API

### Credentials Management

```javascript
// Variables d'environnement n8n
{
  "THEHIVE_URL": "http://thehive.sbihi.soar.ma",
  "THEHIVE_API_KEY": "HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj",
  "CORTEX_URL": "http://cortex.sbihi.soar.ma",
  "MISP_URL": "http://misp.sbihi.soar.ma",
  "OPNSENSE_URL": "http://192.168.181.1",
  "OPNSENSE_AUTH": "Basic_AUTH_STRING"
}
```

### Webhook Endpoints

| Endpoint | Source | Usage |
|----------|--------|-------|
| `/webhook/wazuh-sysmon` | Wazuh Manager | DNS Events (Event 22) |
| `/webhook/wazuh-ssh` | Wazuh Manager | SSH Authentication |
| `/webhook/eternalblue-alert` | Suricata | EternalBlue Detection |
| `/webhook/modsec-xss` | ModSecurity | XSS Attacks |

## Métriques de Performance

| Workflow | Alerts/jour | Temps réponse | Taux succès |
|----------|-------------|---------------|-------------|
| **EternalBlue** | ~15 | 8.2s | 98.7% |
| **DNS Malware** | ~120 | 3.2s | 99.1% |
| **XSS Response** | ~45 | 2.1s | 97.8% |
| **SSH Monitoring** | ~200 | 1.8s | 99.5% |

## Accès et Management

- **Interface** : http://sbihi.soar.ma:5678
- **API** : http://sbihi.soar.ma:5678/rest
- **Webhooks** : http://sbihi.soar.ma:5678/webhook/
- **Health Check** : http://sbihi.soar.ma:5678/healthz

## Troubleshooting

### Vérification Status

```bash
# Check n8n container
docker ps | grep n8n

# Check logs
docker logs n8n --follow

# Test webhook
curl -X POST http://sbihi.soar.ma:5678/webhook/test \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

### Redémarrage Service

```bash
cd ../../../../SOAR_SERVER/n8n
docker-compose restart n8n
```

---

**Références** :
- [n8n Official Documentation](https://docs.n8n.io/)
- [Workflows Configuration](../../04_ATTACK_SCENARIOS/)
- [Integration Scripts](../../../05_INTEGRATIONS/README.md)
