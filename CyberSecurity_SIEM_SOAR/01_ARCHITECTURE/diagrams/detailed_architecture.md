# Architecture Détaillée SIEM/SOAR - Équipe de Sécurité Hospitalière

## Vue d'ensemble

Cette architecture est conçue spécifiquement pour **une équipe de sécurité/RSSI** gérant la cybersécurité d'un environnement hospitalier. L'objectif est de maximiser la visibilité, la détection et la réponse aux incidents de sécurité avec une stack unifiée.

## 🎯 **Architecture Centrée Sécurité**

### **Stack SIEM Pure - Wazuh Platform**
```
🔍 SIEM Central
├── Wazuh Manager - Collecte & Analyse
├── Wazuh Indexer (OpenSearch) - Stockage Sécurisé
└── Wazuh Dashboard - Interface SOC Dédiée
```

### **SOAR Platform - Orchestration**
```
🤖 Réponse Automatisée
├── TheHive - Gestion Incidents & Cases
├── Cortex - Analyse Automatisée & Enrichissement
└── MISP - Threat Intelligence & IOCs
```

## Wazuh : Le Cœur du SIEM

### Capacités Principales de Wazuh

#### 1. Host-based Intrusion Detection System (HIDS)
- **Monitoring en temps réel** des fichiers système
- **Détection d'intégrité** (FIM - File Integrity Monitoring)
- **Analyse comportementale** des processus
- **Rootkit detection** et anti-malware

#### 2. Log Data Analysis
- **Parsing intelligent** de 500+ formats de logs
- **Corrélation événements** multi-sources
- **Enrichissement automatique** des données
- **Machine learning** pour détection d'anomalies

#### 3. Compliance et Conformité
- **HIPAA compliance** native
- **PCI DSS** monitoring automatique
- **GDPR/RGPD** audit trails
- **SOX reporting** intégré

## Intégrations Stratégiques de Wazuh

### 1. Wazuh + Suricata : Détection Réseau Avancée


![Network Security Flow](network_security_flow.png)


**Configuration Suricata-Wazuh :**
dans le Wazuh agent installer dans le serveur ou suricata est installer 
```yaml
# /var/ossec/etc/ossec.conf
<localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
</localfile>

```

## Détection Spécialisée par Type d'Attaque

### 1. XSS Detection

**Wazuh Rules Configuration :**

[Voir la configuration complète des règles Wazuh](../../../SOAR_SERVER/wazuh-docker/single-node/ManagerConfig/rules/0550-modsecurity_rules.xml)
```xml
 <rule id="200000" level="0">
    <decoded_as>modsecurity</decoded_as>
    <description>ModSecurity events grouped.</description>
  </rule>

  <!-- Critical XSS Attack Detection -->
  <rule id="200001" level="12">
    <if_sid>200000</if_sid>
    <field name="transaction.messages">"attack-xss"</field>
    <field name="transaction.response.http_code">403</field>
    <description>ModSecurity: Critical XSS Attack Blocked - Source: $(transaction.client_ip) Target: $(transaction.request.uri)</description>
    <group>attack,web_attack,xss,critical,blocked</group>
    <options>no_email_alert</options>
  </rule>
  
  ....
```


**Stack Integration :**
- **Web Application Firewall** logs → Wazuh
- **Application logs** → Logstash → Elasticsearch
- **Suricata** → Network pattern detection
- **Cortex** → URL/Domain reputation check




Cette architecture offre une solution complète, évolutive et adaptée aux contraintes spécifiques des environnements hospitaliers, avec une focus particulier sur la détection d'attaques sophistiquées et la conformité réglementaire.
YARA