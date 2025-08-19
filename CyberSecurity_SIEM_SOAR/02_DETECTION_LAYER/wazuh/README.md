# 📊 Configuration Wazuh SIEM  
## Security Information and Event Management

> **Wazuh Open Source SIEM Platform**  
> Collecte, analyse et corrélation d'événements sécurité  

---

## 📋 Table des Matières

- [Vue d'Ensemble](#-vue-densemble)
- [Architecture](#-architecture) 
- [Configuration](#-configuration)
- [Règles et Décodeurs](#-règles-et-décodeurs)
- [Intégrations](#-intégrations)
- [Alerting](#-alerting)

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

```
┌─────────────────────────────────────────────────────────────┐
│                    Wazuh Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │ Wazuh Agent │ -> │ Wazuh Server│ -> │ Elasticsearch│    │
│  │ (Forwarder) │    │  (Manager)  │    │   (Index)   │    │
│  └─────────────┘    └─────────────┘    └─────────────┘    │
│         │                   │                   │         │
│         v                   v                   v         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │  Filebeat   │    │  Logstash   │    │   Kibana    │    │
│  │(Log Shipper)│    │(Processing) │    │(Dashboard)  │    │
│  └─────────────┘    └─────────────┘    └─────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Network Topology

```yaml
# Wazuh Services Network Map
services:
  wazuh-manager:
    ip: 192.168.15.2
    ports: [1514/tcp, 1515/tcp, 55000/tcp]
    
  wazuh-dashboard:  
    ip: 192.168.15.2
    ports: [443/tcp]
    
  elasticsearch:
    ip: 192.168.15.2  
    ports: [9200/tcp, 9300/tcp]
```

## ⚙️ Configuration

### Manager Configuration (`ossec.conf`)

#### Global Settings
```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.gmail.com</smtp_server>
    <email_from>wazuh-alerts@soar.lab</email_from>
    <email_to>admin@soar.lab</email_to>
  </global>
</ossec_config>
```

#### Remote Configuration
```xml
<!-- Client configuration -->
<remote>
  <connection>secure</connection>
  <port>1514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.168.15.0/24</allowed-ips>
  <allowed-ips>192.168.181.0/24</allowed-ips>
  <allowed-ips>192.168.183.0/24</allowed-ips>
</remote>

<!-- Agent enrollment -->
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_source_ip>yes</use_source_ip>
  <purge>yes</purge>
  <use_password>yes</use_password>
  <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
</auth>
```

### Agent Configuration

#### Standard Agent (`ossec.conf`)
```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.15.2</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
  </client>

  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    
    <!-- Critical directories -->
    <directories check_all="yes">/etc</directories>
    <directories check_all="yes">/usr/bin</directories>  
    <directories check_all="yes">/usr/sbin</directories>
    <directories check_all="yes">/bin</directories>
    <directories check_all="yes">/sbin</directories>
    <directories check_all="yes">/boot</directories>
    
    <!-- Web directories -->
    <directories check_all="yes">/var/www</directories>
    
    <!-- Ignore certain file types -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
  </syscheck>

  <!-- Log Analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
</ossec_config>
```

#### Agent Installation Script
```bash
#!/bin/bash
# install-wazuh-agent.sh

# Variables
WAZUH_MANAGER="192.168.15.2"
WAZUH_REGISTRATION_SERVER="192.168.15.2"
WAZUH_REGISTRATION_PASSWORD="MySecurePassword123"
AGENT_NAME=$(hostname)

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt update

# Install agent
WAZUH_MANAGER="$WAZUH_MANAGER" \
WAZUH_REGISTRATION_SERVER="$WAZUH_REGISTRATION_SERVER" \
WAZUH_REGISTRATION_PASSWORD="$WAZUH_REGISTRATION_PASSWORD" \
WAZUH_AGENT_NAME="$AGENT_NAME" \
apt install wazuh-agent -y

# Start and enable
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Verify connection
/var/ossec/bin/agent-auth -m $WAZUH_MANAGER -P "$WAZUH_REGISTRATION_PASSWORD" -A $AGENT_NAME
```

## 📝 Règles et Décodeurs

### Custom Rules pour Attaques

#### EternalBlue Detection Rules
```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="eternalblue,windows,smb">
  
  <!-- EternalBlue SMB Exploit Attempts -->
  <rule id="100001" level="12">
    <if_sid>18152</if_sid>
    <match>SMBv1|SMB1</match>
    <description>EternalBlue: SMBv1 connection detected</description>
    <group>exploit_attempt,eternalblue</group>
  </rule>

  <!-- Suspicious SMB Traffic -->
  <rule id="100002" level="10">
    <if_sid>2501</if_sid>
    <match>445/tcp</match>
    <description>EternalBlue: Suspicious SMB traffic on port 445</description>
    <group>network_scan,eternalblue</group>
  </rule>

  <!-- MS17-010 Specific Pattern -->
  <rule id="100003" level="15">
    <decoded_as>windows-eventlog</decoded_as>
    <field name="win.system.eventID">4625</field>
    <match>DoublePulsar|MS17-010</match>
    <description>EternalBlue: MS17-010 exploitation attempt detected</description>
    <group>authentication_failed,eternalblue</group>
  </rule>

  <!-- Process injection detection -->
  <rule id="100004" level="13">
    <decoded_as>windows-eventlog</decoded_as>
    <field name="win.system.eventID">1</field>
    <match>rundll32.exe|powershell.exe</match>
    <regex>CreateRemoteThread|WriteProcessMemory</regex>
    <description>EternalBlue: Process injection detected</description>
    <group>process_injection,eternalblue</group>
  </rule>

</group>
```

#### XSS Attack Detection Rules  
```xml
<group name="web,xss,owasp">

  <!-- XSS Script Tag Injection -->
  <rule id="100010" level="7">
    <if_sid>31103</if_sid>
    <regex type="pcre2">(?i)&lt;script[\s\S]*?&gt;|javascript:|&lt;img[^&gt;]*?onerror|&lt;body[^&gt;]*?onload</regex>
    <description>XSS: Script injection attempt detected</description>
    <group>web_attack,xss</group>
  </rule>

  <!-- XSS Event Handler -->
  <rule id="100011" level="8">
    <if_sid>31103</if_sid>
    <regex type="pcre2">(?i)on(click|load|error|focus|blur|change|submit|mouseover)[\s]*=</regex>
    <description>XSS: Event handler injection attempt</description>
    <group>web_attack,xss</group>
  </rule>

  <!-- XSS Encoded Patterns -->
  <rule id="100012" level="9">
    <if_sid>31103</if_sid>
    <regex type="pcre2">(?i)%3Cscript|&#60;script|&lt;script|\\x3cscript</regex>
    <description>XSS: Encoded script injection detected</description>
    <group>web_attack,xss</group>
  </rule>

  <!-- Multiple XSS attempts -->
  <rule id="100013" level="10" frequency="3" timeframe="60">
    <if_matched_sid>100010</if_matched_sid>
    <same_source_ip />
    <description>XSS: Multiple injection attempts from same IP</description>
    <group>web_attack,xss</group>
  </rule>

</group>
```

#### Malicious Website Rules
```xml
<group name="web,malware,dns">

  <!-- Malicious Domain Access -->
  <rule id="100020" level="8">
    <decoded_as>squid</decoded_as>
    <match>badsite.com|malicious-domain.org|evil-site.net</match>
    <description>Malicious website access detected</description>
    <group>web_access,malware</group>
  </rule>

  <!-- DNS Query to malicious domain -->
  <rule id="100021" level="7">
    <program_name>named</program_name>
    <match>query|IN A</match>
    <regex>badsite\.com|malicious-domain\.org|evil-site\.net</regex>
    <description>DNS query to known malicious domain</description>
    <group>dns_query,malware</group>
  </rule>

  <!-- HTTP Request to malicious site -->
  <rule id="100022" level="9">
    <decoded_as>web-accesslog</decoded_as>
    <match>GET|POST</match>
    <regex>badsite\.com|malicious-domain\.org</regex>
    <description>HTTP request to malicious website</description>
    <group>web_access,malware</group>
  </rule>

  <!-- Download from malicious site -->
  <rule id="100023" level="12">
    <if_sid>100022</if_sid>
    <match>\.exe|\.zip|\.rar|\.bat|\.scr|\.com|\.pif</match>
    <description>File download from malicious website</description>
    <group>web_download,malware</group>
  </rule>

</group>
```

### Custom Decoders

#### EternalBlue Decoder
```xml
<!-- /var/ossec/etc/decoders/local_decoder.xml -->
<decoder name="eternalblue-smb">
  <program_name>smbd</program_name>
  <regex offset="after_parent">^\S+ \S+ (\S+): \S+ from (\S+) \((\S+)\) -> (connect|disconnect|login|auth)</regex>
  <order>timestamp,srcip,srcport,action</order>
</decoder>

<decoder name="eternalblue-exploit">
  <parent>eternalblue-smb</parent>
  <regex>Trans2 overflow|DoublePulsar|MS17-010</regex>
  <order>exploit_type</order>
</decoder>
```

#### XSS Decoder
```xml
<decoder name="xss-attempt">
  <parent>web-accesslog</parent>
  <regex type="pcre2">(?i)(script|javascript|onerror|onload|onclick)</regex>
  <order>xss_pattern</order>
</decoder>

<decoder name="xss-payload">
  <parent>xss-attempt</parent>
  <regex type="pcre2">(?i)(&lt;|%3C|\\x3c)(script|img|body|iframe)</regex>
  <order>payload_type</order>
</decoder>
```

## 🔗 Intégrations

### Suricata Integration

#### Log Collection
```xml
<!-- Suricata Eve JSON -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>

<!-- Suricata Fast Log -->  
<localfile>
  <log_format>suricata-idmef</log_format>
  <location>/var/log/suricata/fast.log</location>
</localfile>
```

#### Suricata Rules Correlation
```xml
<group name="suricata,ids">
  
  <!-- High severity IDS alerts -->
  <rule id="100050" level="12">
    <decoded_as>json</decoded_as>
    <field name="event_type">alert</field>
    <field name="alert.severity">^1$</field>
    <description>Suricata: Critical severity alert</description>
    <group>ids_alert,high_severity</group>
  </rule>

  <!-- Multiple IDS alerts correlation -->
  <rule id="100051" level="10" frequency="5" timeframe="300">
    <if_matched_sid>100050</if_matched_sid>
    <same_field>src_ip</same_field>
    <description>Suricata: Multiple critical alerts from same source</description>
    <group>ids_correlation</group>
  </rule>

</group>
```

### Active Response Integration

#### IP Blocking Response
```xml
<!-- /var/ossec/etc/ossec.conf -->
<command>
  <name>opnsense-block</name>
  <executable>opnsense-block.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
  <expect>srcip</expect>
</command>

<active-response>
  <command>opnsense-block</command>
  <location>server</location>
  <rules_id>100001,100003,100013,100023,100051</rules_id>
  <timeout>3600</timeout>
</active-response>
```

#### Active Response Script
```bash
#!/bin/bash
# /var/ossec/active-response/bin/opnsense-block.sh

# Read input
read INPUT_JSON
SRCIP=$(echo $INPUT_JSON | jq -r .parameters.alert.data.srcip 2>/dev/null)

# Block IP via OPNsense API
if [ -n "$SRCIP" ] && [ "$SRCIP" != "null" ]; then
    curl -X POST "https://192.168.181.1/api/firewall/alias/addHost/blocked_ips" \
         -H "Content-Type: application/json" \
         -H "Authorization: Basic $OPNSENSE_AUTH" \
         -d "{\"host\":\"$SRCIP\"}" \
         --insecure
    
    # Log action
    logger -t wazuh-active-response "Blocked IP $SRCIP via OPNsense"
fi

exit 0
```

### API Integration

#### Wazuh API Configuration
```json
{
  "host": "192.168.15.2",
  "port": 55000,
  "user": "wazuh",
  "password": "wazuh",
  "auth": {
    "user": "wazuh",
    "password": "wazuh"
  }
}
```

#### API Usage Examples
```bash
# Get authentication token
curl -u wazuh:wazuh -k -X POST "https://192.168.15.2:55000/security/user/authenticate"

# Get agents status
curl -k -X GET "https://192.168.15.2:55000/agents" -H "Authorization: Bearer $TOKEN"

# Get recent alerts
curl -k -X GET "https://192.168.15.2:55000/security/events" -H "Authorization: Bearer $TOKEN"

# Get rules information
curl -k -X GET "https://192.168.15.2:55000/rules" -H "Authorization: Bearer $TOKEN"
```

## 🚨 Alerting

### Email Notifications

#### Email Configuration
```xml
<email_alerts>
  <email_to>admin@soar.lab</email_to>
  <level>10</level>
  <rule_id>100001,100003,100013,100023</rule_id>
  <format>full</format>
</email_alerts>

<email_alerts>  
  <email_to>soc@soar.lab</email_to>
  <level>7</level>
  <do_not_delay>yes</do_not_delay>
  <format>full</format>
</email_alerts>
```

### Webhook Integration

#### n8n Webhook Configuration
```xml
<!-- Custom alerting via webhook -->
<integration>
  <name>n8n-webhook</name>
  <hook_url>http://192.168.15.3:5678/webhook/wazuh-alert</hook_url>
  <level>8</level>
  <rule_id>100001,100003,100010,100020,100050</rule_id>
  <alert_format>json</alert_format>
</integration>
```

#### Webhook Processing Script
```bash
#!/bin/bash
# /var/ossec/integrations/n8n-webhook

# Read alert data
read INPUT_JSON

# Parse alert information  
RULE_ID=$(echo $INPUT_JSON | jq -r .rule.id)
LEVEL=$(echo $INPUT_JSON | jq -r .rule.level)
SRCIP=$(echo $INPUT_JSON | jq -r .data.srcip // "unknown")
DESCRIPTION=$(echo $INPUT_JSON | jq -r .rule.description)

# Send to n8n webhook
curl -X POST "http://192.168.15.3:5678/webhook/wazuh-alert" \
     -H "Content-Type: application/json" \
     -d "{
       \"rule_id\": \"$RULE_ID\",
       \"level\": \"$LEVEL\", 
       \"src_ip\": \"$SRCIP\",
       \"description\": \"$DESCRIPTION\",
       \"full_alert\": $INPUT_JSON
     }"

exit 0
```

### Dashboard Integration

#### Wazuh Dashboard Custom Panels
```json
{
  "dashboard": {
    "title": "SOAR Security Dashboard",
    "panels": [
      {
        "title": "Attack Scenarios",
        "type": "table",
        "query": {
          "bool": {
            "should": [
              {"match": {"rule.groups": "eternalblue"}},
              {"match": {"rule.groups": "xss"}}, 
              {"match": {"rule.groups": "malware"}}
            ]
          }
        }
      },
      {
        "title": "Geographic Attack Sources",
        "type": "map",
        "geo_field": "GeoLocation.location"
      },
      {
        "title": "Attack Timeline",
        "type": "histogram", 
        "time_field": "@timestamp"
      }
    ]
  }
}
```

## 📊 Monitoring et Performance

### Health Check Script
```bash
#!/bin/bash
# /opt/wazuh/health-check.sh

# Check Wazuh Manager status
if ! systemctl is-active --quiet wazuh-manager; then
    echo "ERROR: Wazuh Manager not running"
    exit 1
fi

# Check agent connectivity
TOTAL_AGENTS=$(curl -s -k -H "Authorization: Bearer $TOKEN" \
               "https://localhost:55000/agents?limit=1" | jq -r '.data.total_affected_items')

ACTIVE_AGENTS=$(curl -s -k -H "Authorization: Bearer $TOKEN" \
                "https://localhost:55000/agents?status=active&limit=1" | jq -r '.data.total_affected_items')

echo "Agents Status: $ACTIVE_AGENTS/$TOTAL_AGENTS active"

# Check recent alerts
RECENT_ALERTS=$(tail -100 /var/ossec/logs/alerts/alerts.log | wc -l)
echo "Recent alerts: $RECENT_ALERTS"

# Check disk space
DISK_USAGE=$(df /var/ossec | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    echo "WARNING: Disk usage high: $DISK_USAGE%"
fi

echo "Wazuh health check completed"
```

### Performance Tuning
```xml
<!-- Performance optimizations -->
<global>
  <logall>no</logall>
  <logall_json>no</logall_json>
  <memory_size>128</memory_size>
  <white_list>192.168.15.0/24</white_list>
  <white_list>192.168.181.0/24</white_list>
</global>

<!-- Agent buffer settings -->
<client_buffer>
  <disabled>no</disabled>
  <queue_size>5000</queue_size>
  <events_per_second>500</events_per_second>
</client_buffer>
```

---

## 🔗 Références

- **[Documentation Wazuh Officielle](https://documentation.wazuh.com/)**
- **[Wazuh Rules Reference](https://documentation.wazuh.com/current/user-manual/ruleset/)**  
- **[Integration Suricata](../suricata/README.md)**
- **[Active Response Guide](../../07_DOCUMENTATION/troubleshooting/)**

### Fichiers de Configuration

Les fichiers de configuration Wazuh sont disponibles dans le dossier externe :  
**📂 [../../../SOAR_SERVER/wazuh/](../../../SOAR_SERVER/wazuh/)**

---
**Mise à jour** : Août 2025 - Med10S
