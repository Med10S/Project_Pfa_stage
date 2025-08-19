# 🔍 Configuration Suricata IDS/IPS
## Système de Détection d'Intrusion Réseau

> **Suricata Network Security Engine**  
> IDS/IPS haute performance pour la détection réseau  

---

## 📋 Table des Matières

- [Vue d'Ensemble](#-vue-densemble)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Règles de Détection](#-règles-de-détection)
- [Intégration SOAR](#-intégration-soar)
- [Performance](#-performance)

---

## 🎯 Vue d'Ensemble

Suricata est notre moteur principal de détection réseau, opérant en mode **IPS inline** et **IDS passif** pour une protection multicouche.

### Capabilities

| Feature | Description | Status |
|---------|-------------|--------|
| **Signature Detection** | 30,000+ règles ET Open | ✅ Actif |
| **Protocol Analysis** | HTTP, DNS, TLS, SMB, FTP | ✅ Actif |
| **File Extraction** | Malware, PCAP capture | ✅ Actif |
| **Lua Scripting** | Custom detection logic | ✅ Actif |
| **Eve JSON Output** | Structured logging | ✅ Actif |

## 🏗️ Architecture

### Mode de Déploiement

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Topology                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Internet ──┤ pfSense ├── LAN Switch ──┤ Suricata ├── Hosts │
│             Firewall     192.168.x.x    IDS/IPS            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Threading Architecture

```yaml
# Suricata Threading Model
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "0" ]
    - receive-cpu-set:  
        cpu: [ "1" ]
    - worker-cpu-set:
        cpu: [ "2-7" ]
    - verdict-cpu-set:
        cpu: [ "2-7" ]
```

## ⚙️ Configuration

### Fichier Principal (`suricata.yaml`)

#### Interface Configuration
```yaml
# Network interfaces
af-packet:
  - interface: enp0s3
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768
```

#### Detection Engine
```yaml
# Detection settings  
detect:
  profile: high
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  
# Pattern matching
mpm-algo: auto
pattern-matcher:
  - b2gc:
      search-algo: B2gSearchBNDMq
      hash-size: low
      bf-size: medium
```

#### Output Configuration
```yaml
# Outputs
outputs:
  # EVE JSON log
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            packet: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
        - ftp:
        - smb:
        - flow:
```

### Configuration Avancée

#### App Layer Protocols
```yaml
# Application layer configuration
app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          http-body-inline: auto
          
    tls:
      enabled: yes
      detection-ports:
        dp: 443
        
    dns:
      enabled: yes
      
    smtp:
      enabled: yes
      
    smb:
      enabled: yes
```

## 📝 Règles de Détection

### Sources de Règles

#### Emerging Threats Open
```bash
# Configuration des sources ET
rule-files:
  - botcc.rules
  - ciarmy.rules  
  - compromised.rules
  - drop.rules
  - dshield.rules
  - emerging-activex.rules
  - emerging-attack_response.rules
  - emerging-chat.rules
  - emerging-current_events.rules
  - emerging-dns.rules
  - emerging-dos.rules
  - emerging-exploit.rules
  - emerging-ftp.rules
  - emerging-games.rules
  - emerging-icmp_info.rules
  - emerging-icmp.rules
  - emerging-imap.rules
  - emerging-inappropriate.rules
  - emerging-malware.rules
  - emerging-misc.rules
  - emerging-mobile_malware.rules
  - emerging-netbios.rules
  - emerging-p2p.rules
  - emerging-policy.rules
  - emerging-pop3.rules
  - emerging-rpc.rules
  - emerging-scada.rules
  - emerging-scan.rules
  - emerging-shellcode.rules
  - emerging-smtp.rules
  - emerging-snmp.rules
  - emerging-sql.rules
  - emerging-telnet.rules
  - emerging-tftp.rules
  - emerging-trojan.rules
  - emerging-user_agents.rules
  - emerging-voip.rules
  - emerging-web_client.rules
  - emerging-web_server.rules
  - emerging-worm.rules
  - tor.rules
```

### Règles Personnalisées

#### EternalBlue Detection
```bash
# local.rules - EternalBlue  
alert smb any any -> any any (msg:"ET EXPLOIT Possible EternalBlue MS17-010 SMB Exploit"; flow:to_server; content:"|00 00 00 2f fe 53 4d 42 72 00 00 00 00 18 01 20|"; offset:4; depth:16; content:"|00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; distance:14; within:14; classtype:attempted-admin; sid:2024218; rev:1;)

alert tcp any any -> any 445 (msg:"ET EXPLOIT EternalBlue SMB Trans2 SESSION_SETUP overflow attempt"; flow:to_server,established; content:"|00|SMB|72 00 00 00 00 18 01 20|"; content:"|0e 00|"; distance:0; within:2; byte_test:2,>,4100,0,relative,little; classtype:attempted-admin; sid:2024220; rev:1;)
```

#### XSS Detection  
```bash
# XSS patterns
alert http any any -> any any (msg:"ET WEB_SERVER XSS attempt via script tag"; flow:established,to_server; content:"GET"; http_method; content:"<script"; http_uri; nocase; pcre:"/\x3cscript[^\x3e]*\x3e.*?\x3c\/script\x3e/i"; classtype:web-application-attack; sid:2024250; rev:1;)

alert http any any -> any any (msg:"ET WEB_SERVER XSS attempt via javascript"; flow:established,to_server; content:"javascript:"; http_uri; nocase; classtype:web-application-attack; sid:2024251; rev:1;)
```

#### Malicious Website Access
```bash
# Malicious domains  
alert dns any any -> any any (msg:"ET MALWARE DNS Query for known malicious domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"badsite.com"; nocase; classtype:trojan-activity; sid:2024300; rev:1;)

alert http any any -> any any (msg:"ET MALWARE HTTP Request to malicious domain"; flow:established,to_server; content:"Host: badsite.com"; nocase; classtype:trojan-activity; sid:2024301; rev:1;)
```

### Gestion des Règles

#### Mise à jour automatique
```bash
#!/bin/bash
# /usr/local/bin/update-suricata-rules.sh

# Download latest rules
suricata-update

# Test configuration
suricata -T -c /etc/suricata/suricata.yaml

# Reload rules if test passes
if [ $? -eq 0 ]; then
    sudo killall -USR2 suricata
    echo "Rules updated successfully"
else
    echo "Configuration test failed"
    exit 1
fi
```

#### Tuning des règles
```yaml
# modify.conf - Rule modifications
# Disable noisy rules
2024218 disable  # Only for testing
2024220 disable  # Only for testing

# Lower threshold for specific rules  
threshold: type limit, track by_src, count 1, seconds 60, gen_id 1, sig_id 2024250
threshold: type threshold, track by_src, count 10, seconds 60, gen_id 1, sig_id 2024251
```

## 🔗 Intégration SOAR

### Output vers Wazuh

#### Configuration EVE JSON
```yaml
# eve.json pour Wazuh
- eve-log:
    enabled: yes
    filetype: syslog
    facility: local1
    level: notice
    identity: suricata
    types:
      - alert:
          payload: yes
          metadata: yes
          tagged-packets: yes
```

#### Agent Wazuh Configuration
```xml
<!-- /var/ossec/etc/ossec.conf -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>

<localfile>
  <log_format>suricata-idmef</log_format>
  <location>/var/log/suricata/fast.log</location>
</localfile>
```

### Extraction de Fichiers

#### Configuration
```yaml
# File extraction
file-store:
  enabled: yes
  log-dir: /var/log/suricata/files
  force-magic: no
  force-md5: yes
  force-sha1: no  
  force-sha256: yes
  
# Fileinfo in eve.json
- eve-log:
    types:
      - files:
          force-magic: yes
          force-hash: [md5, sha1, sha256]
```

#### Processing automatique
```bash
#!/bin/bash
# /opt/suricata/process-extracted-files.sh

EXTRACTED_DIR="/var/log/suricata/files"
ANALYSIS_DIR="/var/log/suricata/analysis"

for file in $EXTRACTED_DIR/*; do
    if [ -f "$file" ]; then
        # Calculate hashes
        MD5=$(md5sum "$file" | cut -d' ' -f1)
        SHA256=$(sha256sum "$file" | cut -d' ' -f1)
        
        # Send to analysis queue
        echo "{\"file\":\"$file\",\"md5\":\"$MD5\",\"sha256\":\"$SHA256\"}" >> $ANALYSIS_DIR/queue.json
        
        # Trigger n8n webhook
        curl -X POST "http://192.168.15.3:5678/webhook/suricata-file" \
             -H "Content-Type: application/json" \
             -d "{\"file\":\"$file\",\"md5\":\"$MD5\",\"sha256\":\"$SHA256\"}"
    fi
done
```

## 📊 Performance et Monitoring

### Métriques Clés

#### Stats Interface
```bash
# Suricata stats command  
suricata-sc -c stats

# Key metrics à surveiller:
# - capture.kernel_packets
# - capture.kernel_drops  
# - detect.alert
# - flow.tcp
# - flow.udp
```

#### Performance Dashboard
```json
{
  "stats": {
    "capture": {
      "kernel_packets": 1000000,
      "kernel_drops": 0
    },
    "decoder": {
      "pkts": 999950,
      "bytes": 500000000,
      "invalid": 0,
      "ipv4": 800000,
      "ipv6": 199950,
      "ethernet": 999950,
      "tcp": 600000,
      "udp": 300000,
      "icmpv4": 50000
    },
    "detect": {
      "alert": 1234
    }
  }
}
```

### Optimisation Performance

#### Memory Tuning
```yaml
# Memory settings
max-pending-packets: 1024
runmode: workers

# Memory caps
stream:
  memcap: 32mb
  checksum-validation: yes
  
flow:
  memcap: 64mb
  hash-size: 65536
  prealloc: 10000
  
defrag:
  memcap: 32mb
  hash-size: 65536
  prealloc: 1000
```

#### CPU Affinity
```bash
# Set CPU affinity pour Suricata
echo 2-7 > /sys/fs/cgroup/cpuset/suricata/cpuset.cpus
echo 0 > /sys/fs/cgroup/cpuset/suricata/cpuset.mems

# Bind interrupts to specific CPU
echo 1 > /proc/irq/24/smp_affinity_list  # Network card IRQ
```

## 🔧 Maintenance

### Logs et Troubleshooting

#### Log Files
```bash
# Main logs
/var/log/suricata/suricata.log      # Main log
/var/log/suricata/eve.json          # EVE JSON output  
/var/log/suricata/fast.log          # Fast format alerts
/var/log/suricata/stats.log         # Performance stats

# Debug logs
/var/log/suricata/http.log          # HTTP transactions
/var/log/suricata/dns.log           # DNS queries  
/var/log/suricata/tls.log           # TLS handshakes
```

#### Common Issues
```bash
# Check configuration
suricata -T -c /etc/suricata/suricata.yaml

# Check interface
suricata --list-runmodes
suricata --list-app-layer-protos

# Performance issues
suricata-sc -c iface-stat enp0s3
suricata-sc -c memcap-show
```

### Health Monitoring
```bash
#!/bin/bash
# /opt/suricata/health-check.sh

# Check if Suricata is running
if ! pgrep suricata > /dev/null; then
    echo "ERROR: Suricata not running"
    exit 1
fi

# Check packet drops
DROPS=$(suricata-sc -c stats | jq '.stats.capture.kernel_drops')
if [ "$DROPS" -gt 1000 ]; then
    echo "WARNING: High packet drops detected: $DROPS"
fi

# Check disk space
DISK_USAGE=$(df /var/log/suricata | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    echo "WARNING: Disk usage high: $DISK_USAGE%"
fi

echo "Suricata health check OK"
```

---

## 🔗 Références

- **[Configuration officielle Suricata](https://suricata.readthedocs.io/)**
- **[Emerging Threats Rules](https://rules.emergingthreats.net/)**  
- **[Integration Wazuh-Suricata](../wazuh/README.md)**
- **[Performance Tuning Guide](../../07_DOCUMENTATION/troubleshooting/)**

### Fichiers de Configuration

Les fichiers de configuration Suricata sont disponibles dans le dossier externe :  
**📂 [../../../Suricata/](../../../Suricata/)**

---
**Mise à jour** : Août 2025 - Med10S
