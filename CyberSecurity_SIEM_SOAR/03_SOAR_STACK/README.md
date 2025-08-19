# 🤖 Configuration SOAR Stack  
## Security Orchestration, Automation and Response

> **Plateforme SOAR Complète**  
> TheHive + Cortex + MISP + n8n pour l'automatisation sécurité  

---

## 📋 Table des Matières

- [Vue d'Ensemble](#-vue-densemble)
- [Architecture](#-architecture)
- [TheHive](#-thehive)
- [Cortex](#-cortex)
- [MISP](#-misp)
- [n8n](#-n8n)
- [Intégrations](#-intégrations)

---

## 🎯 Vue d'Ensemble

Notre stack SOAR automatise la réponse aux incidents de sécurité en orchestrant les outils de détection, l'analyse de malware, la threat intelligence et les actions de remédiation.

### Composants Principaux

| Composant | Rôle | Port | Status |
|-----------|------|------|--------|
| **🕷️ TheHive** | Gestion d'incidents | 9000 | ✅ Opérationnel |
| **🧠 Cortex** | Analyse & Intelligence | 9001 | ✅ Opérationnel |
| **🔍 MISP** | Threat Intelligence | 80/443 | ✅ Opérationnel |
| **⚡ n8n** | Workflow Automation | 5678 | ✅ Opérationnel |
| **📊 Elasticsearch** | Storage & Search | 9200 | ✅ Opérationnel |

### Workflow Automatisé

```mermaid
graph TB
    A[Détection Alerte] --> B{Type Alerte}
    B -->|IDS/IPS| C[Suricata Eve JSON]
    B -->|SIEM| D[Wazuh Alert] 
    B -->|WAF| E[ModSecurity Log]
    
    C --> F[n8n Webhook]
    D --> F
    E --> F
    
    F --> G[Création Case TheHive]
    G --> H[Analyse Cortex]
    H --> I[Enrichissement MISP]
    I --> J{Score Criticité}
    
    J -->|Critique| K[Blocage Auto IP]
    J -->|Moyen| L[Notification SOC]
    J -->|Faible| M[Log Investigation]
    
    K --> N[Update Firewall]
    L --> O[Email + Slack]
    M --> P[Archive]
```

## 🏗️ Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                   SOAR Network: 192.168.15.0/24            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │   TheHive   │ -> │   Cortex    │ -> │    MISP     │    │
│  │ :9000       │    │ :9001       │    │ :80/443     │    │
│  │ Case Mgmt   │    │ Analyzers   │    │ Threat Intel│    │
│  └─────────────┘    └─────────────┘    └─────────────┘    │
│         │                   │                   │         │
│         v                   v                   v         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    n8n Workflows                   │    │
│  │              :5678 - Automation Engine             │    │
│  └─────────────────────────────────────────────────────┘    │
│         │                                                   │
│         v                                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Elasticsearch Cluster                 │    │
│  │           :9200 - Data Storage & Search            │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Docker Compose Architecture

```yaml
# docker-compose.yml overview
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    ports: ["9200:9200"]
    
  thehive:
    image: thehiveproject/thehive:latest
    ports: ["9000:9000"]
    depends_on: [elasticsearch, cassandra]
    
  cortex:
    image: thehiveproject/cortex:latest  
    ports: ["9001:9001"]
    depends_on: [elasticsearch]
    
  misp:
    image: coolacid/misp-docker:core-latest
    ports: ["80:80", "443:443"]
    
  n8n:
    image: n8nio/n8n:latest
    ports: ["5678:5678"]
    volumes: ["./.n8n:/home/node/.n8n"]
```

## 🕷️ TheHive

### Configuration

#### Application Configuration (`application.conf`)
```hocon
# /opt/thehive/conf/application.conf

# Database configuration
db.janusgraph {
  storage {
    backend: cassandra
    hostname: ["cassandra"]
    port: 9042
    keyspace: thehive
  }
  index {
    search {
      backend: elasticsearch
      hostname: ["elasticsearch"]
      port: 9200
      index-name: thehive
    }
  }
}

# Authentication
auth {
  providers: [
    {name: session}
    {name: basic}
    {name: local}
  ]
}

# Cortex integration
play.modules.enabled += connectors.cortex.CortexConnector
cortex {
  servers: [
    {
      name: "Cortex-Server"
      url: "http://cortex:9001"
      auth {
        type: "bearer"
        key: "YOUR_CORTEX_API_KEY"
      }
    }
  ]
}

# MISP integration  
play.modules.enabled += connectors.misp.MispConnector
misp {
  servers: [
    {
      name: "MISP-Server"
      url: "http://misp"
      auth {
        type: "key"
        key: "YOUR_MISP_API_KEY"
      }
      wsConfig {
        ssl {
          loose {
            acceptAnyCertificate: true
          }
        }
      }
    }
  ]
}
```

#### Case Templates Configuration
```json
{
  "name": "EternalBlue Incident",
  "titlePrefix": "EB-",
  "description": "EternalBlue SMB Exploit Detection and Response",
  "severity": 3,
  "tlp": 2,
  "pap": 2,
  "tags": ["eternalblue", "smb", "exploit", "ms17-010"],
  "tasks": [
    {
      "title": "Initial Analysis",
      "description": "Analyze initial alert and gather IOCs",
      "status": "InProgress"
    },
    {
      "title": "Cortex Analysis", 
      "description": "Run Cortex analyzers on IOCs",
      "status": "Waiting"
    },
    {
      "title": "Threat Intelligence",
      "description": "Enrich with MISP intelligence",
      "status": "Waiting"
    },
    {
      "title": "Containment",
      "description": "Block malicious IPs and isolate systems", 
      "status": "Waiting"
    },
    {
      "title": "Eradication",
      "description": "Remove malware and patch vulnerabilities",
      "status": "Waiting"
    },
    {
      "title": "Recovery",
      "description": "Restore systems and monitor",
      "status": "Waiting"
    }
  ]
}
```

#### Custom Case Creation Script
```python
#!/usr/bin/env python3
# /opt/thehive/scripts/create-case.py

from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, Alert
import json
import sys

# TheHive connection
api = TheHiveApi('http://localhost:9000', 'YOUR_API_KEY')

def create_case(alert_data):
    """Create case from alert data"""
    
    # Determine case template based on alert type
    if 'eternalblue' in alert_data.get('tags', []):
        template = 'EternalBlue Incident'
    elif 'xss' in alert_data.get('tags', []):
        template = 'XSS Attack Response'
    elif 'malware' in alert_data.get('tags', []):
        template = 'Malware Investigation'
    else:
        template = 'Generic Security Incident'
    
    # Create case
    case = Case(
        title=f"{template}: {alert_data.get('source_ip', 'Unknown')}",
        description=alert_data.get('description', ''),
        severity=alert_data.get('severity', 2),
        tlp=2,
        pap=2,
        tags=alert_data.get('tags', []),
        template=template
    )
    
    # Create case via API
    response = api.create_case(case)
    
    if response.status_code == 201:
        case_id = response.json()['id']
        print(f"Case created: {case_id}")
        
        # Add observables
        add_observables(case_id, alert_data)
        
        return case_id
    else:
        print(f"Error creating case: {response.text}")
        return None

def add_observables(case_id, alert_data):
    """Add observables to case"""
    
    observables = []
    
    # IP observables
    if alert_data.get('source_ip'):
        observables.append({
            'dataType': 'ip',
            'data': alert_data['source_ip'],
            'message': 'Source IP from alert',
            'tags': ['source', 'malicious']
        })
    
    # Domain observables
    if alert_data.get('domain'):
        observables.append({
            'dataType': 'domain',
            'data': alert_data['domain'],
            'message': 'Malicious domain',
            'tags': ['malicious', 'domain']
        })
    
    # Hash observables
    if alert_data.get('file_hash'):
        observables.append({
            'dataType': 'hash',
            'data': alert_data['file_hash'],
            'message': 'File hash from detection',
            'tags': ['malware', 'hash']
        })
    
    # Add observables to case
    for obs in observables:
        response = api.create_case_observable(case_id, obs)
        print(f"Observable added: {obs['data']}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        alert_json = sys.argv[1]
        alert_data = json.loads(alert_json)
        create_case(alert_data)
```

## 🧠 Cortex

### Configuration

#### Application Configuration (`application.conf`)
```hocon
# /opt/cortex/conf/application.conf

# Elasticsearch
search {
  uri = "http://elasticsearch:9200"
  index = cortex
  nbshards = 5
  nbreplicas = 1
  connectionRequestTimeout = 120000
  connectTimeout = 120000
  socketTimeout = 120000
}

# Authentication
auth {
  provider = [local]
}

# Analyzer configuration
analyzer {
  urls = ["https://download.thehive-project.org/analyzers.json"]
  fork-join-executor {
    parallelism-min = 2  
    parallelism-factor = 2.0
    parallelism-max = 4
  }
}

# Docker configuration for analyzers
docker {
  uri = "unix:///var/run/docker.sock"
  version = "auto"
  maxMemoryPerJob = 512m
}
```

#### Analyzers Configuration
```json
{
  "analyzers": [
    {
      "name": "Abuse_Finder",
      "version": "2.0",
      "dataTypeList": ["ip", "domain"],
      "dockerImage": "cortexneurons/abuse_finder:2.0",
      "enabled": true
    },
    {
      "name": "VirusTotal_GetReport", 
      "version": "3.0",
      "dataTypeList": ["hash", "domain", "ip", "url"],
      "dockerImage": "cortexneurons/virustotal:3.0",
      "configuration": {
        "key": "YOUR_VIRUSTOTAL_API_KEY",
        "auto_extract_artifacts": true
      },
      "enabled": true
    },
    {
      "name": "Shodan_Info",
      "version": "1.0", 
      "dataTypeList": ["ip"],
      "dockerImage": "cortexneurons/shodan:1.0",
      "configuration": {
        "key": "YOUR_SHODAN_API_KEY"
      },
      "enabled": true
    },
    {
      "name": "MISP_Lookup",
      "version": "2.0",
      "dataTypeList": ["hash", "ip", "domain", "url"],
      "dockerImage": "cortexneurons/misp:2.0",
      "configuration": {
        "url": "http://misp",
        "key": "YOUR_MISP_API_KEY",
        "cert_check": false
      },
      "enabled": true
    },
    {
      "name": "MaxMind_GeoIP",
      "version": "1.0",
      "dataTypeList": ["ip"],
      "dockerImage": "cortexneurons/maxmind:1.0",
      "configuration": {
        "key": "YOUR_MAXMIND_LICENSE_KEY"
      },
      "enabled": true
    }
  ]
}
```

#### Custom Analyzer Development
```python
#!/usr/bin/env python3
# /opt/cortex/analyzers/EternalBlue_Checker/eternalblue_checker.py

from cortexutils.analyzer import Analyzer
import requests
import socket
import struct

class EternalBlueChecker(Analyzer):
    """Check if target is vulnerable to EternalBlue"""
    
    def __init__(self):
        Analyzer.__init__(self)
        
    def summary(self, raw):
        return {
            'service': 'EternalBlue Checker',
            'dataType': self.data_type,
            'vulnerable': raw.get('vulnerable', False),
            'smb_version': raw.get('smb_version', 'unknown')
        }
        
    def run(self):
        try:
            if self.data_type == 'ip':
                ip = self.get_param('data', None, 'Missing IP address')
                result = self.check_eternalblue(ip)
                self.report(result)
            else:
                self.error('Invalid data type')
                
        except Exception as e:
            self.error(str(e))
            
    def check_eternalblue(self, ip):
        """Check EternalBlue vulnerability"""
        try:
            # SMB negotiation packet
            smb_header = (
                b'\x00\x00\x00\x2f'  # NetBIOS header
                b'\xfe\x53\x4d\x42'  # SMB2 header  
                b'\x40\x00\x00\x00'
                b'\x00\x00\x00\x00'
                b'\x00\x00\x3f\x00'
                b'\x00\x00\x00\x00'
                b'\x00\x00\x00\x00'
                b'\x00\x00\x00\x00'
                b'\x00\x00\x00\x00'
            )
            
            # Connect to SMB port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 445))
            
            # Send SMB negotiation
            sock.send(smb_header)
            response = sock.recv(1024)
            sock.close()
            
            # Analyze response
            vulnerable = False
            smb_version = 'unknown'
            
            if len(response) > 60:
                # Check for SMBv1 response
                if b'\xff\x53\x4d\x42' in response:
                    smb_version = 'SMBv1'
                    vulnerable = True
                elif b'\xfe\x53\x4d\x42' in response:
                    smb_version = 'SMBv2/3'
                    vulnerable = False
            
            return {
                'vulnerable': vulnerable,
                'smb_version': smb_version,
                'target_ip': ip,
                'port': 445,
                'details': f'SMB service detected: {smb_version}, EternalBlue vulnerable: {vulnerable}'
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'error': str(e),
                'target_ip': ip
            }

if __name__ == '__main__':
    EternalBlueChecker().run()
```

## 🔍 MISP

### Configuration

#### Bootstrap Configuration
```php
// /var/www/MISP/app/Config/bootstrap.php

Configure::write('MISP.baseurl', 'http://misp.soar.lab');
Configure::write('MISP.external_baseurl', 'http://192.168.15.5');
Configure::write('MISP.org', 'SOAR Lab');
Configure::write('MISP.contact', 'admin@soar.lab');

// Redis configuration
Configure::write('MISP.redis_host', '127.0.0.1');
Configure::write('MISP.redis_port', 6379);
Configure::write('MISP.redis_database', 13);
Configure::write('MISP.redis_password', '');

// Background jobs
Configure::write('MISP.background_jobs', true);
Configure::write('MISP.cached_attachments', true);

// Security settings
Configure::write('Security.auth_enforced', true);
Configure::write('Security.log_each_individual_auth_fail', true);
Configure::write('Security.rest_client_baseurl', '');
Configure::write('Security.advanced_authkeys', true);
Configure::write('Security.password_policy_length', 12);
Configure::write('Security.password_policy_complexity', '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/');
```

#### Threat Intelligence Feeds
```json
{
  "feeds": [
    {
      "name": "CIRCL OSINT",
      "url": "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
      "distribution": "3",
      "default": true,
      "enabled": true
    },
    {
      "name": "Malware Domain List",
      "url": "http://www.malwaredomainlist.com/hostslist/mdl.xml",
      "distribution": "3", 
      "input_source": "network",
      "enabled": true
    },
    {
      "name": "URLhaus",
      "url": "https://urlhaus.abuse.ch/downloads/misp/",
      "distribution": "3",
      "enabled": true
    },
    {
      "name": "Feodo Tracker",
      "url": "https://feodotracker.abuse.ch/downloads/misp/",
      "distribution": "3", 
      "enabled": true
    }
  ]
}
```

#### Custom Event Creation Script
```python
#!/usr/bin/env python3
# /opt/misp/scripts/create-event.py

from pymisp import PyMISP
import json
import sys
from datetime import datetime

# MISP connection
misp = PyMISP('http://localhost', 'YOUR_MISP_API_KEY', False)

def create_eternalblue_event(iocs):
    """Create EternalBlue threat event"""
    
    # Create event
    event = misp.new_event(
        distribution=2,  # Connected communities
        threat_level_id=2,  # Medium
        analysis=1,  # Initial
        info="EternalBlue Exploitation Campaign - " + datetime.now().strftime("%Y-%m-%d")
    )
    
    # Add tags
    misp.tag(event['Event']['uuid'], 'tlp:amber')
    misp.tag(event['Event']['uuid'], 'eternalblue')
    misp.tag(event['Event']['uuid'], 'apt:lazarus')
    misp.tag(event['Event']['uuid'], 'mitre-attack:T1210')
    
    # Add attributes
    for ioc in iocs:
        if ioc['type'] == 'ip':
            misp.add_ip_dst(event, ioc['value'], 
                           comment="EternalBlue C2 Server",
                           to_ids=True)
        elif ioc['type'] == 'domain':
            misp.add_domain(event, ioc['value'],
                           comment="Malicious domain",
                           to_ids=True)
        elif ioc['type'] == 'hash':
            misp.add_hashes(event, sha256=ioc['value'],
                           comment="EternalBlue payload",
                           to_ids=True)
    
    # Add vulnerability reference
    misp.add_other(event, "CVE-2017-0144", 
                  comment="MS17-010 SMBv1 RCE vulnerability")
    
    # Add network signature
    misp.add_pattern_in_traffic(event, 
                               "alert tcp any any -> any 445 (msg:\"EternalBlue Exploit\"; content:\"|ff|SMB|72|\";)",
                               comment="Suricata detection rule")
    
    return event['Event']['id']

def create_xss_event(payload_data):
    """Create XSS attack event"""
    
    event = misp.new_event(
        distribution=1,  # This community 
        threat_level_id=3,  # Low-Medium
        analysis=1,
        info="XSS Attack Campaign - " + datetime.now().strftime("%Y-%m-%d")
    )
    
    # Add tags
    misp.tag(event['Event']['uuid'], 'tlp:white') 
    misp.tag(event['Event']['uuid'], 'xss')
    misp.tag(event['Event']['uuid'], 'mitre-attack:T1189')
    
    # Add XSS payload
    misp.add_other(event, payload_data['payload'],
                  comment="XSS injection payload",
                  to_ids=True)
    
    # Add target URL
    misp.add_url(event, payload_data['target_url'],
                comment="Targeted web application",
                to_ids=False)
    
    return event['Event']['id']

if __name__ == "__main__":
    if len(sys.argv) > 2:
        event_type = sys.argv[1]
        data = json.loads(sys.argv[2])
        
        if event_type == "eternalblue":
            event_id = create_eternalblue_event(data['iocs'])
        elif event_type == "xss":
            event_id = create_xss_event(data)
        
        print(f"MISP Event created: {event_id}")
```

## ⚡ n8n

### Workflows Configuration

#### Main Detection Workflow
```json
{
  "name": "SOAR Detection Pipeline",
  "nodes": [
    {
      "name": "Webhook Trigger",
      "type": "n8n-nodes-base.webhook",
      "webhookId": "soar-alert",
      "httpMethod": "POST",
      "responseMode": "responseNode", 
      "options": {}
    },
    {
      "name": "Parse Alert",
      "type": "n8n-nodes-base.function",
      "functionCode": `
        // Parse incoming alert
        const alert = items[0].json;
        
        // Determine alert type
        let alertType = 'unknown';
        if (alert.rule && alert.rule.groups) {
          if (alert.rule.groups.includes('eternalblue')) {
            alertType = 'eternalblue';
          } else if (alert.rule.groups.includes('xss')) {
            alertType = 'xss';
          } else if (alert.rule.groups.includes('malware')) {
            alertType = 'malware';
          }
        }
        
        // Extract IOCs
        const iocs = {
          source_ip: alert.data?.srcip || null,
          dest_ip: alert.data?.dstip || null,
          domain: alert.data?.http?.hostname || null,
          url: alert.data?.http?.url || null,
          file_hash: alert.data?.fileinfo?.md5 || null
        };
        
        return [{
          json: {
            alert_type: alertType,
            severity: alert.rule?.level || 1,
            iocs: iocs,
            original_alert: alert
          }
        }];
      `
    },
    {
      "name": "Create TheHive Case", 
      "type": "n8n-nodes-base.httpRequest",
      "method": "POST",
      "url": "http://thehive:9000/api/case",
      "headers": {
        "Authorization": "Bearer YOUR_THEHIVE_API_KEY",
        "Content-Type": "application/json"
      },
      "body": `{
        "title": "{{$node['Parse Alert'].json.alert_type}} - {{$node['Parse Alert'].json.iocs.source_ip}}",
        "description": "Automated case creation from SOAR detection",
        "severity": {{$node['Parse Alert'].json.severity}},
        "tlp": 2,
        "pap": 2,
        "tags": ["automated", "{{$node['Parse Alert'].json.alert_type}}"]
      }`
    },
    {
      "name": "Run Cortex Analysis",
      "type": "n8n-nodes-base.httpRequest", 
      "method": "POST",
      "url": "http://cortex:9001/api/analyzer/run",
      "headers": {
        "Authorization": "Bearer YOUR_CORTEX_API_KEY"
      },
      "body": `{
        "data": "{{$node['Parse Alert'].json.iocs.source_ip}}",
        "dataType": "ip",
        "analyzer": "VirusTotal_GetReport"
      }`
    },
    {
      "name": "Check Criticality",
      "type": "n8n-nodes-base.if",
      "conditions": {
        "number": [
          {
            "value1": "={{$node['Parse Alert'].json.severity}}",
            "operation": "largerEqual",
            "value2": 10
          }
        ]
      }
    },
    {
      "name": "Block IP (Critical)",
      "type": "n8n-nodes-base.httpRequest",
      "method": "POST", 
      "url": "https://192.168.181.1/api/firewall/alias/addHost/blocked_ips",
      "headers": {
        "Authorization": "Basic YOUR_OPNSENSE_AUTH",
        "Content-Type": "application/json"
      },
      "body": `{
        "host": "{{$node['Parse Alert'].json.iocs.source_ip}}"
      }`
    },
    {
      "name": "Send Notification",
      "type": "n8n-nodes-base.emailSend",
      "fromEmail": "soar@lab.local",
      "toEmail": "soc@lab.local", 
      "subject": "SOAR Alert: {{$node['Parse Alert'].json.alert_type}}",
      "text": "A {{$node['Parse Alert'].json.alert_type}} attack was detected and processed automatically."
    }
  ],
  "connections": {
    "Webhook Trigger": {
      "main": [["Parse Alert"]]
    },
    "Parse Alert": {
      "main": [["Create TheHive Case", "Run Cortex Analysis", "Check Criticality"]]
    },
    "Check Criticality": {
      "true": [["Block IP (Critical)"]],
      "false": [["Send Notification"]]
    }
  }
}
```

#### File Analysis Workflow
```json
{
  "name": "File Analysis Pipeline",
  "nodes": [
    {
      "name": "File Upload Webhook",
      "type": "n8n-nodes-base.webhook",
      "webhookId": "file-analysis",
      "httpMethod": "POST"
    },
    {
      "name": "Calculate Hashes",
      "type": "n8n-nodes-base.function",
      "functionCode": `
        const crypto = require('crypto');
        const fs = require('fs');
        
        const filePath = items[0].json.file_path;
        const fileBuffer = fs.readFileSync(filePath);
        
        const md5 = crypto.createHash('md5').update(fileBuffer).digest('hex');
        const sha1 = crypto.createHash('sha1').update(fileBuffer).digest('hex');
        const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
        
        return [{
          json: {
            file_path: filePath,
            file_size: fileBuffer.length,
            md5: md5,
            sha1: sha1,
            sha256: sha256
          }
        }];
      `
    },
    {
      "name": "VirusTotal Analysis",
      "type": "n8n-nodes-base.httpRequest",
      "method": "POST",
      "url": "http://cortex:9001/api/analyzer/run",
      "body": `{
        "data": "{{$node['Calculate Hashes'].json.sha256}}",
        "dataType": "hash",
        "analyzer": "VirusTotal_GetReport"
      }`
    },
    {
      "name": "MISP Lookup",
      "type": "n8n-nodes-base.httpRequest",
      "method": "GET",
      "url": "http://misp/attributes/restSearch",
      "headers": {
        "Authorization": "YOUR_MISP_API_KEY"
      },
      "qs": {
        "value": "={{$node['Calculate Hashes'].json.sha256}}"
      }
    },
    {
      "name": "Create MISP Event",
      "type": "n8n-nodes-base.httpRequest",
      "method": "POST",
      "url": "http://misp/events",
      "body": `{
        "info": "Suspicious file detected - {{$node['Calculate Hashes'].json.sha256}}",
        "threat_level_id": 2,
        "analysis": 1,
        "distribution": 2
      }`
    }
  ]
}
```

## 🔗 Intégrations

### Webhook Integrations

#### Wazuh to n8n
```bash
#!/bin/bash
# /var/ossec/integrations/n8n

read INPUT_JSON

# Parse Wazuh alert
RULE_ID=$(echo $INPUT_JSON | jq -r '.rule.id')
LEVEL=$(echo $INPUT_JSON | jq -r '.rule.level')
DESCRIPTION=$(echo $INPUT_JSON | jq -r '.rule.description')

# Forward to n8n webhook
curl -X POST "http://192.168.15.3:5678/webhook/soar-alert" \
     -H "Content-Type: application/json" \
     -d "$INPUT_JSON"
```

#### Suricata to n8n
```bash
#!/bin/bash
# /opt/suricata/scripts/forward-to-n8n.sh

tail -F /var/log/suricata/eve.json | while read line; do
    # Check if it's an alert
    if echo "$line" | jq -e '.event_type == "alert"' > /dev/null; then
        # Forward to n8n
        curl -X POST "http://192.168.15.3:5678/webhook/soar-alert" \
             -H "Content-Type: application/json" \
             -d "$line"
    fi
done
```

### API Integration Scripts

#### TheHive API Client
```python
# /opt/soar/scripts/thehive-client.py

import requests
import json

class TheHiveClient:
    def __init__(self, url, api_key):
        self.url = url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def create_case(self, title, description, severity=2):
        data = {
            'title': title,
            'description': description, 
            'severity': severity,
            'tlp': 2,
            'pap': 2
        }
        
        response = requests.post(
            f'{self.url}/api/case',
            headers=self.headers,
            data=json.dumps(data)
        )
        
        return response.json()
    
    def add_observable(self, case_id, datatype, data, message=''):
        obs_data = {
            'dataType': datatype,
            'data': data,
            'message': message,
            'tags': []
        }
        
        response = requests.post(
            f'{self.url}/api/case/{case_id}/artifact',
            headers=self.headers,
            data=json.dumps(obs_data)
        )
        
        return response.json()
```

### Docker Compose Deployment
```yaml
# /opt/soar/docker-compose.yml

version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    container_name: elasticsearch
    environment:
      - http.host=0.0.0.0
      - discovery.type=single-node
      - cluster.name=hive
      - script.allowed_types=inline
      - thread_pool.search.queue_size=100000
      - thread_pool.write.queue_size=10000
      - gateway.recover_after_nodes=1
      - xpack.security.enabled=false
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms256m -Xmx256m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - ./elasticsearch/data:/usr/share/elasticsearch/data
      - ./elasticsearch/logs:/usr/share/elasticsearch/logs
    networks:
      - soar-network

  cassandra:
    image: cassandra:3.11
    container_name: cassandra
    environment:
      - CASSANDRA_CLUSTER_NAME=thehive
    volumes:
      - ./cassandra/data:/var/lib/cassandra/data
    networks:
      - soar-network

  thehive:
    image: thehiveproject/thehive:latest
    container_name: thehive
    depends_on:
      - elasticsearch
      - cassandra
    ports:
      - "9000:9000"
    volumes:
      - ./thehive/conf:/opt/thp/thehive/conf
      - ./thehive/data:/opt/thp/thehive/data
    command: --no-config-secret
    networks:
      - soar-network

  cortex:
    image: thehiveproject/cortex:latest
    container_name: cortex
    depends_on:
      - elasticsearch
    ports:
      - "9001:9001"
    volumes:
      - ./cortex/conf:/opt/thp/cortex/conf
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - soar-network

  misp:
    image: coolacid/misp-docker:core-latest
    container_name: misp
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./misp/data:/var/www/MISP/app/files
      - ./misp/config:/var/www/MISP/app/Config
    environment:
      - MYSQL_HOST=misp-db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=example
      - MISP_ADMIN_EMAIL=admin@misp.local
      - MISP_ADMIN_PASSPHRASE=admin
    networks:
      - soar-network

  misp-db:
    image: mysql:8.0
    container_name: misp-db
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=example
      - MYSQL_ROOT_PASSWORD=password
    volumes:
      - ./misp/mysql:/var/lib/mysql
    networks:
      - soar-network

  n8n:
    image: n8nio/n8n:latest
    container_name: n8n
    ports:
      - "5678:5678"
    volumes:
      - ./n8n:/home/node/.n8n
    environment:
      - N8N_BASIC_AUTH_ACTIVE=true
      - N8N_BASIC_AUTH_USER=admin
      - N8N_BASIC_AUTH_PASSWORD=admin123
    networks:
      - soar-network

networks:
  soar-network:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.15.0/24
```

---

## 🔗 Références

- **[TheHive Project](https://thehive-project.org/)**
- **[Cortex Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers)**
- **[MISP Project](https://www.misp-project.org/)**
- **[n8n Documentation](https://docs.n8n.io/)**
- **[Docker Compose Guide](../../06_DEPLOYMENT/README.md)**

### Fichiers de Configuration

Les fichiers de configuration SOAR sont disponibles dans le dossier externe :  
**📂 [../../../SOAR_SERVER/](../../../SOAR_SERVER/)**

---
**Mise à jour** : Août 2025 - Med10S
