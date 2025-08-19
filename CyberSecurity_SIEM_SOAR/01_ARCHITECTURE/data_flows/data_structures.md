# 📂 Structure des Données - Workflows n8n

## 🔴 EternalBlue Detection Workflow

### Input Data Structure
```json
{
  "eternalblue_alert": {
    "webhook_endpoint": "http://192.168.15.3:5678/webhook/eternalblue-alert",
    "alert_format": {
      "timestamp": "2025-08-19T14:30:15Z",
      "source": "suricata",
      "rule": {
        "id": "2024001",
        "category": "eternalblue",
        "severity": "critical",
        "message": "ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response"
      },
      "network": {
        "src_ip": "192.168.183.100",
        "dst_ip": "192.168.183.10", 
        "src_port": 45678,
        "dst_port": 445,
        "protocol": "TCP"
      },
      "payload": {
        "size": 2048,
        "hex_data": "ff534d4272000000001801282000000000000000000000000000000000fffe00000000000000",
        "signature_match": "\\xff\\x53\\x4d\\x42\\x72",
        "shellcode_detected": true
      },
      "phase_classification": {
        "phase_1": "SMB_NEGOTIATE_REQUEST",
        "phase_2": "BUFFER_OVERFLOW_ATTEMPT", 
        "phase_3": "PAYLOAD_EXECUTION"
      }
    }
  }
}
```

### Processing Logic
```javascript
// n8n Node: Phase Classification
const alert = $input.item.json;
const ruleId = alert.rule?.id;
const severity = alert.rule?.severity;
const payloadSize = alert.payload?.size || 0;

let phase = 1;
let riskLevel = "low";

// Phase 1: SMB Negotiation
if (ruleId === "2024001" && alert.network.dst_port === 445) {
  phase = 1;
  riskLevel = "low";
}

// Phase 2: Exploit Attempt  
if (alert.payload?.signature_match && payloadSize > 1024) {
  phase = 2;
  riskLevel = "medium";
}

// Phase 3: Critical/Payload
if (alert.payload?.shellcode_detected && severity === "critical") {
  phase = 3;
  riskLevel = "critical";
}

return {
  json: {
    ...alert,
    analysis: {
      phase: phase,
      risk_level: riskLevel,
      requires_immediate_response: riskLevel === "critical"
    }
  }
};
```

### TheHive Case Structure
```json
{
  "thehive_case": {
    "title": "EternalBlue Phase 3 - Critical Payload Execution",
    "description": "Critical EternalBlue attack detected on PACS server 192.168.183.10",
    "severity": 3,
    "tlp": 1,
    "pap": 2,
    "tags": ["eternalblue", "ransomware", "phase3", "pacs-server"],
    "tasks": [
      {
        "title": "Network Isolation",
        "description": "Isolate affected PACS server immediately",
        "status": "InProgress"
      },
      {
        "title": "Forensic Analysis", 
        "description": "Analyze PCAP files and memory dumps",
        "status": "Waiting"
      },
      {
        "title": "Medical Team Notification",
        "description": "Alert medical staff about PACS unavailability", 
        "status": "Completed"
      }
    ],
    "observables": [
      {
        "dataType": "ip",
        "data": "192.168.183.100",
        "message": "Source IP of EternalBlue attack",
        "tags": ["malicious", "attacker"]
      },
      {
        "dataType": "file",
        "data": "/var/log/suricata/eternalblue_192.168.183.100_to_192.168.183.10_20250819143015.pcap",
        "message": "Network capture of EternalBlue attack",
        "tags": ["pcap", "evidence"]
      }
    ]
  }
}
```

---

## 🟡 DNS Malware Analysis Workflow

### Wazuh Sysmon Input
```json
{
  "wazuh_dns_alert": {
    "webhook_endpoint": "http://192.168.15.3:5678/webhook/35f89961-c366-4a7c-8b34-abc123def456",
    "input": {
      "type": "log"
    },
    "agent": {
      "id": "001", 
      "name": "WIN-WORKSTATION-01",
      "ip": "192.168.183.15",
      "type": "windows"
    },
    "manager": {
      "name": "wazuh-manager"
    },
    "rule": {
      "id": "61603",
      "level": 7,
      "description": "Windows Sysmon - DNS query logged",
      "groups": ["sysmon", "dns", "windows"]
    },
    "data": {
      "win": {
        "system": {
          "providerName": "Microsoft-Windows-Sysmon",
          "eventID": "22",
          "computer": "WIN-WORKSTATION-01",
          "processID": "2024"
        },
        "eventdata": {
          "ruleName": "DNS Query",
          "utcTime": "2025-08-19 14:25:30.123",
          "processGuid": "{12345678-1234-5678-9012-123456789012}",
          "processId": "4284",
          "image": "C:\\Windows\\System32\\chrome.exe",
          "user": "HOSPITAL\\doctor01",
          "queryName": "malicious-site.com",
          "queryStatus": "0",
          "queryResults": "type:  5 ::ffff:192.168.183.100;type:  5 ::ffff:185.234.217.25;",
          "queryType": "5"
        }
      }
    },
    "timestamp": "2025-08-19T14:25:30.500Z",
    "location": "EventChannel"
  }
}
```

### Observable Creation Logic
```javascript
// n8n Node: Create Observable
const alertData = $input.item.json.body || $input.item.json;
const eventdata = alertData.data?.win?.eventdata || {};

// Extract domain name
const domain = eventdata.queryName;
if (!domain) {
  throw new Error("No domain found in DNS query");
}

// Extract resolved IPs
const queryResults = eventdata.queryResults || "";
const ipMatches = queryResults.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/g) || [];
const resolvedIPs = ipMatches.map(ip => ip.replace('::ffff:', ''));

// Create primary observable
const observable = {
  dataType: 'domain',
  data: domain,
  message: `DNS query to ${domain} from ${eventdata.image} by ${eventdata.user}`,
  tags: ['dns', 'sysmon', 'windows'],
  context: {
    process: {
      name: eventdata.image,
      pid: eventdata.processId,
      guid: eventdata.processGuid
    },
    user: eventdata.user,
    resolved_ips: resolvedIPs,
    query_type: eventdata.queryType,
    timestamp: eventdata.utcTime
  }
};

return { json: { observable, alert_id: alertData.id } };
```

### Cortex Analysis Results
```json
{
  "cortex_analysis": {
    "observable_id": "6789abcd-ef01-2345-6789-abcdef012345",
    "analyzers_executed": [
      "MISP_2_1",
      "VirusTotal_GetReport_3_0", 
      "Shodan_DNSResolve_1_0"
    ],
    "reports": {
      "misp_report": {
        "service": "MISP_2_1",
        "status": "Success",
        "results": [
          {
            "name": "MISP Instance",
            "result": [
              {
                "id": "12345",
                "info": "Banking Trojan C2 Infrastructure",
                "threat_level_id": "2",
                "analysis": "2",
                "Orgc": {
                  "name": "CIRCL"
                },
                "Tag": [
                  {
                    "name": "tlp:amber"
                  },
                  {
                    "name": "misp-galaxy:threat-actor=\"APT28\""
                  }
                ]
              }
            ]
          }
        ]
      },
      "virustotal_report": {
        "service": "VirusTotal_GetReport_3_0",
        "status": "Success", 
        "taxonomies": [
          {
            "level": "malicious",
            "namespace": "VT",
            "predicate": "GetReport",
            "value": "13/89"
          }
        ]
      }
    },
    "threat_assessment": {
      "overall_level": "malicious",
      "confidence": "high", 
      "requires_case_creation": true,
      "misp_events_found": 1,
      "vt_detections": 13
    }
  }
}
```

### Decision Engine Logic
```javascript
// n8n Node: Threat Analysis Engine
function analyzeReports(localReport, analyzerReport) {
  let threatLevel = "info";
  let hasEvents = false;
  const findings = [];
  
  // Process MISP results
  if (analyzerReport?.full?.results) {
    analyzerReport.full.results.forEach(resultItem => {
      if (resultItem?.result && Array.isArray(resultItem.result)) {
        resultItem.result.forEach(item => {
          hasEvents = true;
          findings.push({
            source: "MISP",
            event_id: item.id,
            info: item.info,
            threat_level: item.threat_level_id,
            tags: item.Tag?.map(tag => tag.name).join(', ')
          });
          
          // Update threat level based on MISP
          if (item.threat_level_id <= 2) {
            threatLevel = "malicious";
          }
        });
      }
    });
  }
  
  // Process VirusTotal taxonomies
  if (localReport?.["VirusTotal_GetReport_3_0"]?.taxonomies) {
    localReport["VirusTotal_GetReport_3_0"].taxonomies.forEach(taxonomy => {
      findings.push({
        source: "VirusTotal",
        level: taxonomy.level,
        value: taxonomy.value
      });
      
      if (taxonomy.level === "malicious") {
        threatLevel = "malicious";
        hasEvents = true;
      }
    });
  }
  
  return {
    threatLevel,
    hasEvents,
    findings,
    createCase: hasEvents || threatLevel !== "info"
  };
}
```

---

## 🟠 XSS Attack Response Workflow

### ModSecurity WAF Input
```json
{
  "modsecurity_xss_alert": {
    "webhook_endpoint": "http://192.168.15.3:5678/webhook/a90f08f5-8a0a-46b7-9c5d-123456789abc",
    "body": {
      "raw_log": {
        "transaction": {
          "timestamp": "2025-08-19T14:35:22Z",
          "request_id": "XsS7k9mP@8bK3nQ1rT4uY",
          "client_ip": "192.168.183.100",
          "method": "POST",
          "uri": "/patient-portal/contact.php",
          "http_version": "HTTP/1.1",
          "headers": {
            "Host": "hospital-app.local",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "187",
            "Cookie": "PHPSESSID=abc123def456",
            "Referer": "https://hospital-app.local/patient-portal/contact.html"
          },
          "request_body": "name=<script>alert('XSS')</script>&email=malicious@attacker.com&message=Test attack&department=emergency",
          "rules_matched": [
            {
              "id": "1001",
              "rev": "2", 
              "msg": "XSS Attack Detected in Arguments",
              "data": "Matched Data: <script>alert('XSS')</script> found within ARGS:name: <script>alert('xss')</script>",
              "severity": "CRITICAL",
              "ver": "OWASP_CRS/3.3.0",
              "maturity": "9",
              "accuracy": "8",
              "file": "/etc/apache2/modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
              "line": "37",
              "logdata": "XSS Attack Detected",
              "tag": ["application-multi", "language-multi", "platform-multi", "attack-xss"]
            }
          ],
          "response": {
            "status": 403,
            "headers": {
              "Content-Type": "text/html",
              "X-Content-Type-Options": "nosniff"
            },
            "body": "<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>Access Denied</h1><p>Your request was blocked due to security policy.</p></body></html>"
          }
        }
      }
    }
  }
}
```

### IP Extraction & Blocking Logic
```javascript
// n8n Node: Extract Client IP
const alertBody = $input.item.json.body;
const transaction = alertBody?.raw_log?.transaction;

if (!transaction || !transaction.client_ip) {
  throw new Error("No client IP found in alert");
}

const clientIP = transaction.client_ip;
const attackDetails = {
  ip: clientIP,
  uri: transaction.uri,
  method: transaction.method,
  user_agent: transaction.headers?.["User-Agent"],
  attack_payload: transaction.request_body,
  rule_triggered: transaction.rules_matched?.[0]?.msg,
  timestamp: transaction.timestamp
};

return { 
  json: { 
    ip_to_block: clientIP,
    attack_details: attackDetails 
  } 
};
```

### OPNsense API Integration
```javascript
// n8n Node: OPNsense IP Blocker
const http = require('http');

const IP_TO_BLOCK = $input.first().json.ip_to_block;
const OPNSENSE_CONFIG = {
  url: "http://192.168.181.1",
  api_key: "ud8fjSvMwTgX9P7fEL4eWUfbOk+3/tiBpmtMh+dQU4OkH4YiJ/iE3aQBpWPXVHpDzyMel5v3Lql98j7e",
  api_secret: "EzfhmRdb8Il60Ab+KQHZ5G1/zbRIU4Kgg5l6HcfQnXXOmHbH2iloqDBjih4EOmfmX1dnf8ifdNndbAND",
  alias_id: "2e9d5f53-be6b-4735-9f32-ffc60baea3f1"
};

// Get current alias content
const currentData = await makeApiCall(`/api/firewall/alias/get_item/${OPNSENSE_CONFIG.alias_id}`);

// Extract existing IPs
let currentIPs = [];
if (currentData.alias?.content) {
  for (const [ip, config] of Object.entries(currentData.alias.content)) {
    if (config?.selected === 1 && ip.includes('.')) {
      currentIPs.push(ip);
    }
  }
}

// Add new IP if not exists
const ipExists = currentIPs.includes(IP_TO_BLOCK);
if (!ipExists) {
  currentIPs.push(IP_TO_BLOCK);
}

// Update alias
const updatePayload = {
  alias: {
    content: currentIPs.join("\n"),
    description: "Automatic XSS block by n8n SOAR",
    enabled: "1", 
    name: "Black_list",
    type: "host"
  }
};

await makeApiCall(`/api/firewall/alias/set_item/${OPNSENSE_CONFIG.alias_id}`, 'POST', updatePayload);
await makeApiCall("/api/firewall/alias/reconfigure", 'POST');

return {
  json: {
    action: "ip_blocked",
    ip: IP_TO_BLOCK,
    total_blocked_ips: currentIPs.length,
    already_existed: ipExists,
    timestamp: new Date().toISOString()
  }
};
```

### Case Creation Structure
```json
{
  "xss_case": {
    "title": "XSS Attack Blocked - IP 192.168.183.100",
    "description": "Cross-Site Scripting attack detected and blocked on patient portal",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["xss", "web-attack", "patient-portal", "blocked"],
    "customFields": {
      "attack_vector": {
        "string": "POST /patient-portal/contact.php"
      },
      "payload": {
        "string": "<script>alert('XSS')</script>"
      },
      "source_ip": {
        "string": "192.168.183.100"
      },
      "blocked_automatically": {
        "boolean": true
      }
    },
    "observables": [
      {
        "dataType": "ip",
        "data": "192.168.183.100",
        "message": "Source IP of XSS attack - automatically blocked",
        "tags": ["malicious", "blocked", "xss-source"]
      },
      {
        "dataType": "url", 
        "data": "https://hospital-app.local/patient-portal/contact.php",
        "message": "Target URL of XSS attack",
        "tags": ["target", "patient-portal"]
      },
      {
        "dataType": "other",
        "data": "<script>alert('XSS')</script>",
        "message": "XSS payload detected in form submission",
        "tags": ["payload", "javascript", "xss"]
      }
    ]
  }
}
```

---

## 📊 Data Flow Summary

### Processing Statistics
```json
{
  "data_processing_stats": {
    "eternalblue_workflow": {
      "avg_execution_time": "12.3 seconds",
      "data_points_processed": 47,
      "pcap_files_generated": 23,
      "critical_alerts": 3,
      "cases_created": 8
    },
    "dns_analysis_workflow": {
      "avg_execution_time": "8.7 seconds", 
      "domains_analyzed": 1247,
      "cortex_analyses": 892,
      "misp_queries": 634,
      "malicious_domains": 45,
      "cases_created": 45
    },
    "xss_response_workflow": {
      "avg_execution_time": "4.2 seconds",
      "ips_processed": 156,
      "ips_blocked": 45,
      "duplicate_attempts": 23,
      "cases_created": 89
    }
  }
}
```

### Integration Points
```json
{
  "api_integrations": {
    "thehive": {
      "endpoint": "http://192.168.15.2:9000/api",
      "auth_method": "Bearer Token",
      "operations": ["create_alert", "create_case", "add_observable", "update_case"],
      "success_rate": "99.2%"
    },
    "cortex": {
      "endpoint": "http://192.168.15.4:9001/api",
      "auth_method": "API Key",
      "analyzers": ["MISP_2_1", "VirusTotal_GetReport_3_0", "Shodan_DNSResolve_1_0"],
      "avg_analysis_time": "6.8 seconds"
    },
    "opnsense": {
      "endpoint": "http://192.168.181.1/api",
      "auth_method": "Basic Auth (API Key + Secret)", 
      "operations": ["get_alias", "update_alias", "reconfigure"],
      "response_time": "1.2 seconds"
    },
    "telegram": {
      "endpoint": "https://api.telegram.org/bot{token}",
      "auth_method": "Bot Token",
      "chat_id": "medical_team_alerts",
      "delivery_rate": "100%"
    }
  }
}
```
