# 🛡️ Configuration ModSecurity WAF
## Web Application Firewall

> **ModSecurity Web Application Firewall**  
> Protection applicative pour serveurs web  

---

## 📋 Table des Matières

- [Vue d'Ensemble](#-vue-densemble)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Règles OWASP CRS](#-règles-owasp-crs)
- [Règles Personnalisées](#-règles-personnalisées)
- [Monitoring](#-monitoring)

---

## 🎯 Vue d'Ensemble

ModSecurity WAF protège nos applications web contre les attaques applicatives (OWASP Top 10) en analysant et filtrant le trafic HTTP/HTTPS en temps réel.

### Protection Coverage

| Attack Type | Protection Level | Detection Method |
|-------------|------------------|------------------|
| **SQL Injection** | ✅ Haute | Pattern matching + ML |
| **XSS (Cross-Site Scripting)** | ✅ Haute | Content analysis |
| **XXE (XML External Entity)** | ✅ Haute | XML parsing |
| **CSRF** | ✅ Moyenne | Token validation |
| **Path Traversal** | ✅ Haute | URL analysis |
| **Command Injection** | ✅ Haute | Command patterns |
| **File Upload** | ✅ Haute | Content inspection |
| **Rate Limiting** | ✅ Haute | Request throttling |

## 🏗️ Architecture

### Deployment Model

```
┌─────────────────────────────────────────────────────────────┐
│                   ModSecurity WAF Flow                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client ──┤ Nginx ├──┤ ModSecurity ├──┤ Web App ├── Backend│
│           Reverse     WAF Engine        Apache/PHP         │
│           Proxy       Rule Engine      Application         │
│                                                             │
│           ┌─────────────┐              ┌─────────────┐    │
│           │ OWASP CRS   │              │ Custom Rules│    │
│           │ Core Rules  │              │ XSS/SQLi    │    │
│           └─────────────┘              └─────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### ModSecurity Phases

```
Phase 1: Request Headers    -> Header analysis
Phase 2: Request Body       -> POST data inspection  
Phase 3: Response Headers   -> Response header check
Phase 4: Response Body      -> Content analysis
Phase 5: Logging           -> Audit logging
```

## 📦 Installation

### Apache Module Installation
```bash
#!/bin/bash
# install-modsecurity.sh

# Install ModSecurity for Apache
apt update
apt install -y libapache2-mod-security2

# Enable module
a2enmod security2

# Create configuration directory
mkdir -p /etc/modsecurity
mkdir -p /var/log/modsecurity
```

### Nginx Module Installation  
```bash
#!/bin/bash
# install-modsecurity-nginx.sh

# Install dependencies
apt install -y build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev uuid-dev

# Download and compile ModSecurity
cd /opt
git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
cd ModSecurity
git submodule init
git submodule update
./build.sh
./configure
make
make install

# Download ModSecurity-nginx connector
cd /opt
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git

# Recompile Nginx with ModSecurity
nginx -V  # Note configure arguments
cd /opt
wget http://nginx.org/download/nginx-1.18.0.tar.gz
tar zxvf nginx-1.18.0.tar.gz
cd nginx-1.18.0
./configure --with-compat --add-dynamic-module=/opt/ModSecurity-nginx [previous_configure_args]
make modules
cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/
```

## ⚙️ Configuration

### Apache Configuration

#### Main Configuration (`security2.conf`)
```apache
# /etc/apache2/mods-enabled/security2.conf

<IfModule mod_security2.c>
    # Basic configuration
    SecRuleEngine On
    SecRequestBodyAccess On
    SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
         "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

    # Request body handling
    SecRequestBodyLimit 134217728
    SecRequestBodyNoFilesLimit 1048576
    SecRequestBodyInMemoryLimit 131072
    SecRequestBodyLimitAction Reject

    # Response body handling
    SecResponseBodyAccess On
    SecResponseBodyMimeType text/plain text/html text/xml
    SecResponseBodyLimit 524288
    SecResponseBodyLimitAction ProcessPartial

    # Filesystem configuration
    SecDataDir /tmp/
    SecTmpDir /tmp/
    SecUploadDir /opt/modsecurity/var/upload/
    SecUploadKeepFiles RelevantOnly
    SecUploadFileMode 0600

    # Debug log configuration
    SecDebugLog /var/log/modsecurity/debug.log
    SecDebugLogLevel 0
    SecAuditEngine RelevantOnly
    SecAuditLogRelevantStatus "^(?:5|4(?!04))"
    SecAuditLogParts ABDEFHIJZ
    SecAuditLogType Serial
    SecAuditLog /var/log/modsecurity/audit.log
    SecAuditLogStorageDir /opt/modsecurity/var/audit/

    # Specify the default actions
    SecDefaultAction "phase:1,deny,log,status:406"
    SecDefaultAction "phase:2,deny,log,status:406"
</IfModule>
```

#### Virtual Host Configuration
```apache
# /etc/apache2/sites-available/secure-app.conf

<VirtualHost *:443>
    ServerName webapp.soar.lab
    DocumentRoot /var/www/html
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/webapp.crt
    SSLCertificateKeyFile /etc/ssl/private/webapp.key
    
    # ModSecurity Configuration
    SecRuleEngine On
    SecAuditEngine On
    SecAuditLog /var/log/modsecurity/webapp_audit.log
    
    # Include OWASP CRS
    Include /usr/share/modsecurity-crs/*.conf
    Include /usr/share/modsecurity-crs/rules/*.conf
    
    # Custom rules
    Include /etc/modsecurity/custom-rules.conf
    
    <Directory /var/www/html>
        Options -Indexes
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
```

### Nginx Configuration

#### Main Configuration (`nginx.conf`)
```nginx
# /etc/nginx/nginx.conf

load_module modules/ngx_http_modsecurity_module.so;

http {
    # ModSecurity configuration
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
}
```

#### ModSecurity Rules File
```nginx
# /etc/nginx/modsec/main.conf

# Include ModSecurity recommended configuration
Include /etc/nginx/modsec/modsecurity.conf

# Include OWASP Core Rule Set
Include /usr/local/modsecurity-crs/crs-setup.conf
Include /usr/local/modsecurity-crs/rules/*.conf

# Custom rules
Include /etc/nginx/modsec/custom-rules.conf
```

## 🛡️ Règles OWASP CRS

### OWASP Core Rule Set Setup
```bash
#!/bin/bash
# setup-owasp-crs.sh

# Download OWASP CRS
cd /opt
git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git
cd owasp-modsecurity-crs
git checkout v3.3/master

# Copy to appropriate location
cp -R /opt/owasp-modsecurity-crs/ /usr/local/modsecurity-crs/

# Setup configuration
cd /usr/local/modsecurity-crs
cp crs-setup.conf.example crs-setup.conf
```

### CRS Configuration (`crs-setup.conf`)
```apache
# /usr/local/modsecurity-crs/crs-setup.conf

# Paranoia Level (1-4, higher = more strict)
SecAction \
 "id:900000,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:tx.paranoia_level=2"

# Anomaly Scoring Threshold
SecAction \
 "id:900110,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:tx.inbound_anomaly_score_threshold=5,\
  setvar:tx.outbound_anomaly_score_threshold=4"

# Application specific settings
SecAction \
 "id:900200,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:tx.allowed_methods=GET HEAD POST OPTIONS,\
  setvar:tx.allowed_request_content_types=|application/x-www-form-urlencoded| |multipart/form-data| |application/json|,\
  setvar:tx.allowed_http_versions=HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0,\
  setvar:tx.restricted_extensions=.asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .resources/ .resx/ .sql/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/,\
  setvar:tx.restricted_headers=/proxy-connection/ /lock-token/ /content-range/ /translate/ /if/"

# Blocking evaluation
SecAction \
 "id:900300,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:tx.do_reput_block=0,\
  setvar:tx.reput_block_flag=0,\
  setvar:tx.do_block=0,\
  setvar:tx.block_flag=0"
```

### Rule Exclusions et Tuning
```apache
# /usr/local/modsecurity-crs/custom-exclusions.conf

# Exclude specific rules for legitimate traffic
SecRuleRemoveById 920230  # Multiple URL encoding
SecRuleRemoveById 921110  # HTTP Request Smuggling

# Application-specific exclusions
SecRule REQUEST_FILENAME "@beginsWith /admin/" \
    "id:1001,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:password"

# Whitelist specific IPs for admin interface
SecRule REMOTE_ADDR "@ipMatch 192.168.181.0/24" \
    "id:1002,\
     phase:1,\
     pass,\
     nolog,\
     ctl:ruleEngine=DetectionOnly"
```

## 🎯 Règles Personnalisées

### Anti-XSS Rules
```apache
# /etc/modsecurity/custom-xss-rules.conf

# Advanced XSS Detection
SecRule ARGS "@detectXSS" \
    "id:1100,\
     phase:2,\
     block,\
     msg:'XSS Attack Detected',\
     logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
     tag:'application-multi',\
     tag:'language-multi',\
     tag:'platform-multi',\
     tag:'attack-xss',\
     tag:'paranoia-level/1',\
     tag:'OWASP_CRS',\
     tag:'capec/1000/152/242',\
     ver:'OWASP_CRS/3.3.0',\
     severity:'CRITICAL',\
     setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
     setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# XSS in URL parameters
SecRule REQUEST_URI "@rx (?i)(\<script[^>]*\>[\s\S]*?\</script\>|javascript:|onerror\s*=|onload\s*=|onclick\s*=)" \
    "id:1101,\
     phase:1,\
     block,\
     msg:'XSS Attack in URL',\
     tag:'attack-xss',\
     logdata:'XSS Pattern: %{MATCHED_VAR}',\
     severity:'HIGH'"

# XSS Event Handlers
SecRule ARGS "@rx (?i)on(abort|blur|change|click|dblclick|dragdrop|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|move|reset|resize|select|submit|unload)\s*=" \
    "id:1102,\
     phase:2,\
     block,\
     msg:'XSS Event Handler Detected',\
     tag:'attack-xss',\
     logdata:'Event Handler: %{MATCHED_VAR}',\
     severity:'HIGH'"

# DOM-based XSS patterns
SecRule ARGS "@rx (?i)(document\.(location|url|domain|referrer)|window\.(location|name)|history\.(pushState|replaceState))" \
    "id:1103,\
     phase:2,\
     block,\
     msg:'Potential DOM-based XSS',\
     tag:'attack-xss',\
     severity:'MEDIUM'"
```

### Anti-SQLi Rules
```apache
# /etc/modsecurity/custom-sqli-rules.conf

# SQL Injection Detection
SecRule ARGS "@detectSQLi" \
    "id:1200,\
     phase:2,\
     block,\
     msg:'SQL Injection Attack Detected',\
     logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
     tag:'application-multi',\
     tag:'language-multi',\
     tag:'platform-multi',\
     tag:'attack-sqli',\
     tag:'paranoia-level/1',\
     tag:'OWASP_CRS',\
     ver:'OWASP_CRS/3.3.0',\
     severity:'CRITICAL'"

# Union-based SQLi
SecRule ARGS "@rx (?i)union\s+(all\s+)?select" \
    "id:1201,\
     phase:2,\
     block,\
     msg:'SQL Injection - UNION SELECT detected',\
     tag:'attack-sqli',\
     severity:'HIGH'"

# Boolean-based blind SQLi
SecRule ARGS "@rx (?i)(and|or)\s+\d+\s*[=<>]\s*\d+(\s+--|\s+#|\s+/\*)" \
    "id:1202,\
     phase:2,\
     block,\
     msg:'SQL Injection - Boolean-based blind SQLi',\
     tag:'attack-sqli',\
     severity:'HIGH'"

# Time-based blind SQLi
SecRule ARGS "@rx (?i)(sleep\(|waitfor\s+delay|benchmark\(|pg_sleep\()" \
    "id:1203,\
     phase:2,\
     block,\
     msg:'SQL Injection - Time-based blind SQLi',\
     tag:'attack-sqli',\
     severity:'HIGH'"

# NoSQL Injection
SecRule ARGS "@rx (?i)(\$where|\$ne|\$in|\$nin|\$gt|\$lt|\$regex|\$exists)" \
    "id:1204,\
     phase:2,\
     block,\
     msg:'NoSQL Injection Attempt',\
     tag:'attack-nosqli',\
     severity:'HIGH'"
```

### Anti-Malware Rules
```apache
# /etc/modsecurity/custom-malware-rules.conf

# Malicious file upload detection
SecRule FILES_TMPNAMES "@inspectFile /opt/modsecurity/bin/malware-scanner.sh" \
    "id:1300,\
     phase:2,\
     block,\
     msg:'Malicious File Upload Detected',\
     tag:'attack-malware',\
     severity:'CRITICAL'"

# Suspicious file extensions
SecRule ARGS "@rx \.(php|asp|aspx|jsp|exe|bat|cmd|com|scr|pif)\." \
    "id:1301,\
     phase:2,\
     block,\
     msg:'Suspicious File Extension in Parameter',\
     tag:'attack-malware',\
     severity:'HIGH'"

# Web shell detection
SecRule RESPONSE_BODY "@rx (?i)(c99|r57|webshell|hacktool|rootkit)" \
    "id:1302,\
     phase:4,\
     block,\
     msg:'Web Shell Content Detected',\
     tag:'attack-webshell',\
     severity:'CRITICAL'"

# Backdoor communication patterns
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap|nmap|nikto|dirb|burp|acunetix)" \
    "id:1303,\
     phase:1,\
     block,\
     msg:'Security Scanner Detected',\
     tag:'attack-scanner',\
     severity:'HIGH'"
```

### Rate Limiting Rules
```apache
# /etc/modsecurity/custom-ratelimit-rules.conf

# Global request rate limiting
SecAction "id:1400,phase:1,nolog,pass,initcol:ip=%{remote_addr},setvar:ip.requests_per_min=+1,expirevar:ip.requests_per_min=60"

SecRule IP:REQUESTS_PER_MIN "@gt 60" \
    "id:1401,\
     phase:1,\
     deny,\
     status:429,\
     msg:'Rate limiting: Too many requests per minute',\
     tag:'dos-protection',\
     severity:'MEDIUM',\
     setenv:RATELIMITED=1"

# Login brute force protection  
SecRule REQUEST_URI "@streq /login" \
    "id:1402,\
     phase:1,\
     nolog,\
     pass,\
     initcol:ip=%{remote_addr},\
     setvar:ip.login_attempts=+1,\
     expirevar:ip.login_attempts=300"

SecRule IP:LOGIN_ATTEMPTS "@gt 5" \
    "id:1403,\
     phase:1,\
     deny,\
     status:429,\
     msg:'Login brute force protection',\
     tag:'brute-force',\
     severity:'HIGH'"

# API rate limiting
SecRule REQUEST_URI "@beginsWith /api/" \
    "id:1404,\
     phase:1,\
     nolog,\
     pass,\
     initcol:ip=%{remote_addr},\
     setvar:ip.api_requests=+1,\
     expirevar:ip.api_requests=60"

SecRule IP:API_REQUESTS "@gt 100" \
    "id:1405,\
     phase:1,\
     deny,\
     status:429,\
     msg:'API rate limit exceeded',\
     tag:'api-abuse',\
     severity:'MEDIUM'"
```

## 📊 Monitoring et Logging

### Audit Log Analysis

#### Log Parser Script
```bash
#!/bin/bash
# /opt/modsecurity/parse-audit-logs.sh

AUDIT_LOG="/var/log/modsecurity/audit.log"
OUTPUT_DIR="/var/log/modsecurity/parsed"

# Parse audit logs for attacks
python3 << EOF
import re
import json
from datetime import datetime

attacks = {
    'xss': 0,
    'sqli': 0,
    'malware': 0,
    'scanner': 0,
    'ratelimit': 0
}

with open('$AUDIT_LOG', 'r') as f:
    content = f.read()
    
    # Count different attack types
    attacks['xss'] = len(re.findall(r'attack-xss', content))
    attacks['sqli'] = len(re.findall(r'attack-sqli', content))  
    attacks['malware'] = len(re.findall(r'attack-malware', content))
    attacks['scanner'] = len(re.findall(r'attack-scanner', content))
    attacks['ratelimit'] = len(re.findall(r'dos-protection|api-abuse', content))

# Output JSON report
report = {
    'timestamp': datetime.now().isoformat(),
    'attacks': attacks,
    'total': sum(attacks.values())
}

with open('$OUTPUT_DIR/attack-summary.json', 'w') as f:
    json.dump(report, f, indent=2)

print(f"Attack summary: {attacks}")
EOF
```

#### Real-time Monitoring
```bash
#!/bin/bash
# /opt/modsecurity/realtime-monitor.sh

# Monitor audit log for high-severity events
tail -f /var/log/modsecurity/audit.log | while read line; do
    if echo "$line" | grep -q "severity='CRITICAL'"; then
        # Extract attack details
        ATTACK_TYPE=$(echo "$line" | grep -o "attack-[a-z]*" | head -1)
        SRC_IP=$(echo "$line" | grep -o "client: [0-9.]*" | cut -d' ' -f2)
        
        # Send alert to SOAR
        curl -X POST "http://192.168.15.3:5678/webhook/modsecurity-alert" \
             -H "Content-Type: application/json" \
             -d "{
               \"timestamp\": \"$(date -Iseconds)\",
               \"severity\": \"CRITICAL\",
               \"attack_type\": \"$ATTACK_TYPE\",
               \"source_ip\": \"$SRC_IP\",
               \"raw_log\": \"$line\"
             }"
        
        # Log to syslog for Wazuh pickup
        logger -t modsecurity-critical "CRITICAL attack detected: $ATTACK_TYPE from $SRC_IP"
    fi
done
```

### Performance Metrics

#### Statistics Script
```bash
#!/bin/bash
# /opt/modsecurity/stats.sh

# Get ModSecurity statistics
echo "=== ModSecurity Statistics ==="
echo "Date: $(date)"

# Count total requests processed
TOTAL_REQUESTS=$(grep -c "ModSecurity: Warning" /var/log/modsecurity/audit.log)
echo "Total requests processed: $TOTAL_REQUESTS"

# Count blocked requests
BLOCKED_REQUESTS=$(grep -c "ModSecurity: Access denied" /var/log/modsecurity/audit.log)
echo "Blocked requests: $BLOCKED_REQUESTS"

# Calculate block rate
if [ $TOTAL_REQUESTS -gt 0 ]; then
    BLOCK_RATE=$(echo "scale=2; $BLOCKED_REQUESTS * 100 / $TOTAL_REQUESTS" | bc)
    echo "Block rate: $BLOCK_RATE%"
fi

# Top attacking IPs
echo -e "\n=== Top Attacking IPs ==="
grep "ModSecurity: Access denied" /var/log/modsecurity/audit.log | \
    grep -o "client: [0-9.]*" | \
    sort | uniq -c | sort -nr | head -10

# Attack types distribution
echo -e "\n=== Attack Types ==="
grep "tag:" /var/log/modsecurity/audit.log | \
    grep -o "attack-[a-zA-Z]*" | \
    sort | uniq -c | sort -nr
```

### Dashboard Integration

#### Grafana Metrics Export
```bash
#!/bin/bash
# /opt/modsecurity/export-metrics.sh

# Export metrics to InfluxDB for Grafana
INFLUX_URL="http://192.168.15.4:8086"
INFLUX_DB="modsecurity"

# Parse last hour of logs
METRICS=$(python3 << EOF
import re
from datetime import datetime, timedelta

# Calculate metrics
xss_attacks = len(re.findall(r'attack-xss', open('/var/log/modsecurity/audit.log').read()))
sqli_attacks = len(re.findall(r'attack-sqli', open('/var/log/modsecurity/audit.log').read()))
blocked_requests = len(re.findall(r'Access denied', open('/var/log/modsecurity/audit.log').read()))

print(f"xss_attacks={xss_attacks}")
print(f"sqli_attacks={sqli_attacks}")  
print(f"blocked_requests={blocked_requests}")
EOF
)

# Send to InfluxDB
for metric in $METRICS; do
    curl -X POST "$INFLUX_URL/write?db=$INFLUX_DB" \
         --data-binary "modsecurity,$metric $(date +%s)000000000"
done
```

## 🔧 Troubleshooting

### Common Issues

#### High False Positives
```apache
# Tuning for false positives
SecRuleUpdateTargetByTag "OWASP_CRS" "!ARGS:legitimate_param"
SecRuleUpdateActionById 942100 "pass"  # Temporarily pass specific rule
```

#### Performance Issues
```apache
# Performance tuning
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecResponseBodyAccess Off  # Disable response inspection if not needed
SecRequestBodyLimit 1048576  # Reduce body limit
```

#### Log Rotation
```bash
# /etc/logrotate.d/modsecurity
/var/log/modsecurity/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 www-data adm
    postrotate
        /bin/kill -USR1 `cat /var/run/apache2/apache2.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
```

---

## 🔗 Références

- **[ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)**
- **[OWASP Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/)**
- **[Integration avec Wazuh](../wazuh/README.md)**
- **[Troubleshooting Guide](../../07_DOCUMENTATION/troubleshooting/)**

### Fichiers de Configuration

Les fichiers de configuration ModSecurity sont disponibles dans le dossier externe :  
**📂 [../../../ModSecurity/](../../../ModSecurity/)**

---
**Mise à jour** : Août 2025 - Med10S
