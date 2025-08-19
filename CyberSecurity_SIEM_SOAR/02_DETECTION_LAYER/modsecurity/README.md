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

git clone --depth 1 https://github.com/Med10S/Project_Pfa_stage
cd Project_Pfa_stage/ModSecurity
docker-compose up -d


```

## ⚙️ Configuration

### Apache Configuration

#### Virtual Host Configuration


```apache
# ModSecurity Apache VirtualHost Configuration
# Generated for: ${ANALYST_NAME:-Med10S}
# Date: 2025-08-09

<VirtualHost *:80>
    ServerAdmin ${ANALYST_NAME:-admin}@${SERVER_NAME:-modsecurity.local}
    ServerName ${SERVER_NAME:-modsecurity.local}
    DocumentRoot /var/www/html
    
    # Logging Configuration
    ErrorLog /var/log/apache2/modsecurity_error.log
    CustomLog /var/log/apache2/modsecurity_access.log combined
    LogLevel ${LOG_LEVEL:-warn}
....
```

[extracted from](../../../ModSecurity/apache-config/000-default.conf)


### Nginx Configuration

#### Main Configuration (`default.conf`)
```nginx
# Nginx configuration for ModSecurity WAF with proper backend routing

# Real IP configuration for multi-hop network topology
# Trust proxy IPs from all network layers:
# - Docker bridge networks (172.20.0.0/16)  
# - VM host-only network (192.168.15.0/24)
# - Local WiFi network (192.168.1.0/24)
set_real_ip_from 172.20.0.0/16;     # Docker bridge network
set_real_ip_from 172.16.0.0/12;     # All Docker networks  
set_real_ip_from 192.168.15.0/24;   # VM host-only network
set_real_ip_from 192.168.1.0/24;    # WiFi network
set_real_ip_from 10.0.0.0/8;        # Private networks
real_ip_header X-Forwarded-For;
real_ip_recursive on;

map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

# Increase buffer sizes to handle large headers
large_client_header_buffers 4 32k;
client_header_buffer_size 8k;
proxy_buffer_size 8k;
proxy_buffers 8 8k;

server {
    listen 80 default_server;
    server_name modsecurity-soar.local;
    
```

[extracted from](../../../ModSecurity/nginx-config/default.conf)


#### ModSecurity Rules File
```nginx
# -- Rule engine initialization ----------------------------------------------

# Enable ModSecurity, attaching it to every transaction. Use On
# to block attacks and provide real protection.
#
SecRuleEngine On


# -- Request body handling ---------------------------------------------------

# Allow ModSecurity to access request bodies. If you don't, ModSecurity
# won't be able to see any POST parameters, which opens a large security
# hole for attackers to exploit.
#
SecRequestBodyAccess On

# Block IPs from external file
# The file should contain ModSecurity rules for blocking IPs
#
Include /etc/modsecurity.d/blocked_ips.conf
```

[extracted from](../../../ModSecurity/modsecurity-config/modsecurity.conf)


## 🔗 Références

- **[ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual)**
- **[OWASP Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/)**
- **[Integration avec Wazuh](../wazuh/README.md)**

### Fichiers de Configuration

Les fichiers de configuration ModSecurity sont disponibles dans le dossier externe :  
**📂 [../../../ModSecurity/](../../../ModSecurity/)**

---
**Mise à jour** : Août 2025 - Med10S
