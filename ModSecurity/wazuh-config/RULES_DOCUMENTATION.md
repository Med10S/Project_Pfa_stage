# ModSecurity Wazuh Rules Documentation
**Created by**: Med10S  
**Date**: August 11, 2025  
**Purpose**: Comprehensive XSS attack detection and SOAR integration

## Rule Categories

### 🔍 Base Detection Rules (100001-100002)
- **100001**: Base ModSecurity JSON audit log detection
- **100002**: Security rule trigger detection

### 🚨 XSS Attack Classification (100101-100104)
- **100101**: XSS Attack Detected and Blocked (libinjection - Rule 1001)
- **100102**: Script Tag XSS Attack Blocked (Rule 1002)  
- **100103**: JavaScript Protocol XSS Attack Blocked (Rule 1003)
- **100104**: Event Handler XSS Attack Blocked (Rule 1004)

### ⚡ Severity Assessment (100201-100203)
- **100201**: Multiple XSS attacks from same IP (Frequency rule)
- **100202**: **CRITICAL** - XSS Attack Allowed (HTTP 200 response)
- **100203**: Large payload XSS attack

### 📊 Custom Alert Processing (100301-100303)
- **100301**: Custom ModSecurity alert log detection
- **100302**: Parse custom XSS alert details
- **100303**: Critical custom alerts

### 🕵️ Attack Source Analysis (100401-100402)
- **100401**: XSS from known security tools
- **100402**: XSS with suspicious referrer

### 🔗 SOAR Integration (100501-100502)
- **100501**: **SOAR Trigger** - High-severity events
- **100502**: Multiple attack vectors from same IP

### 🎯 Advanced Detection (100601)
- **100601**: Composite attack detection (XSS + other attacks)

### 🛡️ False Positive Reduction (100701)
- **100701**: Internal network testing detection

## Severity Levels
- **Level 15**: CRITICAL - Bypassed attacks (HTTP 200)
- **Level 13**: High - SOAR integration triggers
- **Level 12**: High - Multiple attacks/advanced threats
- **Level 11**: Medium-High - Large payloads/suspicious sources
- **Level 10**: Medium - Standard blocked attacks
- **Level 9**: Medium-Low - Suspicious but blocked
- **Level 5**: Low - Internal testing
- **Level 3**: Info - Security rule triggered
- **Level 0**: Debug - Base log entries

## Integration Points

### 🔄 SOAR Platform Triggers
Rules that trigger SOAR workflow:
- Multiple attacks (100201)
- WAF bypasses (100202)  
- Critical custom alerts (100303)
- Advanced threats (100502)

### 📈 Analytics and Correlation
- Frequency-based detection
- Time-based correlation
- IP reputation analysis
- Attack pattern recognition

### 🚀 Active Response
- Automated blocking capabilities
- Alert escalation
- Notification triggers
- Integration with external tools

## Log Sources Monitored
1. **JSON Audit Logs**: `/var/log/apache2/modsec_audit.log`
2. **Custom Alerts**: `/var/log/apache2/modsecurity_custom_alerts.log`
3. **Apache Access**: `/var/log/apache2/access.log`
4. **Apache Error**: `/var/log/apache2/error.log`

## Testing Commands

```bash
# Test XSS detection
curl -H "Host: 192.168.15.2" "http://192.168.15.2/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"

# Check Wazuh alerts
docker logs wazuh-agent-modsec-Med10S

# Monitor custom alerts
tail -f /var/log/apache2/modsecurity_custom_alerts.log

# View Wazuh alerts in JSON
tail -f /var/ossec/logs/alerts/alerts.json
```

## Rule Maintenance
- Rules are automatically loaded by Wazuh agent
- No restart required for rule updates
- Custom decoders enhance log parsing
- SOAR integration points clearly marked

This comprehensive ruleset provides enterprise-grade XSS detection and response capabilities integrated with your SOAR platform.
