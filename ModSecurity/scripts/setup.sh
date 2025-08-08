#!/bin/bash

# Script de configuration ModSecurity + Wazuh
# Créé par Med10S - 2025-08-08

echo "🚀 Configuration ModSecurity + Wazuh SOAR..."

# Création des répertoires
mkdir -p {modsecurity-config,apache-config,logs,ssl,wazuh-config,wazuh-integration,scripts}
mkdir -p logs/audit

# Permissions
chmod +x scripts/*.sh
chmod +x scripts/*.py
chmod 755 logs logs/audit

echo "📥 Téléchargement des règles OWASP CRS..."
if [ ! -d "owasp-crs" ]; then
    git clone https://github.com/coreruleset/coreruleset.git owasp-crs
    cp owasp-crs/rules/*.conf modsecurity-config/
    cp owasp-crs/crs-setup.conf.example modsecurity-config/crs-setup.conf
fi

echo "🔐 Génération certificat SSL..."
if [ ! -f "ssl/server.crt" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout ssl/server.key \
        -out ssl/server.crt \
        -subj "/C=FR/ST=Region/L=City/O=SOAR-Lab/OU=Security/CN=modsecurity.local"
fi

echo "📋 Installation des dépendances Python..."
pip3 install requests urllib3 --quiet

echo "⚙️ Configuration des règles Wazuh..."
cat > wazuh-integration/modsecurity-xss-rules.xml << 'EOL'
<!-- Règles personnalisées ModSecurity XSS pour Wazuh -->
<!-- Par Med10S - 2025-08-08 -->

<group name="modsecurity,xss,">
  
  <!-- Détection XSS générique -->
  <rule id="100200" level="12">
    <if_sid>31103</if_sid>
    <regex type="pcre2">(?i)ModSecurity.*XSS.*Attack</regex>
    <description>ModSecurity: XSS Attack detected</description>
    <group>web,attack,xss</group>
    <mitre>
      <id>T1059.007</id>
    </mitre>
  </rule>

  <!-- XSS dans les arguments -->
  <rule id="100201" level="12">
    <if_sid>31103</if_sid>
    <regex type="pcre2">(?i)script[^>]*>|javascript:|onerror\s*=|onload\s*=</regex>
    <description>XSS pattern detected in web request</description>
    <group>web,attack,xss</group>
  </rule>

  <!-- XSS encodé -->
  <rule id="100202" level="10">
    <if_sid>31103</if_sid>
    <regex type="pcre2">(%3C|%3E|%22|%27).*(%3C|%3E)</regex>
    <description>Possible encoded XSS attempt</description>
    <group>web,attack,xss,evasion</group>
  </rule>

  <!-- XSS par IP répétées (même IP, plusieurs tentatives) -->
  <rule id="100203" level="15" frequency="3" timeframe="300">
    <if_matched_sid>100201</if_matched_sid>
    <same_source_ip />
    <description>Multiple XSS attempts from same IP</description>
    <group>web,attack,xss,multiple_attacks</group>
  </rule>

</group>
EOL

echo "✅ Configuration terminée!"
echo ""
echo "📋 Prochaines étapes:"
echo "1. Modifier WAZUH_MANAGER dans docker-compose.yml"
echo "2. Modifier WEBHOOK_URL dans les scripts"
echo "3. Démarrer: docker-compose up -d"
echo "4. Vérifier: docker-compose logs -f wazuh-agent"
echo "5. Tester DVWA: http://localhost:8080"
echo ""
echo "🔧 Commandes utiles:"
echo "- Logs ModSecurity: docker-compose logs -f modsecurity-apache"
echo "- Logs Wazuh Agent: docker-compose logs -f wazuh-agent"
echo "- Test XSS: curl \"http://localhost/test?param=<script>alert(1)</script>\""