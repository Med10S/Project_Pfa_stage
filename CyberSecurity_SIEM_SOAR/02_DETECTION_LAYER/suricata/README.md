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

## ⚙️ Configuration

### Fichier Principal (`suricata.yaml`)
[extracted from](../../../Suricta/suricata.yaml)



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
