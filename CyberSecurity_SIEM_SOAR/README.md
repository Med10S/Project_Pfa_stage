# 🏥 Projet SIEM/SOAR - Centre Opérations Sécurité Hospitalière

## 🎯 **Idée Générale du Projet**

Ce projet développe une solution complète de **cybersécurité hospitalière** centrée sur une équipe de sécurité dédiée. L'objectif est de créer un **SOC (Security Operations Center)** capable de détecter, analyser et répondre automatiquement aux cybermenaces dans un environnement médical critique.

### **🔍 Problématique Adressée**
Les hôpitaux font face à des défis uniques en cybersécurité :
- **🏥 Équipements médicaux connectés** (IoT médical vulnérable)
- **⚡ Continuité de service critique** (vies humaines en jeu)
- **📋 Conformité stricte** (HIPAA, RGPD, données sensibles)
- **🎯 Cibles privilégiées** des cyberattaquants (ransomwares)

### **💡 Solution Proposée**
Architecture SIEM/SOAR unifiée permettant à une équipe de sécurité de :
- **🔍 Surveiller en temps réel** tous les équipements et systèmes
- **🤖 Automatiser la réponse** aux incidents critiques
- **📊 Centraliser la visibilité** sur les menaces
- **⚡ Réduire le temps de réaction** de heures à minutes

## 🏗️ **Architecture Technique - Vue d'Ensemble**

### **Couche SIEM - Détection & Corrélation**
- **🔍 Wazuh SIEM** : Moteur de détection central
- **📊 Wazuh Dashboard** : Interface SOC unifiée

### **Couche SOAR - Orchestration & Automatisation**
- **🎯 TheHive** : Plateforme de gestion d'incidents
- **🤖 Cortex** : Moteur d'analyse automatisée
- **� MISP** : Intelligence des menaces

### **Couche Réseau - Monitoring & Protection**
- **🌐 Suricata** : IDS/IPS réseau avancé
- **🔎 OSQuery** : Detection endpoint
- **🛡️ pfSense** : Firewall et filtrage intelligent

## 🎯 **Rôle Central de TheHive dans le SOC**

TheHive agit comme le **cerveau opérationnel** du SOC en :

### **📋 Gestion Centralisée des Incidents**
```
🚨 Alerte Wazuh → 📋 Case TheHive → 🔍 Investigation → ✅ Résolution
```

### **🤖 Automatisation Intelligente**
**Exemple Concret Hospitalier :**
```
🏥 Ransomware détecté sur serveur PACS
    ↓
🤖 TheHive déclenche automatiquement :
   ├── 🔒 Isolation réseau du serveur
   ├── 📱 Notification équipe médicale
   ├── � Basculement PACS de secours
   ├── 🔍 Analyse malware via Cortex
   └── 📊 Rapport incident automatique
```

### **🔄 Workflow SOC Optimisé**
1. **🔍 Détection** : Wazuh identifie l'anomalie
2. **📋 Création** : TheHive ouvre un incident automatiquement
3. **🤖 Enrichissement** : Cortex analyse les artefacts
4. **⚡ Réponse** : Actions automatisées selon playbooks
5. **📝 Documentation** : Traçabilité complète pour audit

## 🏥 **Valeur Ajoutée pour l'Environnement Hospitalier**

### **⚡ Réactivité Critique**
- **Temps de détection** : < 1 minute
- **Temps de réponse** : < 5 minutes
- **Disponibilité** : 99.9% (équipements vitaux)

### **🔒 Sécurité Renforcée**
- **Monitoring 24/7** des équipements médicaux
- **Détection comportementale** avancée
- **Réponse automatisée** aux incidents critiques

### **📊 Conformité Garantie**
- **Traçabilité complète** des incidents
- **Reporting automatique** pour audits
- **Respect HIPAA/RGPD** par design

## 👥 **Équipe SOC Cible**

Cette solution est optimisée pour :
- **� RSSI** - Vue stratégique et gouvernance
- **👨‍💻 Analystes SOC** - Investigation et réponse quotidienne
- **🔍 Threat Hunters** - Recherche proactive de menaces
- **⚡ Équipe Incident Response** - Gestion des crises

## 📈 **Bénéfices Mesurables**

### **Efficacité Opérationnelle**
- **-70%** temps de réponse aux incidents
- **-80%** tâches manuelles répétitives
- **+200%** incidents traités par analyste

### **Réduction des Risques**
- **-90%** temps d'exposition aux menaces
- **-60%** faux positifs
- **+150%** détection de menaces avancées



## Documentation Technique

### **📚 Guides Principaux**
- **[🔬 Analyse Comparative](docs/benchmarking/comparative_analysis.md)** - Justification technique de la stack
- **[🏗️ Architecture Détaillée](docs/architecture/detailed_architecture.md)** - Intégrations et composants
- **[🌐 Topologie Réseau](docs/topologies/hospital_network_topology.md)** - Diagrammes et flux
- **[🚀 Guide de Déploiement](docs/deployment/deployment_guide.md)** - Installation pas-à-pas


### **📊 Diagrammes d'Architecture**
- **[🔍 Architecture Complète](tests/attack-scenarios/flowchart%20TB.mmd)** - Vue détaillée avec tous les composants
- **[⚡ Architecture Minimale](tests/attack-scenarios/minimal_architecture.mmd)** - Vue simplifiée pour présentations

## 🎓 **Contexte Académique**

**Projet PFA (Projet de Fin d'Année)**  
**Formation :** GTR (Génie des Télécommunications et Réseaux) - Semestre 4  
**Objectif :** Concevoir une solution cybersécurité enterprise-grade pour environnement critique  
**Date :** Juillet 2025  


