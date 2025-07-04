# Topologie Réseau SOC Hospitalier - Architecture Sécurité Pure

## Vue d'ensemble de l'Architecture

Cette documentation présente la topologie réseau complète d'un environnement hospitalier intégrant notre **stack SIEM/SOAR pure** optimisée pour une équipe de sécurité (Wazuh + TheHive + Cortex + MISP + Suricata).

## 🎯 **Architecture SOC Centrée Sécurité**

L'architecture élimine les composants business/métier pour se concentrer exclusivement sur la **détection, l'investigation et la réponse automatisée** aux incidents de cybersécurité.

## Diagramme Principal - Topologie SOC Hospitalière

```mermaid
---
config:
  layout: elk
  look: classic
---
flowchart TB
 subgraph subGraph2["Wazuh SIEM Cluster"]
        WM1["Wazuh Manager 2<br>SIEM Secondaire"]
        WI["Wazuh Indexer<br>Stockage Sécurité"]
        WD["Wazuh Dashboard<br>Interface SOC"]
  end
 subgraph subGraph3["SOAR - Orchestration Sécurité"]
        THEHIVE["TheHive Platform<br>Gestion Incidents"]
        CORTEX["Cortex Analytics<br>Analyse Automatisée"]
        MISP["MISP Threat Intel<br>Renseignement Menaces"]
  end
 subgraph subGraph5["SOC - Centre Opérations Sécurité"]
        SOC_DASH["Dashboard SOC Principal"]
        ALERT_MGR["Gestionnaire Alertes"]
        FORENSIC["Outils Forensiques"]
  end
 subgraph subGraph6["Infrastructure SIEM/SOAR - Équipe Sécurité"]
        subGraph2
        subGraph3
        subGraph5
  end
 subgraph subGraph7["Équipements Médicaux IoT"]
    direction TB
        MONITOR["Moniteurs Patients<br>10.100.1.13-50"]
  end
 subgraph subGraph8["Imagerie"]
    direction TB
        WORKSTATION["Stations Imagerie<br>10.100.2.20-30"]
  end
 subgraph subGraph9["Réseau Médical - Zone Critique"]
    direction TB
        subGraph7
        subGraph8
  end
 subgraph subGraph10["Serveurs Critiques"]
    direction TB
        DB_SIH["Base de Données SIH<br>10.200.1.11"]
  end
 subgraph subGraph11["Applications Métier"]
    direction TB
        EMR["Dossier Patient<br>10.200.2.10"]
        PHARMACY["Pharmacie<br>10.200.2.11"]
        LAB["Laboratoire<br>10.200.2.12"]
        BILLING["Facturation<br>10.200.2.13"]
  end
 subgraph subGraph12["Système d'Information Hospitalier"]
    direction TB
        subGraph10
        subGraph11
  end
 subgraph subGraph13["Personnel Médical"]
    direction TB
        DOC_PC["PC Médecins<br>10.300.1.10-50"]
        NURSE_PC["PC Infirmières<br>10.300.1.51-100"]
        TECH_PC["PC Techniciens<br>10.300.1.101-120"]
  end
 subgraph Administration["Administration"]
    direction TB
        ADMIN_PC["PC Administratifs<br>10.300.2.10-30"]
        IT_PC["PC Support IT<br>10.300.2.40-45"]
  end
 subgraph subGraph15["Postes Utilisateurs"]
    direction TB
        subGraph13
        Administration
  end
    WM1 --> WI & THEHIVE
    WI --> WD
    WD --> SOC_DASH
    THEHIVE --> CORTEX
    CORTEX --> MISP & ALERT_MGR
    ALERT_MGR --> SOC_DASH
    SOC_DASH --> FORENSIC
    MONITOR -.-> WM1
    WORKSTATION -.-> WM1
    DB_SIH -.-> WM1
    EMR -.-> WM1
    PHARMACY -.-> WM1
    LAB -.-> WM1
    BILLING -.-> WM1
    DOC_PC -.-> WM1
    NURSE_PC -.-> WM1
    TECH_PC -.-> WM1
    ADMIN_PC -.-> WM1
    IT_PC -.-> WM1
     WM1:::siem
     WM1:::siem
     WI:::siem
     WD:::siem
     THEHIVE:::siem
     CORTEX:::siem
     MISP:::siem
     SOC_DASH:::soc
     ALERT_MGR:::soc
     FORENSIC:::soc
     MONITOR:::medical
     WORKSTATION:::medical
     DB_SIH:::critical
     EMR:::critical
     PHARMACY:::critical
     LAB:::critical
     BILLING:::critical
     DOC_PC:::medical
     NURSE_PC:::medical
     TECH_PC:::medical
     ADMIN_PC:::medical
     IT_PC:::medical
    classDef medical fill:#e1f5fe,stroke:#0277bd,stroke-width:2px,color:#000000
    classDef siem fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000000
    classDef critical fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#000000
    classDef network fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px,color:#000000
    classDef soc fill:#fff9c4,stroke:#f57f17,stroke-width:2px,color:#000000

```

