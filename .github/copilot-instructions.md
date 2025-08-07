# 🧑‍💻 Copilot Instructions for Project_Pfa_stage

## Big Picture Architecture
- This project implements a hospital-grade SOC (Security Operations Center) using a unified SIEM/SOAR stack.
- **Major Components:**
  - **SIEM:** Wazuh (central detection, dashboard)
  - **SOAR:** TheHive (incident management), Cortex (automated analysis), MISP (threat intelligence)
  - **Network:** Suricata (IDS/IPS), OSQuery (endpoint detection), pfSense (firewall)
- **Data Flow Example:**
  - Wazuh detects anomaly → sends alert via webhook to n8n
  - n8n orchestrates: creates TheHive task with observables, executes observables (Cortex analyzers including MISP)
  - If threat detected: creates TheHive case from alert, sends email/Telegram notification
  - If no threat: updates alert to ignored
  - Full audit trail maintained
- **Key Diagrams:**
  - `flowData_Complex.png`, `flowData_simple.png`, `docs/architecture/detailed_architecture.md`, `docs/topologies/hospital_network_topology.md`

## Developer Workflows
- **Deployment scripts:**
  - See `scripts/installation/install_complete_stack.sh` and `scripts/wazuh/wazuh_deployment.sh` for stack setup.
  - Configurations in `scripts/configs/` (cortex, thehive)
- **Testing:**
  - Attack scenarios and test flows in `tests/attack-scenarios/` (Mermaid diagrams, markdown)
- **Debugging:**
  - Troubleshooting notes in `help/` (e.g., `debug wazuh.txt`)

## Project-Specific Conventions
- **Incident Response Workflow:**
  - Wazuh alert → TheHive case → Cortex analysis → Automated playbook response
  - All incidents are documented for audit/compliance (HIPAA/RGPD)
- **Documentation:**
  - Technical guides and architecture in `docs/`
  - Project summary in `CyberSecurity_SIEM_SOAR/PROJECT_SUMMARY.md`
- **Naming:**
  - Use clear, descriptive names for scripts, configs, and diagrams

## Integration Points & Dependencies
- **External tools:** Wazuh, TheHive, Cortex, MISP, Suricata, OSQuery, pfSense
- **Config files:**
  - `scripts/configs/cortex_config.conf`, `scripts/configs/thehive_config.conf`
- **Stack orchestration:**
  - Shell scripts automate multi-component deployment

## Patterns & Examples
- **Automated Response Example:**
  - Ransomware detected on PACS server → TheHive triggers:
    - Network isolation
    - Medical team notification
    - Failover to backup
    - Malware analysis via Cortex
    - Incident report generation
- **SOC Workflow:**
  1. Detection (Wazuh)
  2. Case creation (TheHive)
  3. Enrichment (Cortex)
  4. Automated response
  5. Documentation

## Key Files & Directories
- `scripts/installation/`, `scripts/wazuh/`, `scripts/configs/`
- `docs/architecture/`, `docs/topologies/`, `docs/benchmarking/`
- `tests/attack-scenarios/`
- `CyberSecurity_SIEM_SOAR/`

---
**Feedback:** Please review and suggest additions or clarifications for any unclear or incomplete sections.
