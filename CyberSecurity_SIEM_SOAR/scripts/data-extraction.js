// Fonction améliorée pour traiter les alertes Wazuh dans n8n
async function extractAlertDetails(Myitem) {
    const NewResponce = {}
    try {
        const body = Myitem.json.body || {};
        // Données de base
        NewResponce.sourceIP = body.data?.srcip || '';
        NewResponce.targetUser = body.data?.dstuser || '';
        NewResponce.hostName = body.agent?.name || '';
        NewResponce.formattedTime = new Date(body.timestamp).toLocaleString();

        // Severity level
        const ruleLevel = body.rule?.level || 0;
        NewResponce.severity = ruleLevel >= 10 ? 'High' : (ruleLevel >= 7 ? 'Medium' : 'Low');

        // Information sur l'agent (ajout)
        NewResponce.agent = {
            name: body.agent?.name || 'Unknown',
            ip: body.agent?.ip || 'Unknown',
            id: body.agent?.id || 'Unknown'
        };

        // Information MITRE ATT&CK (ajout)
        NewResponce.mitre = {
            tactics: body.rule?.mitre?.tactic || [],
            techniques: body.rule?.mitre?.technique || []
        };

        // Métadonnées de l'alerte pour faciliter le tri
        NewResponce.meta = {
            ruleId: body.rule?.id || '',
            ruleDescription: body.rule?.description || '',
            alertType: determineAlertType(body.rule?.id),
            fullLog: body.full_log || ''
        };

        // Statut du traitement de l'alerte pour le suivi
        NewResponce.processStatus = {
            processed: false,
            actionTaken: determineAutomatedActions(body, NewResponce.severity),
            processingTime: new Date().toISOString()
        };
        NewResponce.extraData = await enrichIpData(body);

    } catch (error) {
        // Gestion des erreurs
        NewResponce.error = {
            message: `Erreur lors du traitement: ${error}`,
            timestamp: new Date().toISOString()
        };
    }

    return NewResponce;
}

// Fonction utilitaire pour déterminer le type d'alerte
function determineAlertType(ruleId) {
    if (!ruleId) return 'unknown';

    // Mapper les ID de règles aux types d'alertes
    const ruleMap = {
        '5758': 'ssh_brute_force',
        '5710': 'ssh_authentication_failure',
        '5760': 'ssh_repeated_failures',
        '5763': 'ssh_possible_breakin',
        '5503': 'ssh_scan',
        '40111': 'ransomware_behavior',
        '2502': 'ssh_root_login',
        '100001': 'medical_device_anomaly',
        '100002': 'unauthorized_medical_access',
        '100003': 'medical_config_change',
        '100004': 'medical_external_comm',
        '100005': 'medical_device_failure'
    };

    return ruleMap[ruleId] || 'other_security_event';
}

// Fonction pour déterminer les actions automatisées SOAR
function determineAutomatedActions(body, severity) {
    const ruleId = body.rule?.id || '';
    const alertType = determineAlertType(ruleId);
    const sourceIP = body.data?.srcip || '';
    const agentName = body.agent?.name || '';

    const actions = {
        immediate: [],
        delayed: [],
        notifications: [],
        investigation: []
    };

    // Actions basées sur la sévérité
    switch (severity) {
        case 'High':
            actions.immediate.push('create_thehive_case');
            actions.immediate.push('slack_alert_critical');
            actions.notifications.push('email_soc_team');
            break;
        case 'Medium':
            actions.delayed.push('create_thehive_alert');
            actions.notifications.push('slack_alert_medium');
            break;
        case 'Low':
            actions.investigation.push('log_for_analysis');
            break;
    }

    // Actions spécifiques par type d'alerte
    switch (alertType) {
        case 'ssh_brute_force':
        case 'ssh_repeated_failures':
        case 'ssh_possible_breakin':
            actions.immediate.push('block_ip_firewall');
            actions.immediate.push('cortex_ip_analysis');
            actions.investigation.push('check_user_accounts');
            actions.delayed.push('update_fail2ban_rules');
            break;

        case 'medical_device_anomaly':
        case 'unauthorized_medical_access':
            actions.immediate.push('isolate_medical_device');
            actions.immediate.push('notify_biomedical_team');
            actions.immediate.push('create_urgent_thehive_case');
            actions.investigation.push('forensic_medical_device');
            actions.notifications.push('email_medical_director');
            break;

        case 'medical_config_change':
            actions.immediate.push('backup_device_config');
            actions.immediate.push('verify_authorized_change');
            actions.investigation.push('audit_config_history');
            actions.notifications.push('notify_device_manufacturer');
            break;

        case 'medical_external_comm':
            actions.immediate.push('block_external_communication');
            actions.immediate.push('cortex_network_analysis');
            actions.investigation.push('trace_communication_path');
            actions.delayed.push('update_firewall_rules');
            break;

        case 'ransomware_behavior':
            actions.immediate.push('isolate_affected_system');
            actions.immediate.push('initiate_backup_restoration');
            actions.immediate.push('activate_incident_response_team');
            actions.immediate.push('notify_management_urgently');
            actions.investigation.push('cortex_malware_analysis');
            actions.investigation.push('check_backup_integrity');
            break;

        case 'medical_device_failure':
            actions.immediate.push('notify_maintenance_team');
            actions.immediate.push('check_device_redundancy');
            actions.investigation.push('analyze_failure_logs');
            actions.delayed.push('schedule_preventive_maintenance');
            break;

        default:
            actions.investigation.push('standard_log_analysis');
            actions.delayed.push('correlate_with_other_events');
            break;
    }

    // Actions spécifiques par IP source
    if (sourceIP && !isInternalIP(sourceIP)) {
        actions.immediate.push('cortex_ip_reputation_check');
        actions.investigation.push('check_threat_intelligence');
        actions.delayed.push('add_to_watchlist');
    }

    // Actions pour équipements médicaux critiques
    if (agentName && isCriticalMedicalDevice(agentName)) {
        actions.immediate.push('priority_escalation');
        actions.immediate.push('patient_safety_check');
        actions.notifications.push('notify_clinical_engineering');
    }

    return {
        severity: severity,
        alertType: alertType,
        executionPlan: actions,
        targetIP: sourceIP,
        targetAgent: agentName,
        executionTimestamp: new Date().toISOString(),
        estimatedExecutionTime: calculateExecutionTime(actions),
        requiredApprovals: getRequiredApprovals(severity, alertType)
    };
}

// Fonction utilitaire pour vérifier si une IP est interne
function isInternalIP(ip) {
    const internalRanges = [
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^127\./,
        /^169\.254\./
    ];
    return internalRanges.some(range => range.test(ip));
}

// Fonction pour identifier les équipements médicaux critiques
function isCriticalMedicalDevice(agentName) {
    const criticalDevices = [
        'scanner-ct', 'scanner-mri', 'ventilator', 'cardiac-monitor',
        'infusion-pump', 'dialysis', 'anesthesia', 'surgical-robot',
        'pacs-server', 'his-server', 'ris-server'
    ];
    return criticalDevices.some(device =>
        agentName.toLowerCase().includes(device)
    );
}

// Fonction pour calculer le temps d'exécution estimé
function calculateExecutionTime(actions) {
    let totalTime = 0;
    totalTime += actions.immediate.length * 30; // 30 secondes par action immédiate
    totalTime += actions.delayed.length * 300; // 5 minutes par action différée
    totalTime += actions.investigation.length * 600; // 10 minutes par investigation
    totalTime += actions.notifications.length * 10; // 10 secondes par notification

    return `${Math.ceil(totalTime / 60)} minutes`;
}

// Fonction pour déterminer les approbations requises
function getRequiredApprovals(severity, alertType) {
    const approvals = [];

    if (severity === 'High') {
        approvals.push('soc_manager');
    }

    if (alertType.includes('medical')) {
        approvals.push('biomedical_engineer');
        if (severity === 'High') {
            approvals.push('medical_director');
        }
    }

    if (alertType === 'ransomware_behavior') {
        approvals.push('incident_commander');
        approvals.push('legal_team');
    }

    return approvals;
}

// Fonction d'enrichissement d'IP corrigée pour n8n
async function enrichIpData(body) {
    const ip = body.data?.srcip;
    const item = {};
    // Vérifier si l'IP est valide
    if (!ip || ip === '') return "Invalid IP address";

    try {
        // Dans n8n, vous devez utiliser un nœud HTTP Request séparé
        // Cette fonction prépare simplement les données pour ce nœud

        // Ajouter l'URL pour le nœud HTTP Request suivant
        item.enrichment = {
            ipInfoUrl: `https://ipinfo.io/${ip}/json`,
            virusTotalUrl: `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
            abuseIPDBUrl: `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`
        };



    } catch (error) {
        item.enrichment = {
            error: 'Failed to prepare enrichment data',
            message: error
        };
    }

    return item;
}


return extractAlertDetails($input.item);