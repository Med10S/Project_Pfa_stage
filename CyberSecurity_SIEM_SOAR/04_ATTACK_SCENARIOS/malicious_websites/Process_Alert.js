// Extract key alert information - adapt for the new structure
const alertJson = $input.item.json; // Assuming the whole JSON is passed to n8n
const alertData = alertJson.body || alertJson; // Extract from _source if present
const type = alertData.input?.type || "log";
const rule = alertData.rule || {};
const data = alertData.data || {};
const win = data.win || {};
const timestamp = alertData.timestamp;
const id = alertData.id;

// Extract relevant fields
let title = `${rule.description || 'DNS Detection Alert'}`;

// Create Markdown-formatted description
let description = `# ${title}\n\n`;
description += `## Alert Details\n\n`;
description += `- **Alert Level**: ${rule.level}\n`;
description += `- **Rule ID**: ${rule.id}\n`;
description += `- **Timestamp**: ${timestamp}\n`;

if (rule.groups && Array.isArray(rule.groups)) {
    description += `- **Rule Groups**: ${rule.groups.join(', ')}\n\n`;
}

// Add agent information
const agent = alertData.agent || {};
description += `## Agent Information\n\n`;
description += `- **Name**: ${agent.name}\n`;
description += `- **ID**: ${agent.id}\n`;
description += `- **IP Address**: ${agent.ip}\n\n`;

// Add Windows event details
const eventdata = win.eventdata || {};
const system = win.system || {};

description += `## Event Details\n\n`;
description += `- **Event ID**: ${system.eventID || 'N/A'}\n`;
description += `- **Event Time**: ${eventdata.utcTime || 'N/A'}\n`;
description += `- **Computer**: ${system.computer || 'N/A'}\n\n`;

// Extract DNS information
description += `## DNS Information\n\n`;
const dnsQuery = {};
if (eventdata.queryName) {
    dnsQuery.domain = eventdata.queryName;
    description += `- **DNS Query**: \`${eventdata.queryName}\`\n`;
}

if (eventdata.queryResults) {
    dnsQuery.result = eventdata.queryResults;
    description += `- **DNS Result**: \`${eventdata.queryResults}\`\n`;

    // Extract IPs from query results
    const ipMatches = eventdata.queryResults.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/g) || [];
    const resolvedIPs = ipMatches.map(ip => ip.replace('::ffff:', ''));

    if (resolvedIPs.length > 0) {
        description += `- **Resolved IPs**:\n`;
        resolvedIPs.forEach(ip => {
            description += `  - \`${ip}\`\n`;
        });
        dnsQuery.ips = resolvedIPs;
    }
}

// Add process information
if (eventdata.image || eventdata.processId || eventdata.processGuid || eventdata.user) {
    description += `\n## Process Information\n\n`;

    if (eventdata.image) {
        description += `- **Process Path**: \`${eventdata.image}\`\n`;
    }

    if (eventdata.processId) {
        description += `- **Process ID**: ${eventdata.processId}\n`;
    }

    if (eventdata.processGuid) {
        description += `- **Process GUID**: ${eventdata.processGuid}\n`;
    }

    if (eventdata.user) {
        description += `- **User**: ${eventdata.user}\n`;
    }
}

// Add a summary section with severity information
description += `\n## Summary\n\n`;
let severityText = rule.level >= 10 ? "HIGH" : (rule.level >= 7 ? "MEDIUM" : "LOW");
description += `This is a **${severityText} SEVERITY** DNS detection from Wazuh Sysmon monitoring. `;
description += `The alert was triggered at ${new Date(timestamp).toISOString().replace('T', ' ').substring(0, 19)} UTC.`;

// Create ONE main observable - the DNS domain
// The other data will be included in the context/metadata
const observable = dnsQuery.domain ? {
    dataType: 'domain',
    data: dnsQuery.domain,
    message: description,  // Use our new Markdown-formatted message
    // Include context about related data
    context: {
        resolvedIPs: dnsQuery.ips || [],
        processInfo: {
            path: eventdata.image,
            pid: eventdata.processId,
            guid: eventdata.processGuid,
            user: eventdata.user
        },
        queryResult: dnsQuery.result
    }
} : null;

// Create tags array
const tagsArray = rule.groups && Array.isArray(rule.groups) ? [...rule.groups] : [];
tagsArray.push('wazuh', 'sysmon', 'dns-query');

// Add severity tags based on level
if (rule.level >= 10) {
    tagsArray.push('high-severity');
} else if (rule.level >= 7) {
    tagsArray.push('medium-severity');
} else {
    tagsArray.push('low-severity');
}

// Return processed data with single observable
return {
    type,
    title,
    id,
    timestamp,
    description,  // Our enhanced Markdown description
    tlp: 2, // TLP:AMBER
    severity: rule.level >= 12 ? 3 : (rule.level >= 7 ? 2 : 1), // Map Wazuh severity to TheHive
    tags: tagsArray,  // Keep as array rather than comma-separated string
    observable, // Single main observable instead of array
    raw: alertData, // Store full alert for reference
    source: 'wazuh-sysmon-dns'
};