// Function Node: Process Observable Results
const observable = $input.first().json; // Get the first item
const alertId = $('Merge').first().json.id


// Get both report sources
const localReport = observable.reports || {};
const analyzerReport = $('Execute analyzer on an observable').first().json?.report || {};

// Function to analyze reports and determine threat level
function analyzeReports(reports) {
    let highestThreatLevel = "info";
    let hasEvents = false;
    const findings = [];

    // Helper function to update threat level
    function updateThreatLevel(level) {
        if (level === "malicious" || level === "high" || level === "1") {
            highestThreatLevel = "high";
        } else if ((level === "suspicious" || level === "medium" || level === "2") && highestThreatLevel !== "high") {
            highestThreatLevel = "medium";
        } else if ((level === "warning" || level === "low" || level === "3") && highestThreatLevel === "info") {
            highestThreatLevel = "low";
        }
    }

    // Process MISP format taxonomies (from observable reports)
    if (reports.localReport) {
        Object.entries(reports.localReport).forEach(([analyzerName, report]) => {
            if (report?.taxonomies && Array.isArray(report.taxonomies)) {
                report.taxonomies.forEach(taxonomy => {
                    // Track findings safely
                    const finding = {
                        analyzer: analyzerName,
                        source: "Observable Report"
                    };

                    // Add properties if they exist
                    if (taxonomy.predicate) finding.type = taxonomy.predicate;
                    if (taxonomy.value) finding.value = taxonomy.value;
                    if (taxonomy.level) finding.level = taxonomy.level;
                    if (taxonomy.namespace) finding.namespace = taxonomy.namespace;

                    findings.push(finding);

                    // Check for events/matches
                    if (taxonomy.value && !taxonomy.value.includes("0 events")) {
                        hasEvents = true;
                        updateThreatLevel(taxonomy.level);

                        // Extract event count if available
                        const eventMatch = taxonomy.value.match(/(\d+)\s*event/);
                        if (eventMatch && eventMatch[1]) {
                            const eventCount = parseInt(eventMatch[1]);
                            if (eventCount >= 3) updateThreatLevel("high");
                            else if (eventCount >= 1) updateThreatLevel("medium");
                        }
                    }
                });
            }

            // Check for summary info
            if (report?.summary && Object.keys(report.summary).length > 0) {
                hasEvents = true;
                findings.push({
                    analyzer: analyzerName,
                    source: "Observable Report",
                    summary: report.summary
                });

                if (highestThreatLevel === "info") highestThreatLevel = "low";
            }
        });
    }

    // Process analyzer report (Execute analyzer on an observable)
    if (reports.analyzerReport) {
        const analyzerName = reports.analyzerReport.analyzerName || "Unknown Analyzer";

        // Handle MISP-specific full report format
        if (reports.analyzerReport.full?.results) {
            try {
                // Safely navigate through potential results array
                reports.analyzerReport.full.results.forEach(resultItem => {
                    if (resultItem?.result && Array.isArray(resultItem.result)) {
                        resultItem.result.forEach(item => {
                            hasEvents = true;

                            const finding = {
                                analyzer: analyzerName,
                                source: resultItem.name || "External Analysis"
                            };

                            // Add all available fields from the item
                            if (item.id) finding.event_id = item.id;
                            if (item.info) finding.info = item.info;
                            if (item.threat_level_id) finding.threat_level_id = item.threat_level_id;
                            if (item.date) finding.date = item.date;
                            if (item.Orgc?.name) finding.organization = item.Orgc.name;
                            if (item.Tag && Array.isArray(item.Tag)) {
                                finding.tags = item.Tag.map(tag => tag.name).join(', ');
                            }

                            findings.push(finding);

                            // Update threat level based on the MISP threat level ID
                            if (item.threat_level_id) {
                                updateThreatLevel(item.threat_level_id.toString());
                            }
                        });
                    }
                });
            } catch (e) {
                // Add error finding if something goes wrong
                findings.push({
                    analyzer: analyzerName,
                    source: "Error",
                    error: "Failed to process analyzer report",
                    details: e.message
                });
            }
        }

        // Also check for taxonomies in the analyzer report
        if (reports.analyzerReport.taxonomies && Array.isArray(reports.analyzerReport.taxonomies)) {
            reports.analyzerReport.taxonomies.forEach(taxonomy => {
                const finding = {
                    analyzer: analyzerName,
                    source: "Analyzer Report"
                };

                if (taxonomy.predicate) finding.type = taxonomy.predicate;
                if (taxonomy.value) finding.value = taxonomy.value;
                if (taxonomy.level) finding.level = taxonomy.level;

                findings.push(finding);

                if (taxonomy.value && !taxonomy.value.includes("0 events")) {
                    hasEvents = true;
                    updateThreatLevel(taxonomy.level);
                }
            });
        }
    }

    return { threatLevel: highestThreatLevel, hasEvents, findings };
}

// Process both report sources
const analysis = analyzeReports({
    localReport: localReport,
    analyzerReport: analyzerReport
});

const createCase = analysis.hasEvents || analysis.threatLevel !== "info";



return {
    analysis: analysis,
    observable: observable._id,
    threatLevel: analysis.threatLevel,
    createCase: createCase,
    hasEvents: analysis.hasEvents,
    findings: analysis.findings,
    // Information for updating the alert
    alertUpdate: {
        id: alertId,
        tags: [...observable.tags, `threatLevel:${analysis.threatLevel}`],
        status: createCase ? "New" : "Ignored",
        follow: createCase
    }
};