    /**
     * n8n Code Node: OPNsense IP Blocker
     * Final working version - 2025-08-13
     * Tested and verified working with OPNsense API
     */

    // Import modules (available in n8n)
    const { URL } = require('url');
    const https = require('https');
    const http = require('http');

    // Configuration
    const OPNSENSE_URL = "http://192.168.181.1";
    const API_KEY = "ud8fjSvMwTgX9P7fEL4eWUfbOk+3/tiBpmtMh+dQU4OkH4YiJ/iE3aQBpWPXVHpDzyMel5v3Lql98j7e";
    const API_SECRET = "EzfhmRdb8Il60Ab+KQHZ5G1/zbRIU4Kgg5l6HcfQnXXOmHbH2iloqDBjih4EOmfmX1dnf8ifdNndbAND";
    const ALIAS_NAME = "Black_list";
    const ALIAS_ID = "2e9d5f53-be6b-4735-9f32-ffc60baea3f1";

    // Get IP to block from input data or use default
    const IP_TO_BLOCK = $input.all()[0]?.json?.ip_to_block || "192.168.183.1";

    console.log(`🚀 Starting OPNsense IP blocking for: ${IP_TO_BLOCK}`);

    // Helper function for API calls using native Node.js
    async function makeApiCall(endpoint, method = 'GET', body = null) {
        return new Promise((resolve, reject) => {
            const fullUrl = `${OPNSENSE_URL}${endpoint}`;
            const urlParts = new URL(fullUrl);
            const auth = 'Basic ' + Buffer.from(API_KEY + ':' + API_SECRET).toString('base64');

            const headers = {
                'Authorization': auth,
                'Accept': 'application/json'
            };
            
            // Add Content-Type only for POST/PUT with body
            if (method !== 'GET' && body) {
                headers['Content-Type'] = 'application/json';
            }

            const options = {
                hostname: urlParts.hostname,
                port: urlParts.port || (urlParts.protocol === 'https:' ? 443 : 80),
                path: urlParts.pathname + urlParts.search,
                method: method,
                headers: headers,
                timeout: 30000,
                rejectUnauthorized: false
            };

            const req = (urlParts.protocol === 'https:' ? https : http).request(options, (res) => {
                let responseData = '';

                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    try {
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            const jsonResponse = JSON.parse(responseData);
                            resolve(jsonResponse);
                        } else {
                            reject(new Error(`API call failed: ${res.statusCode} - ${responseData}`));
                        }
                    } catch (parseError) {
                        reject(new Error(`Invalid JSON response: ${parseError.message}`));
                    }
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            // Write body if present
            if (body) {
                req.write(JSON.stringify(body));
            } else if (method === 'POST') {
                req.write('');
            }

            req.end();
        });
    }

    // Execute the IP blocking process
    try {
        // Step 1: Get current alias data
        console.log("📋 Getting current alias data...");
        const currentData = await makeApiCall(`/api/firewall/alias/get_item/${ALIAS_ID}`);

        // Extract IPs with selected == 1
        let currentIPs = [];
        if (currentData.alias && currentData.alias.content) {
            const content = currentData.alias.content;
            for (const [key, value] of Object.entries(content)) {
                if (value && typeof value === 'object' && value.selected === 1) {
                    if (key.includes('.') && !key.startsWith('__')) {
                        currentIPs.push(key);
                    }
                }
            }
        }

        console.log(`📋 Current IPs: ${currentIPs.length} found`);

        // Step 2: Add new IP if not exists
        const ipAlreadyExists = currentIPs.includes(IP_TO_BLOCK);
        if (!ipAlreadyExists) {
            currentIPs.push(IP_TO_BLOCK);
            console.log(`➕ Adding new IP: ${IP_TO_BLOCK}`);
        } else {
            console.log(`⚠️ IP ${IP_TO_BLOCK} already exists`);
        }

        // Step 3: Update alias
        console.log("📋 Updating alias...");
        const payload = {
            "alias": {
                "authtype": "",
                "categories": "",
                "content": currentIPs.join("\n"),
                "counters": "0",
                "description": "automatique block by n8n",
                "enabled": "1",
                "expire": "",
                "interface": "",
                "name": ALIAS_NAME,
                "password": "",
                "path_expression": "",
                "proto": "",
                "type": "host",
                "updatefreq": "0.041666666666666664",
                "username": ""
            },
            "authgroup_content": "",
            "network_content": ""
        };

        const updateResponse = await makeApiCall(`/api/firewall/alias/set_item/${ALIAS_ID}`, 'POST', payload);
        console.log(`✅ Alias updated: ${updateResponse.result}`);

        // Step 4: Apply firewall changes
        console.log("📋 Applying firewall changes...");
        const applyResponse = await makeApiCall("/api/firewall/alias/reconfigure", 'POST');
        console.log(`✅ Firewall reconfigured: ${applyResponse.status}`);

        return {
            json: {
                success: true,
                status_code: 200,
                message: ipAlreadyExists ? 
                    `IP ${IP_TO_BLOCK} was already in blocklist` : 
                    `IP ${IP_TO_BLOCK} has been successfully blocked`,
                ip_info: {
                    blocked_ip: IP_TO_BLOCK,
                    was_already_blocked: ipAlreadyExists,
                    current_ips: currentIPs,
                    total_ips: currentIPs.length,
                    processed_by: "n8n-opnsense",
                    processed_at: new Date().toISOString()
                },
                api_responses: {
                    update_result: updateResponse.result,
                    apply_status: applyResponse.status
                }
            }
        };

    } catch (error) {
        console.error('💥 IP blocking failed:', error);

        return {
            json: {
                success: false,
                error: error.message,
                ip_info: {
                    blocked_ip: IP_TO_BLOCK,
                    total_ips: 0,
                    processed_by: "n8n-opnsense",
                    processed_at: new Date().toISOString()
                },
                message: `Failed to block IP ${IP_TO_BLOCK}: ${error.message}`
            }
        };
    }
