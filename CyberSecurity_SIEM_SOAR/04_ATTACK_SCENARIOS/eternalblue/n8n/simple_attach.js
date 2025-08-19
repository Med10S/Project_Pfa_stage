// Simple TheHive File Attachment - Matches exact network capture format
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// Configuration - Direct from network capture
const THEHIVE_URL = 'http://thehive.sbihi.soar.ma';
const THEHIVE_API_KEY = 'HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj';
const alert_id = '~81932440';
const file_path = 'C:\\Users\\pc\\personnel\\etude_GTR2\\S4\\Project_Pfa\\CyberSecurity_SIEM_SOAR\\exploites\\eternalBlue\\n8n\\_var_log_suricata_extracted_attacks_eternalblue_phase-2-overflow_192_168_3_100_to_192_168_15_10_20250730190434.pcap';

function attachFile() {
    return new Promise((resolve, reject) => {
        // Check if file exists
        if (!fs.existsSync(file_path)) {
            console.log(`❌ File not found: ${file_path}`);
            resolve(false);
            return;
        }

        const file_name = "attachment.pcap";
        console.log(`📤 Attaching ${file_name} to alert ${alert_id}`);

        // Exact endpoint from network capture
        const endpoint = `/api/v1/alert/${alert_id}/attachments`;
        const url = new URL(endpoint, THEHIVE_URL);

        // Create exact boundary from network capture

        // Read file content
        const file_content = fs.readFileSync(file_path);
        console.log(`📏 File size: ${file_content.length} bytes`);

        const boundary = "----WebKitFormBoundarybwyeFEHh4C1CJwfR";
        // Build exact multipart body as in network capture
        const body_parts = [
            `--${boundary}`,
            `Content-Disposition: form-data; name="attachments"; filename="${file_name}"`,
            `Content-Type: application/octet-stream`,
            `` // Empty line before binary content
        ];

        // Convert header parts to buffer
        const header_text = Buffer.from(body_parts.join('\r\n') + '\r\n', 'utf-8');
        console.log(`📋 Header: ${header_text.length} bytes`);
        console.log(`📋 Header Content: ${header_text} `);

        // Create body by combining header, file content, and footer
        const footer_parts = [
            `\r\n--${boundary}\r\n`,
            `Content-Disposition: form-data; name="canRename"\r\n\r\ntrue\r\n--${boundary}--\r\n`
        ];
        const footer_text = Buffer.from(footer_parts.join(''), 'utf-8');
        console.log(`📋 Footer: ${footer_text.length} bytes`);
        console.log(`📋 Footer Content: ${footer_text} `);
        // Combine all parts
        const body_buffer = Buffer.concat([header_text, file_content, footer_text]);

        // Headers matching network capture
        const headers = {
            'Authorization': `Bearer ${THEHIVE_API_KEY}`,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'fr-FR,fr;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            'Content-Length': body_buffer.length,
            'Origin': 'https://thehive.sbihi.soar.ma',
            'Referer': `https://thehive.sbihi.soar.ma/alerts/${alert_id}/attachments`,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36'
        };
        console.log(headers);


        // Choose the right module based on protocol
        const requestModule = url.protocol === 'https:' ? https : http;

        // Request options
        const options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname,
            method: 'POST',
            headers: headers
        };

        console.log(`🌐 POST ${THEHIVE_URL}${endpoint}`);
        console.log(`📋 Boundary: ${boundary}`);
        console.log(`📏 Body size: ${body_buffer.length} bytes`);

        // Make the request
        const req = requestModule.request(options, (res) => {
            let response_data = '';

            res.on('data', (chunk) => {
                response_data += chunk;
            });

            res.on('end', () => {
                console.log(`📊 Status: ${res.statusCode}`);
                console.log(`📋 Response: ${response_data}`);

                if (res.statusCode === 200 || res.statusCode === 201) {
                    console.log('✅ File attached successfully!');
                    resolve(true);
                } else {
                    console.log('❌ Attachment failed!');
                    resolve(false);
                }
            });
        });

        req.on('error', (error) => {
            console.error('❌ Request error:', error);
            reject(error);
        });

        // Write the body and end the request
        req.write(body_buffer);
        req.end();
    });
}

// Main execution
async function main() {
    console.log('🚀 Simple TheHive File Attachment (JavaScript)');
    console.log('='.repeat(45));

    try {
        await attachFile();
    } catch (error) {
        console.error('❌ Error:', error);
    }
}

// Run if this file is executed directly
if (require.main === module) {
    main();
}

module.exports = { attachFile };


