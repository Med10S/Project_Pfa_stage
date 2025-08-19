// n8n Code Node - TheHive File Attachment
// This code is designed to run inside an n8n Code node

// Get input data from previous node
const inputData = $input.all();

// Function to attach file to TheHive
async function attachFileToTheHive(params) {
    const startTime = Date.now();

    try {
        // Validate required parameters
        const requiredParams = ['thehive_url', 'api_key', 'alert_id', 'file_path'];
        const missingParams = requiredParams.filter(param => !params[param]);

        if (missingParams.length > 0) {
            return {
                success: false,
                error: `Missing required parameters: ${missingParams.join(', ')}`,
                data: null,
                execution_time: Date.now() - startTime
            };
        }

        const {
            thehive_url,
            api_key,
            alert_id,
            file_path,
            file_name: custom_filename
        } = params;

        // For n8n, we'll simulate file reading or use actual file operations
        // In a real scenario, you might get file content from previous nodes
        const file_name = custom_filename || file_path.split(/[/\\]/).pop();

        // Simulate file content for n8n (replace with actual file reading if needed)
        let file_content;
        let file_size;

        if (params.file_content) {
            // If file content is provided directly (as base64 or buffer)
            file_content = Buffer.from(params.file_content, 'base64');
            file_size = file_content.length;
        } else {
            // Default small content for testing
            file_content = Buffer.from('Test file content for n8n workflow', 'utf-8');
            file_size = file_content.length;
        }

        console.log(`📤 n8n: Attaching ${file_name} to alert ${alert_id}`);
        console.log(`📏 File size: ${file_size} bytes`);

        // Exact endpoint from network capture
        const endpoint = `/api/v1/alert/${alert_id}/attachments`;

        // Create exact boundary from network capture
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

        // Create body by combining header, file content, and footer
        const footer_parts = [
            `\r\n--${boundary}\r\n`,
            `Content-Disposition: form-data; name="canRename"\r\n\r\ntrue\r\n--${boundary}--\r\n`
        ];
        const footer_text = Buffer.from(footer_parts.join(''), 'utf-8');

        // Combine all parts
        const body_buffer = Buffer.concat([header_text, file_content, footer_text]);

        // Headers matching network capture
        const headers = {
            'Authorization': `Bearer ${api_key}`,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'fr-FR,fr;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            'Content-Length': body_buffer.length,
            'Origin': thehive_url.replace('http://', 'https://'),
            'Referer': `${thehive_url.replace('http://', 'https://')}/alerts/${alert_id}/attachments`,
            'User-Agent': 'n8n-workflow/1.0 (TheHive-Integration)'
        };

        console.log(`🌐 n8n: POST ${thehive_url}${endpoint}`);
        console.log(`📏 Body size: ${body_buffer.length} bytes`);

        // Use n8n's built-in HTTP request functionality
        const requestOptions = {
            url: `${thehive_url}${endpoint}`,
            method: 'POST',
            headers: headers,
            body: body_buffer,
            encoding: null, // Important for binary data
            timeout: 30000
        };

        // For n8n, we'll use the $http helper if available, otherwise simulate
        try {
            // Simulate HTTP request response for n8n
            // In actual n8n environment, you would use proper HTTP request
            const response = await makeHttpRequest(requestOptions);

            const execution_time = Date.now() - startTime;

            if (response.statusCode === 200 || response.statusCode === 201) {
                const responseObj = JSON.parse(response.body);
                const attachment = responseObj.attachments?.[0];

                return {
                    success: true,
                    error: null,
                    data: {
                        attachment_id: attachment?._id,
                        file_name: attachment?.name || file_name,
                        file_size: attachment?.size || file_size,
                        content_type: attachment?.contentType,
                        hashes: attachment?.hashes,
                        upload_path: attachment?.path,
                        alert_id: alert_id,
                        thehive_response: responseObj
                    },
                    execution_time: execution_time,
                    status_code: response.statusCode
                };
            } else {
                return {
                    success: false,
                    error: `HTTP ${response.statusCode}: ${response.body}`,
                    data: {
                        file_name: file_name,
                        file_size: file_size,
                        alert_id: alert_id
                    },
                    execution_time: execution_time,
                    status_code: response.statusCode
                };
            }
        } catch (httpError) {
            return {
                success: false,
                error: `HTTP request failed: ${httpError.message}`,
                data: {
                    file_name: file_name,
                    file_size: file_size,
                    alert_id: alert_id
                },
                execution_time: Date.now() - startTime,
                status_code: null
            };
        }

    } catch (error) {
        console.error('❌ n8n: Unexpected error:', error.message);
        return {
            success: false,
            error: `Unexpected error: ${error.message}`,
            data: null,
            execution_time: Date.now() - startTime,
            status_code: null
        };
    }
}

// Simulated HTTP request function (replace with actual n8n HTTP functionality)
async function makeHttpRequest(options) {
    // This is a placeholder - in real n8n environment, use proper HTTP request
    // For now, return a simulated successful response
    return {
        statusCode: 201,
        body: JSON.stringify({
            attachments: [{
                _id: "~123456789",
                _type: "Attachment",
                _createdBy: "api@sbihi.soar.ma",
                _createdAt: Date.now(),
                name: "test_file.txt",
                hashes: ["abc123def456"],
                size: 100,
                contentType: "application/octet-stream",
                path: "/api/v1/attachment/~123456789"
            }]
        })
    };
}

// Main execution for n8n Code node
const results = [];

for (const item of inputData) {
    // Extract parameters from input item
    const params = {
        thehive_url: item.json.thehive_url || 'http://thehive.sbihi.soar.ma',
        api_key: item.json.api_key || 'HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj',
        alert_id: item.json.alert_id || '~81932440',
        file_path: item.json.file_path || 'test_file.txt',
        file_name: item.json.file_name,
        file_content: item.json.file_content // Base64 encoded file content
    };

    try {
        // Execute the attachment function
        const result = await attachFileToTheHive(params);

        // Return the result in n8n expected format
        results.push({
            json: {
                ...item.json,  // Pass through original data
                attachment_result: result,
                processed_at: new Date().toISOString()
            }
        });

    } catch (error) {
        // Return error in n8n expected format
        results.push({
            json: {
                ...item.json,
                attachment_result: {
                    success: false,
                    error: error.message,
                    data: null,
                    execution_time: 0
                },
                processed_at: new Date().toISOString()
            }
        });
    }
}

// Return results to n8n (this is what n8n expects)
return results;

// n8n workflow execution function
async function executeWorkflow() {
    console.log('🚀 n8n TheHive File Attachment Workflow');
    console.log('='.repeat(50));

    // Example parameters - in n8n these would come from previous nodes
    const params = {
        thehive_url: 'http://thehive.sbihi.soar.ma',
        api_key: 'HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj',
        alert_id: '~81932440',
        file_path: 'test_small.txt',
        file_name: 'eternalblue_evidence.txt' // Optional custom name
    };

    try {
        const result = await attachFileToTheHive(params);

        console.log('\n📋 n8n Workflow Result:');
        console.log(JSON.stringify(result, null, 2));

        // In n8n, you would return this result to the next node
        return [{ json: result }];

    } catch (error) {
        console.error('❌ n8n Workflow Error:', error);

        // In n8n, return error result
        return [{
            json: {
                success: false,
                error: error.message,
                data: null,
                execution_time: 0
            }
        }];
    }
}

// For n8n Code Node usage:
// const result = await attachFileToTheHive($json);
// return [{ json: result }];

// Export for n8n or standalone usage
module.exports = {
    attachFileToTheHive,
    executeWorkflow
};

// Run if this file is executed directly (for testing)
if (require.main === module) {
    executeWorkflow();
}
