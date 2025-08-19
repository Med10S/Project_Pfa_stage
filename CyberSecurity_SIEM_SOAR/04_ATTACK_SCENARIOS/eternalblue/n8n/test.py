# TheHive File Attachment - Direct File Upload (No Observables)
# Updated to match exact network capture format from addTattachment.txt
# 
# Key changes:
# - Uses form field name 'attachments' (not 'attachment')
# - Includes 'canRename: true' form data
# - Matches exact headers from browser network inspection
# - Uses application/octet-stream content type
#
import requests
import os
import sys
import hashlib
import json

# Configuration
THEHIVE_URL = 'http://thehive.sbihi.soar.ma'
THEHIVE_API_KEY = 'HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj'

alert_id = '~81932440'  # Replace with the actual alert ID
file_path = 'C:\\Users\\pc\\personnel\\etude_GTR2\\S4\\Project_Pfa\\CyberSecurity_SIEM_SOAR\\exploites\\eternalBlue\\n8n\\_var_log_suricata_extracted_attacks_eternalblue_phase-2-overflow_192_168_3_100_to_192_168_15_10_20250730190434.pcap'

def test_api_connection():
    """Test TheHive API connection"""
    print("[TEST] Testing TheHive API connection...")
    try:
        headers = {
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            f"{THEHIVE_URL}/api/user/current",
            headers=headers,
            timeout=10
        )
        
        print(f"[API] Response Status: {response.status_code}")
        
        if response.status_code == 200:
            print("[SUCCESS] TheHive API connection successful")
            user_data = response.json()
            print(f"[USER] Connected as: {user_data.get('login', 'Unknown')}")
            return True
        elif response.status_code == 401:
            print("[ERROR] API authentication failed - check API key")
            return False
        else:
            print(f"[WARNING] API returned status {response.status_code}")
            print(f"[ERROR] Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"[ERROR] API connection error: {str(e)}")
        return False

def validate_file(file_path):
    """Validate file exists and get info"""
    print(f"[FILE] Validating file: {os.path.basename(file_path)}")
    
    if not os.path.exists(file_path):
        print("[ERROR] File does not exist!")
        return False
    
    file_size = os.path.getsize(file_path)
    print(f"[FILE] File size: {file_size:,} bytes")
    
    if file_size == 0:
        print("[ERROR] File is empty!")
        return False
    
    print("[SUCCESS] File validation passed")
    return True

def attach_file_directly(alert_id, file_path):
    """Attach file directly as attachment to TheHive alert using exact network inspection format"""
    print(f"[ATTACH] Attaching file directly to alert {alert_id}")
    print(f"[ATTACH] File: {os.path.basename(file_path)}")
    
    file_name = os.path.basename(file_path)
    
    # Use the exact endpoint from network inspection
    endpoint = f"{THEHIVE_URL}/api/v1/alert/{alert_id}/attachments"
    
    # Use Bearer token authentication (instead of session cookie for API access)
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "fr-FR,fr;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Origin": THEHIVE_URL.replace('http://', 'https://'),  # Adjust protocol if needed
        "Referer": f"{THEHIVE_URL}/alerts/{alert_id}/attachments"
        # Note: DO NOT set Content-Type - requests will set multipart/form-data automatically
    }
    
    print(f"[TRY] Using API endpoint: {endpoint}")
    
    try:
        # Use exact format from network inspection
        with open(file_path, 'rb') as f:
            # Match the exact form field names from network capture
            files = {
                'attachments': (file_name, f, 'application/octet-stream')
            }
            
            # Add the canRename field as seen in network capture
            data = {
                'canRename': 'true'
            }
            
            print("[UPLOAD] Uploading file with exact network capture format...")
            print(f"[UPLOAD] Form field name: 'attachments' (not 'attachment')")
            print(f"[UPLOAD] Additional data: canRename=true")
            
            response = requests.post(
                endpoint,
                headers=headers,
                files=files,
                data=data,
                timeout=120
            )
            
            print(f"[RESPONSE] Status: {response.status_code}")
            print(f"[RESPONSE] Headers: {dict(response.headers)}")
            print(f"[RESPONSE] Body: {response.text}")
            
            if response.status_code in [200, 201]:
                print(f"[RESPONSE] Status {response.status_code} - Validating response...")
                
                # Validate response according to network inspection
                try:
                    response_data = response.json()
                    
                    # Check if response has the required attachment object structure from network inspection
                    required_fields = ['_id', '_type', '_createdBy', 'name', 'hashes', 'size', 'contentType']
                    if isinstance(response_data, dict) and all(key in response_data for key in required_fields):
                        print("[SUCCESS] File attached successfully - Valid attachment object returned!")
                        print(f"[ATTACHMENT] ID: {response_data.get('_id')}")
                        print(f"[ATTACHMENT] Type: {response_data.get('_type')}")
                        print(f"[ATTACHMENT] Name: {response_data.get('name')}")
                        print(f"[ATTACHMENT] Size: {response_data.get('size')} bytes")
                        print(f"[ATTACHMENT] Content Type: {response_data.get('contentType')}")
                        print(f"[ATTACHMENT] Created By: {response_data.get('_createdBy')}")
                        if 'hashes' in response_data:
                            print(f"[ATTACHMENT] Hashes: {response_data.get('hashes')}")
                        return True
                    elif isinstance(response_data, dict) and 'attachments' in response_data:
                        # Check if attachments array is empty (indicates failure)
                        if not response_data['attachments']:
                            print("[ERROR] Attachment failed - Empty attachments array returned")
                            print("[ERROR] API returned success but no attachment was created")
                            return False
                        else:
                            # Check first attachment in array
                            attachment = response_data['attachments'][0]
                            if '_id' in attachment and 'name' in attachment:
                                print("[SUCCESS] File attached successfully - Found in attachments array!")
                                print(f"[ATTACHMENT] ID: {attachment.get('_id')}")
                                print(f"[ATTACHMENT] Name: {attachment.get('name')}")
                                print(f"[ATTACHMENT] Size: {attachment.get('size', 'Unknown')} bytes")
                                return True
                            else:
                                print("[ERROR] Invalid attachment object in response")
                                return False
                    else:
                        print("[ERROR] Invalid API response format - Missing required fields")
                        print(f"[ERROR] Expected fields: {required_fields}")
                        print(f"[ERROR] Got: {list(response_data.keys()) if isinstance(response_data, dict) else 'Non-dict response'}")
                        return False
                        
                except json.JSONDecodeError:
                    print("[ERROR] Invalid JSON response from API")
                    print(f"[ERROR] Raw response: {response.text}")
                    return False
                    
            else:
                print(f"[ERROR] API returned status {response.status_code}")
                if response.text:
                    print(f"[ERROR] Response: {response.text}")
                
                # Try alternative approaches if the main method fails
                print("[FALLBACK] Trying alternative attachment methods...")
                return try_alternative_attachment(alert_id, file_path)
                
    except Exception as e:
        print(f"[ERROR] Upload failed: {str(e)}")
        print("[FALLBACK] Trying alternative attachment methods...")
        return try_alternative_attachment(alert_id, file_path)

def try_alternative_attachment(alert_id, file_path):
    """Try alternative attachment methods with exact network capture format"""
    print("[ALT] Trying alternative attachment approach...")
    
    file_name = os.path.basename(file_path)
    
    # Try different API versions and endpoints
    alternative_endpoints = [
        f"{THEHIVE_URL}/api/alert/{alert_id}/attachments",
        f"{THEHIVE_URL}/api/v1/alert/{alert_id}/attachment",
        f"{THEHIVE_URL}/api/alert/{alert_id}/attachment"
    ]
    
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "fr-FR,fr;q=0.9"
    }
    
    for endpoint in alternative_endpoints:
        print(f"[ALT] Trying endpoint: {endpoint}")
        
        try:
            with open(file_path, 'rb') as f:
                # Use exact format from network capture
                files = {'attachments': (file_name, f, 'application/octet-stream')}
                data = {'canRename': 'true'}
                
                response = requests.post(endpoint, headers=headers, files=files, data=data, timeout=120)
                
                print(f"[ALT] Response Status: {response.status_code}")
                print(f"[ALT] Response: {response.text}")
                
                if response.status_code in [200, 201]:
                    try:
                        response_data = response.json()
                        
                        # Check for valid attachment response
                        if isinstance(response_data, dict) and '_id' in response_data and 'name' in response_data:
                            print(f"[SUCCESS] Alternative method worked! Attachment ID: {response_data.get('_id')}")
                            return True
                        elif isinstance(response_data, dict) and 'attachments' in response_data and response_data['attachments']:
                            print("[SUCCESS] Alternative method worked! Found in attachments array")
                            return True
                        else:
                            print("[WARNING] Alternative method returned success but invalid format")
                            
                    except json.JSONDecodeError:
                        print("[WARNING] Alternative method returned non-JSON response")
                        
        except Exception as e:
            print(f"[ALT] Endpoint {endpoint} failed: {str(e)}")
            continue
    
    # Try with different parameter names while keeping the network capture format
    print("[ALT] Trying with different parameter names...")
    file_params = ['file', 'data', 'upload', 'document', 'attachment']
    endpoint = f"{THEHIVE_URL}/api/v1/alert/{alert_id}/attachments"
    
    for param_name in file_params:
        print(f"[ALT] Trying parameter name: {param_name}")
        
        try:
            with open(file_path, 'rb') as f:
                files = {param_name: (file_name, f, 'application/octet-stream')}
                data = {'canRename': 'true'}
                
                response = requests.post(endpoint, headers=headers, files=files, data=data, timeout=120)
                
                if response.status_code in [200, 201]:
                    try:
                        response_data = response.json()
                        if '_id' in response_data or ('attachments' in response_data and response_data['attachments']):
                            print(f"[SUCCESS] Parameter '{param_name}' worked!")
                            return True
                    except:
                        pass
                        
        except Exception as e:
            print(f"[ALT] Parameter '{param_name}' failed: {str(e)}")
            continue
    
    print("[FAILED] All alternative attachment methods failed")
    return False

def main():
    """Main execution function"""
    print("=" * 60)
    print("TheHive Direct File Attachment Tool")
    print("NO OBSERVABLES - DIRECT FILE ATTACHMENT ONLY")
    print("=" * 60)
    
    # Validate file first
    if not validate_file(file_path):
        sys.exit(1)
    
    print(f"[CONFIG] Alert ID: {alert_id}")
    print(f"[CONFIG] TheHive URL: {THEHIVE_URL}")
    print("")
    
    # Test API connection
    if not test_api_connection():
        print("[ERROR] API connection test failed. Cannot proceed.")
        sys.exit(1)
    
    print("")
    
    # Perform direct file attachment
    success = attach_file_directly(alert_id, file_path)
    
    print("")
    print("=" * 60)
    if success:
        print("[SUCCESS] File attachment completed successfully!")
        print("[INFO] File is now attached to the alert as an attachment")
        print("[INFO] Check TheHive web interface under alert attachments")
    else:
        print("[ERROR] File attachment failed!")
        print("[INFO] The file could not be attached as an attachment")
        sys.exit(1)

# Execute the program
if __name__ == "__main__":
    main()

def create_alert_artifact_with_file(api, alert_id, file_path):
    """Create alert artifact with file attachment using thehive4py"""
    print(f"📎 Creating alert artifact with file attachment...")
    print(f"🎯 Target Alert: {alert_id}")
    print(f"📁 File: {os.path.basename(file_path)}")
    
    try:
        file_name = os.path.basename(file_path)
        file_hash = calculate_file_hash(file_path)
        
        # Create file artifact using thehive4py (as per API reference)
        # For file artifacts, we need to pass the file data properly
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Create AlertArtifact for file type (based on API reference)
        artifact = AlertArtifact(
            dataType='file',
            data=[{file_name: file_data}],  # File data format as per API
            message=f"EternalBlue PCAP Evidence - {file_name}",
            tags=['pcap', 'eternalblue', 'phase-2-overflow', 'evidence'],
            ioc=True,
            sighted=True,
            tlp=2  # TLP:AMBER
        )
        
        # Create the alert artifact using the API (as per reference)
        print("📤 Uploading file artifact to alert...")
        response = api.create_alert_artifact(alert_id, artifact)
        
        print(f"📊 Response Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print("✅ File artifact created successfully!")
            artifact_data = response.json()
            print(f"🆔 Artifact ID: {artifact_data.get('_id', 'N/A')}")
            print(f"📋 Artifact Type: {artifact_data.get('dataType', 'N/A')}")
            return True
        else:
            print(f"❌ File artifact creation failed: {response.status_code}")
            print(f"📝 Error: {response.text}")
            
            # Fallback: try creating hash and filename artifacts separately
            print("🔄 Trying fallback approach with separate artifacts...")
            return create_separate_artifacts(api, alert_id, file_path, file_hash)
            
    except Exception as e:
        print(f"❌ Error creating file artifact: {str(e)}")
        # Fallback approach
        print("🔄 Trying fallback approach...")
        return create_separate_artifacts(api, alert_id, file_path)

def create_separate_artifacts(api, alert_id, file_path, file_hash=None):
    """Create separate artifacts for file hash and filename"""
    print("📝 Creating separate artifacts for file metadata...")
    
    try:
        file_name = os.path.basename(file_path)
        if not file_hash:
            file_hash = calculate_file_hash(file_path)
        
        success_count = 0
        
        # Create hash artifact
        print("🔐 Creating hash artifact...")
        hash_artifact = AlertArtifact(
            dataType='hash',
            data=file_hash,
            message=f"SHA256 hash of EternalBlue PCAP: {file_name}",
            tags=['pcap-hash', 'eternalblue', 'sha256', 'evidence'],
            ioc=True,
            sighted=True,
            tlp=2
        )
        
        response1 = api.create_alert_artifact(alert_id, hash_artifact)
        
        if response1.status_code in [200, 201]:
            print("✅ Hash artifact created successfully!")
            success_count += 1
        else:
            print(f"⚠️ Hash artifact creation failed: {response1.status_code}")
            print(f"📝 Error: {response1.text}")
        
        # Create filename artifact
        print("📄 Creating filename artifact...")
        filename_artifact = AlertArtifact(
            dataType='filename',
            data=file_name,
            message=f"EternalBlue PCAP filename - Path: {file_path}",
            tags=['pcap-filename', 'eternalblue', 'evidence'],
            ioc=False,
            sighted=True,
            tlp=2
        )
        
        response2 = api.create_alert_artifact(alert_id, filename_artifact)
        
        if response2.status_code in [200, 201]:
            print("✅ Filename artifact created successfully!")
            success_count += 1
        else:
            print(f"⚠️ Filename artifact creation failed: {response2.status_code}")
            print(f"📝 Error: {response2.text}")
        
        # Create other artifact (file path)
        print("🗂️ Creating file path artifact...")
        path_artifact = AlertArtifact(
            dataType='other',
            data=f"File-Path: {file_path}",
            message=f"Full path to EternalBlue PCAP evidence",
            tags=['pcap-path', 'eternalblue', 'evidence'],
            ioc=False,
            sighted=True,
            tlp=2
        )
        
        response3 = api.create_alert_artifact(alert_id, path_artifact)
        
        if response3.status_code in [200, 201]:
            print("✅ File path artifact created successfully!")
            success_count += 1
        else:
            print(f"⚠️ File path artifact creation failed: {response3.status_code}")
            print(f"📝 Error: {response3.text}")
        
        return success_count > 0
        
    except Exception as e:
        print(f"❌ Error creating separate artifacts: {str(e)}")
        return False

def main():
    """Main execution function"""
    print("🚀 TheHive Alert File Attachment Tool (thehive4py)")
    print("=" * 60)
    
    # Validate file first
    if not validate_file(file_path):
        sys.exit(1)
    
    print(f"🎯 Alert ID: {alert_id}")
    print(f"🌐 TheHive URL: {THEHIVE_URL}")
    print()
    
    # Initialize TheHive API (as per API reference)
    try:
        print("🔧 Initializing TheHive API client...")
        api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)
        print("✅ API client initialized")
    except Exception as e:
        print(f"❌ Failed to initialize API client: {str(e)}")
        sys.exit(1)
    
    # Test API connection
    if not test_api_connection(api):
        print("❌ API connection test failed. Cannot proceed.")
        sys.exit(1)
    
    print()
    
    # Perform file attachment
    success = create_alert_artifact_with_file(api, alert_id, file_path)
    
    print()
    print("=" * 60)
    if success:
        print("✅ Alert file attachment process completed successfully!")
        print("📋 Check TheHive web interface to verify the artifacts")
    else:
        print("❌ Alert file attachment process failed!")
        sys.exit(1)

# Execute the program
if __name__ == "__main__":
    main()
import json

# Configuration
THEHIVE_URL = 'http://thehive.sbihi.soar.ma'
THEHIVE_API_KEY = 'HSTx8PnJZNVvHwYFGs+564VD7pfqsRAj'

alert_id = '~81932440'  # Replace with the actual alert ID
file_path = 'C:\\Users\\pc\\personnel\\etude_GTR2\\S4\\Project_Pfa\\CyberSecurity_SIEM_SOAR\\exploites\\eternalBlue\\n8n\\_var_log_suricata_extracted_attacks_eternalblue_phase-2-overflow_192_168_3_100_to_192_168_15_10_20250730190434.pcap'

def test_api_connection():
    """Test TheHive API connection"""
    print("🔗 Testing TheHive API connection...")
    try:
        headers = {
            "Authorization": f"Bearer {THEHIVE_API_KEY}",
            "Content-Type": "application/json"
        }
        
        # Test with getting current user info (simple endpoint)
        response = requests.get(
            f"{THEHIVE_URL}/api/v1/user/current",
            headers=headers,
            timeout=10
        )
        
        print(f"📊 API Response Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ TheHive API connection successful")
            user_data = response.json()
            print(f"👤 Connected as: {user_data.get('login', 'Unknown')}")
            return True
        elif response.status_code == 401:
            print("❌ API authentication failed - check API key")
            return False
        else:
            print(f"⚠️ API returned status {response.status_code}")
            print(f"📝 Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to TheHive server")
        return False
    except requests.exceptions.Timeout:
        print("❌ API connection timeout")
        return False
    except Exception as e:
        print(f"❌ API test error: {str(e)}")
        return False

def validate_file(file_path):
    """Validate file exists and get info"""
    print(f"📁 Validating file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"❌ File does not exist: {file_path}")
        return False
    
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    
    print(f"✅ File found: {file_name}")
    print(f"📏 File size: {file_size:,} bytes")
    
    return True

def attach_file_to_alert(api, alert_id, file_path):
    """Attach file to TheHive alert with proper error handling"""
    
    file_name = os.path.basename(file_path)
    print(f"📤 Attempting to attach {file_name} to alert {alert_id}")
    
    try:
        # Method 1: Try add_alert_attachment
        print("🔄 Trying api.add_alert_attachment...")
        with open(file_path, 'rb') as f:
            response = api.add_alert_attachment(alert_id, f, filename=file_name)
        
        print(f"📊 Response Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print("✅ File attached successfully using add_alert_attachment!")
            return True
        else:
            print(f"⚠️ add_alert_attachment failed: {response.status_code}")
            if hasattr(response, 'text'):
                print(f"📝 Error: {response.text}")
            
            # Method 2: Try creating an artifact with file
            print("🔄 Trying to create artifact with file...")
            return create_file_artifact(api, alert_id, file_path)
            
    except AttributeError as e:
        print(f"⚠️ Method add_alert_attachment not available: {e}")
        print("🔄 Trying alternative method...")
        return create_file_artifact(api, alert_id, file_path)
        
    except Exception as e:
        print(f"❌ Error in add_alert_attachment: {str(e)}")
        print("🔄 Trying alternative method...")
        return create_file_artifact(api, alert_id, file_path)

def create_file_artifact(api, alert_id, file_path):
    """Create file artifact for the alert"""
    
    print("📝 Creating file artifact...")
    
    try:
        # Import required models
        from thehive4py.models import AlertArtifact
        
        file_name = os.path.basename(file_path)
        
        # Create artifact
        artifact = AlertArtifact(
            dataType='file',
            data=file_name,
            message=f"EternalBlue PCAP Evidence: {file_name}",
            tags=['pcap', 'eternalblue', 'phase-2-overflow', 'evidence'],
            ioc=True,
            sighted=True
        )
        
        # Create artifact with file attachment
        response = api.create_alert_artifact(alert_id, artifact, file_path)
        
        print(f"📊 Artifact Response Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print("✅ File artifact created successfully!")
            return True
        else:
            print(f"⚠️ Artifact creation failed: {response.status_code}")
            if hasattr(response, 'text'):
                print(f"📝 Error: {response.text}")
            
            # Method 3: Create observable with file metadata
            print("🔄 Trying to create observable with file metadata...")
            return create_file_observable(api, alert_id, file_path)
            
    except ImportError as e:
        print(f"⚠️ AlertArtifact model not available: {e}")
        return create_file_observable(api, alert_id, file_path)
        
    except Exception as e:
        print(f"❌ Error creating artifact: {str(e)}")
        return create_file_observable(api, alert_id, file_path)

def create_file_observable(api, alert_id, file_path):
    """Create observable with file metadata as fallback"""
    
    print("📝 Creating file observable with metadata...")
    
    try:
        import hashlib
        
        file_name = os.path.basename(file_path)
        
        # Calculate file hash
        print("🔍 Calculating file hash...")
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        file_hash = sha256_hash.hexdigest()
        print(f"📝 File hash: {file_hash}")
        
        # Create observable for the file hash
        from thehive4py.models import AlertArtifact
        
        hash_artifact = AlertArtifact(
            dataType='hash',
            data=file_hash,
            message=f"SHA256 hash of EternalBlue PCAP: {file_name}",
            tags=['pcap-hash', 'eternalblue', 'sha256', 'evidence'],
            ioc=True,
            sighted=True
        )
        
        response = api.create_alert_artifact(alert_id, hash_artifact)
        
        print(f"📊 Observable Response Status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            print("✅ File hash observable created successfully!")
            print(f"📝 File metadata preserved in alert {alert_id}")
            return True
        else:
            print(f"❌ Observable creation failed: {response.status_code}")
            if hasattr(response, 'text'):
                print(f"📝 Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error creating observable: {str(e)}")
        return False

def main():
    """Main execution function using exact network capture format"""
    print("🚀 TheHive File Attachment Tool - Network Capture Format")
    print("=" * 60)
    print("📋 Using exact format from browser network inspection")
    print("=" * 60)
    
    # Configuration summary
    print(f"🎯 Alert ID: {alert_id}")
    print(f"🌐 TheHive URL: {THEHIVE_URL}")
    print(f"📁 File: {os.path.basename(file_path)}")
    print()
    
    # Step 1: Validate file
    if not validate_file(file_path):
        print("❌ File validation failed. Cannot proceed.")
        sys.exit(1)
    
    print()
    
    # Step 2: Test API connection
    if not test_api_connection():
        print("❌ API connection test failed. Cannot proceed.")
        sys.exit(1)
    
    print()
    
    # Step 3: Attach file using exact network capture format
    print("📤 Starting file attachment with network capture format...")
    success = attach_file_directly(alert_id, file_path)
    
    print()
    print("=" * 60)
    if success:
        print("✅ File attachment completed successfully!")
        print("📋 Check TheHive web interface under alert attachments")
        print("🔗 URL:", f"{THEHIVE_URL}/alerts/{alert_id}/attachments")
    else:
        print("❌ File attachment failed!")
        print("💡 Possible issues:")
        print("   - Alert ID may not exist in TheHive")
        print("   - API key may lack attachment permissions") 
        print("   - File may be too large or invalid format")
        print("   - TheHive server may be experiencing issues")
        sys.exit(1)

if __name__ == "__main__":
    main()