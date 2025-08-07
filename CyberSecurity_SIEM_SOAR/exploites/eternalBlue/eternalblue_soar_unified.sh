#!/bin/bash

# ============================================================================
# ETERNALBLUE SOAR UNIFIED EXTRACTOR v4.0
# One Script to Rule Them All - Complete EternalBlue Detection & Extraction
# ============================================================================
# Author: SOC Automation Team
# Date: 2025-08-04
# Purpose: Complete EternalBlue detection with smart deduplication & PCAP extraction
# 
# Features:
# ✅ Multi-phase attack detection and correlation
# ✅ Smart session deduplication (no more duplicates!)
# ✅ Intelligent PCAP reuse system
# ✅ Extended PCAP capture windows (30+ seconds)
# ✅ Progressive alert escalation to n8n/TheHive
# ✅ Anti-corruption PCAP handling
# ✅ Medical environment specific adaptations
# ✅ New Suricata time_block.pcap.* support
# ============================================================================

# ============================================================================
# CONFIGURATION - All settings in one place
# ============================================================================

SURICATA_LOG="/var/log/suricata/eve.json"
PCAP_DIR="/var/log/suricata"
FILTERED_PCAP_DIR="/var/log/suricata/extracted_attacks"
TEMP_DIR="/tmp/pcap_processing"
CORRELATION_DIR="/tmp/eternalblue_correlation"
N8N_WEBHOOK="http://192.168.15.3:5678/webhook/eternalblue-alert"
LOG_FILE="/var/log/suricata/eternalblue_soar_extractor.log"

# DEBUG MODE - Set to "true" to force extraction even without matching traffic
DEBUG_FORCE_EXTRACTION="${DEBUG_FORCE_EXTRACTION:-false}"

# Create directories
mkdir -p "$FILTERED_PCAP_DIR" "$TEMP_DIR" "$CORRELATION_DIR" "$CORRELATION_DIR/archived"

# ============================================================================
# ATTACK PHASE DEFINITIONS - All phases in one place
# ============================================================================

declare -A ATTACK_PHASES=(
    ["9000001"]="PHASE_1_INITIAL"
    ["9000002"]="PHASE_1_SMB3"
    ["9000003"]="PHASE_2_OVERFLOW"
    ["9000004"]="PHASE_2_GROOMING"
    ["9000005"]="PHASE_2_OVERSIZED"
    ["9000006"]="PHASE_3_SUCCESS"
    ["9000007"]="PHASE_3_RESPONSE"
    ["9000008"]="PHASE_3_PAYLOAD"
    ["9000009"]="PHASE_3_OPERATION"
    ["9000010"]="POST_EXPLOIT_DOUBLEPULSAR"
    ["9000011"]="POST_EXPLOIT_NAMEDPIPE"
    ["9000020"]="CORRELATION_FULL_CHAIN"
    ["9000021"]="CORRELATION_ALTERNATIVE"
    ["9000022"]="CORRELATION_HIGH_CONFIDENCE"
    ["9000023"]="CORRELATION_SMB3_CHAIN"
    ["9000025"]="MEDICAL_TARGET"
    # Legacy rule support
    ["10001254"]="PHASE_1_LEGACY_TRANS2"
    ["1000012"]="PHASE_1_LEGACY_SMB3"
)

declare -A PRIORITY_LEVELS=(
    ["PHASE_1_INITIAL"]="MEDIUM"
    ["PHASE_1_SMB3"]="MEDIUM"
    ["PHASE_1_LEGACY_TRANS2"]="MEDIUM"
    ["PHASE_1_LEGACY_SMB3"]="MEDIUM"
    ["PHASE_2_OVERFLOW"]="HIGH"
    ["PHASE_2_GROOMING"]="HIGH" 
    ["PHASE_2_OVERSIZED"]="HIGH"
    ["PHASE_3_SUCCESS"]="CRITICAL"
    ["PHASE_3_RESPONSE"]="CRITICAL"
    ["PHASE_3_PAYLOAD"]="x  "
    ["PHASE_3_OPERATION"]="CRITICAL"
    ["POST_EXPLOIT_DOUBLEPULSAR"]="CRITICAL"
    ["POST_EXPLOIT_NAMEDPIPE"]="CRITICAL"
    ["CORRELATION_FULL_CHAIN"]="CRITICAL"
    ["CORRELATION_ALTERNATIVE"]="CRITICAL"
    ["CORRELATION_HIGH_CONFIDENCE"]="HIGH"
    ["CORRELATION_SMB3_CHAIN"]="HIGH"
    ["MEDICAL_TARGET"]="CRITICAL"
)

declare -A CAPTURE_WINDOWS=(
    ["PHASE_1_INITIAL"]="15"
    ["PHASE_1_SMB3"]="15"
    ["PHASE_1_LEGACY_TRANS2"]="15"
    ["PHASE_1_LEGACY_SMB3"]="15"
    ["PHASE_2_OVERFLOW"]="30"
    ["PHASE_2_GROOMING"]="30"
    ["PHASE_2_OVERSIZED"]="30"
    ["PHASE_3_SUCCESS"]="45"
    ["PHASE_3_RESPONSE"]="45"
    ["PHASE_3_PAYLOAD"]="45"
    ["PHASE_3_OPERATION"]="45"
    ["POST_EXPLOIT_DOUBLEPULSAR"]="60"
    ["POST_EXPLOIT_NAMEDPIPE"]="60"
    ["CORRELATION_FULL_CHAIN"]="60"
    ["CORRELATION_ALTERNATIVE"]="60"
    ["CORRELATION_HIGH_CONFIDENCE"]="45"
    ["CORRELATION_SMB3_CHAIN"]="45"
    ["MEDICAL_TARGET"]="60"
)

# ============================================================================
# DEDUPLICATION SYSTEM - Smart session tracking
# ============================================================================

declare -A PROCESSED_SESSIONS=()
declare -A SESSION_PCAPS=()
declare -A SESSION_START_TIME=()

is_duplicate_session() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local phase="$4"
    
    local session_key="${src_ip}_${dest_ip}"
    local reverse_session_key="${dest_ip}_${src_ip}"
    local current_epoch=$(date -d "$timestamp" +%s)
    
    for session_id in "$session_key" "$reverse_session_key"; do
        if [ -n "${SESSION_START_TIME[$session_id]}" ]; then
            local session_start="${SESSION_START_TIME[$session_id]}"
            local time_diff=$((current_epoch - session_start))
            
            if [ $time_diff -le 120 ]; then
                log_message "⚠️ Duplicate session detected: $session_id (${time_diff}s ago)"
                return 0
            fi
        fi
    done
    
    return 1
}

mark_session_processed() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local pcap_path="$4"
    
    local session_key="${src_ip}_${dest_ip}"
    local current_epoch=$(date -d "$timestamp" +%s)
    
    SESSION_START_TIME["$session_key"]="$current_epoch"
    SESSION_PCAPS["$session_key"]="$pcap_path"
    PROCESSED_SESSIONS["$session_key"]="$timestamp"
    
    log_message "📝 Session marked as processed: $session_key"
}

get_existing_session_pcap() {
    local src_ip="$1"
    local dest_ip="$2"
    
    local session_key="${src_ip}_${dest_ip}"
    local reverse_session_key="${dest_ip}_${src_ip}"
    
    for session_id in "$session_key" "$reverse_session_key"; do
        if [ -n "${SESSION_PCAPS[$session_id]}" ] && [ -f "${SESSION_PCAPS[$session_id]}" ]; then
            echo "${SESSION_PCAPS[$session_id]}"
            return 0
        fi
    done
    
    return 1
}

# ============================================================================
# LOGGING & UTILITIES
# ============================================================================

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [ETERNALBLUE-UNIFIED] $1" | tee -a "$LOG_FILE" >&2
}

force_rotation_before_extraction() {
    log_message "🔄 Forcing PCAP rotation..."
    
    local suricata_pid=$(pgrep -f "suricata.*-c /etc/suricata" | head -1)
    if [ -n "$suricata_pid" ]; then
        kill -USR2 "$suricata_pid" 2>/dev/null
        sleep 3
        kill -USR2 "$suricata_pid" 2>/dev/null
        sleep 2
    fi
    
    local recent_files=$(find "$PCAP_DIR" -name "time_block.pcap.*" -newermt "10 seconds ago" | wc -l)
    log_message "✅ Rotation complete - $recent_files new files"
}

# ============================================================================
# PCAP TESTING & REPAIR - Enhanced with attack-specific validation
# ============================================================================

test_and_fix_pcap() {
    local pcap_file="$1"
    local src_ip="$2"
    local dest_ip="$3"
    local base_name=$(basename "$pcap_file")

    log_message "🔍 Testing PCAP: $base_name"

    # Check file permissions and fix if needed
    if [ ! -r "$pcap_file" ]; then
        log_message "⚠️ PCAP not readable, fixing permissions: $base_name"
        chmod 644 "$pcap_file" 2>/dev/null || {
            log_message "❌ Cannot fix permissions for: $base_name"
            return 1
        }
    fi

    # Quick permission test first
    local quick_test=$(timeout 5s tcpdump -r "$pcap_file" -c 0 2>&1)
    if echo "$quick_test" | grep -q "Permission denied"; then
        log_message "❌ Permission denied for PCAP: $base_name"
        return 1
    fi

    # Perform a full integrity scan, capturing only error messages.
    log_message "   🔬 Performing full integrity scan on PCAP..."
    local test_output=$(timeout 20s tcpdump -r "$pcap_file" 2>&1 >/dev/null)
    
    # ============================================================================
    # FINAL FIX: The logic to handle tcpdump's output
    # ============================================================================
    if echo "$test_output" | grep -q "truncated dump file\|corrupt"; then
        # This block is for KNOWN, REPAIRABLE errors.
        log_message "⚠️ Corrupted PCAP detected: $base_name"
        
        local fixed_file="$TEMP_DIR/repaired_$(basename "$pcap_file")"
        log_message "🔧 Attempting PCAP repair (like 'tcpdump -w')..."
        
        if timeout 30s tcpdump -r "$pcap_file" -w "$fixed_file" 2>/dev/null; then
            if [ -f "$fixed_file" ] && [ -s "$fixed_file" ]; then
                if test_pcap_content "$fixed_file" "$src_ip" "$dest_ip"; then
                    log_message "✅ PCAP repair successful: $base_name"
                    echo "$fixed_file"
                    return 0
                fi
            fi
        fi
        
        log_message "❌ PCAP repair failed: $base_name"
        return 1
    elif echo "$test_output" | grep -q "reading from file"; then
        # This block handles the case where the ONLY output is the standard
        # "reading from file..." header, which means the file is HEALTHY.
        if test_pcap_content "$pcap_file" "$src_ip" "$dest_ip"; then
            log_message "✅ PCAP is healthy and contains target traffic: $base_name"
            echo "$pcap_file"
            return 0
        elif [ "$DEBUG_FORCE_EXTRACTION" = "true" ]; then
            log_message "🔧 DEBUG MODE: Forcing extraction despite no target traffic"
            echo "$pcap_file"
            return 0
        else
            log_message "⚠️ PCAP healthy but no target traffic: $base_name"
            return 1
        fi
    else
        # This block is for any other UNEXPECTED errors.
        log_message "❌ PCAP file unreadable or has other errors: $base_name"
        log_message "   Error details: $test_output"
        return 1
    fi
}


# Test if PCAP contains traffic for specific IPs
test_pcap_content() {
    local pcap_file="$1"
    local src_ip="$2"
    local dest_ip="$3"
    
    log_message "   🔬 DEEP PCAP ANALYSIS for $(basename "$pcap_file")"
    
    # Verify PCAP is readable before testing
    if [ ! -r "$pcap_file" ]; then
        log_message "   ❌ PCAP file not readable, attempting permission fix..."
        chmod 644 "$pcap_file" 2>/dev/null || {
            log_message "   ❌ Cannot read PCAP file: $(basename "$pcap_file")"
            return 1
        }
    fi
    
    # ============================================================================
    # FIX: Use a more flexible filter. Check for EITHER IP address.
    # This is more robust than a strict bidirectional filter.
    # ============================================================================
    local traffic_filter="host $src_ip or host $dest_ip"
    log_message "   🔧 Using robust filter: '$traffic_filter'"
    
    local traffic_count_output=$(timeout 15s tcpdump -r "$pcap_file" "$traffic_filter" 2>&1)
    local tcpdump_result=$?
    
    if [ $tcpdump_result -ne 0 ]; then
        log_message "   ❌ tcpdump error: $traffic_count_output"
        return 1
    fi
    
    # Count packets found by reading the output lines
    local traffic_count=$(echo "$traffic_count_output" | wc -l || echo "0")
    
    if [ "$traffic_count" -gt 0 ]; then
        log_message "   ✅ Found $traffic_count packets involving $src_ip or $dest_ip"
        return 0
    fi
    
    # Debug: comprehensive analysis of PCAP content if no match
    local total_packets_output=$(timeout 10s tcpdump -r "$pcap_file" 2>&1)
    local total_packets=$(echo "$total_packets_output" | wc -l || echo "0")
    
    # Check for tcpdump errors
    if echo "$total_packets_output" | grep -q "Permission denied"; then
        log_message "   ❌ Permission denied reading PCAP: $(basename "$pcap_file")"
        return 1
    fi
    
    log_message "   📊 Total packets in PCAP: $total_packets"
    
    if [ "$total_packets" -gt 0 ]; then
        log_message "    PCAP contains traffic but not for target IPs"
        
        # Show ALL unique IPs in PCAP for debugging
        log_message "   🔍 Analyzing ALL IPs in PCAP..."
        local all_ips=$(timeout 15s tcpdump -r "$pcap_file" -n 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | head -20)
        if [ -n "$all_ips" ]; then
            log_message "   📋 ALL IPs found in PCAP:"
            echo "$all_ips" | while read -r ip; do
                if [ -n "$ip" ]; then
                    local ip_count=$(timeout 10s tcpdump -r "$pcap_file" "host $ip" 2>/dev/null | wc -l || echo "0")
                    log_message "       🌐 $ip: $ip_count packets"
                fi
            done
        else
            log_message "   ⚠️ No IP addresses found in PCAP (might be encrypted or non-IP traffic)"
        fi
        
        # Show protocol breakdown
        local tcp_count=$(timeout 10s tcpdump -r "$pcap_file" tcp 2>/dev/null | wc -l || echo "0")
        local udp_count=$(timeout 10s tcpdump -r "$pcap_file" udp 2>/dev/null | wc -l || echo "0")
        local icmp_count=$(timeout 10s tcpdump -r "$pcap_file" icmp 2>/dev/null | wc -l || echo "0")
        log_message "   📋 Protocol breakdown: TCP=$tcp_count, UDP=$udp_count, ICMP=$icmp_count"
        
        # Show sample packets
        log_message "   📋 Sample packet headers:"
        timeout 10s tcpdump -r "$pcap_file" -n -c 3 2>/dev/null | while read -r line; do
            log_message "       📦 $line"
        done
    else
        log_message "   ⚠️ PCAP file is empty (0 packets)"
    fi
    
    return 1
}

# ============================================================================
# CORRELATION SYSTEM
# ============================================================================

store_attack_event() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local phase="$4"
    local signature="$5"
    local alert_json="$6"
    
    local session_id="${src_ip}_${dest_ip}"
    local correlation_file="$CORRELATION_DIR/session_${session_id//\./_}.json"
    
    local event_entry=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "phase": "$phase",
    "signature": "$signature",
    "src_ip": "$src_ip",
    "dest_ip": "$dest_ip",
    "alert_data": $alert_json,
    "detection_time": "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')"
}
EOF
    )
    
    if [ -f "$correlation_file" ]; then
        jq ". += [$event_entry]" "$correlation_file" > "${correlation_file}.tmp" && mv "${correlation_file}.tmp" "$correlation_file"
    else
        echo "[$event_entry]" > "$correlation_file"
    fi
    
    log_message "📊 Attack event stored for correlation: $session_id ($phase)"
}

update_session_correlation() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local phase="$4"
    local signature="$5"
    local alert_json="$6"
    
    local session_key="${src_ip}_${dest_ip}"
    local reverse_session_key="${dest_ip}_${src_ip}"
    local correlation_file=""
    
    # Find existing correlation file (bidirectional)
    for session_id in "$session_key" "$reverse_session_key"; do
        local potential_file="$CORRELATION_DIR/session_${session_id//\./_}.json"
        if [ -f "$potential_file" ]; then
            correlation_file="$potential_file"
            break
        fi
    done
    
    if [ -z "$correlation_file" ]; then
        correlation_file="$CORRELATION_DIR/session_${session_key//\./_}.json"
    fi
    
    # Check for duplicate phases
    if [ -f "$correlation_file" ]; then
        local existing_phases=$(jq -r '.[].phase' "$correlation_file" 2>/dev/null | sort -u)
        if echo "$existing_phases" | grep -q "^$phase$"; then
            log_message "⚠️ Phase $phase already recorded for session, skipping..."
            return 1
        fi
    fi
    
    # Store the event
    store_attack_event "$src_ip" "$dest_ip" "$timestamp" "$phase" "$signature" "$alert_json"
    return 0
}

analyze_attack_progression() {
    local src_ip="$1"
    local dest_ip="$2"
    local current_phase="$3"
    
    local session_id="${src_ip}_${dest_ip}"
    local correlation_file="$CORRELATION_DIR/session_${session_id//\./_}.json"
    
    if [ ! -f "$correlation_file" ]; then
        echo "NEW_ATTACK"
        return
    fi
    
    local phases_detected=$(jq -r '.[].phase' "$correlation_file" | sort -u)
    local total_events=$(jq length "$correlation_file")
    local first_detection=$(jq -r '.[0].timestamp' "$correlation_file")
    local time_span=$(($(date -d "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')" +%s) - $(date -d "$first_detection" +%s)))
    
    log_message "📈 Attack Progression Analysis for $session_id:"
    log_message "   🔍 Phases: $(echo "$phases_detected" | tr '\n' ', ')"
    log_message "   📊 Events: $total_events | ⏱️ Span: ${time_span}s | 🎯 Current: $current_phase"
    
    if echo "$phases_detected" | grep -q "PHASE_3\|POST_EXPLOIT\|CORRELATION_FULL_CHAIN"; then
        echo "SUCCESSFUL_COMPROMISE"
    elif echo "$phases_detected" | grep -q "PHASE_2"; then
        echo "EXPLOITATION_IN_PROGRESS"
    elif echo "$phases_detected" | grep -q "PHASE_1"; then
        echo "INITIAL_RECONNAISSANCE"
    else
        echo "UNKNOWN"
    fi
}

# ============================================================================
# MAIN EXTRACTION FUNCTION - The heart of the system
# ============================================================================

extract_eternalblue_traffic() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local signature="$4"
    local phase="$5"
    local alert_json="$6"
    
    log_message "=== 🚨 ETERNALBLUE DETECTION - UNIFIED EXTRACTION ==="
    log_message "🎯 Phase: $phase | Priority: ${PRIORITY_LEVELS[$phase]}"
    log_message "🔗 Session: $src_ip ↔ $dest_ip"
    
    # Update correlation and check for duplicates
    if ! update_session_correlation "$src_ip" "$dest_ip" "$timestamp" "$phase" "$signature" "$alert_json"; then
        log_message "❌ Skipping - duplicate phase detected"
        return 1
    fi
    
    local attack_status=$(analyze_attack_progression "$src_ip" "$dest_ip" "$phase")
    log_message "📊 Attack Status: $attack_status"
    
    # Check for existing PCAP from same session (SMART REUSE!)
    local existing_pcap=""
    if existing_pcap=$(get_existing_session_pcap "$src_ip" "$dest_ip"); then
        log_message "♻️ SMART REUSE: $(basename "$existing_pcap")"
        send_alert_with_pcap "$src_ip" "$dest_ip" "$timestamp" "$signature" "$existing_pcap" "$phase" "$attack_status" "pcap_reuse" "session_bidirectional"
        return 0
    fi
    
    # Check for duplicate sessions within time window
    if is_duplicate_session "$src_ip" "$dest_ip" "$timestamp" "$phase"; then
        log_message "⚠️ Duplicate session - sending alert without new extraction"
        send_alert_duplicate_session "$src_ip" "$dest_ip" "$timestamp" "$signature" "$phase" "$attack_status"
        return 1
    fi
    
    # NEW EXTRACTION NEEDED
    local capture_window="${CAPTURE_WINDOWS[$phase]:-30}"
    log_message "📏 New extraction - Window: ${capture_window}s"
    
    force_rotation_before_extraction
    
    local start_time_epoch=$(($(date -d "$timestamp" +%s) - capture_window))
    local end_time_epoch=$(($(date -d "$timestamp" +%s) + capture_window))
    
    log_message "🔍 Searching time range: $(date -d "@$start_time_epoch") to $(date -d "@$end_time_epoch")"
    
    # ENHANCED PCAP SEARCH - Ignore timestamp issues, prioritize recent files
    log_message "🔍 Smart PCAP search strategy..."
    
    # Strategy 1: Recent time_block files (ignore alert timestamps due to potential clock skew)
    local candidate_files=$(find "$PCAP_DIR" -name "time_block.pcap.*" -type f -mmin -10 -printf '%T@ %p\n' 2>/dev/null | sort -nr | cut -d' ' -f2-)
    
    if [ -z "$candidate_files" ]; then
        log_message "⚠️ No recent time_block PCAPs, expanding search..."
        candidate_files=$(find "$PCAP_DIR" -name "time_block.pcap.*" -type f -mmin -60 -printf '%T@ %p\n' 2>/dev/null | sort -nr | cut -d' ' -f2-)
    fi
    
    if [ -z "$candidate_files" ]; then
        log_message "⚠️ No time_block files in last hour, searching ALL time_block files..."
        candidate_files=$(find "$PCAP_DIR" -name "time_block.pcap.*" -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | cut -d' ' -f2-)
    fi
    
    if [ -z "$candidate_files" ]; then
        log_message "⚠️ No time_block files found, trying any PCAP files..."
        candidate_files=$(find "$PCAP_DIR" -name "*.pcap*" -type f -mmin -60 -printf '%T@ %p\n' 2>/dev/null | sort -nr | cut -d' ' -f2-)
    fi
    
    if [ -z "$candidate_files" ]; then
        log_message "❌ No candidate PCAP files found"
        send_alert_no_pcap "$src_ip" "$dest_ip" "$timestamp" "$signature" "$phase" "$attack_status"
        return 1
    fi
    
    local files_count=$(echo "$candidate_files" | wc -l)
    log_message "📂 Found $files_count candidate files"
    
    # Test and find working PCAP with attack-specific validation
    local working_pcap=""
    local is_temp_file=false
    
    while IFS= read -r pcap_file; do
        if [ -z "$working_pcap" ] && [ -f "$pcap_file" ]; then
            log_message "🧪 Testing: $(basename "$pcap_file")"
            
            # Pass attack IPs to PCAP test function
            local fixed_file=$(test_and_fix_pcap "$pcap_file" "$src_ip" "$dest_ip")
            local fix_result=$?
            
            if [ $fix_result -eq 0 ] && [ -n "$fixed_file" ] && [ -f "$fixed_file" ]; then
                log_message "✅ USABLE PCAP FOUND: $(basename "$fixed_file")"
                working_pcap="$fixed_file"
                if [[ "$fixed_file" == "$TEMP_DIR"* ]]; then
                    is_temp_file=true
                fi
                break
            fi
        fi
    done <<< "$candidate_files"
    
    if [ -z "$working_pcap" ]; then
        log_message "❌ No PCAP contains traffic for target IPs: $src_ip ↔ $dest_ip"
        log_message "🔍 Debug: Listing all available PCAP files..."
        find "$PCAP_DIR" -name "*.pcap*" -type f -mmin -120 -printf '%T+ %p\n' | head -10 | while read -r line; do
            log_message "   📁 $line"
        done
        send_alert_extraction_failed "$src_ip" "$dest_ip" "$timestamp" "$signature" "$phase" "$attack_status"
        return 1
    fi
    
    # EXTRACT TRAFFIC
    local timestamp_clean=$(echo "$timestamp" | sed 's/[^0-9]//g' | cut -c1-14)
    local phase_clean=$(echo "$phase" | tr '[:upper:]' '[:lower:]' | sed 's/_/-/g')
    local output_filename="eternalblue_${phase_clean}_${src_ip//\./_}_to_${dest_ip//\./_}_${timestamp_clean}.pcap"
    local output_path="$FILTERED_PCAP_DIR/$output_filename"
    
    # Smart filter selection based on phase
    local filter=""
    local extraction_method=""
    
    # Correct tcpdump filters using proven v3 syntax
    if [[ "$phase" =~ ^PHASE_[23]|POST_EXPLOIT|CORRELATION ]]; then
        filter="((src host $src_ip and dst host $dest_ip) or (src host $dest_ip and dst host $src_ip)) and (port 445 or port 139 or port 135)"
        extraction_method="advanced_bidirectional"
    else
        filter="((src host $src_ip and dst host $dest_ip) or (src host $dest_ip and dst host $src_ip)) and port 445"
        extraction_method="standard_bidirectional"
    fi
    
    log_message "🔍 Extracting with $extraction_method filter"
    log_message "   🔧 Filter: $filter"
    
    # Debug: Test filter before extraction
    local test_extract=$(timeout 10s tcpdump -r "$working_pcap" "$filter" 2>/dev/null | wc -l || echo "0")
    log_message "   📊 Filter test: $test_extract packets match filter"
    
    if timeout 60s tcpdump -r "$working_pcap" -w "$output_path" "$filter" 2>> "$LOG_FILE"; then
        if [ -f "$output_path" ] && [ -s "$output_path" ]; then
            local packet_count=$(timeout 20s tcpdump -r "$output_path" 2>/dev/null | wc -l || echo "0")
            if [ "$packet_count" -gt 0 ]; then
                log_message "🎉 EXTRACTION SUCCESS: $packet_count packets"
                
                mark_session_processed "$src_ip" "$dest_ip" "$timestamp" "$output_path"
                send_alert_with_pcap "$src_ip" "$dest_ip" "$timestamp" "$signature" "$output_path" "$phase" "$attack_status" "$extraction_method" "$filter"
                
                if [ "$is_temp_file" = true ]; then
                    rm -f "$working_pcap"
                fi
                return 0
            else
                log_message "⚠️ Extraction created empty file"
            fi
        else
            log_message "⚠️ Extraction failed to create output file"
        fi
    else
        log_message "⚠️ tcpdump extraction command failed"
    fi
    
    # Fallback extraction
    log_message "⚠️ Primary extraction failed, trying fallback..."
    rm -f "$output_path" 2>/dev/null
    
    local fallback_filter="((src host $src_ip and dst host $dest_ip) or (src host $dest_ip and dst host $src_ip))"
    log_message "   🔧 Fallback filter: $fallback_filter"
    
    # Debug: Test fallback filter
    local fallback_test=$(timeout 10s tcpdump -r "$working_pcap" "$fallback_filter" 2>/dev/null | wc -l || echo "0")
    log_message "   📊 Fallback filter test: $fallback_test packets match"
    
    if timeout 60s tcpdump -r "$working_pcap" -w "$output_path" "$fallback_filter" 2>/dev/null; then
        if [ -f "$output_path" ] && [ -s "$output_path" ]; then
            local packet_count=$(timeout 20s tcpdump -r "$output_path" 2>/dev/null | wc -l || echo "0")
            if [ "$packet_count" -gt 0 ]; then
                log_message "✅ Fallback extraction successful: $packet_count packets"
                mark_session_processed "$src_ip" "$dest_ip" "$timestamp" "$output_path"
                send_alert_with_pcap "$src_ip" "$dest_ip" "$timestamp" "$signature" "$output_path" "$phase" "$attack_status" "fallback_broad" "$fallback_filter"
                
                if [ "$is_temp_file" = true ]; then
                    rm -f "$working_pcap"
                fi
                return 0
            else
                log_message "⚠️ Fallback extraction created empty file"
            fi
        else
            log_message "⚠️ Fallback extraction failed to create output file"
        fi
    else
        log_message "⚠️ Fallback tcpdump command failed $output_path"
    fi
    
    log_message "❌ All extraction attempts failed"
    send_alert_extraction_failed "$src_ip" "$dest_ip" "$timestamp" "$signature" "$phase" "$attack_status"
    return 1
}

# ============================================================================
# WEBHOOK ALERT FUNCTIONS - Unified alert system
# ============================================================================

send_alert_with_pcap() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local signature="$4"
    local pcap_path="$5"
    local phase="$6"
    local attack_status="$7"
    local extraction_method="$8"
    local filter_used="$9"
    
    local file_size=$(stat -c%s "$pcap_path" 2>/dev/null || echo "0")
    local file_hash=$(timeout 30s sha256sum "$pcap_path" 2>/dev/null | cut -d' ' -f1 || echo "calculating...")
    local packet_count=$(timeout 30s tcpdump -r "$pcap_path" 2>/dev/null | wc -l || echo "0")
    local priority="${PRIORITY_LEVELS[$phase]}"
    
    local advanced_analysis=""
    if [[ "$phase" =~ ^PHASE_[23]|POST_EXPLOIT|CORRELATION ]]; then
        local smb_packets=$(timeout 20s tcpdump -r "$pcap_path" port 445 2>/dev/null | wc -l || echo "0")
        local large_packets=$(timeout 20s tcpdump -r "$pcap_path" greater 1000 2>/dev/null | wc -l || echo "0")
        
        advanced_analysis=$(cat <<EOF
        "advanced_analysis": {
            "smb_packet_count": $smb_packets,
            "large_packet_count": $large_packets,
            "analysis_performed": true
        },
EOF
        )
    else
        advanced_analysis='"advanced_analysis": {"analysis_performed": false},'
    fi
    
    local json_payload=$(cat <<EOF
{
    "alert_type": "eternalblue_multi_phase_detection",
    "timestamp": "$timestamp",
    "source_ip": "$src_ip",
    "destination_ip": "$dest_ip",
    "signature": "$signature",
    "attack_analysis": {
        "phase": "$phase",
        "attack_status": "$attack_status",
        "priority_level": "$priority",
        "extraction_method": "$extraction_method",
        "filter_used": "$filter_used",
        "extraction_status": "success"
    },
    $advanced_analysis
    "pcap_file": {
        "path": "$pcap_path",
        "filename": "$(basename "$pcap_path")",
        "size_bytes": $file_size,
        "packet_count": $packet_count,
        "sha256": "$file_hash"
    },
    "investigation_priority": "$(echo "$priority" | tr '[:upper:]' '[:lower:]')",
    "auto_created": true,
    "detection_engine": "suricata_eternalblue_soar_unified_v4.0",
    "processing_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')",
    "correlation_data": {
        "session_id": "${src_ip}_${dest_ip}",
        "correlation_file": "$CORRELATION_DIR/session_${src_ip//\./_}_${dest_ip//\./_}.json"
    },
    "medical_environment": {
        "is_medical_target": $([ "$phase" = "MEDICAL_TARGET" ] && echo "true" || echo "false"),
        "requires_immediate_response": $([ "$priority" = "CRITICAL" ] && echo "true" || echo "false")
    }
}
EOF
    )
    
    send_webhook "$json_payload"
}

send_alert_duplicate_session() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local signature="$4"
    local phase="$5"
    local attack_status="$6"
    
    local existing_pcap=""
    if existing_pcap=$(get_existing_session_pcap "$src_ip" "$dest_ip"); then
        local file_size=$(stat -c%s "$existing_pcap" 2>/dev/null || echo "0")
        local file_hash=$(timeout 30s sha256sum "$existing_pcap" 2>/dev/null | cut -d' ' -f1 || echo "existing...")
        local packet_count=$(timeout 30s tcpdump -r "$existing_pcap" 2>/dev/null | wc -l || echo "0")
        
        local json_payload=$(cat <<EOF
{
    "alert_type": "eternalblue_multi_phase_detection",
    "timestamp": "$timestamp",
    "source_ip": "$src_ip",
    "destination_ip": "$dest_ip",
    "signature": "$signature",
    "attack_analysis": {
        "phase": "$phase",
        "attack_status": "$attack_status",
        "priority_level": "${PRIORITY_LEVELS[$phase]}",
        "extraction_method": "pcap_reuse",
        "extraction_status": "reused_existing"
    },
    "pcap_file": {
        "path": "$existing_pcap",
        "filename": "$(basename "$existing_pcap")",
        "size_bytes": $file_size,
        "packet_count": $packet_count,
        "sha256": "$file_hash",
        "reused": true
    },
    "investigation_priority": "$(echo "${PRIORITY_LEVELS[$phase]}" | tr '[:upper:]' '[:lower:]')",
    "auto_created": true,
    "detection_engine": "suricata_eternalblue_soar_unified_v4.0",
    "processing_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')",
    "correlation_data": {
        "session_id": "${src_ip}_${dest_ip}",
        "is_duplicate_phase": true
    }
}
EOF
        )
    else
        local json_payload=$(cat <<EOF
{
    "alert_type": "eternalblue_multi_phase_detection",
    "timestamp": "$timestamp",
    "source_ip": "$src_ip",
    "destination_ip": "$dest_ip",
    "signature": "$signature",
    "attack_analysis": {
        "phase": "$phase",
        "attack_status": "$attack_status",
        "priority_level": "${PRIORITY_LEVELS[$phase]}",
        "extraction_status": "duplicate_session_skipped"
    },
    "pcap_file": {
        "path": null,
        "size_bytes": 0,
        "duplicate_session": true
    },
    "investigation_priority": "$(echo "${PRIORITY_LEVELS[$phase]}" | tr '[:upper:]' '[:lower:]')",
    "auto_created": true,
    "detection_engine": "suricata_eternalblue_soar_unified_v4.0",
    "processing_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')",
    "error": "Duplicate session detected within time window"
}
EOF
        )
    fi
    
    send_webhook "$json_payload"
}

send_alert_extraction_failed() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local signature="$4"
    local phase="$5"
    local attack_status="$6"
    
    local json_payload=$(cat <<EOF
{
    "alert_type": "eternalblue_multi_phase_detection",
    "timestamp": "$timestamp",
    "source_ip": "$src_ip",
    "destination_ip": "$dest_ip",
    "signature": "$signature",
    "attack_analysis": {
        "phase": "$phase",
        "attack_status": "$attack_status",
        "priority_level": "${PRIORITY_LEVELS[$phase]}",
        "extraction_status": "failed"
    },
    "pcap_file": {
        "path": null,
        "size_bytes": 0,
        "extraction_error": "pcap_corruption_or_unavailable"
    },
    "investigation_priority": "$(echo "${PRIORITY_LEVELS[$phase]}" | tr '[:upper:]' '[:lower:]')",
    "auto_created": true,
    "detection_engine": "suricata_eternalblue_soar_unified_v4.0",
    "processing_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')",
    "error": "PCAP extraction failed - corruption or timing issues"
}
EOF
    )
    
    send_webhook "$json_payload"
}

send_alert_no_pcap() {
    local src_ip="$1"
    local dest_ip="$2"
    local timestamp="$3"
    local signature="$4"
    local phase="$5"
    local attack_status="$6"
    
    local json_payload=$(cat <<EOF
{
    "alert_type": "eternalblue_multi_phase_detection",
    "timestamp": "$timestamp",
    "source_ip": "$src_ip",
    "destination_ip": "$dest_ip",
    "signature": "$signature",
    "attack_analysis": {
        "phase": "$phase",
        "attack_status": "$attack_status",
        "priority_level": "${PRIORITY_LEVELS[$phase]}",
        "extraction_status": "no_pcap_available"
    },
    "pcap_file": {
        "path": null,
        "size_bytes": 0
    },
    "investigation_priority": "$(echo "${PRIORITY_LEVELS[$phase]}" | tr '[:upper:]' '[:lower:]')",
    "auto_created": true,
    "detection_engine": "suricata_eternalblue_soar_unified_v4.0",
    "processing_timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')",
    "error": "No PCAP files available for time window"
}
EOF
    )
    
    send_webhook "$json_payload"
}

send_webhook() {
    local json_payload="$1"
    
    log_message "📡 Sending SOAR webhook to n8n..."
    
    if timeout 30s curl -X POST \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "$N8N_WEBHOOK" \
        --silent \
        --fail; then
        
        log_message "✅ Webhook sent successfully"
        return 0
    else
        log_message "❌ Webhook failed - queuing for retry"
        echo "$json_payload" >> "/tmp/n8n_eternalblue_retry_queue.json"
        return 1
    fi
}

# ============================================================================
# MAIN MONITORING LOOP - The brain of the operation
# ============================================================================

monitor_eternalblue_alerts() {
    log_message "=== 🚀 ETERNALBLUE SOAR UNIFIED EXTRACTOR v4.0 STARTED ==="
    log_message "✅ Multi-Phase Detection Strategy Enabled"
    log_message "✅ Smart Deduplication System Active"
    log_message "✅ Intelligent PCAP Reuse System Ready"
    log_message "✅ New Suricata time_block.pcap.* Support"
    log_message "📁 Log Source: $SURICATA_LOG"
    log_message "📁 PCAP Directory: $PCAP_DIR"
    log_message "📁 Correlation Directory: $CORRELATION_DIR"
    log_message "🌐 SOAR Webhook: $N8N_WEBHOOK"
    
    # Wait for Suricata log file
    while [ ! -f "$SURICATA_LOG" ]; do
        log_message "⏳ Waiting for Suricata log file..."
        sleep 5
    done
    
    log_message "🎯 Starting EternalBlue monitoring... (Ctrl+C to stop)"
    
    # Monitor Suricata alerts in real-time
    tail -F "$SURICATA_LOG" 2>/dev/null | while IFS= read -r line; do
        if echo "$line" | jq -e '.event_type == "alert"' >/dev/null 2>&1; then
            local alert_signature=$(echo "$line" | jq -r '.alert.signature // empty' 2>/dev/null)
            local alert_sid=$(echo "$line" | jq -r '.alert.signature_id // empty' 2>/dev/null)
            
            # Check if this is an EternalBlue-related alert
            if [ -n "${ATTACK_PHASES[$alert_sid]}" ]; then
                local src_ip=$(echo "$line" | jq -r '.src_ip // empty')
                local dest_ip=$(echo "$line" | jq -r '.dest_ip // empty')
                local timestamp=$(echo "$line" | jq -r '.timestamp // empty')
                local phase="${ATTACK_PHASES[$alert_sid]}"
                local priority="${PRIORITY_LEVELS[$phase]}"
                
                if [ -n "$src_ip" ] && [ -n "$dest_ip" ] && [ -n "$timestamp" ]; then
                    log_message "🚨 ETERNALBLUE ALERT DETECTED [$priority]"
                    log_message "   📍 Phase: $phase | 🎯 Target: $src_ip → $dest_ip"
                    log_message "   📝 Signature: $alert_signature | 🆔 SID: $alert_sid"
                    
                    # Control extraction concurrency
                    local bg_jobs=$(jobs -r | wc -l)
                    if [ "$bg_jobs" -gt 3 ]; then
                        log_message "⏸️ Queue full ($bg_jobs jobs), waiting..."
                        wait
                    fi
                    
                    # Extract in background
                    extract_eternalblue_traffic "$src_ip" "$dest_ip" "$timestamp" "$alert_signature" "$phase" "$line" &
                    sleep 2
                fi
            else
                # Legacy EternalBlue signatures (backward compatibility)
                if echo "$alert_signature" | grep -qiE "eternalblue|trans2|wannacry|petya|doublepulsar|exploit.*smb"; then
                    local src_ip=$(echo "$line" | jq -r '.src_ip // empty')
                    local dest_ip=$(echo "$line" | jq -r '.dest_ip // empty')
                    local timestamp=$(echo "$line" | jq -r '.timestamp // empty')
                    
                    if [ -n "$src_ip" ] && [ -n "$dest_ip" ] && [ -n "$timestamp" ]; then
                        log_message "🚨 LEGACY ETERNALBLUE PATTERN: $src_ip → $dest_ip"
                        log_message "   📝 Signature: $alert_signature"
                        
                        extract_eternalblue_traffic "$src_ip" "$dest_ip" "$timestamp" "$alert_signature" "PHASE_1_LEGACY_UNKNOWN" "$line" &
                        sleep 3
                    fi
                fi
            fi
        fi
    done
}

# ============================================================================
# CLEANUP AND SHUTDOWN
# ============================================================================

cleanup() {
    log_message "🛑 Shutting down EternalBlue SOAR Unified Extractor..."
    
    # Kill background jobs
    jobs -p | xargs -r kill 2>/dev/null
    
    # Clean temporary files (keep correlation data)
    rm -f "$TEMP_DIR"/repaired_*
    rm -f "$TEMP_DIR"/partial_*
    
    # Archive old correlation data (older than 24 hours)
    find "$CORRELATION_DIR" -name "session_*.json" -mtime +1 -exec mv {} "$CORRELATION_DIR/archived/" \; 2>/dev/null
    
    log_message "✅ Cleanup completed - Unified extractor stopped"
    exit 0
}

trap cleanup SIGTERM SIGINT

# ============================================================================
# STARTUP - Let's rock and roll! 🚀
# ============================================================================

log_message "🔥 UNIFIED ETERNALBLUE SOAR EXTRACTOR v4.0"
log_message "🎯 One script to rule them all - no more code mess!"
log_message "🚀 Starting in 3 seconds..."

sleep 3

# Start monitoring
monitor_eternalblue_alerts