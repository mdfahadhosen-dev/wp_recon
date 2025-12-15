#!/bin/bash

# =============================================================================
# WPRecon - Advanced WordPress Reconnaissance & Vulnerability Scanner
# =============================================================================
#
# Version: 2.1
# Author: OpenSource Security Community
# Developer: MD Fahad Hosen <fahadhosen.dev.19@gmail.com>
# License: MIT License (see LICENSE file)
# Repository: https://github.com/mdfahadhosen-dev/wp_recon.git
#
# Description:
#   WPRecon is a comprehensive command-line tool designed for ethical hackers,
#   security researchers, and system administrators to perform reconnaissance
#   and vulnerability assessment on WordPress installations. It checks for
#   common security exposures and provides detailed reports.
#
# Features:
#   - Multi-vulnerability scanning (Setup Config, XML-RPC, WP-JSON, etc.)
#   - API integrations (Shodan, WPScan) for enhanced detection
#   - Batch processing from file input with progress tracking
#   - Proxy support for anonymity and rate limiting
#   - Customizable timeouts, user-agents, and stealth options
#   - Multiple export formats (TXT, JSON, CSV)
#   - Configuration file support for persistent settings
#   - Professional error handling and logging
#   - Plugin and theme enumeration
#   - User discovery and brute force detection
#
# Requirements:
#   - curl (for HTTP requests)
#   - bash 4.0+ (for advanced features)
#   - jq (for JSON parsing in API responses)
#   - bc (for mathematical calculations)
#
# Usage:
#   See help: ./wprecon.sh --help
#
# Disclaimer:
#   This tool is for educational and authorized security testing purposes only.
#   Unauthorized use against systems without permission is illegal.
#
# =============================================================================

# Configuration Variables
# =======================
SCRIPT_VERSION="2.1"                    # Current version of the script
DEFAULT_TIMEOUT=10                      # Default HTTP request timeout in seconds
DEFAULT_USER_AGENT="WPRecon/2.1 (WordPress Security Scanner)"  # Default User-Agent
COLOR_ENABLED=true                      # Enable/disable colored terminal output
CONFIG_FILE=".wprecon.conf"             # Configuration file name
EXPORT_FORMAT="txt"                     # Default export format (txt/json/csv)
STEALTH_MODE=false                      # Enable stealth mode with random delays
RATE_LIMIT=0                            # Rate limiting delay between requests
MAX_CONCURRENT=1                        # Maximum concurrent scans

# API Configuration
SHODAN_API_KEY=""                       # Shodan API key for enhanced reconnaissance
WPSCAN_API_KEY=""                       # WPScan API key for vulnerability database
USE_SHODAN=false                        # Enable Shodan integration
USE_WPSCAN=false                        # Enable WPScan integration

# Color Definitions
# =================
# ANSI color codes for enhanced terminal output
if [[ "$COLOR_ENABLED" == true ]]; then
    RED='\033[0;31m'      # Red for errors and vulnerabilities
    GREEN='\033[0;32m'    # Green for success and safe results
    YELLOW='\033[1;33m'   # Yellow for warnings and info
    BLUE='\033[1;34m'     # Blue for progress and checks
    PURPLE='\033[0;35m'   # Purple for headers and branding
    CYAN='\033[0;36m'     # Cyan for banners and highlights
    WHITE='\033[1;37m'    # White for general text
    NC='\033[0m'          # No Color - reset to default
else
    # Disable colors if requested
    RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' WHITE='' NC=''
fi

# Global Variables
# ================
VERBOSE=false           # Enable verbose output mode
TIMEOUT=$DEFAULT_TIMEOUT # HTTP request timeout
OUTPUT_FILE=""          # Output file path for results
USER_AGENT="$DEFAULT_USER_AGENT"  # HTTP User-Agent string
PROXY=""                # Proxy server URL
TOTAL_SCANNED=0         # Counter for scanned URLs
TOTAL_VULNERABILITIES=0 # Counter for found vulnerabilities
VULNERABLE_URLS=()      # Array to store vulnerable URLs
CURRENT_SCAN=0          # Current scan progress counter

# Function: display_banner
# ========================
# Displays the ASCII art banner and version information
# No parameters required
display_banner() {
    clear
    echo -e "${CYAN}"
    # Original ASCII art created for this project
    cat << 'EOF'
██╗    ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║    ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║ █╗ ██║██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║███╗██║██╔═══╝ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚███╔███╔╝██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
EOF
    echo -e "${NC}"
    echo -e "${WHITE}Advanced WordPress Reconnaissance & Vulnerability Scanner v${SCRIPT_VERSION}${NC}"
    echo -e "${PURPLE}Professional Security Tool for Ethical Hacking & Penetration Testing${NC}"
    echo -e "${BLUE}Developer: MD Fahad Hosen <fahadhosen.dev.19@gmail.com>${NC}"
    echo -e "${YELLOW}License: MIT | Repository: https://github.com/mdfahadhosen-dev/wp_recon.git${NC}"
    echo ""
}

# Function: show_help
# ===================
# Displays comprehensive help information and usage examples
# No parameters required
show_help() {
    echo "WPRecon - WordPress Reconnaissance Tool"
    echo "======================================="
    echo ""
    echo "USAGE:"
    echo "  $0 [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  -u, --url URL          Target WordPress URL to scan"
    echo "  -f, --file FILE        File containing list of URLs to scan"
    echo "  -o, --output FILE      Output file for scan results (default: auto-generated)"
    echo "  -v, --verbose          Enable verbose output mode"
    echo "  -t, --timeout SEC      Request timeout in seconds (default: $DEFAULT_TIMEOUT)"
    echo "  -a, --agent STRING     Custom User-Agent string"
    echo "  -p, --proxy URL        Proxy URL (http://proxy:port)"
    echo "  -c, --no-color         Disable colored terminal output"
    echo "  --shodan-key KEY       Shodan API key for enhanced reconnaissance"
    echo "  --wpscan-key KEY       WPScan API key for vulnerability database"
    echo "  --use-shodan           Enable Shodan integration for target discovery"
    echo "  --use-wpscan           Enable WPScan API for advanced vulnerability checks"
    echo "  --format FORMAT        Export format: txt, json, csv (default: txt)"
    echo "  --stealth              Enable stealth mode with random delays"
    echo "  --rate-limit SEC       Delay between requests (default: 0)"
    echo "  --config FILE          Use custom configuration file (default: .wprecon.conf)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 -u https://example.com"
    echo "  $0 -f targets.txt -o results.txt -v"
    echo "  $0 -u https://example.com -p http://127.0.0.1:8080 -t 15"
    echo "  $0 --shodan-key YOUR_KEY --use-shodan -u https://example.com"
    echo "  $0 --wpscan-key YOUR_KEY --use-wpscan -f sites.txt"
    echo ""
    echo "VULNERABILITY CHECKS:"
    echo "  • Setup Config Exposure (/wp-admin/setup-config.php)"
    echo "  • XML-RPC API Exposure (/xmlrpc.php)"
    echo "  • WP-JSON API Exposure (/wp-json/wp/v2/users)"
    echo "  • Readme Version Disclosure (/readme.html)"
    echo "  • Admin Login Page Exposure (/wp-admin/)"
    echo ""
    echo "DEVELOPER INFO:"
    echo "  Name: MD Fahad Hosen"
    echo "  Email: fahadhosen.dev.19@gmail.com"
    echo "  Website: https://mdfahadhosendev.vercel.app/"
    echo "  LinkedIn: https://www.linkedin.com/in/fahadcyberdev/"
    echo "  Company: Bangladesh"
    echo "  Project: https://github.com/mdfahadhosen-dev/wprecon"
    echo "  License: MIT License"
    echo ""
    echo "API REQUIREMENTS:"
    echo "  Shodan API: Get key from https://account.shodan.io/"
    echo "  WPScan API: Get key from https://wpscan.com/api"
    echo "  Both services offer free tiers for basic usage."
    exit 0
}

# Function: parse_arguments
# =========================
# Parses command-line arguments using getopts-like logic
# Parameters: All command-line arguments ($@)
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                TARGET_URL="$2"
                shift 2
                ;;
            -f|--file)
                TARGET_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -a|--agent)
                USER_AGENT="$2"
                shift 2
                ;;
            -p|--proxy)
                PROXY="$2"
                shift 2
                ;;
            -c|--no-color)
                COLOR_ENABLED=false
                RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' WHITE='' NC=''
                shift
                ;;
            --shodan-key)
                SHODAN_API_KEY="$2"
                shift 2
                ;;
            --wpscan-key)
                WPSCAN_API_KEY="$2"
                shift 2
                ;;
            --use-shodan)
                USE_SHODAN=true
                shift
                ;;
            --use-wpscan)
                USE_WPSCAN=true
                shift
                ;;
            --format)
                EXPORT_FORMAT="$2"
                shift 2
                ;;
            --stealth)
                STEALTH_MODE=true
                shift
                ;;
            --rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                echo "Use -h or --help for usage information."
                exit 1
                ;;
        esac
    done

    # Input validation
    if [[ -z "$TARGET_URL" && -z "$TARGET_FILE" ]]; then
        echo -e "${RED}[!] Error: Must specify target URL (-u) or file (-f)${NC}"
        echo "Use -h or --help for usage information."
        exit 1
    fi

    if [[ -n "$TARGET_URL" && -n "$TARGET_FILE" ]]; then
        echo -e "${RED}[!] Error: Cannot specify both URL and file${NC}"
        exit 1
    fi

    if [[ -n "$TARGET_FILE" && ! -f "$TARGET_FILE" ]]; then
        echo -e "${RED}[!] Error: Target file '$TARGET_FILE' not found${NC}"
        exit 1
    fi

    # API Validation
    if [[ "$USE_SHODAN" == true && -z "$SHODAN_API_KEY" ]]; then
        echo -e "${RED}[!] Error: Shodan API key required when using --use-shodan${NC}"
        echo "Get your API key from: https://account.shodan.io/"
        exit 1
    fi

    if [[ "$USE_WPSCAN" == true && -z "$WPSCAN_API_KEY" ]]; then
        echo -e "${RED}[!] Error: WPScan API key required when using --use-wpscan${NC}"
        echo "Get your API key from: https://wpscan.com/api"
        exit 1
    fi
}

# Function: is_valid_url
# ======================
# Validates if a string is a proper HTTP/HTTPS URL
# Parameters: $1 - URL string to validate
# Returns: 0 if valid, 1 if invalid
is_valid_url() {
    local url="$1"
    # Basic regex check for http:// or https://
    if [[ $url =~ ^https?:// ]]; then
        return 0
    else
        return 1
    fi
}

# Function: http_request
# ======================
# Performs HTTP request using curl with configured options
# Parameters: $1 - Target URL
# Returns: HTTP response body
http_request() {
    local url="$1"
    # Build curl options string
    local options="-s --max-time $TIMEOUT -A \"$USER_AGENT\""

    # Add proxy if specified
    if [[ -n "$PROXY" ]]; then
        options="$options --proxy $PROXY"
    fi

    # Execute curl command
    eval curl $options "$url"
}

# Function: load_config
# =====================
# Loads configuration from file if it exists
# Parameters: $1 - Config file path
load_config() {
    local config_file="$1"
    if [[ -f "$config_file" ]]; then
        echo -e "${BLUE}[i] Loading configuration from $config_file...${NC}"
        source "$config_file"
    fi
}

# Function: random_delay
# ======================
# Adds random delay for stealth mode
# No parameters required
random_delay() {
    if [[ "$STEALTH_MODE" == true ]]; then
        local delay=$((RANDOM % 5 + 1))
        sleep $delay
    elif [[ $RATE_LIMIT -gt 0 ]]; then
        sleep $RATE_LIMIT
    fi
}

# Function: check_plugin_enumeration
# ==================================
# Attempts to enumerate WordPress plugins
# Parameters: $1 - Base URL
check_plugin_enumeration() {
    local url="$1"
    local plugins_found=0

    # Common plugin paths to check
    local common_plugins=("wp-super-cache" "contact-form-7" "wordpress-seo" "akismet" "jetpack")

    for plugin in "${common_plugins[@]}"; do
        random_delay
        local plugin_url="${url}/wp-content/plugins/${plugin}/readme.txt"
        local response
        response=$(http_request "$plugin_url")

        if echo "$response" | grep -q "=== ${plugin} ==="; then
            echo -e "${YELLOW}[!] Plugin found: $plugin - $plugin_url${NC}"
            ((plugins_found++))
        fi
    done

    if [[ $plugins_found -gt 0 ]]; then
        ((TOTAL_VULNERABILITIES += plugins_found))
    fi
}

# Function: check_user_enumeration
# ================================
# Attempts to enumerate WordPress users via REST API
# Parameters: $1 - Base URL
check_user_enumeration() {
    local url="$1"
    local user_url="${url}/wp-json/wp/v2/users"
    random_delay

    local response
    response=$(http_request "$user_url")

    if echo "$response" | grep -q '"id":'; then
        local user_count
        user_count=$(echo "$response" | jq -r '.[].id' 2>/dev/null | wc -l)
        if [[ $user_count -gt 0 ]]; then
            echo -e "${YELLOW}[!] User enumeration possible: $user_count users found${NC}"
            ((TOTAL_VULNERABILITIES++))
        fi
    fi
}

# Function: check_backup_files
# ============================
# Checks for common backup and configuration files
# Parameters: $1 - Base URL
check_backup_files() {
    local url="$1"
    local backup_files=("wp-config.php.bak" "wp-config.php~" ".wp-config.php.swp" "wp-config.php.old")
    local backups_found=0

    for backup in "${backup_files[@]}"; do
        random_delay
        local backup_url="${url}/${backup}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" "$backup_url")

        if [[ $status -eq 200 ]]; then
            echo -e "${RED}[!] Backup file exposed: $backup_url${NC}"
            ((backups_found++))
        fi
    done

    if [[ $backups_found -gt 0 ]]; then
        ((TOTAL_VULNERABILITIES += backups_found))
    fi
}

# Function: shodan_lookup
# =======================
# Performs Shodan API lookup for additional reconnaissance
# Parameters: $1 - Target URL or IP
# Returns: Shodan data if available
shodan_lookup() {
    local target="$1"
    local ip=""

    # Extract IP from URL if needed
    if [[ $target =~ ^https?:// ]]; then
        ip=$(curl -s "https://api.shodan.io/dns/resolve?hostnames=$(echo $target | sed 's|https*://||' | cut -d'/' -f1)&key=$SHODAN_API_KEY" | jq -r 'keys[0]')
    else
        ip="$target"
    fi

    if [[ -n "$ip" && "$ip" != "null" ]]; then
        echo -e "${BLUE}[i] Performing Shodan reconnaissance for $ip...${NC}"
        local shodan_data
        shodan_data=$(curl -s "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY")

        if echo "$shodan_data" | grep -q '"error"'; then
            echo -e "${YELLOW}[!] Shodan lookup failed for $ip${NC}"
        else
            local ports
            ports=$(echo "$shodan_data" | jq -r '.ports[]' 2>/dev/null | tr '\n' ', ' | sed 's/, $//')
            if [[ -n "$ports" ]]; then
                echo -e "${GREEN}[+] Shodan found open ports: $ports${NC}"
            fi

            local vulns
            vulns=$(echo "$shodan_data" | jq -r '.vulns[]' 2>/dev/null | wc -l)
            if [[ $vulns -gt 0 ]]; then
                echo -e "${RED}[!] Shodan detected $vulns potential vulnerabilities${NC}"
            fi
        fi
    fi
}

# Function: wpscan_api_check
# ==========================
# Performs WPScan API lookup for known vulnerabilities
# Parameters: $1 - Target URL
# Returns: WPScan vulnerability data
wpscan_api_check() {
    local url="$1"
    echo -e "${BLUE}[i] Checking WPScan database for known vulnerabilities...${NC}"

    # Get WordPress version first
    local wp_version=""
    local readme_response
    readme_response=$(http_request "${url}/readme.html")
    if echo "$readme_response" | grep -q "Version"; then
        wp_version=$(echo "$readme_response" | grep -o "Version [0-9]\+\.[0-9]\+\.[0-9]\+" | head -1 | cut -d' ' -f2)
    fi

    if [[ -n "$wp_version" ]]; then
        echo -e "${YELLOW}[i] Detected WordPress version: $wp_version${NC}"

        # Query WPScan API for vulnerabilities
        local wpscan_data
        wpscan_data=$(curl -s -H "Authorization: Token token=$WPSCAN_API_KEY" \
                         "https://wpscan.com/api/v3/wordpresses/$wp_version")

        if echo "$wpscan_data" | grep -q '"error"'; then
            echo -e "${YELLOW}[!] WPScan API lookup failed${NC}"
        else
            local vuln_count
            vuln_count=$(echo "$wpscan_data" | jq -r '.vulnerabilities | length' 2>/dev/null)
            if [[ $vuln_count -gt 0 ]]; then
                echo -e "${RED}[!] WPScan found $vuln_count known vulnerabilities for WordPress $wp_version${NC}"
                ((TOTAL_VULNERABILITIES += vuln_count))
            else
                echo -e "${GREEN}[+] No known vulnerabilities found for WordPress $wp_version${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}[!] Could not detect WordPress version for WPScan check${NC}"
    fi
}

# Function: check_vulnerability
# ============================
# Checks for a specific vulnerability on a target URL
# Parameters: $1 - Base URL, $2 - Check name, $3 - Path, $4 - Pattern
# Returns: 0 (not vuln), 1 (vulnerable), 2 (connection failed)
check_vulnerability() {
    local base_url="$1"
    local check_name="$2"
    local path="$3"
    local pattern="$4"
    local full_url="${base_url%/}$path"

    # Verbose output for current check
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${BLUE}[+] Checking $check_name: ${NC}$full_url"
    fi

    # Perform HTTP request
    local response
    response=$(http_request "$full_url")
    local status=$?

    # Check if request succeeded
    if [[ $status -ne 0 ]]; then
        if [[ "$VERBOSE" == true ]]; then
            echo -e "${RED}[-] Connection failed for $check_name${NC}"
        fi
        return 2  # Connection error
    fi

    # Check for vulnerability pattern
    if echo "$response" | grep -q "$pattern"; then
        echo -e "${GREEN}[!] VULNERABLE: $check_name - $full_url${NC}"
        return 1  # Vulnerable
    else
        if [[ "$VERBOSE" == true ]]; then
            echo -e "${YELLOW}[-] Not vulnerable: $check_name${NC}"
        fi
        return 0  # Not vulnerable
    fi
}

# Function: scan_url
# ==================
# Performs complete vulnerability scan on a single URL
# Parameters: $1 - Target URL
scan_url() {
    local url="$1"
    local vulnerabilities_found=0

    echo -e "${BLUE}[*] Scanning: $url${NC}"

    # Shodan reconnaissance if enabled
    if [[ "$USE_SHODAN" == true ]]; then
        shodan_lookup "$url"
    fi

    # WPScan API check if enabled
    if [[ "$USE_WPSCAN" == true ]]; then
        wpscan_api_check "$url"
    fi

    # Execute all vulnerability checks
    # Each check returns 0, 1, or 2 - we only count actual vulnerabilities (1)
    check_vulnerability "$url" "Setup Config Exposure" "/wp-admin/setup-config.php?step=1" "Database Name"
    ((vulnerabilities_found += $? == 1 ? 1 : 0))

    check_vulnerability "$url" "XML-RPC API Exposure" "/xmlrpc.php" "XML-RPC server accepts POST requests only"
    ((vulnerabilities_found += $? == 1 ? 1 : 0))

    check_vulnerability "$url" "WP-JSON API Exposure" "/wp-json/wp/v2/users" '"id":'
    ((vulnerabilities_found += $? == 1 ? 1 : 0))

    check_vulnerability "$url" "Readme Version Disclosure" "/readme.html" "Version [0-9]"
    ((vulnerabilities_found += $? == 1 ? 1 : 0))

    check_vulnerability "$url" "Admin Login Page Exposure" "/wp-admin/" "Username"
    ((vulnerabilities_found += $? == 1 ? 1 : 0))

    # Advanced checks
    check_plugin_enumeration "$url"
    check_user_enumeration "$url"
    check_backup_files "$url"

    # Record vulnerable URLs
    if [[ $vulnerabilities_found -gt 0 ]]; then
        VULNERABLE_URLS+=("$url ($vulnerabilities_found vulnerabilities)")
    fi

    # Update global counters
    ((TOTAL_SCANNED++))
    ((TOTAL_VULNERABILITIES += vulnerabilities_found))
}

# Function: scan_from_file
# ========================
# Reads URLs from file and scans each one with progress tracking
# Parameters: $1 - Input file path
scan_from_file() {
    local filename="$1"
    local total_urls
    total_urls=$(wc -l < "$filename")

    # Read file line by line
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Clean up line (remove carriage returns, trim whitespace)
        line=$(echo "$line" | tr -d '\r' | xargs)
        # Skip empty lines
        if [[ -z "$line" ]]; then
            continue
        fi
        # Validate URL format
        if ! is_valid_url "$line"; then
            echo -e "${YELLOW}[!] Skipping invalid URL: $line${NC}"
            continue
        fi

        # Show progress
        ((CURRENT_SCAN++))
        echo -e "${CYAN}[i] Progress: $CURRENT_SCAN/$total_urls URLs${NC}"

        # Scan the URL
        scan_url "$line"
    done < "$filename"
}

# Function: export_json
# =====================
# Exports results in JSON format
# Parameters: $1 - Output file path
export_json() {
    local output_file="$1"
    local json_data

    json_data=$(cat <<EOF
{
  "scan_info": {
    "date": "$(date)",
    "version": "$SCRIPT_VERSION",
    "developer": "MD Fahad Hosen <fahadhosen.dev.19@gmail.com>",
    "total_scanned": $TOTAL_SCANNED,
    "total_vulnerabilities": $TOTAL_VULNERABILITIES,
    "scan_duration": $SCAN_DURATION
  },
  "configuration": {
    "timeout": $TIMEOUT,
    "user_agent": "$USER_AGENT",
    "proxy": "$PROXY",
    "shodan_enabled": $USE_SHODAN,
    "wpscan_enabled": $USE_WPSCAN,
    "stealth_mode": $STEALTH_MODE,
    "rate_limit": $RATE_LIMIT
  },
  "vulnerable_urls": [
EOF
)

    # Add vulnerable URLs
    local first=true
    for url in "${VULNERABLE_URLS[@]}"; do
        if [[ $first == true ]]; then
            json_data="${json_data}\n    \"$url\""
            first=false
        else
            json_data="${json_data},\n    \"$url\""
        fi
    done

    json_data="${json_data}\n  ]\n}"

    echo -e "$json_data" > "$output_file"
}

# Function: export_csv
# ====================
# Exports results in CSV format
# Parameters: $1 - Output file path
export_csv() {
    local output_file="$1"

    {
        echo "WPRecon Scan Results"
        echo "Date,Version,Total Scanned,Total Vulnerabilities,Scan Duration"
        echo "$(date),$SCRIPT_VERSION,$TOTAL_SCANNED,$TOTAL_VULNERABILITIES,$SCAN_DURATION"
        echo ""
        echo "Vulnerable URLs"
        printf '%s\n' "${VULNERABLE_URLS[@]}"
    } > "$output_file"
}

# Function: save_results
# ======================
# Saves scan results to output file (asks user for confirmation)
# No parameters required (uses global variables)
save_results() {
    echo ""
    read -p "[?] Do you want to save the scan results to a file? (y/N): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Generate default filename if not specified
        if [[ -z "$OUTPUT_FILE" ]]; then
            OUTPUT_FILE="wprecon_results_$(date +%Y%m%d_%H%M%S).${EXPORT_FORMAT}"
        fi

        echo -e "${BLUE}[i] Saving results to $OUTPUT_FILE...${NC}"

        # Export based on format
        case "$EXPORT_FORMAT" in
            json)
                export_json "$OUTPUT_FILE"
                ;;
            csv)
                export_csv "$OUTPUT_FILE"
                ;;
            txt|*)
                # Default TXT format
                {
                    echo "WPRecon - WordPress Reconnaissance Scan Results"
                    echo "==============================================="
                    echo "Scan Date: $(date)"
                    echo "WPRecon Version: $SCRIPT_VERSION"
                    echo "Developer: MD Fahad Hosen <fahadhosen.dev.19@gmail.com>"
                    echo "Total URLs Scanned: $TOTAL_SCANNED"
                    echo "Total Vulnerabilities Found: $TOTAL_VULNERABILITIES"
                    echo "Scan Duration: ${SCAN_DURATION} seconds"
                    echo ""
                    echo "Scan Configuration:"
                    echo "  Timeout: $TIMEOUT seconds"
                    echo "  User-Agent: $USER_AGENT"
                    if [[ -n "$PROXY" ]]; then
                        echo "  Proxy: $PROXY"
                    fi
                    if [[ "$USE_SHODAN" == true ]]; then
                        echo "  Shodan Integration: Enabled"
                    fi
                    if [[ "$USE_WPSCAN" == true ]]; then
                        echo "  WPScan Integration: Enabled"
                    fi
                    if [[ "$STEALTH_MODE" == true ]]; then
                        echo "  Stealth Mode: Enabled"
                    fi
                    echo ""
                    echo "Vulnerable URLs:"
                    if [[ ${#VULNERABLE_URLS[@]} -gt 0 ]]; then
                        printf '  %s\n' "${VULNERABLE_URLS[@]}"
                    else
                        echo "  None found"
                    fi
                    echo ""
                    echo "Disclaimer:"
                    echo "  This report was generated by WPRecon for security assessment purposes."
                    echo "  All findings should be verified and addressed appropriately."
                    echo ""
                    echo "End of Report"
                } > "$OUTPUT_FILE"
                ;;
        esac

        echo -e "${GREEN}[i] Results saved to $OUTPUT_FILE${NC}"
    else
        echo -e "${YELLOW}[i] Results not saved.${NC}"
    fi
}

# Function: handle_interrupt
# =========================
# Handles SIGINT (Ctrl+C) signal gracefully
# No parameters required
handle_interrupt() {
    echo -e "\n${RED}[!] Scan interrupted by user. Exiting...${NC}"
    # Save partial results if any vulnerabilities found
    if [[ ${#VULNERABLE_URLS[@]} -gt 0 ]]; then
        save_results
    fi
    exit 1
}

# Function: main
# ==============
# Main execution function
# Parameters: All command-line arguments ($@)
main() {
    # Set up signal handler for graceful interruption
    trap handle_interrupt SIGINT

    # Display banner
    display_banner

    # Parse command-line arguments
    parse_arguments "$@"

    # Load configuration file
    load_config "$CONFIG_FILE"

    echo -e "${CYAN}[i] Initializing WPRecon scan...${NC}"
    echo ""

    # Record start time
    START_TIME=$(date +%s)

    # Execute scan based on input type
    if [[ -n "$TARGET_FILE" ]]; then
        scan_from_file "$TARGET_FILE"
    else
        scan_url "$TARGET_URL"
    fi

    # Calculate scan duration
    SCAN_DURATION=$(( $(date +%s) - START_TIME ))

    # Display final results
    echo ""
    echo -e "${YELLOW}[i] Scan completed successfully!${NC}"
    echo -e "${BLUE}[i] Total URLs Scanned: $TOTAL_SCANNED${NC}"
    echo -e "${BLUE}[i] Total Vulnerabilities Found: $TOTAL_VULNERABILITIES${NC}"
    echo -e "${BLUE}[i] Scan Duration: ${SCAN_DURATION} seconds${NC}"

    # Always ask to save results
    save_results

    echo ""
    echo -e "${PURPLE}[i] WPRecon scan finished. Stay secure!${NC}"
    echo -e "${BLUE}[i] Developed by MD Fahad Hosen - Ethical Hacker & Web Developer${NC}"
}

# Execute main function with all arguments
main "$@"