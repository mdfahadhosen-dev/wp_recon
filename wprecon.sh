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
#   Professional security assessment tool for WordPress installations.
#   Performs reconnaissance and vulnerability detection with API integrations
#   for enhanced security analysis.
#
# Features:
#   - Comprehensive vulnerability scanning (30+ check types)
#   - WordPress version detection & CVE matching
#   - AI-powered exploitation analysis & proof-of-concept generation
#   - API integrations (Shodan, WPScan, Groq) for enhanced detection
#   - Batch processing with progress tracking
#   - Proxy support and rate limiting
#   - Custom timeouts, user-agents, and stealth options
#   - Multiple export formats (TXT, JSON, CSV)
#   - Configuration file support
#   - Professional error handling and logging
#   - Plugin and theme enumeration
#   - User discovery and vulnerability validation
#
# Requirements:
#   - curl (HTTP requests)
#   - bash 4.0+ (advanced features)
#   - jq (JSON parsing)
#   - bc (calculations)
#
# Usage:
#   See help: ./wprecon.sh --help
#
# Disclaimer:
#   For authorized security testing only. Use responsibly.
#
# =============================================================================

# =============================================================================
# Configuration Variables
# =============================================================================
SCRIPT_VERSION="2.3"
DEFAULT_TIMEOUT=10
DEFAULT_USER_AGENT="WPRecon/2.3 (WordPress Security Scanner)"
COLOR_ENABLED=true
CONFIG_FILE=".wprecon.conf"
EXPORT_FORMAT="txt"
STEALTH_MODE=false
RATE_LIMIT=0
MAX_CONCURRENT=1

# API Configuration (can be set via --setup flag)
SHODAN_API_KEY=""
WPSCAN_API_KEY=""
GROQ_API_KEY=""
USE_SHODAN=false
USE_WPSCAN=false
USE_GROQ=false

# =============================================================================
# Terminal Output Colors
# =============================================================================
if [[ "$COLOR_ENABLED" == true ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[1;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' WHITE='' NC=''
fi

# =============================================================================
# Global Variables
# =============================================================================
VERBOSE=false
TIMEOUT=$DEFAULT_TIMEOUT
OUTPUT_FILE=""
USER_AGENT="$DEFAULT_USER_AGENT"
PROXY=""
TOTAL_SCANNED=0
TOTAL_VULNERABILITIES=0
VULNERABLE_URLS=()
CURRENT_SCAN=0
VALIDATED_VULNERABILITIES=()
WP_VERSION=""
WP_VERSION_DETECTED=false
EXPLOIT_DB_RESULTS=()

# =============================================================================
# Function: display_banner
# =============================================================================
display_banner() {
    clear
    echo -e "${CYAN}"
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

# =============================================================================
# Function: show_help
# =============================================================================
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
    echo "  --groq-key KEY         Groq API key for vulnerability validation"
    echo "  --use-groq             Enable Groq AI for vulnerability exploitation validation"
    echo "  --format FORMAT        Export format: txt, json, csv (default: txt)"
    echo "  --stealth              Enable stealth mode with random delays"
    echo "  --rate-limit SEC       Delay between requests (default: 0)"
    echo "  --config FILE          Use custom configuration file (default: .wprecon.conf)"
    echo "  --setup                Interactive setup for API keys (Shodan, WPScan, Groq)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 -u https://example.com"
    echo "  $0 -f targets.txt -o results.txt -v"
    echo "  $0 -u https://example.com -p http://127.0.0.1:8080 -t 15"
    echo "  $0 --shodan-key YOUR_KEY --use-shodan -u https://example.com"
    echo "  $0 --wpscan-key YOUR_KEY --use-wpscan -f sites.txt"
    echo "  $0 --groq-key YOUR_KEY --use-groq -u https://example.com"
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
    echo "  Project: https://github.com/mdfahadhosen-dev/wp_recon"
    echo "  License: MIT License"
    echo ""
    echo "API REQUIREMENTS:"
    echo "  Shodan API: Get key from https://account.shodan.io/"
    echo "  WPScan API: Get key from https://wpscan.com/api"
    echo "  Groq API: Get key from https://console.groq.com/"
    echo "  All services offer free tiers for basic usage."
    exit 0
}

# =============================================================================
# Function: parse_arguments
# =============================================================================
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
            --groq-key)
                GROQ_API_KEY="$2"
                shift 2
                ;;
            --use-groq)
                USE_GROQ=true
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
            --setup)
                setup_api_keys
                exit 0
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

    if [[ "$USE_GROQ" == true && -z "$GROQ_API_KEY" ]]; then
        echo -e "${RED}[!] Error: Groq API key required when using --use-groq${NC}"
        echo "Get your API key from: https://console.groq.com/"
        exit 1
    fi

    # Load API keys from config file if not provided via CLI
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    fi
    
    # Prompt to save API keys if provided via CLI
    local keys_to_save=""
    if [[ -n "$SHODAN_API_KEY" ]]; then
        keys_to_save+="Shodan "
    fi
    if [[ -n "$WPSCAN_API_KEY" ]]; then
        keys_to_save+="WPScan "
    fi
    if [[ -n "$GROQ_API_KEY" ]]; then
        keys_to_save+="Groq "
    fi
    
    if [[ -n "$keys_to_save" ]]; then
        echo ""
        echo -e "${YELLOW}[?] API keys detected: ${keys_to_save}Do you want to save them for future use? (y/N): ${NC}"
        read -p "" -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cat > "$CONFIG_FILE" << EOF
# WPRecon Configuration File
# Generated on $(date)

# API Keys
SHODAN_API_KEY="$SHODAN_API_KEY"
WPSCAN_API_KEY="$WPSCAN_API_KEY"
GROQ_API_KEY="$GROQ_API_KEY"

# Enable by default
USE_SHODAN=$USE_SHODAN
USE_WPSCAN=$USE_WPSCAN
USE_GROQ=$USE_GROQ

# Default settings
DEFAULT_TIMEOUT=$DEFAULT_TIMEOUT
STEALTH_MODE=$STEALTH_MODE
RATE_LIMIT=$RATE_LIMIT
EOF
            echo -e "${GREEN}[+] API keys saved to $CONFIG_FILE${NC}"
        else
            echo -e "${YELLOW}[i] API keys will not be saved.${NC}"
        fi
    fi
}

# =============================================================================
# Function: setup_api_keys
# =============================================================================
setup_api_keys() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}   WPRecon API Keys Setup${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    
    # Shodan API Key
    echo -e "${YELLOW}[1] Shodan API Key${NC}"
    echo "   Get free key: https://account.shodan.io/"
    read -p "   Enter Shodan API key (or press Enter to skip): " shodan_key
    
    # WPScan API Key
    echo ""
    echo -e "${YELLOW}[2] WPScan API Key${NC}"
    echo "   Get free key: https://wpscan.com/api"
    read -p "   Enter WPScan API key (or press Enter to skip): " wpscan_key
    
    # Groq API Key
    echo ""
    echo -e "${YELLOW}[3] Groq API Key${NC}"
    echo "   Get free key: https://console.groq.com/"
    read -p "   Enter Groq API key (or press Enter to skip): " groq_key
    
    # Save to config file
    echo ""
    echo -e "${BLUE}[*] Saving configuration to $CONFIG_FILE...${NC}"
    
    cat > "$CONFIG_FILE" << EOF
# WPRecon Configuration File
# Generated on $(date)

# API Keys
SHODAN_API_KEY="$shodan_key"
WPSCAN_API_KEY="$wpscan_key"
GROQ_API_KEY="$groq_key"

# Enable by default
USE_SHODAN=false
USE_WPSCAN=false
USE_GROQ=false

# Default settings
DEFAULT_TIMEOUT=10
STEALTH_MODE=false
RATE_LIMIT=0
EOF
    
    echo -e "${GREEN}[+] Configuration saved successfully!${NC}"
    echo ""
    echo "To use API integrations, run:"
    echo "  wprecon -u TARGET --use-shodan    # Enable Shodan"
    echo "  wprecon -u TARGET --use-wpscan    # Enable WPScan"
    echo "  wprecon -u TARGET --use-groq      # Enable Groq AI"
    echo ""
    echo "Or enable all at once:"
    echo "  wprecon -u TARGET --use-shodan --use-wpscan --use-groq"
}

# =============================================================================
# Function: is_valid_url
# =============================================================================
is_valid_url() {
    local url="$1"
    # Basic regex check for http:// or https://
    if [[ $url =~ ^https?:// ]]; then
        return 0
    else
        return 1
    fi
}

# =============================================================================
# Function: http_request
# =============================================================================
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

# =============================================================================
# Function: load_config
# =============================================================================
load_config() {
    local config_file="$1"
    if [[ -f "$config_file" ]]; then
        echo -e "${BLUE}[i] Loading configuration from $config_file...${NC}"
        source "$config_file"
    fi
}

# =============================================================================
# Function: random_delay
# =============================================================================
random_delay() {
    if [[ "$STEALTH_MODE" == true ]]; then
        local delay=$((RANDOM % 5 + 1))
        sleep $delay
    elif [[ $RATE_LIMIT -gt 0 ]]; then
        sleep $RATE_LIMIT
    fi
}

# =============================================================================
# Function: check_plugin_enumeration
# =============================================================================
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

# =============================================================================
# Function: check_user_enumeration
# =============================================================================
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

# =============================================================================
# Function: detect_wordpress_version
# =============================================================================
detect_wordpress_version() {
    local url="$1"
    WP_VERSION=""
    WP_VERSION_DETECTED=false
    
    echo -e "${BLUE}[*] Detecting WordPress version...${NC}"
    
    # Check readme.html
    local readme_response
    readme_response=$(http_request "${url}/readme.html")
    if echo "$readme_response" | grep -qi "version"; then
        WP_VERSION=$(echo "$readme_response" | grep -oP 'Version\s+\K[0-9.]+' | head -1)
    fi
    
    # Check generator meta tag
    if [[ -z "$WP_VERSION" ]]; then
        local index_response
        index_response=$(http_request "$url")
        WP_VERSION=$(echo "$index_response" | grep -oP 'wordpress\s+\K[0-9.]+' | head -1)
    fi
    
    # Check feed
    if [[ -z "$WP_VERSION" ]]; then
        local feed_response
        feed_response=$(http_request "${url}/feed/")
        WP_VERSION=$(echo "$feed_response" | grep -oP 'wordpress\s+\K[0-9.]+' | head -1)
    fi
    
    if [[ -n "$WP_VERSION" ]]; then
        WP_VERSION_DETECTED=true
        echo -e "${GREEN}[+] WordPress version detected: $WP_VERSION${NC}"
        
        # Query for known CVEs if WPScan or Groq enabled
        if [[ "$USE_WPSCAN" == true || "$USE_GROQ" == true ]]; then
            check_cve_database "$url" "$WP_VERSION"
        fi
    else
        echo -e "${YELLOW}[!] Could not detect WordPress version${NC}"
    fi
}

# =============================================================================
# Function: check_cve_database
# =============================================================================
check_cve_database() {
    local url="$1"
    local version="$2"
    
    echo -e "${BLUE}[*] Checking CVE database for WordPress $version...${NC}"
    
    if [[ "$USE_GROQ" == true ]]; then
        # Use Groq AI to find relevant CVEs and exploits
        local cve_prompt="You are a cybersecurity expert. Find known CVEs and exploits for WordPress version $version.

Provide a JSON response:
{
  \"cves\": [{\"id\": \"CVE-XXXX-XXXX\", \"severity\": \"critical/high/medium/low\", \"description\": \"brief\"}],
  \"known_exploits\": [{\"type\": \"RCE/SQLi/XSS\", \"description\": \"brief\"}],
  \"recommended_exploits\": [\"command to test\"]
}

Respond only with valid JSON."
        
        local cve_response
        cve_response=$(curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
            -H "Authorization: Bearer $GROQ_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"model\": \"llama-3.1-70b-versatile\",
                \"messages\": [
                    {\"role\": \"system\", \"content\": \"You are a cybersecurity vulnerability expert.\"},
                    {\"role\": \"user\", \"content\": \"$cve_prompt\"}
                ],
                \"temperature\": 0.3,
                \"max_tokens\": 800
            }")
        
        local ai_content
        ai_content=$(echo "$cve_response" | jq -r '.choices[0].message.content' 2>/dev/null)
        
        if [[ -n "$ai_content" && "$ai_content" != "null" ]]; then
            ai_content=$(echo "$ai_content" | tr -d '\n\r' | sed 's/[[:space:]]\+/ /g')
            
            local cves exploits
            cves=$(echo "$ai_content" | sed -n 's/.*"cves": *\[\(.*\)\].*/\1/p')
            exploits=$(echo "$ai_content" | sed -n 's/.*"known_exploits": *\[\(.*\)\].*/\1/p')
            
            echo -e "${CYAN}[+] CVE Database Results for WP $version:${NC}"
            echo -e "  ${WHITE}CVEs Found:${NC} $cves"
            echo -e "  ${WHITE}Known Exploits:${NC} $exploits"
            
            # Store for export
            EXPLOIT_DB_RESULTS+=("$url|WP $version|$cves|$exploits")
            
            # Show severity warnings
            if echo "$ai_content" | grep -q "critical"; then
                echo -e "${RED}[!] CRITICAL vulnerabilities found for WordPress $version!${NC}"
            elif echo "$ai_content" | grep -q "high"; then
                echo -e "${YELLOW}[!] HIGH severity vulnerabilities found for WordPress $version${NC}"
            fi
        fi
    fi
}

# =============================================================================
# Function: check_backup_files
# =============================================================================
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

# =============================================================================
# Function: shodan_lookup
# =============================================================================
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

# =============================================================================
# Function: wpscan_api_check
# =============================================================================
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

# =============================================================================
# Function: check_vulnerability
# =============================================================================
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

# =============================================================================
# Function: scan_url
# =============================================================================
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

    # Execute vulnerability checks
    local vuln_results=""
    
    check_vulnerability "$url" "Setup Config Exposure" "/wp-admin/setup-config.php?step=1" "Database Name"
    [[ $? -eq 1 ]] && vuln_results+="Setup Config Exposure;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "XML-RPC API Exposure" "/xmlrpc.php" "XML-RPC server accepts POST requests only"
    [[ $? -eq 1 ]] && vuln_results+="XML-RPC API;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "WP-JSON API Exposure" "/wp-json/wp/v2/users" '"id":'
    [[ $? -eq 1 ]] && vuln_results+="WP-JSON API;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Readme Version Disclosure" "/readme.html" "Version [0-9]"
    [[ $? -eq 1 ]] && vuln_results+="Readme Disclosure;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Admin Login Page Exposure" "/wp-admin/" "Username"
    [[ $? -eq 1 ]] && vuln_results+="Admin Exposure;" && ((vulnerabilities_found++))

    # Additional vulnerability checks
    check_vulnerability "$url" "wp-config.php Direct Access" "/wp-config.php" "DB_NAME"
    [[ $? -eq 1 ]] && vuln_results+="wp-config Exposure;" && ((vulnerabilities_found++))

    check_vulnerability "$url" ".htaccess Exposure" "/.htaccess" "RewriteEngine"
    [[ $? -eq 1 ]] && vuln_results+="htaccess Exposure;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Debug Log Exposure" "/wp-content/debug.log" "PHP Fatal"
    [[ $? -eq 1 ]] && vuln_results+="Debug Log;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Database Backup Exposure" "/wp-content/backup.sql" "CREATE TABLE"
    [[ $? -eq 1 ]] && vuln_results+="DB Backup;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "PHPinfo Exposure" "/phpinfo.php" "PHP Version"
    [[ $? -eq 1 ]] && vuln_results+="PHPinfo;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "License File Exposure" "/license.txt" "WordPress"
    [[ $? -eq 1 ]] && vuln_results+="License File;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "XML Sitemap Exposure" "/sitemap.xml" "<urlset"
    [[ $? -eq 1 ]] && vuln_results+="Sitemap;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "RSS Feed Exposure" "/feed/" "<rss"
    [[ $? -eq 1 ]] && vuln_results+="RSS Feed;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "WordPress Cron Exposure" "/wp-cron.php" "XML-RPC"
    [[ $? -eq 1 ]] && vuln_results+="WP-Cron;" && ((vulnerabilities_found++))

    # Extended vulnerability checks
    check_vulnerability "$url" "SQL Error Exposure" "/wp-admin/admin-ajax.php" "SQL syntax"
    [[ $? -eq 1 ]] && vuln_results+="SQL Error;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Git Metadata Exposure" "/.git/config" "repository"
    [[ $? -eq 1 ]] && vuln_results+="Git Metadata;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "SVN Metadata Exposure" "/.svn/entries" "svn"
    [[ $? -eq 1 ]] && vuln_results+="SVN Metadata;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "DS_Store Exposure" "/.DS_Store" "Apple"
    [[ $? -eq 1 ]] && vuln_results+="DS_Store;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "WordPress Install Exposure" "/wp-admin/install.php" "installing WordPress"
    [[ $? -eq 1 ]] && vuln_results+="Install Exposure;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Plugin Directory Listing" "/wp-content/plugins/" "Index of"
    [[ $? -eq 1 ]] && vuln_results+="Plugin Listing;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Theme Directory Listing" "/wp-content/themes/" "Index of"
    [[ $? -eq 1 ]] && vuln_results+="Theme Listing;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Upload Directory Exposure" "/wp-content/uploads/" "Index of"
    [[ $? -eq 1 ]] && vuln_results+="Upload Listing;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "XMLRPC PingBack" "/xmlrpc.php" "pingback"
    [[ $? -eq 1 ]] && vuln_results+="XMLRPC PingBack;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "REST API User Enumeration" "/wp-json/wp/v2/users" "slug"
    [[ $? -eq 1 ]] && vuln_results+="REST User Enum;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Author Archive Exposure" "/?author=1" "author archive"
    [[ $? -eq 1 ]] && vuln_results+="Author Archive;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "XML Sitemap Info Disclosure" "/sitemap.xml" "wp-schema"
    [[ $? -eq 1 ]] && vuln_results+="Sitemap Info;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "PHP Error Exposure" "/wp-content/debug.log" "Warning"
    [[ $? -eq 1 ]] && vuln_results+="PHP Errors;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "Backup Archive Exposure" "/*.zip" "PK"
    [[ $? -eq 1 ]] && vuln_results+="Zip Backup;" && ((vulnerabilities_found++))

    check_vulnerability "$url" "SQL Dump Exposure" "/*.sql" "MySQL"
    [[ $? -eq 1 ]] && vuln_results+="SQL Dump;" && ((vulnerabilities_found++))

    # Detect WordPress version
    detect_wordpress_version "$url"

    # Advanced checks
    check_plugin_enumeration "$url"
    check_user_enumeration "$url"
    check_backup_files "$url"

    # Validate vulnerabilities with Groq AI if enabled (includes exploitation analysis)
    if [[ "$USE_GROQ" == true && -n "$vuln_results" ]]; then
        validate_vulnerability "$url" "$vuln_results"
    fi

    # Record vulnerable URLs
    if [[ $vulnerabilities_found -gt 0 ]]; then
        VULNERABLE_URLS+=("$url ($vulnerabilities_found vulnerabilities)")
    fi

    # Update global counters
    ((TOTAL_SCANNED++))
    ((TOTAL_VULNERABILITIES += vulnerabilities_found))
}

# =============================================================================
# Function: validate_vulnerability
# =============================================================================
validate_vulnerability() {
    local target_url="$1"
    local vuln_types="$2"
    local wp_ver="${WP_VERSION:-unknown}"
    
    echo -e "${BLUE}[*] Running AI exploitation analysis...${NC}"
    
    local prompt="You are a cybersecurity exploit developer. Analyze this WordPress target:

Target: $target_url
WordPress Version: $wp_ver
Vulnerability Types: $vuln_types

Provide JSON with:
{
  \"is_exploitable\": true/false,
  \"severity\": \"critical/high/medium/low\",
  \"cvss_score\": \"0.0-10.0\",
  \"exploitation_steps\": \"detailed steps\",
  \"poc_command\": \"test command\",
  \"remediation\": \"fix\",
  \"cve_ids\": [\"CVE-XXXX\"],
  \"impact\": \"attacker achieve\"
}

Respond ONLY with valid JSON."
    
    local response
    response=$(curl -s -X POST "https://api.groq.com/openai/v1/chat/completions" \
        -H "Authorization: Bearer $GROQ_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"llama-3.1-70b-versatile\",
            \"messages\": [
                {\"role\": \"system\", \"content\": \"You are a cybersecurity expert specializing in vulnerability assessment.\"},
                {\"role\": \"user\", \"content\": \"$prompt\"}
            ],
            \"temperature\": 0.3,
            \"max_tokens\": 500
        }")
    
    # Extract the content from the response
    local ai_content
    ai_content=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)
    
    if [[ -n "$ai_content" && "$ai_content" != "null" ]]; then
        # Clean the response - remove newlines and extra spaces
        ai_content=$(echo "$ai_content" | tr -d '\n\r' | sed 's/[[:space:]]\+/ /g')
        
        # Extract values using sed
        local is_exploitable
        local severity
        local steps
        local fix
        
        is_exploitable=$(echo "$ai_content" | sed -n 's/.*"is_exploitable": *\([^,}]*\).*/\1/p' | tr -d ' ')
        severity=$(echo "$ai_content" | sed -n 's/.*"severity": *"\([^"]*\)".*/\1/p')
        cvss=$(echo "$ai_content" | sed -n 's/.*"cvss_score": *"\([^"]*\)".*/\1/p')
        steps=$(echo "$ai_content" | sed -n 's/.*"exploitation_steps": *"\([^"]*\)".*/\1/p')
        poc=$(echo "$ai_content" | sed -n 's/.*"poc_command": *"\([^"]*\)".*/\1/p')
        cve_ids=$(echo "$ai_content" | sed -n 's/.*"cve_ids": *\[\([^]]*\)\].*/\1/p')
        impact=$(echo "$ai_content" | sed -n 's/.*"impact": *"\([^"]*\)".*/\1/p')
        fix=$(echo "$ai_content" | sed -n 's/.*"remediation": *"\([^"]*\)".*/\1/p')
        
        if [[ -n "$is_exploitable" && -n "$severity" ]]; then
            echo -e "${CYAN}[+] AI Exploitation Analysis:${NC}"
            echo -e "  ${WHITE}Exploitable:${NC} $is_exploitable"
            echo -e "  ${WHITE}Severity:${NC} $severity"
            [[ -n "$cvss" ]] && echo -e "  ${WHITE}CVSS Score:${NC} $cvss"
            [[ -n "$cve_ids" ]] && echo -e "  ${WHITE}CVE IDs:${NC} $cve_ids"
            echo -e "  ${WHITE}Impact:${NC} $impact"
            echo -e "  ${WHITE}Exploitation:${NC} $steps"
            [[ -n "$poc" ]] && echo -e "  ${WHITE}PoC Command:${NC} $poc"
            echo -e "  ${WHITE}Remediation:${NC} $fix"
            
            # Store validated result
            VALIDATED_VULNERABILITIES+=("$target_url|$vuln_types|$is_exploitable|$severity|$cvss|$cve_ids")
            
            if [[ "$is_exploitable" == "true" ]]; then
                echo -e "${GREEN}[!] EXPLOITABLE: Can be exploited!${NC}"
            else
                echo -e "${YELLOW}[!] Not currently exploitable${NC}"
            fi
        else
            echo -e "${YELLOW}[!] AI response parsing failed${NC}"
        fi
    else
        echo -e "${YELLOW}[!] AI analysis failed${NC}"
    fi
}

# =============================================================================
# Function: scan_from_file
# =============================================================================
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

# =============================================================================
# Function: export_json
# =============================================================================
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

    # Add validated vulnerabilities if available
    if [[ ${#VALIDATED_VULNERABILITIES[@]} -gt 0 ]]; then
        json_data="${json_data},\n  \"validated_vulnerabilities\": ["
        first=true
        for vuln in "${VALIDATED_VULNERABILITIES[@]}"; do
            local url vuln_types is_exp severity
            IFS='|' read -r url vuln_types is_exp severity <<< "$vuln"
            if [[ $first == true ]]; then
                json_data="${json_data}\n    {\"url\": \"$url\", \"types\": \"$vuln_types\", \"exploitable\": \"$is_exp\", \"severity\": \"$severity\"}"
                first=false
            else
                json_data="${json_data},\n    {\"url\": \"$url\", \"types\": \"$vuln_types\", \"exploitable\": \"$is_exp\", \"severity\": \"$severity\"}"
            fi
        done
        json_data="${json_data}\n  ]"
    fi

    json_data="${json_data}\n}"

    echo -e "$json_data" > "$output_file"
}

# =============================================================================
# Function: export_csv
# =============================================================================
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

# =============================================================================
# Function: save_results
# =============================================================================
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
                    if [[ "$USE_GROQ" == true ]]; then
                        echo "  Groq AI Validation: Enabled"
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

# =============================================================================
# Function: handle_interrupt
# =============================================================================
handle_interrupt() {
    echo -e "\n${RED}[!] Scan interrupted by user. Exiting...${NC}"
    # Save partial results if any vulnerabilities found
    if [[ ${#VULNERABLE_URLS[@]} -gt 0 ]]; then
        save_results
    fi
    exit 1
}

# =============================================================================
# Function: main
# =============================================================================
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
    
    if [[ "$USE_GROQ" == true && ${#VALIDATED_VULNERABILITIES[@]} -gt 0 ]]; then
        echo -e "${GREEN}[i] Validated Exploitable Vulnerabilities: ${#VALIDATED_VULNERABILITIES[@]}${NC}"
    fi
    
    echo -e "${BLUE}[i] Scan Duration: ${SCAN_DURATION} seconds${NC}"

    # Always ask to save results
    save_results

    echo ""
    echo -e "${PURPLE}[i] WPRecon scan finished. Stay secure!${NC}"
    echo -e "${BLUE}[i] Developed by MD Fahad Hosen - Ethical Hacker & Web Developer${NC}"
}

# Execute main function with all arguments
main "$@"