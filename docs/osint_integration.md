# OSINT & Threat Intelligence Integration Guide

Lotus provides comprehensive integration with popular OSINT (Open Source Intelligence) and threat intelligence tools, allowing you to build powerful reconnaissance and threat detection scripts.

## Table of Contents

- [Secrets Management](#secrets-management)
- [Quick Start](#quick-start)
- [Available Tool Integrations](#available-tool-integrations)
- [Core OSINT Functions](#core-osint-functions)
- [Tool-Specific APIs](#tool-specific-apis)
  - [BBOT](#bbot---recursive-osint-automation)
  - [Amass](#amass---subdomain-enumeration)
  - [SpiderFoot](#spiderfoot---automated-osint)
  - [FinalRecon](#finalrecon---web-reconnaissance)
  - [theHarvester](#theharvester---email--subdomain-discovery)
  - [Shodan](#shodan---internet-device-search)
  - [Nuclei](#nuclei---vulnerability-scanning)
  - [RITA](#rita---threat-detection)
  - [DNSMonster](#dnsmonster---dns-monitoring)
  - [Zeek](#zeek---network-analysis)
- [Building Custom OSINT Scripts](#building-custom-osint-scripts)
- [Example Scripts](#example-scripts)

---

## Secrets Management

Lotus provides a centralized secrets manager for API keys that automatically loads from environment variables and config files.

### Quick Setup

**Option 1: Environment Variables**
```bash
export SHODAN_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"
export GITHUB_TOKEN="your-token"
```

**Option 2: Config File** (`.lotus_secrets.json` in current dir or `~/.lotus_secrets.json`)
```json
{
    "shodan": "your-shodan-api-key",
    "virustotal": "your-virustotal-api-key",
    "github": "your-github-token",
    "abuseipdb": "your-abuseipdb-key"
}
```

**Option 3: KEY=VALUE File** (`.lotus_secrets`)
```
shodan=your-shodan-api-key
virustotal=your-virustotal-api-key
github=your-github-token
```

### Using Secrets in Scripts

```lua
-- Get a secret (returns nil if not found)
local shodan_key = get_secret("shodan")

-- Require a secret (throws error if not found)
local vt_key = require_secret("virustotal")

-- Check if secret exists
if has_secret("github") then
    println("GitHub token is configured")
end

-- Use the Secrets manager directly
local key = Secrets:get("shodan")
local key = Secrets:get_or("shodan", "default-value")
local key = Secrets:require("shodan")  -- errors if missing

-- See what's configured
local services = Secrets:configured_services()
for _, service in ipairs(services) do
    println("Configured: " .. service)
end

-- Load from custom file
Secrets:load_file("/path/to/custom_secrets.json")

-- Save current secrets
Secrets:save("/path/to/backup_secrets.json")
```

### Supported Environment Variables

The secrets manager automatically loads from these environment variables:

| Service | Environment Variables |
|---------|----------------------|
| Shodan | `SHODAN_API_KEY`, `SHODAN_KEY` |
| VirusTotal | `VIRUSTOTAL_API_KEY`, `VT_API_KEY` |
| SecurityTrails | `SECURITYTRAILS_API_KEY`, `ST_API_KEY` |
| Censys | `CENSYS_API_ID`, `CENSYS_API_SECRET` |
| Hunter.io | `HUNTER_API_KEY`, `HUNTERIO_API_KEY` |
| GitHub | `GITHUB_TOKEN`, `GH_TOKEN` |
| GitLab | `GITLAB_TOKEN` |
| AbuseIPDB | `ABUSEIPDB_API_KEY` |
| AlienVault OTX | `OTX_API_KEY`, `ALIENVAULT_API_KEY` |
| BinaryEdge | `BINARYEDGE_API_KEY` |
| Chaos (PD) | `CHAOS_API_KEY`, `PDCP_API_KEY` |
| Cloudflare | `CLOUDFLARE_API_KEY`, `CF_API_KEY` |
| PassiveTotal | `PASSIVETOTAL_API_KEY`, `RISKIQ_API_KEY` |
| URLScan | `URLSCAN_API_KEY` |
| WhoisXML | `WHOISXML_API_KEY` |
| ZoomEye | `ZOOMEYE_API_KEY` |
| Fofa | `FOFA_API_KEY`, `FOFA_EMAIL` |
| Netlas | `NETLAS_API_KEY` |
| FullHunt | `FULLHUNT_API_KEY` |
| Onyphe | `ONYPHE_API_KEY` |
| IntelX | `INTELX_API_KEY` |
| LeakIX | `LEAKIX_API_KEY` |
| SpiderFoot HX | `SPIDERFOOT_API_KEY` |
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| HuggingFace | `HF_TOKEN`, `HUGGINGFACE_TOKEN` |

### Example: Using Secrets with Tools

```lua
SCAN_TYPE = 1

function main()
    local domain = INPUT_DATA
    
    -- Check for required API keys
    if not has_secret("shodan") then
        log_warn("Shodan API key not configured, skipping Shodan lookups")
    end
    
    -- Use Shodan with API key
    if has_secret("shodan") then
        local shodan = Shodan
        shodan:init(get_secret("shodan"))
        local result = shodan:domain(domain)
        -- process results...
    end
    
    -- Use VirusTotal
    if has_secret("virustotal") then
        local vt_key = get_secret("virustotal")
        local resp = http:send{
            url = "https://www.virustotal.com/api/v3/domains/" .. domain,
            headers = {["x-apikey"] = vt_key}
        }
        -- process results...
    end
    
    -- Get API endpoint from config
    local endpoint = APIConfig:endpoint("shodan")  -- "https://api.shodan.io"
end
```

---

## Quick Start

### Basic Domain Reconnaissance

```lua
SCAN_TYPE = 1  -- HOSTS input

function main()
    local domain = INPUT_DATA
    
    -- DNS lookup
    local ips = dns_lookup(domain)
    for _, ip in ipairs(ips) do
        println("IP: " .. ip)
    end
    
    -- WHOIS lookup
    local whois_result = whois(domain)
    println(whois_result:stdout())
    
    -- Run Amass subdomain enumeration
    local amass = Amass
    local result = amass:enum{domain = domain, passive = true}
    println(result:stdout())
end
```

### Running the Script

```bash
echo "example.com" | lotus scan osint_script.lua
```

---

## Available Tool Integrations

| Tool | Purpose | Lua Client |
|------|---------|------------|
| **BBOT** | Recursive OSINT automation | `BBOT` |
| **Amass** | Subdomain enumeration | `Amass` |
| **SpiderFoot** | Automated OSINT collection | `SpiderFoot` |
| **FinalRecon** | Web reconnaissance | `FinalRecon` |
| **theHarvester** | Email/subdomain harvesting | `TheHarvester` |
| **Shodan** | Internet device search | `Shodan` |
| **Nuclei** | Vulnerability scanning | `Nuclei` |
| **Subfinder** | Fast subdomain discovery | `Subfinder` |
| **httpx** | HTTP probing | `Httpx` |
| **RITA** | C2/Beacon detection | `RITA` |
| **DNSMonster** | Passive DNS capture | `DNSMonster` |
| **Zeek** | Network traffic analysis | `Zeek` |

---

## Core OSINT Functions

### Shell Command Execution

```lua
-- Simple command
local result = exec("nmap -sV target.com")
println(result:stdout())

-- With options
local result = exec{
    cmd = "nmap",
    args = {"-sV", "-p", "1-1000", "target.com"},
    timeout = 300
}

-- Background execution (returns PID)
local pid = exec_bg("long_running_tool", {"--arg1", "value"})
```

### DNS Operations

```lua
-- Forward DNS lookup
local ips = dns_lookup("example.com")
for _, ip in ipairs(ips) do
    println(ip)
end

-- Reverse DNS
local hostname = reverse_dns("93.184.216.34")
println(hostname)

-- WHOIS lookup
local result = whois("example.com")
if result:success() then
    println(result:stdout())
end
```

### File Operations

```lua
-- Read JSON file
local data = read_json("/path/to/data.json")
println(data.key)

-- Write JSON file
write_json("/path/to/output.json", {
    target = "example.com",
    findings = {"sub1.example.com", "sub2.example.com"}
})

-- Append to file
append_file("/path/to/log.txt", "New finding: " .. finding)

-- Check file existence
if file_exists("/path/to/config.json") then
    local config = read_json("/path/to/config.json")
end

-- Create directory
mkdir("/tmp/osint_output")
```

### Environment & Utilities

```lua
-- Environment variables
local api_key = getenv("SHODAN_API_KEY")
setenv("MY_VAR", "value")

-- Timestamps
local ts = timestamp()  -- Unix timestamp

-- UUID generation
local id = uuid()  -- e.g., "550e8400-e29b-41d4-a716-446655440000"
```

---

## Tool-Specific APIs

### BBOT - Recursive OSINT Automation

BBOT chains together multiple OSINT tools for comprehensive reconnaissance.

```lua
local bbot = BBOT
-- bbot:set_path("/path/to/bbot")
-- bbot:set_config("~/.config/bbot/bbot.yml")

-- Subdomain enumeration
local result = bbot:subdomain_enum("example.com")

-- Web reconnaissance (basic or thorough)
local result = bbot:web_recon("example.com", true)  -- true = thorough

-- Cloud enumeration (find S3 buckets, etc.)
local result = bbot:cloud_enum("example.com")

-- Email enumeration
local result = bbot:email_enum("example.com")

-- Custom scan with specific modules
local result = bbot:run_modules("example.com", {"httpx", "nuclei", "secretsdb"})

-- Full custom scan
local result = bbot:scan{
    target = "example.com",
    preset = "web-thorough",      -- or modules = {"mod1", "mod2"}
    flags = {"safe", "passive"},
    output = "/tmp/bbot_output",
    format = "json",
    strict_scope = true
}

-- List available modules/presets
local modules = bbot:list_modules()
local presets = bbot:list_presets()
```

### Amass - Subdomain Enumeration

```lua
local amass = Amass
-- amass:set_path("/path/to/amass")
-- amass:set_config("/path/to/config.ini")

-- Passive enumeration
local result = amass:enum{
    domain = "example.com",
    passive = true,
    timeout = 60
}

-- Active enumeration
local result = amass:enum{
    domain = "example.com",
    passive = false,
    timeout = 120,
    output = "/tmp/amass_results.txt"
}

-- Intelligence gathering
local result = amass:intel{
    domain = "example.com",
    org = "Example Corp",
    asn = 12345,
    whois = true
}

-- Database operations
local result = amass:db{
    domain = "example.com",
    list = true,
    names = true
}
```

### SpiderFoot - Automated OSINT

```lua
local sf = SpiderFoot
-- sf:set_path("/path/to/spiderfoot")
-- sf:set_api("http://localhost:5001", "api_key")

-- Run scan with specific modules
local result = sf:scan("example.com", {
    "sfp_dnsresolve",
    "sfp_whois",
    "sfp_shodan",
    "sfp_virustotal"
})

-- Get available modules
local modules = sf:modules()

-- Get data types
local types = sf:types()
```

### FinalRecon - Web Reconnaissance

```lua
local fr = FinalRecon
-- fr:set_path("/path/to/finalrecon")
-- fr:set_output("/tmp/finalrecon_output")

-- Full scan
local result = fr:full("https://example.com")

-- Individual modules
local headers = fr:headers("https://example.com")
local ssl = fr:sslinfo("https://example.com")
local whois = fr:whois("https://example.com")
local dns = fr:dns("https://example.com")
local subdomains = fr:sub("https://example.com")
local crawl = fr:crawl("https://example.com")
local wayback = fr:wayback("https://example.com")

-- Directory enumeration with wordlist
local dirs = fr:dir("https://example.com", "/path/to/wordlist.txt")

-- Port scan
local ports = fr:ps("https://example.com", "1-1000")
```

### theHarvester - Email & Subdomain Discovery

```lua
local harvester = TheHarvester
-- harvester:set_path("/path/to/theHarvester")

-- Harvest emails and subdomains
local result = harvester:harvest{
    domain = "example.com",
    source = "all",      -- or specific: "google,bing,linkedin"
    limit = 500,
    output = "/tmp/harvest.html"
}

-- Parse results
for line in result:stdout():gmatch("[^\r\n]+") do
    if str(line):contains("@") then
        println("Email: " .. line)
    end
end
```

### Shodan - Internet Device Search

```lua
local shodan = Shodan
-- shodan:set_path("/path/to/shodan")

-- Initialize with API key
shodan:init("your-api-key")
-- Or use environment: SHODAN_API_KEY

-- Host lookup
local result = shodan:host("93.184.216.34")

-- Search query
local result = shodan:search("apache port:443 country:US")

-- Domain lookup
local result = shodan:domain("example.com")

-- Account info
local info = shodan:info()
```

### Nuclei - Vulnerability Scanning

```lua
local nuclei = Nuclei
-- nuclei:set_path("/path/to/nuclei")
-- nuclei:set_templates("/path/to/nuclei-templates")

-- Basic scan
local result = nuclei:scan{
    target = "https://example.com",
    severity = "medium,high,critical",
    tags = "cve,misconfig",
    rate_limit = 100
}

-- Parse JSONL output
for line in result:stdout():gmatch("[^\r\n]+") do
    local ok, finding = pcall(function() return json(line):value() end)
    if ok then
        println("[" .. finding.info.severity .. "] " .. finding.info.name)
    end
end

-- Update templates
nuclei:update()
```

### RITA - Threat Detection (C2/Beacon Analysis)

```lua
local rita = RITA
-- rita:set_path("/path/to/rita")
-- rita:set_config("/etc/rita/config.yaml")

-- Import Zeek logs
local result = rita:import{
    logs = "/path/to/zeek/logs",
    database = "network_analysis",
    rolling = true
}

-- Detect beacons (C2 communication)
local beacons = rita:show_beacons("network_analysis")

-- DNS beacon detection
local dns_beacons = rita:show_dns_beacons("network_analysis")

-- Long connections
local long_conns = rita:show_long_connections("network_analysis")

-- Port scan detection
local strobes = rita:show_strobes("network_analysis")

-- Blacklisted connections
local blacklist = rita:show_bl_hostnames("network_analysis")

-- User agents
local useragents = rita:show_useragents("network_analysis")

-- Generate HTML report
rita:html_report("network_analysis", "/tmp/rita_report")

-- List databases
local dbs = rita:list_databases()
```

### DNSMonster - DNS Monitoring

```lua
local dnsmon = DNSMonster
-- dnsmon:set_path("/path/to/dnsmonster")
-- dnsmon:set_config("/etc/dnsmonster/config.ini")

-- Capture from interface
local result = dnsmon:capture{
    interface = "eth0",
    output = "json",
    filter = "port 53",
    count = 1000
}

-- Analyze PCAP file
local result = dnsmon:analyze_pcap("/path/to/capture.pcap")
```

### Zeek - Network Analysis

```lua
local zeek = Zeek
-- zeek:set_path("/path/to/zeek")

-- Analyze PCAP file
local result = zeek:analyze{
    pcap = "/path/to/capture.pcap",
    scripts = {"local.zeek"},
    output_dir = "/tmp/zeek_logs"
}

-- Live capture
local result = zeek:capture("eth0")
```

---

## Building Custom OSINT Scripts

### Template: Comprehensive Domain Scanner

```lua
SCAN_TYPE = 1  -- HOSTS

local CONFIG = {
    output_dir = "/tmp/osint_results"
}

-- Check if tool is available
local function tool_available(name, test_cmd)
    local result = exec(test_cmd .. " --version 2>/dev/null || echo 'not found'")
    return result:success() and not str(result:stdout()):contains("not found")
end

function main()
    local target = INPUT_DATA
    mkdir(CONFIG.output_dir)
    
    local results = {
        target = target,
        timestamp = timestamp(),
        subdomains = {},
        emails = {},
        vulnerabilities = {}
    }
    
    -- Subdomain enumeration
    if tool_available("amass", "amass") then
        local amass = Amass
        local result = amass:enum{domain = target, passive = true}
        -- Parse results...
    end
    
    -- Email harvesting
    if tool_available("theHarvester", "theHarvester") then
        local harvester = TheHarvester
        local result = harvester:harvest{domain = target, source = "all"}
        -- Parse results...
    end
    
    -- Vulnerability scanning
    if tool_available("nuclei", "nuclei") then
        local nuclei = Nuclei
        local result = nuclei:scan{target = "https://" .. target}
        -- Parse results...
    end
    
    -- Save report
    write_json(CONFIG.output_dir .. "/" .. target .. "_report.json", results)
    
    -- Add to Lotus reports
    Reports:add{
        name = "OSINT Scan",
        target = target,
        findings = results
    }
end
```

### Working with OsintResult

All tool integrations return an `OsintResult` object:

```lua
local result = Amass:enum{domain = "example.com", passive = true}

-- Check success
if result:success() then
    -- Get stdout
    local output = result:stdout()
    
    -- Get stderr
    local errors = result:stderr()
    
    -- Get exit code
    local code = result:exit_code()
    
    -- Parse as JSON (if applicable)
    local data = result:json()
    
    -- Parse as lines
    local lines = result:lines()
    for _, line in ipairs(lines) do
        println(line)
    end
end
```

---

## Example Scripts

### Subdomain Discovery Pipeline

```bash
# Simple subdomain enumeration
echo "example.com" | lotus scan examples/amass_osint.lua

# Full BBOT scan
echo "example.com" | lotus scan examples/bbot_scanner.lua --env PRESET=full

# Web reconnaissance with FinalRecon
echo "https://example.com" | lotus scan examples/finalrecon_scanner.lua
```

### Threat Intelligence Workflow

```bash
# Comprehensive threat intel scan
echo "example.com" | lotus scan examples/threat_intel_scanner.lua

# With API keys
export SHODAN_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"
echo "example.com" | lotus scan examples/threat_intel_scanner.lua
```

### Batch Scanning

```bash
# Scan multiple domains
cat domains.txt | lotus scan examples/bbot_scanner.lua --workers 5

# With custom output
cat domains.txt | lotus scan examples/threat_intel_scanner.lua -o results.json
```

---

## Best Practices

1. **API Keys**: Store API keys in environment variables, not in scripts
2. **Rate Limiting**: Respect rate limits of third-party services
3. **Scope Control**: Always verify you have authorization to scan targets
4. **Output Management**: Use structured JSON output for post-processing
5. **Error Handling**: Use `pcall()` for operations that may fail
6. **Tool Availability**: Check if tools are installed before using them

```lua
-- Example: Safe tool usage
local function safe_scan(tool, method, ...)
    local status, result = pcall(function()
        return tool[method](tool, ...)
    end)
    
    if not status then
        log_error("Tool error: " .. tostring(result))
        return nil
    end
    
    return result
end
```

---

## Installing Required Tools

```bash
# BBOT
pip install bbot

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# theHarvester
pip install theHarvester

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Shodan CLI
pip install shodan

# FinalRecon
pip install finalrecon

# RITA
# See: https://github.com/activecm/rita

# Zeek
# See: https://zeek.org/get-zeek/
```
