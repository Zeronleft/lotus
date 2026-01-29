-- Comprehensive Threat Intelligence Scanner
-- Combines multiple OSINT tools for thorough reconnaissance and threat detection
--
-- Integrates: Amass, SpiderFoot, FinalRecon, Shodan, TheHarvester, Nuclei, RITA
--
-- Prerequisites:
--   Install desired tools (script will skip unavailable tools)
--
-- Usage:
--   echo "example.com" | lotus scan threat_intel_scanner.lua
--   echo "example.com" | lotus scan threat_intel_scanner.lua --env FULL_SCAN=true

SCAN_TYPE = 1  -- HOSTS input type

-- ============================================================================
-- Configuration
-- ============================================================================

local CONFIG = {
    output_dir = "/tmp/lotus_threat_intel",
    
    -- Enable/disable specific tools
    tools = {
        amass = true,
        spiderfoot = false,  -- Can be slow, disable by default
        finalrecon = true,
        shodan = true,       -- Requires API key
        theharvester = true,
        nuclei = true,
        dnsmonster = false,  -- Requires packet capture
        rita = false         -- Requires Zeek logs
    },
    
    -- Scan intensity: "passive", "normal", "aggressive"
    intensity = "normal",
    
    -- Timeouts (seconds)
    timeouts = {
        passive = 60,
        normal = 300,
        aggressive = 600
    },
    
    -- Shodan API key (can also use SHODAN_API_KEY env var)
    shodan_api_key = nil
}

-- ============================================================================
-- Tool availability checker
-- ============================================================================

local function check_tool(name, test_cmd)
    local result = exec(test_cmd .. " --version 2>/dev/null || " .. test_cmd .. " -h 2>/dev/null || echo 'not found'")
    local available = result:success() and not str(result:stdout()):contains("not found")
    if available then
        println("[+] " .. name .. " is available")
    else
        println("[-] " .. name .. " is not available, skipping...")
    end
    return available
end

local function check_available_tools()
    println("\n[*] Checking available tools...")
    local available = {}
    
    available.amass = CONFIG.tools.amass and check_tool("Amass", "amass")
    available.finalrecon = CONFIG.tools.finalrecon and check_tool("FinalRecon", "finalrecon")
    available.shodan = CONFIG.tools.shodan and check_tool("Shodan CLI", "shodan")
    available.theharvester = CONFIG.tools.theharvester and check_tool("theHarvester", "theHarvester")
    available.nuclei = CONFIG.tools.nuclei and check_tool("Nuclei", "nuclei")
    available.spiderfoot = CONFIG.tools.spiderfoot and check_tool("SpiderFoot", "spiderfoot")
    
    return available
end

-- ============================================================================
-- Subdomain Enumeration Module
-- ============================================================================

local function enumerate_subdomains(domain, tools_available)
    println("\n" .. string.rep("-", 60))
    println("[*] SUBDOMAIN ENUMERATION")
    println(string.rep("-", 60))
    
    local all_subdomains = {}
    
    -- Amass passive enumeration
    if tools_available.amass then
        println("[*] Running Amass passive enumeration...")
        local amass = Amass
        local result = amass:enum{
            domain = domain,
            passive = true,
            timeout = CONFIG.timeouts[CONFIG.intensity]
        }
        
        for line in result:stdout():gmatch("[^\r\n]+") do
            if str(line):contains(domain) then
                local subdomain = str(line):trim():value()
                if subdomain ~= "" then
                    all_subdomains[subdomain] = { source = "amass" }
                end
            end
        end
        println("[+] Amass found " .. count_table(all_subdomains) .. " subdomains")
    end
    
    -- theHarvester
    if tools_available.theharvester then
        println("[*] Running theHarvester...")
        local harvester = TheHarvester
        local result = harvester:harvest{
            domain = domain,
            source = "all",
            limit = 500
        }
        
        for line in result:stdout():gmatch("[^\r\n]+") do
            if str(line):contains(domain) and not str(line):contains("@") then
                local subdomain = str(line):trim():value()
                if subdomain ~= "" and not all_subdomains[subdomain] then
                    all_subdomains[subdomain] = { source = "theHarvester" }
                end
            end
        end
        println("[+] Total unique subdomains: " .. count_table(all_subdomains))
    end
    
    -- Certificate Transparency
    println("[*] Checking Certificate Transparency logs...")
    local ct_url = "https://crt.sh/?q=%25." .. domain .. "&output=json"
    local status, resp = pcall(function()
        return http:send{url = ct_url, timeout = 30}
    end)
    
    if status and resp:status_ok() then
        local ok, ct_data = pcall(function()
            return resp:json()
        end)
        if ok and ct_data then
            for _, cert in ipairs(ct_data) do
                local name = cert.name_value or cert.common_name
                if name and str(name):contains(domain) and not all_subdomains[name] then
                    all_subdomains[name] = { source = "crt.sh" }
                end
            end
        end
    end
    println("[+] Total unique subdomains after CT: " .. count_table(all_subdomains))
    
    return all_subdomains
end

-- ============================================================================
-- Infrastructure Discovery Module
-- ============================================================================

local function discover_infrastructure(domain, subdomains, tools_available)
    println("\n" .. string.rep("-", 60))
    println("[*] INFRASTRUCTURE DISCOVERY")
    println(string.rep("-", 60))
    
    local infrastructure = {
        ips = {},
        ports = {},
        services = {},
        technologies = {}
    }
    
    -- DNS resolution for all subdomains
    println("[*] Resolving DNS for discovered subdomains...")
    for subdomain, data in pairs(subdomains) do
        local ips = dns_lookup(subdomain)
        if ips and #ips > 0 then
            for _, ip in ipairs(ips) do
                if not infrastructure.ips[ip] then
                    infrastructure.ips[ip] = { hostnames = {} }
                end
                table.insert(infrastructure.ips[ip].hostnames, subdomain)
            end
        end
    end
    println("[+] Discovered " .. count_table(infrastructure.ips) .. " unique IP addresses")
    
    -- Shodan lookup for discovered IPs
    if tools_available.shodan then
        println("[*] Querying Shodan for IP intelligence...")
        local shodan = Shodan
        
        -- Initialize with API key if available
        local api_key = CONFIG.shodan_api_key or getenv("SHODAN_API_KEY")
        if api_key then
            shodan:init(api_key)
        end
        
        local count = 0
        for ip, data in pairs(infrastructure.ips) do
            if count >= 10 then  -- Limit to avoid rate limits
                println("[*] Shodan lookup limited to 10 IPs")
                break
            end
            
            local result = shodan:host(ip)
            if result:success() then
                local output = result:stdout()
                
                -- Parse ports
                for port in output:gmatch("(%d+)/tcp") do
                    infrastructure.ports[ip .. ":" .. port] = true
                end
                
                -- Parse organization
                local org = str(output):find("Organization:[^\n]*")
                if org then
                    data.organization = org:value()
                end
            end
            count = count + 1
        end
    end
    
    return infrastructure
end

-- ============================================================================
-- Email Harvesting Module
-- ============================================================================

local function harvest_emails(domain, tools_available)
    println("\n" .. string.rep("-", 60))
    println("[*] EMAIL HARVESTING")
    println(string.rep("-", 60))
    
    local emails = {}
    
    -- theHarvester for emails
    if tools_available.theharvester then
        println("[*] Harvesting emails with theHarvester...")
        local harvester = TheHarvester
        local result = harvester:harvest{
            domain = domain,
            source = "all",
            limit = 500
        }
        
        for line in result:stdout():gmatch("[^\r\n]+") do
            if str(line):contains("@") and str(line):contains(domain) then
                local email = str(line):trim():value()
                emails[email] = { source = "theHarvester" }
            end
        end
    end
    
    -- Check for email patterns on website
    println("[*] Checking website for email addresses...")
    local url = "https://" .. domain
    local status, resp = pcall(function()
        return http:send{url = url, timeout = 10}
    end)
    
    if status and resp:status_ok() then
        local body = resp.body
        -- Simple email regex
        for email in body:gmatch("[%w%.%-_]+@[%w%.%-]+%.[%w]+") do
            if str(email):contains(domain) and not emails[email] then
                emails[email] = { source = "website" }
            end
        end
    end
    
    println("[+] Found " .. count_table(emails) .. " email addresses")
    
    return emails
end

-- ============================================================================
-- Vulnerability Scanning Module
-- ============================================================================

local function scan_vulnerabilities(domain, subdomains, tools_available)
    println("\n" .. string.rep("-", 60))
    println("[*] VULNERABILITY SCANNING")
    println(string.rep("-", 60))
    
    local vulnerabilities = {}
    
    if tools_available.nuclei then
        println("[*] Running Nuclei vulnerability scanner...")
        local nuclei = Nuclei
        
        -- Create target list
        local targets = { "https://" .. domain }
        local count = 0
        for subdomain, _ in pairs(subdomains) do
            if count < 10 then  -- Limit targets
                table.insert(targets, "https://" .. subdomain)
                count = count + 1
            end
        end
        
        -- Scan main domain first
        local result = nuclei:scan{
            target = "https://" .. domain,
            severity = "low,medium,high,critical",
            rate_limit = 50
        }
        
        if result:success() then
            for line in result:stdout():gmatch("[^\r\n]+") do
                if str(line):startswith("{") then
                    local ok, finding = pcall(function()
                        return json(line):value()
                    end)
                    if ok and finding then
                        table.insert(vulnerabilities, finding)
                        local severity = finding.info and finding.info.severity or "unknown"
                        local name = finding.info and finding.info.name or finding["template-id"]
                        println("[!] " .. string.upper(severity) .. ": " .. name)
                    end
                end
            end
        end
    end
    
    -- Manual security checks
    println("[*] Running manual security checks...")
    
    -- Check for common security issues
    local checks = {
        { path = "/.git/config", name = "Git repository exposed" },
        { path = "/.env", name = "Environment file exposed" },
        { path = "/robots.txt", name = "Robots.txt (informational)" },
        { path = "/sitemap.xml", name = "Sitemap (informational)" },
        { path = "/.well-known/security.txt", name = "Security.txt present" },
        { path = "/wp-login.php", name = "WordPress detected" },
        { path = "/admin", name = "Admin panel" },
        { path = "/phpmyadmin", name = "phpMyAdmin" }
    }
    
    for _, check in ipairs(checks) do
        local url = "https://" .. domain .. check.path
        local status, resp = pcall(function()
            return http:send{url = url, timeout = 5, redirect = 0}
        end)
        
        if status and resp.status == 200 then
            table.insert(vulnerabilities, {
                type = "exposure",
                name = check.name,
                url = url,
                severity = str(check.name):contains("exposed") and "high" or "info"
            })
            if str(check.name):contains("exposed") then
                println("[!] HIGH: " .. check.name .. " at " .. check.path)
            else
                println("[*] INFO: " .. check.name .. " at " .. check.path)
            end
        end
    end
    
    return vulnerabilities
end

-- ============================================================================
-- Threat Intelligence Correlation
-- ============================================================================

local function correlate_threat_intel(domain, infrastructure)
    println("\n" .. string.rep("-", 60))
    println("[*] THREAT INTELLIGENCE CORRELATION")
    println(string.rep("-", 60))
    
    local threats = {
        malicious_ips = {},
        blacklisted_domains = {},
        indicators = {}
    }
    
    -- Check IPs against threat feeds (using free APIs)
    println("[*] Checking IPs against threat intelligence feeds...")
    
    for ip, data in pairs(infrastructure.ips) do
        -- AbuseIPDB check (requires API key)
        local abuse_key = getenv("ABUSEIPDB_API_KEY")
        if abuse_key then
            local abuse_url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" .. ip
            local status, resp = pcall(function()
                return http:send{
                    url = abuse_url,
                    headers = { ["Key"] = abuse_key, ["Accept"] = "application/json" },
                    timeout = 10
                }
            end)
            
            if status and resp:status_ok() then
                local ok, result = pcall(function() return resp:json() end)
                if ok and result and result.data then
                    local score = result.data.abuseConfidenceScore or 0
                    if score > 50 then
                        threats.malicious_ips[ip] = {
                            score = score,
                            reports = result.data.totalReports
                        }
                        println("[!] THREAT: IP " .. ip .. " has abuse score of " .. score)
                    end
                end
            end
        end
    end
    
    -- Check domain reputation
    println("[*] Checking domain reputation...")
    
    -- VirusTotal (requires API key)
    local vt_key = getenv("VIRUSTOTAL_API_KEY")
    if vt_key then
        local vt_url = "https://www.virustotal.com/api/v3/domains/" .. domain
        local status, resp = pcall(function()
            return http:send{
                url = vt_url,
                headers = { ["x-apikey"] = vt_key },
                timeout = 10
            }
        end)
        
        if status and resp:status_ok() then
            local ok, result = pcall(function() return resp:json() end)
            if ok and result and result.data then
                local stats = result.data.attributes.last_analysis_stats
                if stats and stats.malicious > 0 then
                    threats.blacklisted_domains[domain] = {
                        malicious = stats.malicious,
                        suspicious = stats.suspicious
                    }
                    println("[!] THREAT: Domain flagged by " .. stats.malicious .. " engines")
                else
                    println("[+] Domain reputation: Clean")
                end
            end
        end
    else
        println("[*] Set VIRUSTOTAL_API_KEY for domain reputation checks")
    end
    
    return threats
end

-- ============================================================================
-- Report Generation
-- ============================================================================

local function generate_report(domain, results)
    println("\n" .. string.rep("-", 60))
    println("[*] GENERATING REPORT")
    println(string.rep("-", 60))
    
    local report = {
        target = domain,
        timestamp = timestamp(),
        scan_id = uuid(),
        scan_type = "threat_intelligence",
        intensity = CONFIG.intensity,
        findings = results,
        summary = {}
    }
    
    -- Calculate summary
    report.summary.subdomains = count_table(results.subdomains or {})
    report.summary.unique_ips = count_table(results.infrastructure and results.infrastructure.ips or {})
    report.summary.emails = count_table(results.emails or {})
    report.summary.vulnerabilities = #(results.vulnerabilities or {})
    
    -- Calculate risk score
    local risk_score = 0
    
    -- Vulnerabilities
    for _, vuln in ipairs(results.vulnerabilities or {}) do
        local severity = vuln.severity or vuln.info and vuln.info.severity or "low"
        if severity == "critical" then risk_score = risk_score + 40
        elseif severity == "high" then risk_score = risk_score + 20
        elseif severity == "medium" then risk_score = risk_score + 10
        elseif severity == "low" then risk_score = risk_score + 5
        end
    end
    
    -- Threat indicators
    risk_score = risk_score + (count_table(results.threats and results.threats.malicious_ips or {}) * 25)
    risk_score = risk_score + (count_table(results.threats and results.threats.blacklisted_domains or {}) * 50)
    
    report.summary.risk_score = risk_score
    report.summary.risk_level = risk_score >= 100 and "CRITICAL" or
                                 (risk_score >= 50 and "HIGH" or
                                 (risk_score >= 20 and "MEDIUM" or "LOW"))
    
    -- Save report
    mkdir(CONFIG.output_dir)
    local output_file = CONFIG.output_dir .. "/" .. domain:gsub("[^%w]", "_") .. "_" .. report.scan_id .. ".json"
    write_json(output_file, report)
    
    println("[+] Report saved: " .. output_file)
    
    -- Add to Lotus reports
    Reports:add{
        name = "Threat Intelligence Report",
        target = domain,
        scan_id = report.scan_id,
        risk_level = report.summary.risk_level,
        risk_score = report.summary.risk_score,
        subdomains_found = report.summary.subdomains,
        vulnerabilities_found = report.summary.vulnerabilities,
        output_file = output_file
    }
    
    return report
end

-- ============================================================================
-- Utility Functions
-- ============================================================================

function count_table(t)
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    return count
end

-- ============================================================================
-- Main Function
-- ============================================================================

function main()
    local domain = INPUT_DATA
    
    if not domain or domain == "" then
        log_error("No domain provided")
        return
    end
    
    -- Clean domain
    domain = str(domain):trim():lower():value()
    domain = domain:gsub("^https?://", ""):gsub("/.*", "")
    
    println("\n" .. string.rep("=", 70))
    println("  COMPREHENSIVE THREAT INTELLIGENCE SCANNER")
    println("  Target: " .. domain)
    println("  Intensity: " .. CONFIG.intensity)
    println("  Timestamp: " .. os.date("%Y-%m-%d %H:%M:%S"))
    println(string.rep("=", 70))
    
    -- Check which tools are available
    local tools_available = check_available_tools()
    
    local results = {}
    
    -- Run all modules
    results.subdomains = enumerate_subdomains(domain, tools_available)
    results.infrastructure = discover_infrastructure(domain, results.subdomains, tools_available)
    results.emails = harvest_emails(domain, tools_available)
    results.vulnerabilities = scan_vulnerabilities(domain, results.subdomains, tools_available)
    results.threats = correlate_threat_intel(domain, results.infrastructure)
    
    -- Generate comprehensive report
    local report = generate_report(domain, results)
    
    -- Print summary
    println("\n" .. string.rep("=", 70))
    println("  SCAN COMPLETE")
    println(string.rep("=", 70))
    println("  Subdomains discovered:  " .. report.summary.subdomains)
    println("  Unique IP addresses:    " .. report.summary.unique_ips)
    println("  Email addresses found:  " .. report.summary.emails)
    println("  Vulnerabilities found:  " .. report.summary.vulnerabilities)
    println("  Risk Score:             " .. report.summary.risk_score)
    println("  Risk Level:             " .. report.summary.risk_level)
    println(string.rep("=", 70))
end
