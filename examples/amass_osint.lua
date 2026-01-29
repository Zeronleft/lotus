-- OWASP Amass OSINT Integration Example
-- Demonstrates integration with Amass for subdomain enumeration and reconnaissance
--
-- Prerequisites:
--   1. Install Amass: go install -v github.com/owasp-amass/amass/v4/...@master
--   2. Or download binary: https://github.com/OWASP/Amass/releases
--   3. Optional: Configure API keys in ~/.config/amass/config.ini
--
-- Usage:
--   echo "example.com" | lotus scan amass_osint.lua
--   echo "Example Corp" | lotus scan amass_osint.lua --env ORG_SEARCH=true

SCAN_TYPE = 1  -- HOSTS input type

-- Configuration
local CONFIG = {
    output_dir = "/tmp/lotus_amass",
    passive_timeout = 60,    -- seconds
    active_timeout = 120,    -- seconds
    config_file = nil,       -- Set to path of amass config.ini
    data_sources = true      -- Use data sources (APIs)
}

-- Initialize Amass client
local amass = Amass
-- amass:set_path("/usr/local/bin/amass")  -- Uncomment to set custom path

-- Check if this is an organization search vs domain
local function is_org_search()
    return getenv("ORG_SEARCH") == "true"
end

-- Parse Amass JSON output (newline-delimited JSON)
local function parse_amass_json(result)
    if not result:success() then
        local stderr = result:stderr()
        if stderr ~= "" then
            log_warn("Amass warning: " .. stderr)
        end
    end

    local findings = {}
    for line in result:stdout():gmatch("[^\r\n]+") do
        if str(line):startswith("{") then
            local ok, data = pcall(function()
                return json(line):value()
            end)
            if ok and data then
                table.insert(findings, data)
            end
        else
            -- Plain text output (one result per line)
            if line ~= "" then
                table.insert(findings, { name = line })
            end
        end
    end
    return findings
end

-- Run passive subdomain enumeration
local function passive_enum(domain)
    println("[*] Running passive subdomain enumeration...")
    println("[*] Target domain: " .. domain)
    
    local results = {
        subdomains = {},
        sources = {}
    }
    
    -- Run Amass enum in passive mode
    local amass_result = amass:enum{
        domain = domain,
        passive = true,
        timeout = CONFIG.passive_timeout
    }
    
    local findings = parse_amass_json(amass_result)
    
    for _, finding in ipairs(findings) do
        local subdomain = finding.name
        if subdomain and not results.subdomains[subdomain] then
            results.subdomains[subdomain] = {
                name = subdomain,
                addresses = finding.addresses or {},
                sources = finding.sources or {},
                tag = finding.tag or "unknown"
            }
            
            -- Track data sources used
            if finding.sources then
                for _, src in ipairs(finding.sources) do
                    results.sources[src] = (results.sources[src] or 0) + 1
                end
            end
            
            -- Print findings
            local ip_info = ""
            if finding.addresses and #finding.addresses > 0 then
                ip_info = " -> " .. table.concat(finding.addresses, ", ")
            end
            println("[+] " .. subdomain .. ip_info)
        end
    end
    
    local count = 0
    for _ in pairs(results.subdomains) do count = count + 1 end
    println("[*] Found " .. count .. " unique subdomains")
    
    return results
end

-- Run active subdomain enumeration (with DNS resolution)
local function active_enum(domain)
    println("[*] Running active subdomain enumeration...")
    
    local results = {
        subdomains = {},
        resolved = {},
        unresolved = {}
    }
    
    -- Run Amass enum in active mode
    local amass_result = amass:enum{
        domain = domain,
        passive = false,
        timeout = CONFIG.active_timeout
    }
    
    local findings = parse_amass_json(amass_result)
    
    for _, finding in ipairs(findings) do
        local subdomain = finding.name
        if subdomain then
            results.subdomains[subdomain] = finding
            
            if finding.addresses and #finding.addresses > 0 then
                results.resolved[subdomain] = finding.addresses
                println("[+] " .. subdomain .. " -> " .. table.concat(finding.addresses, ", "))
            else
                results.unresolved[subdomain] = true
                println("[~] " .. subdomain .. " (unresolved)")
            end
        end
    end
    
    return results
end

-- Run organization/ASN intelligence gathering
local function intel_gathering(target)
    println("[*] Running intelligence gathering...")
    
    local results = {
        organizations = {},
        asns = {},
        domains = {},
        networks = {}
    }
    
    local intel_opts = {}
    
    -- Determine if target is an IP, ASN, CIDR, or organization name
    if str(target):match("^%d+$") then
        -- ASN number
        println("[*] Searching by ASN: " .. target)
        intel_opts.asn = tonumber(target)
    elseif str(target):match("^%d+%.%d+%.%d+%.%d+") then
        -- IP address or CIDR
        if str(target):contains("/") then
            println("[*] Searching by CIDR: " .. target)
            intel_opts.cidr = target
        else
            println("[*] Searching by IP: " .. target)
            intel_opts.cidr = target .. "/24"
        end
    else
        -- Organization name
        println("[*] Searching by organization: " .. target)
        intel_opts.org = target
        intel_opts.whois = true
    end
    
    local amass_result = amass:intel(intel_opts)
    
    local findings = parse_amass_json(amass_result)
    
    for _, finding in ipairs(findings) do
        if finding.name then
            -- Domain discovered
            if not results.domains[finding.name] then
                results.domains[finding.name] = true
                println("[+] Domain: " .. finding.name)
            end
        end
        
        if finding.asn then
            results.asns[tostring(finding.asn)] = finding.desc or ""
        end
    end
    
    -- Also parse plain text output for domain names
    for line in amass_result:stdout():gmatch("[^\r\n]+") do
        if not str(line):startswith("{") and str(line):contains(".") then
            local domain = str(line):trim():value()
            if domain ~= "" and not results.domains[domain] then
                results.domains[domain] = true
                println("[+] Domain: " .. domain)
            end
        end
    end
    
    return results
end

-- Query Amass database for historical data
local function query_database(domain)
    println("[*] Querying Amass database for: " .. domain)
    
    local results = {
        historical = {}
    }
    
    -- List enumeration history
    local list_result = amass:db{
        domain = domain,
        list = true
    }
    
    if list_result:success() then
        println("[*] Enumeration history:")
        for line in list_result:stdout():gmatch("[^\r\n]+") do
            println("    " .. line)
        end
    end
    
    -- Get stored names
    local names_result = amass:db{
        domain = domain,
        names = true
    }
    
    if names_result:success() then
        for line in names_result:stdout():gmatch("[^\r\n]+") do
            if line ~= "" then
                results.historical[line] = true
            end
        end
    end
    
    local count = 0
    for _ in pairs(results.historical) do count = count + 1 end
    println("[*] Found " .. count .. " historical subdomains in database")
    
    return results
end

-- Perform DNS resolution and categorization
local function resolve_and_categorize(subdomains)
    println("[*] Resolving and categorizing subdomains...")
    
    local categories = {
        web = {},       -- www, portal, web, app
        mail = {},      -- mail, smtp, imap, pop
        api = {},       -- api, rest, graphql
        dev = {},       -- dev, staging, test, qa
        admin = {},     -- admin, manage, cpanel
        vpn = {},       -- vpn, remote, gateway
        other = {}
    }
    
    local patterns = {
        web = {"^www", "^portal", "^web", "^app", "^site"},
        mail = {"^mail", "^smtp", "^imap", "^pop", "^mx", "^email"},
        api = {"^api", "^rest", "^graphql", "^ws"},
        dev = {"^dev", "^staging", "^test", "^qa", "^uat", "^sandbox"},
        admin = {"^admin", "^manage", "^cpanel", "^panel", "^dashboard"},
        vpn = {"^vpn", "^remote", "^gateway", "^fw", "^firewall"}
    }
    
    for subdomain, data in pairs(subdomains) do
        local categorized = false
        local name = str(subdomain):lower():value()
        
        for category, pats in pairs(patterns) do
            for _, pattern in ipairs(pats) do
                if str(name):match(pattern) then
                    categories[category][subdomain] = data
                    categorized = true
                    break
                end
            end
            if categorized then break end
        end
        
        if not categorized then
            categories.other[subdomain] = data
        end
    end
    
    -- Print summary
    println("\n[*] Subdomain Categories:")
    for category, items in pairs(categories) do
        local count = 0
        for _ in pairs(items) do count = count + 1 end
        if count > 0 then
            println("    " .. category:upper() .. ": " .. count)
        end
    end
    
    return categories
end

-- Generate comprehensive report
local function generate_report(target, all_results)
    local report = {
        target = target,
        timestamp = timestamp(),
        scan_id = uuid(),
        tool = "amass",
        findings = all_results
    }
    
    -- Count total findings
    local total_subdomains = 0
    if all_results.passive and all_results.passive.subdomains then
        for _ in pairs(all_results.passive.subdomains) do
            total_subdomains = total_subdomains + 1
        end
    end
    
    report.summary = {
        total_subdomains = total_subdomains,
        data_sources = all_results.passive and all_results.passive.sources or {}
    }
    
    -- Save to JSON file
    mkdir(CONFIG.output_dir)
    local safe_target = target:gsub("[^%w]", "_")
    local output_file = CONFIG.output_dir .. "/" .. safe_target .. "_amass_" .. report.scan_id .. ".json"
    write_json(output_file, report)
    println("\n[+] Report saved to: " .. output_file)
    
    -- Add to Lotus reports
    Reports:add{
        name = "Amass OSINT Reconnaissance",
        target = target,
        scan_id = report.scan_id,
        timestamp = report.timestamp,
        subdomain_count = total_subdomains,
        output_file = output_file,
        categories = all_results.categories or {}
    }
    
    return report
end

-- Main function
function main()
    local target = INPUT_DATA
    
    if not target or target == "" then
        log_error("No target provided")
        return
    end
    
    println("=" .. string.rep("=", 60))
    println("OWASP Amass OSINT Scanner")
    println("Target: " .. target)
    println("=" .. string.rep("=", 60))
    
    local all_results = {}
    
    if is_org_search() then
        -- Organization/ASN intelligence gathering
        all_results.intel = intel_gathering(target)
        
        -- For each discovered domain, run subdomain enum
        if all_results.intel.domains then
            all_results.domain_scans = {}
            for domain, _ in pairs(all_results.intel.domains) do
                println("\n[*] Scanning discovered domain: " .. domain)
                all_results.domain_scans[domain] = passive_enum(domain)
            end
        end
    else
        -- Standard domain enumeration
        all_results.passive = passive_enum(target)
        
        -- Categorize subdomains
        if all_results.passive.subdomains then
            all_results.categories = resolve_and_categorize(all_results.passive.subdomains)
        end
        
        -- Check database for historical data
        all_results.database = query_database(target)
    end
    
    -- Generate final report
    local report = generate_report(target, all_results)
    
    println("\n" .. string.rep("=", 60))
    println("Amass scan completed for: " .. target)
    println(string.rep("=", 60))
end
