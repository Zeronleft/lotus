-- SpiderFoot OSINT Integration Example
-- Demonstrates integration with SpiderFoot for automated reconnaissance
--
-- Prerequisites:
--   1. Install SpiderFoot: pip3 install spiderfoot
--   2. Or run SpiderFoot server: python3 sf.py -l 127.0.0.1:5001
--
-- Usage:
--   echo "example.com" | lotus scan spiderfoot_osint.lua
--   echo "192.168.1.1" | lotus scan spiderfoot_osint.lua

SCAN_TYPE = 1  -- HOSTS input type

-- Configuration
local CONFIG = {
    -- SpiderFoot modules for different reconnaissance types
    modules = {
        passive = {
            "sfp_dnsresolve",
            "sfp_whois",
            "sfp_shodan",
            "sfp_virustotal",
            "sfp_alienvault",
            "sfp_censys",
            "sfp_securitytrails"
        },
        subdomain = {
            "sfp_dnsresolve",
            "sfp_dnsbrute",
            "sfp_certspotter",
            "sfp_crt",
            "sfp_sublist3r",
            "sfp_threatcrowd"
        },
        network = {
            "sfp_portscan_tcp",
            "sfp_portscan_udp",
            "sfp_shodan",
            "sfp_censys"
        },
        email = {
            "sfp_hunter",
            "sfp_emailformat",
            "sfp_haveibeenpwned"
        }
    },
    output_dir = "/tmp/lotus_osint"
}

-- Initialize SpiderFoot client
local sf = SpiderFoot
-- sf:set_path("/path/to/sf.py")  -- Uncomment to set custom path

-- Helper: Parse SpiderFoot JSON output
local function parse_sf_results(result)
    if not result:success() then
        log_warn("SpiderFoot scan failed: " .. result:stderr())
        return nil
    end

    local findings = {}
    for line in result:stdout():gmatch("[^\r\n]+") do
        local ok, data = pcall(function()
            return json(line):value()
        end)
        if ok and data then
            table.insert(findings, data)
        end
    end
    return findings
end

-- Run passive reconnaissance
local function passive_recon(target)
    println("[*] Running passive reconnaissance on: " .. target)
    
    local results = {}
    
    -- WHOIS lookup
    println("[*] Performing WHOIS lookup...")
    local whois_result = whois(target)
    if whois_result:success() then
        results.whois = whois_result:stdout()
        
        -- Extract key WHOIS info
        local registrar = str(results.whois):find("Registrar:[^\n]*")
        local creation = str(results.whois):find("Creation Date:[^\n]*")
        if registrar then
            println("[+] " .. registrar:value())
        end
        if creation then
            println("[+] " .. creation:value())
        end
    end
    
    -- DNS lookups
    println("[*] Performing DNS lookups...")
    local dns_records = dns_lookup(target)
    results.dns = {}
    for _, ip in ipairs(dns_records) do
        println("[+] DNS A Record: " .. ip)
        table.insert(results.dns, ip)
        
        -- Reverse DNS
        local rdns = reverse_dns(ip)
        if rdns and rdns ~= "" then
            println("[+] Reverse DNS: " .. rdns)
            results.reverse_dns = rdns
        end
    end
    
    -- Run SpiderFoot passive modules
    println("[*] Running SpiderFoot passive scan...")
    local sf_result = sf:scan(target, CONFIG.modules.passive)
    local sf_findings = parse_sf_results(sf_result)
    if sf_findings then
        results.spiderfoot = sf_findings
        println("[+] SpiderFoot found " .. #sf_findings .. " data points")
    end
    
    return results
end

-- Run subdomain enumeration
local function subdomain_enum(target)
    println("[*] Running subdomain enumeration on: " .. target)
    
    local results = {
        subdomains = {}
    }
    
    -- SpiderFoot subdomain modules
    local sf_result = sf:scan(target, CONFIG.modules.subdomain)
    local sf_findings = parse_sf_results(sf_result)
    
    if sf_findings then
        for _, finding in ipairs(sf_findings) do
            if finding.type == "INTERNET_NAME" or finding.type == "DOMAIN_NAME" then
                local subdomain = finding.data
                if not results.subdomains[subdomain] then
                    results.subdomains[subdomain] = true
                    println("[+] Subdomain: " .. subdomain)
                end
            end
        end
    end
    
    -- Also try Certificate Transparency via HTTP
    local ct_url = "https://crt.sh/?q=%25." .. target .. "&output=json"
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
                if name and not results.subdomains[name] then
                    results.subdomains[name] = true
                    println("[+] CT Subdomain: " .. name)
                end
            end
        end
    end
    
    return results
end

-- Run network reconnaissance
local function network_recon(target)
    println("[*] Running network reconnaissance on: " .. target)
    
    local results = {
        ports = {},
        services = {}
    }
    
    -- SpiderFoot network modules
    local sf_result = sf:scan(target, CONFIG.modules.network)
    local sf_findings = parse_sf_results(sf_result)
    
    if sf_findings then
        for _, finding in ipairs(sf_findings) do
            if finding.type == "TCP_PORT_OPEN" then
                local port = finding.data
                results.ports[port] = true
                println("[+] Open Port: " .. port)
            elseif finding.type == "RAW_RIR_DATA" or finding.type == "OPERATING_SYSTEM" then
                table.insert(results.services, finding.data)
            end
        end
    end
    
    return results
end

-- Check for email addresses
local function email_harvest(target)
    println("[*] Harvesting email addresses for: " .. target)
    
    local results = {
        emails = {}
    }
    
    -- SpiderFoot email modules
    local sf_result = sf:scan(target, CONFIG.modules.email)
    local sf_findings = parse_sf_results(sf_result)
    
    if sf_findings then
        for _, finding in ipairs(sf_findings) do
            if finding.type == "EMAILADDR" then
                local email = finding.data
                if not results.emails[email] then
                    results.emails[email] = true
                    println("[+] Email: " .. email)
                end
            elseif finding.type == "EMAILADDR_COMPROMISED" then
                local email = finding.data
                println("[!] Compromised Email: " .. email)
                results.emails[email] = "compromised"
            end
        end
    end
    
    return results
end

-- Generate threat intelligence report
local function generate_report(target, all_results)
    local report = {
        target = target,
        timestamp = timestamp(),
        scan_id = uuid(),
        findings = all_results
    }
    
    -- Save to JSON file
    mkdir(CONFIG.output_dir)
    local output_file = CONFIG.output_dir .. "/" .. target:gsub("[^%w]", "_") .. "_" .. report.scan_id .. ".json"
    write_json(output_file, report)
    println("\n[+] Report saved to: " .. output_file)
    
    -- Add to Lotus reports
    Reports:add{
        name = "OSINT Reconnaissance",
        target = target,
        scan_id = report.scan_id,
        timestamp = report.timestamp,
        dns_records = all_results.passive and all_results.passive.dns or {},
        subdomain_count = all_results.subdomains and #all_results.subdomains or 0,
        output_file = output_file
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
    println("SpiderFoot OSINT Scanner")
    println("Target: " .. target)
    println("=" .. string.rep("=", 60))
    
    local all_results = {}
    
    -- Run all reconnaissance phases
    all_results.passive = passive_recon(target)
    all_results.subdomains = subdomain_enum(target)
    all_results.network = network_recon(target)
    all_results.emails = email_harvest(target)
    
    -- Generate final report
    local report = generate_report(target, all_results)
    
    println("\n" .. string.rep("=", 60))
    println("OSINT scan completed for: " .. target)
    println(string.rep("=", 60))
end
