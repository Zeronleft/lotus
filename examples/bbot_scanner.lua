-- BBOT OSINT Automation Scanner
-- Uses Black Lantern Security's BBOT for recursive OSINT
--
-- Prerequisites:
--   pip install bbot
--   Or: pipx install bbot
--
-- Usage:
--   echo "example.com" | lotus scan bbot_scanner.lua
--   echo "example.com" | lotus scan bbot_scanner.lua --env PRESET=web-thorough
--   echo "example.com" | lotus scan bbot_scanner.lua --env MODULES=httpx,nuclei

SCAN_TYPE = 1  -- HOSTS input type

-- Configuration
local CONFIG = {
    output_dir = "/tmp/lotus_bbot",
    default_preset = "subdomain-enum",  -- subdomain-enum, web-basic, web-thorough, cloud-enum, email-enum
    max_findings_display = 50
}

-- Initialize BBOT client
local bbot = BBOT
-- bbot:set_path("/path/to/bbot")  -- Custom path
-- bbot:set_config("~/.config/bbot/bbot.yml")  -- Custom config

-- Parse BBOT NDJSON output
local function parse_bbot_output(result)
    local findings = {
        dns_names = {},
        ip_addresses = {},
        urls = {},
        emails = {},
        open_ports = {},
        technologies = {},
        vulnerabilities = {},
        storage_buckets = {},
        findings = {},
        raw_events = {}
    }
    
    if not result:success() then
        log_warn("BBOT scan had issues: " .. result:stderr())
    end
    
    -- Parse NDJSON output (one JSON object per line)
    for line in result:stdout():gmatch("[^\r\n]+") do
        if str(line):startswith("{") then
            local ok, event = pcall(function()
                return json(line):value()
            end)
            
            if ok and event then
                table.insert(findings.raw_events, event)
                local event_type = event.type or ""
                local data = event.data or ""
                
                -- Categorize by event type
                if event_type == "DNS_NAME" or event_type == "DNS_NAME_UNRESOLVED" then
                    findings.dns_names[data] = {
                        resolved = event_type == "DNS_NAME",
                        source = event.source or "unknown"
                    }
                    
                elseif event_type == "IP_ADDRESS" then
                    findings.ip_addresses[data] = {
                        source = event.source or "unknown"
                    }
                    
                elseif event_type == "URL" or event_type == "URL_UNVERIFIED" then
                    findings.urls[data] = {
                        verified = event_type == "URL",
                        status_code = event.status_code,
                        title = event.title
                    }
                    
                elseif event_type == "EMAIL_ADDRESS" then
                    findings.emails[data] = {
                        source = event.source or "unknown"
                    }
                    
                elseif event_type == "OPEN_TCP_PORT" then
                    findings.open_ports[data] = {
                        source = event.source or "unknown"
                    }
                    
                elseif event_type == "TECHNOLOGY" then
                    findings.technologies[data] = {
                        url = event.url,
                        source = event.source or "unknown"
                    }
                    
                elseif event_type == "VULNERABILITY" then
                    table.insert(findings.vulnerabilities, {
                        data = data,
                        severity = event.severity,
                        description = event.description,
                        url = event.url
                    })
                    
                elseif event_type == "STORAGE_BUCKET" then
                    findings.storage_buckets[data] = {
                        url = event.url,
                        source = event.source or "unknown"
                    }
                    
                elseif event_type == "FINDING" then
                    table.insert(findings.findings, {
                        data = data,
                        description = event.description,
                        severity = event.severity
                    })
                end
            end
        end
    end
    
    return findings
end

-- Count table entries
local function count_table(t)
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    return count
end

-- Print findings summary
local function print_findings(category, items, max_display)
    max_display = max_display or CONFIG.max_findings_display
    local count = count_table(items)
    
    if count == 0 then return end
    
    println("\n[" .. category .. "] Found " .. count .. " items:")
    
    local displayed = 0
    for item, data in pairs(items) do
        if displayed >= max_display then
            println("    ... and " .. (count - max_display) .. " more")
            break
        end
        
        local extra = ""
        if type(data) == "table" then
            if data.status_code then
                extra = " [" .. data.status_code .. "]"
            elseif data.severity then
                extra = " [" .. string.upper(data.severity) .. "]"
            elseif data.resolved == false then
                extra = " [unresolved]"
            end
        end
        
        println("    " .. item .. extra)
        displayed = displayed + 1
    end
end

-- Run subdomain enumeration
local function run_subdomain_enum(target)
    println("\n" .. string.rep("-", 60))
    println("[*] SUBDOMAIN ENUMERATION")
    println("[*] Using BBOT subdomain-enum preset")
    println(string.rep("-", 60))
    
    local result = bbot:subdomain_enum(target)
    local findings = parse_bbot_output(result)
    
    print_findings("Subdomains", findings.dns_names, 30)
    print_findings("IP Addresses", findings.ip_addresses, 20)
    
    return findings
end

-- Run web reconnaissance
local function run_web_recon(target, thorough)
    println("\n" .. string.rep("-", 60))
    println("[*] WEB RECONNAISSANCE")
    println("[*] Using BBOT " .. (thorough and "web-thorough" or "web-basic") .. " preset")
    println(string.rep("-", 60))
    
    local result = bbot:web_recon(target, thorough)
    local findings = parse_bbot_output(result)
    
    print_findings("URLs", findings.urls, 30)
    print_findings("Technologies", findings.technologies, 20)
    print_findings("Open Ports", findings.open_ports, 20)
    
    if #findings.vulnerabilities > 0 then
        println("\n[VULNERABILITIES] Found " .. #findings.vulnerabilities .. " vulnerabilities:")
        for i, vuln in ipairs(findings.vulnerabilities) do
            if i <= 20 then
                local severity = vuln.severity and string.upper(vuln.severity) or "UNKNOWN"
                println("    [" .. severity .. "] " .. vuln.data)
            end
        end
    end
    
    return findings
end

-- Run cloud enumeration
local function run_cloud_enum(target)
    println("\n" .. string.rep("-", 60))
    println("[*] CLOUD ENUMERATION")
    println("[*] Using BBOT cloud-enum preset")
    println(string.rep("-", 60))
    
    local result = bbot:cloud_enum(target)
    local findings = parse_bbot_output(result)
    
    print_findings("Storage Buckets", findings.storage_buckets, 20)
    
    return findings
end

-- Run email enumeration
local function run_email_enum(target)
    println("\n" .. string.rep("-", 60))
    println("[*] EMAIL ENUMERATION")
    println("[*] Using BBOT email-enum preset")
    println(string.rep("-", 60))
    
    local result = bbot:email_enum(target)
    local findings = parse_bbot_output(result)
    
    print_findings("Email Addresses", findings.emails, 30)
    
    return findings
end

-- Run custom modules
local function run_custom_modules(target, modules)
    println("\n" .. string.rep("-", 60))
    println("[*] CUSTOM MODULE SCAN")
    println("[*] Running modules: " .. table.concat(modules, ", "))
    println(string.rep("-", 60))
    
    local result = bbot:run_modules(target, modules)
    local findings = parse_bbot_output(result)
    
    -- Print all findings
    print_findings("Subdomains", findings.dns_names, 20)
    print_findings("IP Addresses", findings.ip_addresses, 15)
    print_findings("URLs", findings.urls, 20)
    print_findings("Technologies", findings.technologies, 15)
    print_findings("Open Ports", findings.open_ports, 15)
    
    return findings
end

-- Generate comprehensive report
local function generate_report(target, all_findings)
    local report = {
        target = target,
        timestamp = timestamp(),
        scan_id = uuid(),
        tool = "bbot",
        findings = {}
    }
    
    -- Merge all findings
    local merged = {
        dns_names = {},
        ip_addresses = {},
        urls = {},
        emails = {},
        open_ports = {},
        technologies = {},
        vulnerabilities = {},
        storage_buckets = {}
    }
    
    for scan_type, findings in pairs(all_findings) do
        for category, items in pairs(findings) do
            if type(items) == "table" and merged[category] then
                if category == "vulnerabilities" then
                    for _, v in ipairs(items) do
                        table.insert(merged.vulnerabilities, v)
                    end
                else
                    for item, data in pairs(items) do
                        merged[category][item] = data
                    end
                end
            end
        end
    end
    
    report.findings = merged
    
    -- Summary
    report.summary = {
        subdomains = count_table(merged.dns_names),
        ip_addresses = count_table(merged.ip_addresses),
        urls = count_table(merged.urls),
        emails = count_table(merged.emails),
        open_ports = count_table(merged.open_ports),
        technologies = count_table(merged.technologies),
        vulnerabilities = #merged.vulnerabilities,
        storage_buckets = count_table(merged.storage_buckets)
    }
    
    -- Risk score
    local risk_score = 0
    for _, vuln in ipairs(merged.vulnerabilities) do
        local sev = vuln.severity or "low"
        if sev == "critical" then risk_score = risk_score + 40
        elseif sev == "high" then risk_score = risk_score + 20
        elseif sev == "medium" then risk_score = risk_score + 10
        else risk_score = risk_score + 5 end
    end
    risk_score = risk_score + (count_table(merged.storage_buckets) * 15)
    
    report.risk_score = risk_score
    report.risk_level = risk_score >= 100 and "CRITICAL" or
                         (risk_score >= 50 and "HIGH" or
                         (risk_score >= 20 and "MEDIUM" or "LOW"))
    
    -- Save report
    mkdir(CONFIG.output_dir)
    local safe_target = target:gsub("[^%w]", "_")
    local output_file = CONFIG.output_dir .. "/" .. safe_target .. "_bbot_" .. report.scan_id .. ".json"
    write_json(output_file, report)
    
    println("\n[+] Report saved: " .. output_file)
    
    -- Add to Lotus reports
    Reports:add{
        name = "BBOT OSINT Scan",
        target = target,
        scan_id = report.scan_id,
        risk_level = report.risk_level,
        risk_score = report.risk_score,
        subdomains = report.summary.subdomains,
        vulnerabilities = report.summary.vulnerabilities,
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
    
    -- Clean target
    target = str(target):trim():lower():value()
    target = target:gsub("^https?://", ""):gsub("/.*", "")
    
    println("\n" .. string.rep("=", 70))
    println("  BBOT OSINT AUTOMATION SCANNER")
    println("  Target: " .. target)
    println("  Time: " .. os.date("%Y-%m-%d %H:%M:%S"))
    println(string.rep("=", 70))
    
    -- Check for custom settings via environment
    local preset = getenv("PRESET") or CONFIG.default_preset
    local modules_env = getenv("MODULES")
    
    local all_findings = {}
    
    if modules_env then
        -- Run specific modules
        local modules = {}
        for mod in modules_env:gmatch("[^,]+") do
            table.insert(modules, str(mod):trim():value())
        end
        all_findings.custom = run_custom_modules(target, modules)
    else
        -- Run preset-based scan
        if preset == "subdomain-enum" then
            all_findings.subdomains = run_subdomain_enum(target)
        elseif preset == "web-basic" then
            all_findings.subdomains = run_subdomain_enum(target)
            all_findings.web = run_web_recon(target, false)
        elseif preset == "web-thorough" then
            all_findings.subdomains = run_subdomain_enum(target)
            all_findings.web = run_web_recon(target, true)
        elseif preset == "cloud-enum" then
            all_findings.subdomains = run_subdomain_enum(target)
            all_findings.cloud = run_cloud_enum(target)
        elseif preset == "email-enum" then
            all_findings.emails = run_email_enum(target)
        elseif preset == "full" then
            -- Full scan - all presets
            all_findings.subdomains = run_subdomain_enum(target)
            all_findings.web = run_web_recon(target, true)
            all_findings.cloud = run_cloud_enum(target)
            all_findings.emails = run_email_enum(target)
        end
    end
    
    -- Generate report
    local report = generate_report(target, all_findings)
    
    -- Print summary
    println("\n" .. string.rep("=", 70))
    println("  SCAN COMPLETE")
    println(string.rep("=", 70))
    println("  Subdomains:      " .. report.summary.subdomains)
    println("  IP Addresses:    " .. report.summary.ip_addresses)
    println("  URLs:            " .. report.summary.urls)
    println("  Emails:          " .. report.summary.emails)
    println("  Open Ports:      " .. report.summary.open_ports)
    println("  Technologies:    " .. report.summary.technologies)
    println("  Vulnerabilities: " .. report.summary.vulnerabilities)
    println("  Storage Buckets: " .. report.summary.storage_buckets)
    println(string.rep("-", 70))
    println("  Risk Score:      " .. report.risk_score)
    println("  Risk Level:      " .. report.risk_level)
    println(string.rep("=", 70))
end
