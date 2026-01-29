-- FinalRecon Web Reconnaissance Scanner
-- Comprehensive web reconnaissance using FinalRecon
--
-- Prerequisites:
--   pip3 install finalrecon
--   Or: git clone https://github.com/thewhiteh4t/FinalRecon.git
--
-- Usage:
--   echo "https://example.com" | lotus scan finalrecon_scanner.lua

SCAN_TYPE = 2  -- Full URL with parameters

-- Configuration
local CONFIG = {
    output_dir = "/tmp/lotus_finalrecon",
    run_all_modules = true,
    timeout = 300  -- 5 minutes per module
}

-- Initialize FinalRecon client
local fr = FinalRecon
-- fr:set_path("/path/to/finalrecon")  -- Uncomment to set custom path
-- fr:set_output(CONFIG.output_dir)     -- Set output directory

-- Parse FinalRecon output (extract key findings)
local function parse_output(result, module_name)
    local findings = {
        module = module_name,
        success = result:success(),
        data = {}
    }
    
    if not result:success() then
        findings.error = result:stderr()
        return findings
    end
    
    local output = result:stdout()
    
    -- Extract based on module type
    if module_name == "headers" then
        -- Parse security headers
        local headers = {}
        for line in output:gmatch("[^\r\n]+") do
            if str(line):contains(":") then
                local key, value = line:match("([^:]+):%s*(.+)")
                if key then
                    headers[str(key):trim():value()] = str(value):trim():value()
                end
            end
        end
        findings.data = headers
        
    elseif module_name == "ssl" then
        -- Parse SSL info
        findings.data.raw = output
        -- Look for key SSL details
        local issuer = str(output):find("Issuer:[^\n]*")
        local expiry = str(output):find("Not After[^\n]*")
        if issuer then findings.data.issuer = issuer:value() end
        if expiry then findings.data.expiry = expiry:value() end
        
    elseif module_name == "whois" then
        -- Parse WHOIS
        findings.data.raw = output
        local registrar = str(output):find("Registrar:[^\n]*")
        local creation = str(output):find("Creation Date:[^\n]*")
        if registrar then findings.data.registrar = registrar:value() end
        if creation then findings.data.creation = creation:value() end
        
    elseif module_name == "dns" then
        -- Parse DNS records
        findings.data.records = {}
        for line in output:gmatch("[^\r\n]+") do
            if str(line):match("^%s*[A-Z]+%s+") then
                table.insert(findings.data.records, str(line):trim():value())
            end
        end
        
    elseif module_name == "subdomains" then
        -- Parse subdomains
        findings.data.subdomains = {}
        for line in output:gmatch("[^\r\n]+") do
            local subdomain = str(line):trim():value()
            if subdomain ~= "" and str(subdomain):contains(".") then
                table.insert(findings.data.subdomains, subdomain)
            end
        end
        
    elseif module_name == "wayback" then
        -- Parse wayback URLs
        findings.data.urls = {}
        for line in output:gmatch("[^\r\n]+") do
            if str(line):startswith("http") then
                table.insert(findings.data.urls, line)
            end
        end
        
    elseif module_name == "crawl" then
        -- Parse crawled URLs
        findings.data.internal_urls = {}
        findings.data.external_urls = {}
        findings.data.js_files = {}
        for line in output:gmatch("[^\r\n]+") do
            if str(line):contains(".js") then
                table.insert(findings.data.js_files, line)
            elseif str(line):startswith("http") then
                table.insert(findings.data.internal_urls, line)
            end
        end
    else
        findings.data.raw = output
    end
    
    return findings
end

-- Analyze security headers
local function analyze_headers(headers)
    local issues = {}
    local security_headers = {
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    }
    
    for _, header in ipairs(security_headers) do
        local found = false
        for k, _ in pairs(headers) do
            if str(k):lower():value() == str(header):lower():value() then
                found = true
                break
            end
        end
        if not found then
            table.insert(issues, "Missing: " .. header)
        end
    end
    
    return issues
end

-- Run header analysis
local function scan_headers(url)
    println("[*] Analyzing HTTP headers...")
    local result = fr:headers(url)
    local findings = parse_output(result, "headers")
    
    if findings.success and findings.data then
        local issues = analyze_headers(findings.data)
        if #issues > 0 then
            println("[!] Security header issues found:")
            for _, issue in ipairs(issues) do
                println("    - " .. issue)
            end
            findings.security_issues = issues
        else
            println("[+] All recommended security headers present")
        end
    end
    
    return findings
end

-- Run SSL analysis
local function scan_ssl(url)
    println("[*] Analyzing SSL/TLS configuration...")
    local result = fr:sslinfo(url)
    local findings = parse_output(result, "ssl")
    
    if findings.success then
        if findings.data.issuer then
            println("[+] " .. findings.data.issuer)
        end
        if findings.data.expiry then
            println("[+] " .. findings.data.expiry)
        end
    end
    
    return findings
end

-- Run WHOIS lookup
local function scan_whois(url)
    println("[*] Performing WHOIS lookup...")
    local result = fr:whois(url)
    local findings = parse_output(result, "whois")
    
    if findings.success then
        if findings.data.registrar then
            println("[+] " .. findings.data.registrar)
        end
        if findings.data.creation then
            println("[+] " .. findings.data.creation)
        end
    end
    
    return findings
end

-- Run DNS enumeration
local function scan_dns(url)
    println("[*] Enumerating DNS records...")
    local result = fr:dns(url)
    local findings = parse_output(result, "dns")
    
    if findings.success and findings.data.records then
        println("[+] Found " .. #findings.data.records .. " DNS records")
        for i, record in ipairs(findings.data.records) do
            if i <= 10 then  -- Show first 10
                println("    " .. record)
            end
        end
        if #findings.data.records > 10 then
            println("    ... and " .. (#findings.data.records - 10) .. " more")
        end
    end
    
    return findings
end

-- Run subdomain enumeration
local function scan_subdomains(url)
    println("[*] Enumerating subdomains...")
    local result = fr:sub(url)
    local findings = parse_output(result, "subdomains")
    
    if findings.success and findings.data.subdomains then
        println("[+] Found " .. #findings.data.subdomains .. " subdomains")
        for i, sub in ipairs(findings.data.subdomains) do
            if i <= 20 then
                println("    " .. sub)
            end
        end
        if #findings.data.subdomains > 20 then
            println("    ... and " .. (#findings.data.subdomains - 20) .. " more")
        end
    end
    
    return findings
end

-- Run wayback machine lookup
local function scan_wayback(url)
    println("[*] Querying Wayback Machine...")
    local result = fr:wayback(url)
    local findings = parse_output(result, "wayback")
    
    if findings.success and findings.data.urls then
        println("[+] Found " .. #findings.data.urls .. " archived URLs")
        
        -- Look for interesting files
        local interesting = {}
        for _, archived_url in ipairs(findings.data.urls) do
            if str(archived_url):match("%.sql") or 
               str(archived_url):match("%.bak") or
               str(archived_url):match("%.old") or
               str(archived_url):match("%.backup") or
               str(archived_url):match("%.zip") or
               str(archived_url):match("%.tar") or
               str(archived_url):match("%.config") then
                table.insert(interesting, archived_url)
            end
        end
        
        if #interesting > 0 then
            println("[!] Potentially interesting archived files:")
            for _, url in ipairs(interesting) do
                println("    " .. url)
            end
            findings.data.interesting_files = interesting
        end
    end
    
    return findings
end

-- Run crawler
local function scan_crawl(url)
    println("[*] Crawling website...")
    local result = fr:crawl(url)
    local findings = parse_output(result, "crawl")
    
    if findings.success then
        if findings.data.js_files and #findings.data.js_files > 0 then
            println("[+] Found " .. #findings.data.js_files .. " JavaScript files")
        end
        if findings.data.internal_urls and #findings.data.internal_urls > 0 then
            println("[+] Found " .. #findings.data.internal_urls .. " internal URLs")
        end
    end
    
    return findings
end

-- Generate report
local function generate_report(url, all_findings)
    local report = {
        target = url,
        timestamp = timestamp(),
        scan_id = uuid(),
        tool = "FinalRecon",
        findings = all_findings
    }
    
    -- Calculate risk score based on findings
    local risk_score = 0
    
    if all_findings.headers and all_findings.headers.security_issues then
        risk_score = risk_score + (#all_findings.headers.security_issues * 5)
    end
    
    if all_findings.wayback and all_findings.wayback.data and 
       all_findings.wayback.data.interesting_files then
        risk_score = risk_score + (#all_findings.wayback.data.interesting_files * 10)
    end
    
    report.risk_score = risk_score
    report.risk_level = risk_score > 50 and "HIGH" or (risk_score > 20 and "MEDIUM" or "LOW")
    
    -- Save report
    mkdir(CONFIG.output_dir)
    local safe_url = url:gsub("[^%w]", "_")
    local output_file = CONFIG.output_dir .. "/" .. safe_url .. "_" .. report.scan_id .. ".json"
    write_json(output_file, report)
    println("\n[+] Report saved to: " .. output_file)
    
    -- Add to Lotus reports
    Reports:add{
        name = "FinalRecon Web Reconnaissance",
        url = url,
        scan_id = report.scan_id,
        risk_level = report.risk_level,
        risk_score = report.risk_score,
        output_file = output_file
    }
    
    return report
end

-- Main function
function main()
    local url = HttpMessage:url()
    
    println("=" .. string.rep("=", 60))
    println("FinalRecon Web Reconnaissance Scanner")
    println("Target: " .. url)
    println("=" .. string.rep("=", 60))
    
    local all_findings = {}
    
    -- Run all reconnaissance modules
    all_findings.headers = scan_headers(url)
    all_findings.ssl = scan_ssl(url)
    all_findings.whois = scan_whois(url)
    all_findings.dns = scan_dns(url)
    all_findings.subdomains = scan_subdomains(url)
    all_findings.wayback = scan_wayback(url)
    all_findings.crawl = scan_crawl(url)
    
    -- Generate final report
    local report = generate_report(url, all_findings)
    
    println("\n" .. string.rep("=", 60))
    println("Scan Complete - Risk Level: " .. report.risk_level)
    println(string.rep("=", 60))
end
