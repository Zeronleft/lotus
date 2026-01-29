use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliErrors {
    #[error(
        "No input URLs provided\n\n\
        SOLUTION: Provide URLs via stdin or --urls flag:\n\
        \n\
        Via stdin:\n\
          echo \"https://example.com\" | lotus scan script.lua\n\
          cat urls.txt | lotus scan script.lua\n\
        \n\
        Via file:\n\
          lotus scan script.lua --urls targets.txt\n\
        \n\
        For OSINT/host scanning (SCAN_TYPE=1):\n\
          echo \"example.com\" | lotus scan osint_script.lua"
    )]
    EmptyStdin,

    #[error(
        "Cannot read file\n\n\
        TROUBLESHOOTING:\n\
        • Check the file path exists and is accessible\n\
        • Ensure you have read permissions\n\
        • For scripts, use relative or absolute paths:\n\
          lotus scan ./scripts/scanner.lua\n\
          lotus scan /full/path/to/script.lua"
    )]
    ReadingError,

    #[error(
        "Invalid regex pattern\n\n\
        TROUBLESHOOTING:\n\
        • Check your regex syntax\n\
        • Escape special characters: . * + ? [ ] ( ) {{ }} | \\ ^ $\n\
        • Test patterns at: https://regex101.com\n\
        • In Lua, use double backslashes: \\\\d+ instead of \\d+"
    )]
    RegexError,

    #[error(
        "Cannot write to file\n\n\
        TROUBLESHOOTING:\n\
        • Check you have write permissions to the directory\n\
        • Ensure the parent directory exists\n\
        • Try a different output path"
    )]
    WritingError,

    #[error(
        "File already exists\n\n\
        SOLUTION: Use a different filename or delete the existing file"
    )]
    FileExists,

    #[error(
        "Invalid regex pattern\n\n\
        TROUBLESHOOTING:\n\
        • Check for unmatched brackets or parentheses\n\
        • Escape special regex characters\n\
        • In Lua use: is_match(\"\\\\d+\", text) for digits"
    )]
    RegexPatternError,

    #[error(
        "Unsupported script type\n\n\
        SUPPORTED TYPES for 'lotus new' command:\n\
          fuzz    - Parameter fuzzing scanner (aliases: fuzzer, param)\n\
          cve     - CVE/vulnerability detector (aliases: vuln, vulnerability)\n\
          service - Service/OSINT scanner (aliases: osint, recon)\n\
        \n\
        Example:\n\
          lotus new -s fuzz -f my_scanner.lua\n\
          lotus new -s osint -f recon_tool.lua"
    )]
    UnsupportedScript,

    #[error(
        "Missing SCAN_TYPE in Lua script\n\n\
        SOLUTION: Add a SCAN_TYPE variable at the top of your script:\n\
        \n\
          -- For domain/host input (OSINT scanning)\n\
          SCAN_TYPE = 1\n\
        \n\
          -- For full URL with parameters (vuln scanning)\n\
          SCAN_TYPE = 2\n\
        \n\
          -- For URL paths only\n\
          SCAN_TYPE = 3\n\
        \n\
          -- For custom input handler\n\
          SCAN_TYPE = 4\n\
        \n\
        See docs/lua_scripting.md for more information"
    )]
    NoScanType,

    #[error("Lua script error")]
    LuaCodeErr,

    #[error(
        "Invalid content-type\n\n\
        VALID OPTIONS (comma-separated):\n\
          url     - Scan URL parameters\n\
          body    - Scan request body\n\
          json    - Scan JSON body fields\n\
          headers - Scan request headers\n\
        \n\
        Examples:\n\
          --content-type url,body\n\
          --content-type json\n\
          -c url,body,headers"
    )]
    UnsupportedScanType,
}

#[derive(Error, Debug)]
pub enum Network {
    #[error(
        "Connection timeout\n\n\
        TROUBLESHOOTING:\n\
        • Target may be slow or unresponsive\n\
        • Increase timeout: lotus scan script.lua -t 30\n\
        • Check network connectivity\n\
        • If using proxy, verify it's running"
    )]
    ConnectionTimeout,
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error(
        "Connection timeout after {0}s\n\n\
        TROUBLESHOOTING:\n\
        • Target may be slow or unresponsive\n\
        • Increase timeout: lotus scan script.lua -t 30\n\
        • Check network connectivity\n\
        • If using proxy, verify it's running"
    )]
    ConnectionTimeout(u64),

    #[error(
        "Connection refused to {0}\n\n\
        TROUBLESHOOTING:\n\
        • Verify the target URL is correct\n\
        • Check if target is accessible\n\
        • Firewall may be blocking connections\n\
        • If using proxy, check proxy settings"
    )]
    ConnectionRefused(String),

    #[error(
        "SSL/TLS error: {0}\n\n\
        TROUBLESHOOTING:\n\
        • Certificate may be invalid or expired\n\
        • Try with HTTP instead of HTTPS\n\
        • For self-signed certs, consider using proxy"
    )]
    SslError(String),

    #[error(
        "DNS resolution failed for: {0}\n\n\
        TROUBLESHOOTING:\n\
        • Verify the domain name is correct\n\
        • Check your DNS settings\n\
        • Try: dig {0} or nslookup {0}"
    )]
    DnsError(String),

    #[error(
        "Proxy error: {0}\n\n\
        TROUBLESHOOTING:\n\
        • Verify proxy is running: curl -x {1} http://example.com\n\
        • Check proxy URL format: http://host:port or socks5://host:port\n\
        • Ensure proxy allows connections to target"
    )]
    ProxyError(String, String),
}
