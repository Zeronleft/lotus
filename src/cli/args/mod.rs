pub mod new;
pub mod scan;
use new::NewOpts;
use scan::UrlsOpts;
use structopt::StructOpt;

const ABOUT: &str = r#"
Lotus - Fast Web Security Scanner & OSINT Tool
===============================================

A powerful security automation framework using Lua scripts for:
  • Web vulnerability scanning (XSS, SQLi, SSTI, etc.)
  • OSINT and reconnaissance (subdomains, emails, infrastructure)
  • Threat intelligence gathering
  • Custom security automation

QUICK START:
  # Scan a URL with scripts
  echo "https://example.com" | lotus scan ./scripts/

  # Scan with a single script
  echo "example.com" | lotus scan osint_scanner.lua

  # Scan multiple URLs from file
  lotus scan ./scripts/ --urls targets.txt -o results.json

  # With verbose output and custom workers
  cat urls.txt | lotus scan ./scripts/ -v -w 20

SECRETS MANAGEMENT:
  Set API keys via environment variables:
    export SHODAN_API_KEY="your-key"
    export VIRUSTOTAL_API_KEY="your-key"
  
  Or create ~/.lotus_secrets.json (see docs/osint_integration.md)

For more information: https://github.com/BugBlocker/lotus
Documentation: docs/lua_scripting.md, docs/osint_integration.md
"#;

const SCAN_ABOUT: &str = r#"
Run security scans using Lua scripts against target URLs/hosts.

EXAMPLES:
  # Basic URL scanning
  echo "https://target.com/page?id=1" | lotus scan xss_scanner.lua

  # OSINT reconnaissance
  echo "example.com" | lotus scan examples/threat_intel_scanner.lua

  # Scan with output file
  cat targets.txt | lotus scan ./vuln_scripts/ -o results.json

  # With proxy (for Burp/ZAP)
  echo "https://target.com" | lotus scan script.lua -p http://127.0.0.1:8080

  # Pass environment variables to scripts
  echo "target.com" | lotus scan script.lua --env-vars '{"API_KEY":"xxx"}'

  # Resume interrupted scan
  lotus scan ./scripts/ --urls targets.txt --resume resume.cfg

INPUT TYPES (set SCAN_TYPE in your Lua script):
  1 = HOSTS     - Domain/IP only (e.g., "example.com")
  2 = URLS      - Full URL with parameters (e.g., "https://example.com/?id=1")
  3 = PATHS     - URL paths without parameters
  4 = CUSTOM    - Custom input via --input-handler
"#;

const NEW_ABOUT: &str = r#"
Generate a new Lua script template for security scanning.

EXAMPLES:
  # Create a URL parameter scanner
  lotus new --type 2 -o my_scanner.lua

  # Create a host/domain scanner (for OSINT)
  lotus new --type 1 -o osint_recon.lua

SCRIPT TYPES:
  1 = HOST scanner   - For domain/IP reconnaissance
  2 = URL scanner    - For URL parameter testing
  3 = PATH scanner   - For path/directory scanning
  4 = CUSTOM scanner - For custom input handling
"#;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "lotus",
    about = "Fast Web Security Scanner & OSINT Tool",
    long_about = ABOUT,
    after_help = "Use 'lotus <command> --help' for more information about a command.\nReport issues: https://github.com/BugBlocker/lotus/issues"
)]
pub enum Opts {
    #[structopt(about = "Create a new Lua script template", long_about = NEW_ABOUT)]
    New(NewOpts),
    #[structopt(
        name = "scan",
        about = "Run security scans with Lua scripts",
        long_about = SCAN_ABOUT,
        visible_alias = "s"
    )]
    Scan(UrlsOpts),
}
