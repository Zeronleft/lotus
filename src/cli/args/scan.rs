use crate::cli::errors::CliErrors;
use crate::cli::input::parse_requests::{InjectionLocation, SCAN_CONTENT_TYPE};
use crate::lua::threads::runner::{
    LAST_CUSTOM_SCAN_ID, LAST_HOST_SCAN_ID, LAST_HTTP_SCAN_ID, LAST_PATH_SCAN_ID, LAST_URL_SCAN_ID,
};
use futures::executor::block_on;
use reqwest::header::HeaderMap;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use structopt::StructOpt;

fn parse_scan_content_type(input_content: &str) -> Result<(), CliErrors> {
    let mut is_error = false;
    // Removing The Default Option
    block_on(async { SCAN_CONTENT_TYPE.lock().await.clear() });

    input_content.split(",").for_each(|the_scan_type| {
        if the_scan_type == "url" {
            block_on(async { SCAN_CONTENT_TYPE.lock().await.push(InjectionLocation::Url) });
        } else if the_scan_type == "body" {
            block_on(async { SCAN_CONTENT_TYPE.lock().await.push(InjectionLocation::Body) });
        } else if the_scan_type == "json" {
            block_on(async {
                SCAN_CONTENT_TYPE
                    .lock()
                    .await
                    .push(InjectionLocation::BodyJson)
            });
        } else if the_scan_type == "headers" {
            block_on(async {
                SCAN_CONTENT_TYPE
                    .lock()
                    .await
                    .push(InjectionLocation::Headers)
            });
        } else {
            is_error = true;
        }
    });
    if is_error {
        Err(CliErrors::UnsupportedScanType)
    } else {
        Ok(())
    }
}

fn read_resume_file(file_path: &str) -> Result<(), std::io::Error> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() != 2 {
            continue;
        }

        match parts[0] {
            "HTTP_SCAN_ID" => {
                let mut scan_id = block_on(LAST_HTTP_SCAN_ID.lock());
                *scan_id = parts[1].parse().unwrap_or(0);
            }
            "URL_SCAN_ID" => {
                let mut scan_id = block_on(LAST_URL_SCAN_ID.lock());
                *scan_id = parts[1].parse().unwrap_or(0);
            }
            "HOST_SCAN_ID" => {
                let mut scan_id = block_on(LAST_HOST_SCAN_ID.lock());
                *scan_id = parts[1].parse().unwrap_or(0);
            }
            "PATH_SCAN_ID" => {
                let mut scan_id = block_on(LAST_PATH_SCAN_ID.lock());
                *scan_id = parts[1].parse().unwrap_or(0);
            }
            "CUSTOM_SCAN_ID" => {
                let mut scan_id = block_on(LAST_CUSTOM_SCAN_ID.lock());
                *scan_id = parts[1].parse().unwrap_or(0);
            }
            _ => {}
        }
    }

    Ok(())
}

fn parse_headers(raw_headers: &str) -> Result<HeaderMap, serde_json::Error> {
    let parsed_json = serde_json::from_str::<HashMap<String, String>>(raw_headers);

    if let Err(..) = parsed_json {
        return Err(parsed_json.unwrap_err());
    }
    let mut user_headers = HeaderMap::new();
    user_headers.insert(
        HeaderName::from_bytes("User-agent".as_bytes()).unwrap(),
        HeaderValue::from_bytes(
            "Mozilla/5.0 (X11; Manjaro; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0"
                .as_bytes(),
        )
        .unwrap(),
    );
    parsed_json
        .unwrap()
        .iter()
        .for_each(|(headername, headervalue)| {
            user_headers.insert(
                HeaderName::from_bytes(headername.as_bytes()).unwrap(),
                HeaderValue::from_bytes(headervalue.as_bytes()).unwrap(),
            );
        });
    Ok(user_headers)
}
fn get_env_vars(env_vars_json: &str) -> Result<Value, serde_json::Error> {
    let parsed_vars = serde_json::from_str(env_vars_json)?;
    Ok(parsed_vars)
}

#[derive(Debug, StructOpt)]
#[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
pub struct UrlsOpts {
    /// Path to Lua script file or directory containing scripts
    /// 
    /// Can be a single .lua file or a directory. If directory,
    /// all .lua files will be loaded and executed.
    /// 
    /// Examples:
    ///   lotus scan xss_scanner.lua
    ///   lotus scan ./security_scripts/
    #[structopt(
        parse(from_os_str),
        help = "Lua script file or directory path",
        value_name = "SCRIPT_PATH"
    )]
    pub script_path: PathBuf,

    /// Save scan results to JSON file
    /// 
    /// Results are appended as newline-delimited JSON.
    /// Useful for processing results with other tools.
    #[structopt(
        short = "o",
        long = "output",
        parse(from_os_str),
        help = "Output JSON file for results",
        value_name = "FILE"
    )]
    pub output: Option<PathBuf>,

    /// Number of concurrent URL workers
    /// 
    /// Controls how many URLs are processed in parallel.
    /// Increase for faster scans, decrease if hitting rate limits.
    #[structopt(
        short = "w",
        long = "workers",
        default_value = "10",
        help = "Concurrent URL workers [default: 10]",
        value_name = "NUM"
    )]
    pub workers: usize,

    /// Number of concurrent fuzzing workers per URL
    /// 
    /// Used by ParamScan and LuaThreader for parallel payload testing.
    #[structopt(
        long = "fuzz-workers",
        default_value = "15",
        help = "Fuzzing workers per URL [default: 15]",
        value_name = "NUM"
    )]
    pub fuzz_workers: usize,

    /// Scripts to run concurrently per URL
    /// 
    /// When scanning with multiple scripts, this controls
    /// how many run simultaneously against each URL.
    #[structopt(
        long = "scripts-worker",
        short = "sw",
        default_value = "10",
        help = "Concurrent scripts per URL [default: 10]",
        value_name = "NUM"
    )]
    pub scripts_workers: usize,

    /// HTTP request timeout in seconds
    /// 
    /// Connections that exceed this timeout will fail.
    /// Increase for slow targets or time-based attacks.
    #[structopt(
        short = "t",
        long = "timeout",
        default_value = "10",
        help = "HTTP timeout in seconds [default: 10]",
        value_name = "SECS"
    )]
    pub timeout: u64,

    /// Maximum HTTP redirects to follow
    /// 
    /// Set to 0 to disable redirect following.
    #[structopt(
        short = "r",
        long = "redirects",
        default_value = "10",
        help = "Max redirects to follow [default: 10]",
        value_name = "NUM"
    )]
    pub redirects: u32,

    /// HTTP/SOCKS proxy URL
    /// 
    /// Route all requests through a proxy (e.g., Burp Suite).
    /// 
    /// Examples:
    ///   -p http://127.0.0.1:8080
    ///   -p socks5://127.0.0.1:9050
    #[structopt(
        short = "p",
        long = "proxy",
        help = "Proxy URL (http://host:port or socks5://host:port)",
        value_name = "URL"
    )]
    pub proxy: Option<String>,

    /// Enable verbose output
    /// 
    /// Shows HTTP requests being sent and detailed progress.
    /// Useful for debugging scripts.
    #[structopt(
        short = "v",
        long = "verbose",
        help = "Show detailed output and requests"
    )]
    pub verbose: bool,

    /// Read target URLs from file
    /// 
    /// One URL per line. Can be combined with stdin input.
    /// 
    /// Example:
    ///   lotus scan script.lua --urls targets.txt
    #[structopt(
        long = "urls",
        parse(from_os_str),
        help = "Read URLs from file (one per line)",
        value_name = "FILE"
    )]
    pub urls: Option<PathBuf>,

    /// Default HTTP headers as JSON
    /// 
    /// These headers are sent with every request.
    /// Script headers can override these.
    /// 
    /// Example:
    ///   --headers '{"Authorization": "Bearer token123"}'
    #[structopt(
        long = "headers",
        parse(try_from_str = parse_headers),
        default_value = "{}",
        help = "Default headers as JSON object",
        value_name = "JSON"
    )]
    pub headers: HeaderMap,

    /// Environment variables for Lua scripts
    /// 
    /// Accessible in scripts via ENV global table.
    /// Useful for passing configuration without modifying scripts.
    /// 
    /// Example:
    ///   --env-vars '{"API_KEY": "xxx", "DEBUG": "true"}'
    /// 
    /// In Lua:
    ///   local key = ENV.API_KEY
    #[structopt(
        long = "env-vars",
        parse(try_from_str = get_env_vars),
        default_value = "{}",
        help = "Variables for scripts as JSON",
        value_name = "JSON"
    )]
    pub env_vars: Value,

    /// Custom input handler Lua script
    /// 
    /// Transform stdin input before passing to main scripts.
    /// Must define a parse_input(input) function.
    /// 
    /// Example:
    ///   lotus scan main.lua --input-handler parser.lua
    #[structopt(
        long = "input-handler",
        parse(from_os_str),
        help = "Lua script to preprocess input",
        value_name = "FILE"
    )]
    pub input_handler: Option<PathBuf>,

    /// Content types to scan for full HTTP requests
    /// 
    /// Comma-separated list: url,body,json,headers
    /// Only applies when using SCAN_TYPE=5 (full HTTP)
    #[structopt(
        short = "c",
        long = "content-type",
        default_value = "url,body,headers",
        parse(try_from_str = parse_scan_content_type),
        help = "Scan locations: url,body,json,headers",
        value_name = "TYPES"
    )]
    pub _content_type: (),

    /// Rate limit: max requests before delay
    /// 
    /// After this many requests, the scanner pauses.
    /// Helps avoid triggering rate limits.
    #[structopt(
        long = "requests-limit",
        default_value = "2000",
        help = "Requests before rate limit delay",
        value_name = "NUM"
    )]
    pub requests_limit: i32,

    /// Delay after hitting request limit (seconds)
    #[structopt(
        long = "delay",
        default_value = "5",
        help = "Delay after request limit [default: 5s]",
        value_name = "SECS"
    )]
    pub delay: u64,

    /// Save debug logs to file
    /// 
    /// Contains detailed execution info for troubleshooting.
    /// Use with -v for maximum detail.
    #[structopt(
        long = "log",
        help = "Save debug logs to file",
        value_name = "FILE"
    )]
    pub log: Option<PathBuf>,

    /// Exit after N script errors
    /// 
    /// Prevents infinite loops on persistent errors.
    /// Set to 0 to disable.
    #[structopt(
        long = "exit-after-errors",
        default_value = "2000",
        help = "Exit after N errors [default: 2000]",
        value_name = "NUM"
    )]
    pub exit_after: i32,

    /// Resume scan from checkpoint file
    /// 
    /// Use the resume.cfg file from a previous interrupted scan.
    /// Lotus saves progress automatically during scans.
    /// 
    /// Example:
    ///   lotus scan script.lua --urls targets.txt --resume resume.cfg
    #[structopt(
        long = "resume",
        parse(try_from_str = read_resume_file),
        help = "Resume from checkpoint file",
        value_name = "FILE"
    )]
    _resume: Option<()>,
}
