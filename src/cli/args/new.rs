use crate::cli::errors::CliErrors;
use std::path::PathBuf;
use structopt::StructOpt;

fn get_script_type(script_type: &str) -> Result<ScriptType, CliErrors> {
    let script_type = match script_type.to_lowercase().as_str() {
        "fuzz" | "fuzzer" | "param" => ScriptType::Fuzz,
        "cve" | "vuln" | "vulnerability" => ScriptType::CVE,
        "service" | "osint" | "recon" => ScriptType::SERVICE,
        _ => ScriptType::NotSupported,
    };
    if script_type == ScriptType::NotSupported {
        Err(CliErrors::UnsupportedScript)
    } else {
        Ok(script_type)
    }
}

#[derive(Debug, PartialEq)]
pub enum ScriptType {
    Fuzz,
    CVE,
    SERVICE,
    NotSupported,
}

#[derive(Debug, StructOpt)]
#[structopt(setting = structopt::clap::AppSettings::ColoredHelp)]
pub struct NewOpts {
    /// Type of script template to generate
    /// 
    /// AVAILABLE TYPES:
    ///   fuzz    - Parameter fuzzing/injection scanner
    ///   cve     - CVE/vulnerability detection script
    ///   service - Service detection / OSINT reconnaissance
    /// 
    /// ALIASES:
    ///   fuzz: fuzzer, param
    ///   cve: vuln, vulnerability
    ///   service: osint, recon
    #[structopt(
        short = "s",
        long = "scan-type",
        parse(try_from_str = get_script_type),
        help = "Script type: fuzz, cve, or service",
        value_name = "TYPE"
    )]
    pub scan_type: ScriptType,

    /// Output file path for the generated script
    /// 
    /// Example:
    ///   lotus new -s fuzz -f my_scanner.lua
    #[structopt(
        short = "f",
        long = "file",
        help = "Output filename for new script",
        value_name = "FILE"
    )]
    pub file_name: PathBuf,
}
