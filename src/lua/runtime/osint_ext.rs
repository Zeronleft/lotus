use crate::lua::model::LuaRunTime;
use mlua::{UserData, Value};
use std::process::{Command, Stdio};

macro_rules! set_global_function {
    ($lua:expr, $name:expr, $func:expr) => {
        $lua.globals().set($name, $func).unwrap();
    };
}

// ============================================================================
// OsintResult - Wrapper for command execution results
// ============================================================================

#[derive(Clone, Debug)]
pub struct OsintResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

impl OsintResult {
    pub fn new(stdout: String, stderr: String, exit_code: i32) -> Self {
        Self {
            stdout,
            stderr,
            exit_code,
            success: exit_code == 0,
        }
    }
}

impl UserData for OsintResult {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method("stdout", |_, this, ()| Ok(this.stdout.clone()));
        methods.add_method("stderr", |_, this, ()| Ok(this.stderr.clone()));
        methods.add_method("exit_code", |_, this, ()| Ok(this.exit_code));
        methods.add_method("success", |_, this, ()| Ok(this.success));
        
        // Parse stdout as JSON
        methods.add_method("json", |lua, this, ()| {
            match serde_json::from_str::<serde_json::Value>(&this.stdout) {
                Ok(v) => {
                    let table = json_to_lua_value(lua, &v)?;
                    Ok(table)
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("JSON parse error: {}", e))),
            }
        });

        // Parse stdout as lines
        methods.add_method("lines", |lua, this, ()| {
            let table = lua.create_table()?;
            for (i, line) in this.stdout.lines().enumerate() {
                table.set(i + 1, line)?;
            }
            Ok(table)
        });
    }
}

// ============================================================================
// SpiderFootClient - SpiderFoot CLI integration
// ============================================================================

#[derive(Clone, Debug)]
pub struct SpiderFootClient {
    pub bin_path: String,
    pub api_url: Option<String>,
    pub api_key: Option<String>,
}

impl Default for SpiderFootClient {
    fn default() -> Self {
        Self {
            bin_path: "spiderfoot".to_string(),
            api_url: None,
            api_key: None,
        }
    }
}

impl UserData for SpiderFootClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        // Configure SpiderFoot path
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Configure API URL for SpiderFoot HX
        methods.add_method_mut("set_api", |_, this, (url, key): (String, Option<String>)| {
            this.api_url = Some(url);
            this.api_key = key;
            Ok(())
        });

        // Run a scan with SpiderFoot CLI
        methods.add_method("scan", |_, this, (target, modules): (String, Option<Vec<String>>)| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-s").arg(&target);
            
            if let Some(mods) = modules {
                cmd.arg("-m").arg(mods.join(","));
            }
            
            // Output as JSON
            cmd.arg("-o").arg("json");
            
            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("SpiderFoot error: {}", e))),
            }
        });

        // Get available modules
        methods.add_method("modules", |_, this, ()| {
            let output = Command::new(&this.bin_path)
                .arg("-M")
                .output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    let exit_code = out.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("SpiderFoot error: {}", e))),
            }
        });

        // Get available types/data elements
        methods.add_method("types", |_, this, ()| {
            let output = Command::new(&this.bin_path)
                .arg("-T")
                .output();

            match output {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    let exit_code = out.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("SpiderFoot error: {}", e))),
            }
        });
    }
}

// ============================================================================
// AmassClient - OWASP Amass CLI integration
// ============================================================================

#[derive(Clone, Debug)]
pub struct AmassClient {
    pub bin_path: String,
    pub config_path: Option<String>,
}

impl Default for AmassClient {
    fn default() -> Self {
        Self {
            bin_path: "amass".to_string(),
            config_path: None,
        }
    }
}

impl UserData for AmassClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        // Configure Amass path
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Set config file
        methods.add_method_mut("set_config", |_, this, path: String| {
            this.config_path = Some(path);
            Ok(())
        });

        // Run subdomain enumeration (amass enum)
        methods.add_method("enum", |_, this, opts: mlua::Table| {
            let domain: String = opts.get("domain")?;
            let passive: bool = opts.get("passive").unwrap_or(true);
            let timeout: Option<u64> = opts.get("timeout").ok();
            let output_file: Option<String> = opts.get("output").ok();

            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("enum");
            cmd.arg("-d").arg(&domain);

            if passive {
                cmd.arg("-passive");
            }

            if let Some(t) = timeout {
                cmd.arg("-timeout").arg(t.to_string());
            }

            if let Some(config) = &this.config_path {
                cmd.arg("-config").arg(config);
            }

            if let Some(out) = &output_file {
                cmd.arg("-o").arg(out);
            }

            // JSON output
            cmd.arg("-json").arg("-");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Amass error: {}", e))),
            }
        });

        // Run intelligence gathering (amass intel)
        methods.add_method("intel", |_, this, opts: mlua::Table| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("intel");

            if let Ok(domain) = opts.get::<_, String>("domain") {
                cmd.arg("-d").arg(domain);
            }

            if let Ok(org) = opts.get::<_, String>("org") {
                cmd.arg("-org").arg(org);
            }

            if let Ok(asn) = opts.get::<_, i64>("asn") {
                cmd.arg("-asn").arg(asn.to_string());
            }

            if let Ok(cidr) = opts.get::<_, String>("cidr") {
                cmd.arg("-cidr").arg(cidr);
            }

            if let Ok(whois) = opts.get::<_, bool>("whois") {
                if whois {
                    cmd.arg("-whois");
                }
            }

            if let Some(config) = &this.config_path {
                cmd.arg("-config").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Amass error: {}", e))),
            }
        });

        // Database operations (amass db)
        methods.add_method("db", |_, this, opts: mlua::Table| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("db");

            if let Ok(domain) = opts.get::<_, String>("domain") {
                cmd.arg("-d").arg(domain);
            }

            if let Ok(list) = opts.get::<_, bool>("list") {
                if list {
                    cmd.arg("-list");
                }
            }

            if let Ok(names) = opts.get::<_, bool>("names") {
                if names {
                    cmd.arg("-names");
                }
            }

            if let Ok(show) = opts.get::<_, bool>("show") {
                if show {
                    cmd.arg("-show");
                }
            }

            if let Some(config) = &this.config_path {
                cmd.arg("-config").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Amass error: {}", e))),
            }
        });
    }
}

// ============================================================================
// FinalReconClient - FinalRecon web reconnaissance tool integration
// https://github.com/thewhiteh4t/FinalRecon
// ============================================================================

#[derive(Clone, Debug)]
pub struct FinalReconClient {
    pub bin_path: String,
    pub output_dir: Option<String>,
}

impl Default for FinalReconClient {
    fn default() -> Self {
        Self {
            bin_path: "finalrecon".to_string(),
            output_dir: None,
        }
    }
}

impl UserData for FinalReconClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        // Configure FinalRecon path
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Set output directory
        methods.add_method_mut("set_output", |_, this, path: String| {
            this.output_dir = Some(path);
            Ok(())
        });

        // Full reconnaissance scan
        methods.add_method("full", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--full").arg("--url").arg(&url);
            
            if let Some(out) = &this.output_dir {
                cmd.arg("-o").arg(out);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // Header analysis
        methods.add_method("headers", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--headers").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // SSL certificate info
        methods.add_method("sslinfo", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--sslinfo").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // WHOIS lookup
        methods.add_method("whois", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--whois").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // Crawl website
        methods.add_method("crawl", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--crawl").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // DNS enumeration
        methods.add_method("dns", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--dns").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // Subdomain enumeration
        methods.add_method("sub", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--sub").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // Directory enumeration
        methods.add_method("dir", |_, this, (url, wordlist): (String, Option<String>)| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--dir").arg("--url").arg(&url);
            
            if let Some(wl) = wordlist {
                cmd.arg("-w").arg(wl);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // Port scan
        methods.add_method("ps", |_, this, (url, ports): (String, Option<String>)| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--ps").arg("--url").arg(&url);
            
            if let Some(p) = ports {
                cmd.arg("-p").arg(p);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // Wayback machine lookup
        methods.add_method("wayback", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--wayback").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });

        // Parameter discovery
        methods.add_method("param", |_, this, url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--ps").arg("--url").arg(&url);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("FinalRecon error: {}", e))),
            }
        });
    }
}

// ============================================================================
// SeekerClient - Seeker geolocation tool integration
// https://github.com/thewhiteh4t/seeker
// ============================================================================

#[derive(Clone, Debug)]
pub struct SeekerClient {
    pub bin_path: String,
    pub template: Option<String>,
}

impl Default for SeekerClient {
    fn default() -> Self {
        Self {
            bin_path: "seeker".to_string(),
            template: None,
        }
    }
}

impl UserData for SeekerClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        // Configure Seeker path
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Set template
        methods.add_method_mut("set_template", |_, this, template: String| {
            this.template = Some(template);
            Ok(())
        });

        // Run Seeker with ngrok
        methods.add_method("run_ngrok", |_, this, opts: mlua::Table| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-t").arg("manual");
            
            if let Some(template) = &this.template {
                cmd.arg("-k").arg(template);
            } else if let Ok(t) = opts.get::<_, String>("template") {
                cmd.arg("-k").arg(t);
            }
            
            if let Ok(port) = opts.get::<_, u16>("port") {
                cmd.arg("-p").arg(port.to_string());
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            // Note: Seeker runs as a server, this just starts it
            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Seeker error: {}", e))),
            }
        });

        // List available templates
        methods.add_method("templates", |_, this, ()| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--list");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Seeker error: {}", e))),
            }
        });
    }
}

// ============================================================================
// TheHarvesterClient - theHarvester OSINT tool integration
// ============================================================================

#[derive(Clone, Debug)]
pub struct TheHarvesterClient {
    pub bin_path: String,
}

impl Default for TheHarvesterClient {
    fn default() -> Self {
        Self {
            bin_path: "theHarvester".to_string(),
        }
    }
}

impl UserData for TheHarvesterClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Run harvest
        methods.add_method("harvest", |_, this, opts: mlua::Table| {
            let domain: String = opts.get("domain")?;
            let source: String = opts.get("source").unwrap_or_else(|_| "all".to_string());
            let limit: i32 = opts.get("limit").unwrap_or(500);

            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-d").arg(&domain)
               .arg("-b").arg(&source)
               .arg("-l").arg(limit.to_string());
            
            if let Ok(output_file) = opts.get::<_, String>("output") {
                cmd.arg("-f").arg(output_file);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("theHarvester error: {}", e))),
            }
        });
    }
}

// ============================================================================
// ShodanClient - Shodan CLI integration
// ============================================================================

#[derive(Clone, Debug)]
pub struct ShodanClient {
    pub bin_path: String,
    pub api_key: Option<String>,
}

impl Default for ShodanClient {
    fn default() -> Self {
        Self {
            bin_path: "shodan".to_string(),
            api_key: None,
        }
    }
}

impl UserData for ShodanClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        methods.add_method_mut("set_api_key", |_, this, key: String| {
            this.api_key = Some(key);
            Ok(())
        });

        // Initialize with API key
        methods.add_method("init", |_, this, key: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("init").arg(&key);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Shodan error: {}", e))),
            }
        });

        // Host lookup
        methods.add_method("host", |_, this, ip: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("host").arg(&ip);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Shodan error: {}", e))),
            }
        });

        // Search
        methods.add_method("search", |_, this, query: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("search").arg("--fields").arg("ip_str,port,org,hostnames").arg(&query);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Shodan error: {}", e))),
            }
        });

        // Domain lookup
        methods.add_method("domain", |_, this, domain: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("domain").arg(&domain);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Shodan error: {}", e))),
            }
        });

        // Get info about API plan
        methods.add_method("info", |_, this, ()| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("info");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Shodan error: {}", e))),
            }
        });
    }
}

// ============================================================================
// NucleiClient - ProjectDiscovery Nuclei integration
// ============================================================================

#[derive(Clone, Debug)]
pub struct NucleiClient {
    pub bin_path: String,
    pub templates_path: Option<String>,
}

impl Default for NucleiClient {
    fn default() -> Self {
        Self {
            bin_path: "nuclei".to_string(),
            templates_path: None,
        }
    }
}

impl UserData for NucleiClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        methods.add_method_mut("set_templates", |_, this, path: String| {
            this.templates_path = Some(path);
            Ok(())
        });

        // Run scan
        methods.add_method("scan", |_, this, opts: mlua::Table| {
            let target: String = opts.get("target")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-u").arg(&target).arg("-jsonl");
            
            if let Some(templates) = &this.templates_path {
                cmd.arg("-t").arg(templates);
            } else if let Ok(t) = opts.get::<_, String>("templates") {
                cmd.arg("-t").arg(t);
            }
            
            if let Ok(severity) = opts.get::<_, String>("severity") {
                cmd.arg("-s").arg(severity);
            }
            
            if let Ok(tags) = opts.get::<_, String>("tags") {
                cmd.arg("-tags").arg(tags);
            }
            
            if let Ok(rate_limit) = opts.get::<_, i32>("rate_limit") {
                cmd.arg("-rl").arg(rate_limit.to_string());
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Nuclei error: {}", e))),
            }
        });

        // Update templates
        methods.add_method("update", |_, this, ()| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-ut");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Nuclei error: {}", e))),
            }
        });
    }
}

// ============================================================================
// DNSMonsterClient - Passive DNS capture/monitoring integration
// https://github.com/mosajjal/dnsmonster
// ============================================================================

#[derive(Clone, Debug)]
pub struct DNSMonsterClient {
    pub bin_path: String,
    pub config_path: Option<String>,
}

impl Default for DNSMonsterClient {
    fn default() -> Self {
        Self {
            bin_path: "dnsmonster".to_string(),
            config_path: None,
        }
    }
}

impl UserData for DNSMonsterClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        methods.add_method_mut("set_config", |_, this, path: String| {
            this.config_path = Some(path);
            Ok(())
        });

        // Capture from interface
        methods.add_method("capture", |_, this, opts: mlua::Table| {
            let mut cmd = Command::new(&this.bin_path);
            
            if let Ok(interface) = opts.get::<_, String>("interface") {
                cmd.arg("--devName").arg(interface);
            }
            
            if let Ok(pcap_file) = opts.get::<_, String>("pcap") {
                cmd.arg("--pcapFile").arg(pcap_file);
            }
            
            if let Ok(output) = opts.get::<_, String>("output") {
                cmd.arg("--stdoutOutputType").arg(output); // json, csv, etc.
            } else {
                cmd.arg("--stdoutOutputType").arg("json");
            }
            
            if let Ok(filter) = opts.get::<_, String>("filter") {
                cmd.arg("--filter").arg(filter);
            }
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            // Set packet count limit if specified
            if let Ok(count) = opts.get::<_, i64>("count") {
                cmd.arg("--packetLimit").arg(count.to_string());
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("DNSMonster error: {}", e))),
            }
        });

        // Analyze PCAP file
        methods.add_method("analyze_pcap", |_, this, pcap_file: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--pcapFile").arg(&pcap_file)
               .arg("--stdoutOutputType").arg("json");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("DNSMonster error: {}", e))),
            }
        });
    }
}

// ============================================================================
// RITAClient - Real Intelligence Threat Analytics integration
// https://www.activecountermeasures.com/free-tools/rita/
// ============================================================================

#[derive(Clone, Debug)]
pub struct RITAClient {
    pub bin_path: String,
    pub config_path: Option<String>,
}

impl Default for RITAClient {
    fn default() -> Self {
        Self {
            bin_path: "rita".to_string(),
            config_path: None,
        }
    }
}

impl UserData for RITAClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        methods.add_method_mut("set_config", |_, this, path: String| {
            this.config_path = Some(path);
            Ok(())
        });

        // Import Zeek/Bro logs
        methods.add_method("import", |_, this, opts: mlua::Table| {
            let logs_path: String = opts.get("logs")?;
            let database: String = opts.get("database")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("import");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            if let Ok(rolling) = opts.get::<_, bool>("rolling") {
                if rolling {
                    cmd.arg("--rolling");
                }
            }
            
            cmd.arg(&logs_path).arg(&database);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // Show beacons (C2 detection)
        methods.add_method("show_beacons", |_, this, database: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("show-beacons");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            cmd.arg("-H") // Human readable
               .arg(&database);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // Show DNS beacons
        methods.add_method("show_dns_beacons", |_, this, database: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("show-dns-beacons");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            cmd.arg("-H").arg(&database);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // Show long connections
        methods.add_method("show_long_connections", |_, this, database: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("show-long-connections");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            cmd.arg("-H").arg(&database);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // Show strobes (port scanning detection)
        methods.add_method("show_strobes", |_, this, database: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("show-strobes");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            cmd.arg("-H").arg(&database);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // Show blacklisted connections
        methods.add_method("show_bl_hostnames", |_, this, database: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("show-bl-hostnames");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            cmd.arg("-H").arg(&database);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // Show user agents
        methods.add_method("show_useragents", |_, this, database: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("show-useragents");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            cmd.arg("-H").arg(&database);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // Generate HTML report
        methods.add_method("html_report", |_, this, (database, output_path): (String, String)| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("html-report");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }
            
            cmd.arg(&database).arg(&output_path);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });

        // List databases
        methods.add_method("list_databases", |_, this, ()| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("show-databases");
            
            if let Some(config) = &this.config_path {
                cmd.arg("--config").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("RITA error: {}", e))),
            }
        });
    }
}

// ============================================================================
// ZeekClient - Zeek/Bro network analysis integration
// ============================================================================

#[derive(Clone, Debug)]
pub struct ZeekClient {
    pub bin_path: String,
}

impl Default for ZeekClient {
    fn default() -> Self {
        Self {
            bin_path: "zeek".to_string(),
        }
    }
}

impl UserData for ZeekClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Analyze PCAP file
        methods.add_method("analyze", |_, this, opts: mlua::Table| {
            let pcap_file: String = opts.get("pcap")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-r").arg(&pcap_file);
            
            if let Ok(scripts) = opts.get::<_, Vec<String>>("scripts") {
                for script in scripts {
                    cmd.arg(&script);
                }
            }
            
            if let Ok(output_dir) = opts.get::<_, String>("output_dir") {
                cmd.current_dir(&output_dir);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Zeek error: {}", e))),
            }
        });

        // Live capture
        methods.add_method("capture", |_, this, interface: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-i").arg(&interface);

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Zeek error: {}", e))),
            }
        });
    }
}

// ============================================================================
// BBOTClient - Black Lantern Security BBOT OSINT automation
// https://github.com/blacklanternsecurity/bbot
// ============================================================================

#[derive(Clone, Debug)]
pub struct BBOTClient {
    pub bin_path: String,
    pub config_path: Option<String>,
}

impl Default for BBOTClient {
    fn default() -> Self {
        Self {
            bin_path: "bbot".to_string(),
            config_path: None,
        }
    }
}

impl UserData for BBOTClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        methods.add_method_mut("set_config", |_, this, path: String| {
            this.config_path = Some(path);
            Ok(())
        });

        // Run a scan with specified presets/modules
        methods.add_method("scan", |_, this, opts: mlua::Table| {
            let target: String = opts.get("target")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-t").arg(&target);
            
            // Preset (subdomain-enum, web-basic, web-thorough, etc.)
            if let Ok(preset) = opts.get::<_, String>("preset") {
                cmd.arg("-p").arg(preset);
            }
            
            // Specific modules
            if let Ok(modules) = opts.get::<_, Vec<String>>("modules") {
                cmd.arg("-m").arg(modules.join(","));
            }
            
            // Flags
            if let Ok(flags) = opts.get::<_, Vec<String>>("flags") {
                cmd.arg("-f").arg(flags.join(","));
            }
            
            // Output directory
            if let Ok(output) = opts.get::<_, String>("output") {
                cmd.arg("-o").arg(output);
            }
            
            // Output format (json, csv, etc.)
            if let Ok(format) = opts.get::<_, String>("format") {
                cmd.arg("--output-format").arg(format);
            } else {
                cmd.arg("--output-format").arg("json");
            }
            
            // Scan name
            if let Ok(name) = opts.get::<_, String>("name") {
                cmd.arg("-n").arg(name);
            }
            
            // Strict scope
            if let Ok(strict) = opts.get::<_, bool>("strict_scope") {
                if strict {
                    cmd.arg("--strict-scope");
                }
            }
            
            // Config file
            if let Some(config) = &this.config_path {
                cmd.arg("-c").arg(config);
            } else if let Ok(config) = opts.get::<_, String>("config") {
                cmd.arg("-c").arg(config);
            }
            
            // Yes to all prompts
            cmd.arg("-y");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });

        // Subdomain enumeration preset
        methods.add_method("subdomain_enum", |_, this, target: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-t").arg(&target)
               .arg("-p").arg("subdomain-enum")
               .arg("--output-format").arg("json")
               .arg("-y");

            if let Some(config) = &this.config_path {
                cmd.arg("-c").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });

        // Web reconnaissance preset
        methods.add_method("web_recon", |_, this, (target, thorough): (String, Option<bool>)| {
            let preset = if thorough.unwrap_or(false) { "web-thorough" } else { "web-basic" };
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-t").arg(&target)
               .arg("-p").arg(preset)
               .arg("--output-format").arg("json")
               .arg("-y");

            if let Some(config) = &this.config_path {
                cmd.arg("-c").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });

        // Cloud enumeration
        methods.add_method("cloud_enum", |_, this, target: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-t").arg(&target)
               .arg("-p").arg("cloud-enum")
               .arg("--output-format").arg("json")
               .arg("-y");

            if let Some(config) = &this.config_path {
                cmd.arg("-c").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });

        // Email enumeration
        methods.add_method("email_enum", |_, this, target: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-t").arg(&target)
               .arg("-p").arg("email-enum")
               .arg("--output-format").arg("json")
               .arg("-y");

            if let Some(config) = &this.config_path {
                cmd.arg("-c").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });

        // List available modules
        methods.add_method("list_modules", |_, this, ()| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--list-modules");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });

        // List available presets
        methods.add_method("list_presets", |_, this, ()| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("--list-presets");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });

        // Run specific modules
        methods.add_method("run_modules", |_, this, (target, modules): (String, Vec<String>)| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-t").arg(&target)
               .arg("-m").arg(modules.join(","))
               .arg("--output-format").arg("json")
               .arg("-y");

            if let Some(config) = &this.config_path {
                cmd.arg("-c").arg(config);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BBOT error: {}", e))),
            }
        });
    }
}

// ============================================================================
// SubfinderClient - Fast subdomain discovery tool
// https://github.com/projectdiscovery/subfinder
// ============================================================================

#[derive(Clone, Debug)]
pub struct SubfinderClient {
    pub bin_path: String,
}

impl Default for SubfinderClient {
    fn default() -> Self {
        Self {
            bin_path: "subfinder".to_string(),
        }
    }
}

impl UserData for SubfinderClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Run subdomain enumeration
        methods.add_method("enum", |_, this, opts: mlua::Table| {
            let domain: String = opts.get("domain")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-d").arg(&domain).arg("-silent");
            
            if let Ok(output) = opts.get::<_, String>("output") {
                cmd.arg("-o").arg(output);
            }
            
            if let Ok(json) = opts.get::<_, bool>("json") {
                if json {
                    cmd.arg("-oJ");
                }
            }
            
            if let Ok(sources) = opts.get::<_, Vec<String>>("sources") {
                cmd.arg("-sources").arg(sources.join(","));
            }
            
            if let Ok(recursive) = opts.get::<_, bool>("recursive") {
                if recursive {
                    cmd.arg("-recursive");
                }
            }
            
            if let Ok(all) = opts.get::<_, bool>("all") {
                if all {
                    cmd.arg("-all");
                }
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Subfinder error: {}", e))),
            }
        });
    }
}

// ============================================================================
// HttpxClient - Fast HTTP toolkit
// https://github.com/projectdiscovery/httpx
// ============================================================================

#[derive(Clone, Debug)]
pub struct HttpxClient {
    pub bin_path: String,
}

impl Default for HttpxClient {
    fn default() -> Self {
        Self {
            bin_path: "httpx".to_string(),
        }
    }
}

impl UserData for HttpxClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Probe URLs
        methods.add_method("probe", |_, this, opts: mlua::Table| {
            let mut cmd = Command::new(&this.bin_path);
            
            if let Ok(target) = opts.get::<_, String>("target") {
                cmd.arg("-u").arg(target);
            } else if let Ok(list) = opts.get::<_, String>("list") {
                cmd.arg("-l").arg(list);
            }
            
            cmd.arg("-silent");
            
            if let Ok(json) = opts.get::<_, bool>("json") {
                if json {
                    cmd.arg("-json");
                }
            }
            
            if let Ok(status) = opts.get::<_, bool>("status_code") {
                if status {
                    cmd.arg("-status-code");
                }
            }
            
            if let Ok(title) = opts.get::<_, bool>("title") {
                if title {
                    cmd.arg("-title");
                }
            }
            
            if let Ok(tech) = opts.get::<_, bool>("tech_detect") {
                if tech {
                    cmd.arg("-tech-detect");
                }
            }
            
            if let Ok(screenshot) = opts.get::<_, bool>("screenshot") {
                if screenshot {
                    cmd.arg("-screenshot");
                }
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("httpx error: {}", e))),
            }
        });
    }
}

// ============================================================================
// BrokenHillClient - BishopFox LLM Red Teaming Tool
// https://github.com/BishopFox/BrokenHill
// ============================================================================

#[derive(Clone, Debug)]
pub struct BrokenHillClient {
    pub bin_path: String,
    pub model_path: Option<String>,
}

impl Default for BrokenHillClient {
    fn default() -> Self {
        Self {
            bin_path: "python".to_string(),  // BrokenHill is a Python tool
            model_path: None,
        }
    }
}

impl UserData for BrokenHillClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        methods.add_method_mut("set_model", |_, this, path: String| {
            this.model_path = Some(path);
            Ok(())
        });

        // Run GCG attack (Greedy Coordinate Gradient)
        methods.add_method("gcg_attack", |_, this, opts: mlua::Table| {
            let target_prompt: String = opts.get("target")?;
            let goal: String = opts.get("goal")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-m").arg("brokenhill");
            cmd.arg("--attack-type").arg("gcg");
            cmd.arg("--target-prompt").arg(&target_prompt);
            cmd.arg("--goal").arg(&goal);
            
            if let Some(model) = &this.model_path {
                cmd.arg("--model").arg(model);
            } else if let Ok(model) = opts.get::<_, String>("model") {
                cmd.arg("--model").arg(model);
            }
            
            if let Ok(iterations) = opts.get::<_, i32>("iterations") {
                cmd.arg("--iterations").arg(iterations.to_string());
            }
            
            if let Ok(output) = opts.get::<_, String>("output") {
                cmd.arg("--output").arg(output);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BrokenHill error: {}", e))),
            }
        });

        // Run prompt injection test
        methods.add_method("test_injection", |_, this, opts: mlua::Table| {
            let prompt: String = opts.get("prompt")?;
            let payload: String = opts.get("payload")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("-m").arg("brokenhill");
            cmd.arg("--attack-type").arg("injection");
            cmd.arg("--prompt").arg(&prompt);
            cmd.arg("--payload").arg(&payload);
            
            if let Some(model) = &this.model_path {
                cmd.arg("--model").arg(model);
            } else if let Ok(model) = opts.get::<_, String>("model") {
                cmd.arg("--model").arg(model);
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("BrokenHill error: {}", e))),
            }
        });
    }
}

// ============================================================================
// GitleaksClient - Secret scanning in git repos
// https://github.com/gitleaks/gitleaks
// ============================================================================

#[derive(Clone, Debug)]
pub struct GitleaksClient {
    pub bin_path: String,
}

impl Default for GitleaksClient {
    fn default() -> Self {
        Self {
            bin_path: "gitleaks".to_string(),
        }
    }
}

impl UserData for GitleaksClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Detect secrets in a directory
        methods.add_method("detect", |_, this, opts: mlua::Table| {
            let path: String = opts.get("path")?;
            
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("detect").arg("--source").arg(&path);
            
            if let Ok(output) = opts.get::<_, String>("report") {
                cmd.arg("--report-path").arg(output);
            }
            
            if let Ok(format) = opts.get::<_, String>("format") {
                cmd.arg("--report-format").arg(format);
            } else {
                cmd.arg("--report-format").arg("json");
            }
            
            if let Ok(config) = opts.get::<_, String>("config") {
                cmd.arg("--config").arg(config);
            }
            
            if let Ok(verbose) = opts.get::<_, bool>("verbose") {
                if verbose {
                    cmd.arg("--verbose");
                }
            }

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Gitleaks error: {}", e))),
            }
        });

        // Scan git history
        methods.add_method("detect_git", |_, this, repo_path: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("detect")
               .arg("--source").arg(&repo_path)
               .arg("--report-format").arg("json")
               .arg("--log-opts").arg("--all");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Gitleaks error: {}", e))),
            }
        });
    }
}

// ============================================================================
// TruffleHogClient - Secret scanning
// https://github.com/trufflesecurity/trufflehog
// ============================================================================

#[derive(Clone, Debug)]
pub struct TruffleHogClient {
    pub bin_path: String,
}

impl Default for TruffleHogClient {
    fn default() -> Self {
        Self {
            bin_path: "trufflehog".to_string(),
        }
    }
}

impl UserData for TruffleHogClient {
    fn add_methods<'lua, M: mlua::UserDataMethods<'lua, Self>>(methods: &mut M) {
        methods.add_method_mut("set_path", |_, this, path: String| {
            this.bin_path = path;
            Ok(())
        });

        // Scan git repo
        methods.add_method("git", |_, this, repo_url: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("git").arg(&repo_url).arg("--json");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("TruffleHog error: {}", e))),
            }
        });

        // Scan GitHub org
        methods.add_method("github", |_, this, org: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("github").arg("--org").arg(&org).arg("--json");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("TruffleHog error: {}", e))),
            }
        });

        // Scan filesystem
        methods.add_method("filesystem", |_, this, path: String| {
            let mut cmd = Command::new(&this.bin_path);
            cmd.arg("filesystem").arg(&path).arg("--json");

            cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());

            match cmd.output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let exit_code = output.status.code().unwrap_or(-1);
                    Ok(OsintResult::new(stdout, stderr, exit_code))
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("TruffleHog error: {}", e))),
            }
        });
    }
}

// ============================================================================
// OsintEXT trait implementation
// ============================================================================

pub trait OsintEXT {
    fn add_osint_funcs(&self);
}

impl OsintEXT for LuaRunTime<'_> {
    fn add_osint_funcs(&self) {
        // ====================================================
        // Shell command execution
        // ====================================================

        // exec(cmd) or exec{cmd="...", args={...}, timeout=30}
        set_global_function!(
            self.lua,
            "exec",
            self.lua.create_function(|_, opts: Value| {
                match opts {
                    Value::String(cmd_str) => {
                        let cmd = cmd_str.to_str().unwrap_or("");
                        execute_shell_command(cmd, vec![], None)
                    }
                    Value::Table(table) => {
                        let cmd: String = table.get("cmd")?;
                        let args: Vec<String> = table.get("args").unwrap_or_default();
                        let timeout: Option<u64> = table.get("timeout").ok();
                        execute_shell_command(&cmd, args, timeout)
                    }
                    _ => Err(mlua::Error::RuntimeError("exec requires string or table".to_string())),
                }
            }).unwrap()
        );

        // exec_async - execute and return immediately (for long-running commands)
        set_global_function!(
            self.lua,
            "exec_bg",
            self.lua.create_function(|_, (cmd, args): (String, Option<Vec<String>>)| {
                let args = args.unwrap_or_default();
                match Command::new(&cmd)
                    .args(&args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn() 
                {
                    Ok(child) => Ok(child.id()),
                    Err(e) => Err(mlua::Error::RuntimeError(format!("exec_bg error: {}", e))),
                }
            }).unwrap()
        );

        // ====================================================
        // File operations for OSINT data
        // ====================================================

        // read_json(path) - Read and parse JSON file
        set_global_function!(
            self.lua,
            "read_json",
            self.lua.create_function(|lua, path: String| {
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        match serde_json::from_str::<serde_json::Value>(&content) {
                            Ok(v) => json_to_lua_value(lua, &v),
                            Err(e) => Err(mlua::Error::RuntimeError(format!("JSON parse error: {}", e))),
                        }
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("File read error: {}", e))),
                }
            }).unwrap()
        );

        // write_json(path, data) - Write Lua table as JSON
        set_global_function!(
            self.lua,
            "write_json",
            self.lua.create_function(|_, (path, data): (String, Value)| {
                let json_value = lua_value_to_json(data)?;
                let content = serde_json::to_string_pretty(&json_value)
                    .map_err(|e| mlua::Error::RuntimeError(format!("JSON encode error: {}", e)))?;
                std::fs::write(&path, content)
                    .map_err(|e| mlua::Error::RuntimeError(format!("File write error: {}", e)))?;
                Ok(())
            }).unwrap()
        );

        // append_file(path, content) - Append to file
        set_global_function!(
            self.lua,
            "append_file",
            self.lua.create_function(|_, (path, content): (String, String)| {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .map_err(|e| mlua::Error::RuntimeError(format!("File open error: {}", e)))?;
                writeln!(file, "{}", content)
                    .map_err(|e| mlua::Error::RuntimeError(format!("File write error: {}", e)))?;
                Ok(())
            }).unwrap()
        );

        // ====================================================
        // DNS/Network utilities for OSINT
        // ====================================================

        // dns_lookup(domain) - Basic DNS lookup
        set_global_function!(
            self.lua,
            "dns_lookup",
            self.lua.create_function(|lua, domain: String| {
                let output = Command::new("dig")
                    .args(["+short", &domain])
                    .output();

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        let table = lua.create_table()?;
                        for (i, line) in stdout.lines().enumerate() {
                            if !line.is_empty() {
                                table.set(i + 1, line)?;
                            }
                        }
                        Ok(table)
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("DNS lookup error: {}", e))),
                }
            }).unwrap()
        );

        // reverse_dns(ip) - Reverse DNS lookup
        set_global_function!(
            self.lua,
            "reverse_dns",
            self.lua.create_function(|_, ip: String| {
                let output = Command::new("dig")
                    .args(["+short", "-x", &ip])
                    .output();

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        Ok(stdout)
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("Reverse DNS error: {}", e))),
                }
            }).unwrap()
        );

        // whois(target) - WHOIS lookup
        set_global_function!(
            self.lua,
            "whois",
            self.lua.create_function(|_, target: String| {
                let output = Command::new("whois")
                    .arg(&target)
                    .output();

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                        let exit_code = out.status.code().unwrap_or(-1);
                        Ok(OsintResult::new(stdout, stderr, exit_code))
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("WHOIS error: {}", e))),
                }
            }).unwrap()
        );

        // ====================================================
        // OSINT Tool Clients
        // ====================================================

        // SpiderFoot client - Automated OSINT
        set_global_function!(
            self.lua,
            "SpiderFoot",
            SpiderFootClient::default()
        );

        // Amass client - Subdomain enumeration
        set_global_function!(
            self.lua,
            "Amass",
            AmassClient::default()
        );

        // FinalRecon client - Web reconnaissance
        set_global_function!(
            self.lua,
            "FinalRecon",
            FinalReconClient::default()
        );

        // Seeker client - Geolocation
        set_global_function!(
            self.lua,
            "Seeker",
            SeekerClient::default()
        );

        // theHarvester client - Email/subdomain harvesting
        set_global_function!(
            self.lua,
            "TheHarvester",
            TheHarvesterClient::default()
        );

        // Shodan client - Internet device search
        set_global_function!(
            self.lua,
            "Shodan",
            ShodanClient::default()
        );

        // Nuclei client - Vulnerability scanning
        set_global_function!(
            self.lua,
            "Nuclei",
            NucleiClient::default()
        );

        // DNSMonster client - Passive DNS monitoring
        set_global_function!(
            self.lua,
            "DNSMonster",
            DNSMonsterClient::default()
        );

        // RITA client - Threat detection/C2 analysis
        set_global_function!(
            self.lua,
            "RITA",
            RITAClient::default()
        );

        // Zeek client - Network analysis
        set_global_function!(
            self.lua,
            "Zeek",
            ZeekClient::default()
        );

        // BBOT client - Recursive OSINT automation
        set_global_function!(
            self.lua,
            "BBOT",
            BBOTClient::default()
        );

        // Subfinder client - Fast subdomain discovery
        set_global_function!(
            self.lua,
            "Subfinder",
            SubfinderClient::default()
        );

        // Httpx client - HTTP probing toolkit
        set_global_function!(
            self.lua,
            "Httpx",
            HttpxClient::default()
        );

        // BrokenHill client - LLM red teaming
        set_global_function!(
            self.lua,
            "BrokenHill",
            BrokenHillClient::default()
        );

        // Gitleaks client - Secret scanning
        set_global_function!(
            self.lua,
            "Gitleaks",
            GitleaksClient::default()
        );

        // TruffleHog client - Secret scanning
        set_global_function!(
            self.lua,
            "TruffleHog",
            TruffleHogClient::default()
        );

        // ====================================================
        // Environment & Configuration helpers
        // ====================================================

        // getenv(name) - Get environment variable
        set_global_function!(
            self.lua,
            "getenv",
            self.lua.create_function(|_, name: String| {
                Ok(std::env::var(&name).ok())
            }).unwrap()
        );

        // setenv(name, value) - Set environment variable (for child processes)
        set_global_function!(
            self.lua,
            "setenv",
            self.lua.create_function(|_, (name, value): (String, String)| {
                std::env::set_var(&name, &value);
                Ok(())
            }).unwrap()
        );

        // file_exists(path) - Check if file exists
        set_global_function!(
            self.lua,
            "file_exists",
            self.lua.create_function(|_, path: String| {
                Ok(std::path::Path::new(&path).exists())
            }).unwrap()
        );

        // mkdir(path) - Create directory (with parents)
        set_global_function!(
            self.lua,
            "mkdir",
            self.lua.create_function(|_, path: String| {
                std::fs::create_dir_all(&path)
                    .map_err(|e| mlua::Error::RuntimeError(format!("mkdir error: {}", e)))?;
                Ok(())
            }).unwrap()
        );

        // timestamp() - Get current Unix timestamp
        set_global_function!(
            self.lua,
            "timestamp",
            self.lua.create_function(|_, ()| {
                Ok(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs())
            }).unwrap()
        );

        // uuid() - Generate a UUID
        set_global_function!(
            self.lua,
            "uuid",
            self.lua.create_function(|_, ()| {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let uuid = format!(
                    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                    rng.gen::<u32>(),
                    rng.gen::<u16>(),
                    (rng.gen::<u16>() & 0x0fff) | 0x4000, // Version 4
                    (rng.gen::<u16>() & 0x3fff) | 0x8000, // Variant
                    rng.gen::<u64>() & 0xffffffffffff
                );
                Ok(uuid)
            }).unwrap()
        );
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn execute_shell_command(cmd: &str, args: Vec<String>, _timeout_secs: Option<u64>) -> Result<OsintResult, mlua::Error> {
    let mut command = if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(cmd);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    };

    for arg in args {
        command.arg(arg);
    }

    command.stdout(Stdio::piped())
           .stderr(Stdio::piped());

    match command.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);
            Ok(OsintResult::new(stdout, stderr, exit_code))
        }
        Err(e) => Err(mlua::Error::RuntimeError(format!("Command execution error: {}", e))),
    }
}

fn json_to_lua_value<'lua>(lua: &'lua mlua::Lua, value: &serde_json::Value) -> Result<Value<'lua>, mlua::Error> {
    match value {
        serde_json::Value::Null => Ok(Value::Nil),
        serde_json::Value::Bool(b) => Ok(Value::Boolean(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::Number(f))
            } else {
                Err(mlua::Error::RuntimeError("Invalid JSON number".to_string()))
            }
        }
        serde_json::Value::String(s) => Ok(Value::String(lua.create_string(s)?)),
        serde_json::Value::Array(arr) => {
            let table = lua.create_table()?;
            for (i, val) in arr.iter().enumerate() {
                table.set(i + 1, json_to_lua_value(lua, val)?)?;
            }
            Ok(Value::Table(table))
        }
        serde_json::Value::Object(obj) => {
            let table = lua.create_table()?;
            for (key, val) in obj.iter() {
                table.set(key.as_str(), json_to_lua_value(lua, val)?)?;
            }
            Ok(Value::Table(table))
        }
    }
}

fn lua_value_to_json(value: Value) -> Result<serde_json::Value, mlua::Error> {
    match value {
        Value::Nil => Ok(serde_json::Value::Null),
        Value::Boolean(b) => Ok(serde_json::Value::Bool(b)),
        Value::Integer(i) => Ok(serde_json::Value::Number(i.into())),
        Value::Number(n) => {
            if let Some(num) = serde_json::Number::from_f64(n) {
                Ok(serde_json::Value::Number(num))
            } else {
                Err(mlua::Error::RuntimeError("Invalid number for JSON".to_string()))
            }
        }
        Value::String(s) => Ok(serde_json::Value::String(s.to_str()?.to_string())),
        Value::Table(table) => {
            let mut is_array = true;
            let mut max_index = 0i64;
            for pair in table.clone().pairs::<Value, Value>() {
                let (key, _) = pair?;
                match key {
                    Value::Integer(i) if i > 0 => {
                        if i > max_index { max_index = i; }
                    }
                    _ => { is_array = false; break; }
                }
            }

            if is_array && max_index > 0 {
                let mut arr = Vec::new();
                for i in 1..=max_index {
                    let val: Value = table.get(i)?;
                    arr.push(lua_value_to_json(val)?);
                }
                Ok(serde_json::Value::Array(arr))
            } else {
                let mut map = serde_json::Map::new();
                for pair in table.pairs::<Value, Value>() {
                    let (key, val) = pair?;
                    let key_str = match key {
                        Value::String(s) => s.to_str()?.to_string(),
                        Value::Integer(i) => i.to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => return Err(mlua::Error::RuntimeError("JSON object keys must be strings".to_string())),
                    };
                    map.insert(key_str, lua_value_to_json(val)?);
                }
                Ok(serde_json::Value::Object(map))
            }
        }
        _ => Err(mlua::Error::RuntimeError("Cannot convert value to JSON".to_string())),
    }
}
