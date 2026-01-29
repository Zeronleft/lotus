use crate::cli::input::parse_requests::FullRequest;
use crate::lua::runtime::{encode_ext::EncodeEXT, http_ext::HTTPEXT, osint_ext::OsintEXT, secrets_ext::SecretsEXT, utils_ext::UtilsEXT};
use crate::utils::bar::GLOBAL_PROGRESS_BAR;
use crate::{
    lua::{
        model::{LuaOptions, LuaRunTime},
        network::http::Sender,
        output::report::AllReports,
    },
    RequestOpts, ScanTypes,
};
use mlua::{Lua, LuaSerdeExt};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone)]
pub struct LuaLoader {
    output_dir: Option<PathBuf>,
    request: RequestOpts,
}

macro_rules! set_global_value {
    ($lua:expr, $name:expr, $value:expr) => {
        $lua.globals().set($name, $value).unwrap();
    };
}

macro_rules! set_http_sender {
    ($lua:expr, $request:expr) => {
        $lua.globals()
            .set(
                "http",
                Sender::init(
                    $request.headers.clone(),
                    $request.proxy.clone(),
                    $request.timeout,
                    $request.redirects,
                ),
            )
            .unwrap();
    };
}

/// Start Lotus by adding the ProgressBar and http request options
/// * `request` - Request Options
/// * `output_dir` - output file
impl LuaLoader {
    pub fn new(request: RequestOpts, output_dir: Option<PathBuf>) -> LuaLoader {
        Self {
            output_dir,
            request,
        }
    }

    fn set_lua(&self, target_url: Option<&str>, fullhttp_msg: Option<FullRequest>, lua: &Lua) {
        let lua_eng = LuaRunTime { lua };
        lua_eng.add_httpfuncs(target_url, fullhttp_msg);
        lua_eng.add_encode_function();
        lua_eng.add_printfunc();
        lua_eng.add_matchingfunc();
        lua_eng.add_threadsfunc();
        lua_eng.add_osint_funcs();
        lua_eng.add_secrets_funcs();
        set_global_value!(
            lua,
            "ERR_STRING",
            lua.create_function(|_, error: mlua::Error| Ok(error.to_string()))
                .unwrap()
        );
        set_http_sender!(lua, self.request);
    }

    fn write_report(&self, results: &str) {
        OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(self.output_dir.as_ref().unwrap())
            .expect("Could not open file")
            .write_all(format!("{}\n", results).as_str().as_bytes())
            .expect("Could not write to file");
    }

    pub async fn run_scan<'a>(&self, lua_opts: LuaOptions<'_>) -> Result<(), mlua::Error> {
        let lua = unsafe { Lua::unsafe_new_with(mlua::StdLib::ALL_SAFE, mlua::LuaOptions::new()) };
        let env_vars: mlua::Value = lua.to_value(&lua_opts.env_vars).unwrap();

        set_global_value!(lua, "ENV", env_vars);
        set_global_value!(lua, "SCRIPT_PATH", lua_opts.script_dir);
        set_global_value!(lua, "FUZZ_WORKERS", lua_opts.fuzz_workers);

        match lua_opts.target_type {
            ScanTypes::FULL_HTTP => {
                let request_value: FullRequest =
                    serde_json::from_value(lua_opts.target_url.unwrap().clone()).unwrap();
                self.set_lua(None, Some(request_value), &lua);
            }
            ScanTypes::HOSTS => {
                self.set_lua(None, None, &lua);
                set_global_value!(
                    lua,
                    "INPUT_DATA",
                    lua_opts.target_url.unwrap().as_str().unwrap().to_string()
                );
            }
            ScanTypes::URLS | ScanTypes::PATHS => {
                self.set_lua(
                    Some(&lua_opts.target_url.unwrap().as_str().unwrap().to_string()),
                    None,
                    &lua,
                );
            }
            ScanTypes::CUSTOM => {
                let serde_value = serde_json::to_value(lua_opts.target_url).unwrap();
                set_global_value!(lua, "INPUT_DATA", lua.to_value(&serde_value).unwrap());
                self.set_lua(None, None, &lua);
            }
        };

        let run_code = lua.load(lua_opts.script_code).exec_async().await;

        if let Err(e) = run_code {
            let error_msg = format!("An error occurred while running the script:\n\n{}\n\nPlease check the script code and try again.", e);
            {
                let bar = GLOBAL_PROGRESS_BAR.lock().unwrap().clone().unwrap();
                bar.inc(1);
                log::error!("{}", error_msg);
            };
            return Err(e);
        }

        if let Err(e) = self.execute_main_function(&lua, &lua_opts.script_dir).await {
            let msg = format!("[{}] Script Error: {:?}", lua_opts.script_dir, e);
            log::error!("{}", msg);
        }

        Ok(())
    }

    async fn execute_main_function(&self, lua: &Lua, script_dir: &str) -> Result<(), mlua::Error> {
        let main_func = lua.globals().get::<_, mlua::Function>("main");

        if main_func.is_err() {
            let msg = format!("The script in directory [{}] does not contain a main function.\n\nThe main function is required to execute the script. Please make sure that the script contains a main function and try again.", script_dir);
            log::error!("{}", msg);
            return Ok(());
        }

        log::debug!("Calling the main function: {}", script_dir);
        let run_scan = main_func
            .unwrap()
            .call_async::<_, mlua::Value>(mlua::Value::Nil)
            .await;

        {
            GLOBAL_PROGRESS_BAR.lock().unwrap().clone().unwrap().inc(1)
        };

        if let Err(e) = run_scan {
            let msg = format!("[{}] Script Error: {:?}", script_dir, e);
            log::error!("{}", msg);
        } else {
            self.process_script_report(lua, script_dir).await;
        }

        Ok(())
    }

    async fn process_script_report(&self, lua: &Lua, script_dir: &str) {
        let script_report = lua.globals().get::<_, AllReports>("Reports").unwrap();

        if !script_report.reports.is_empty() {
            let results = serde_json::to_string(&script_report.reports).unwrap();
            let report_count = script_report.reports.len();
            let log_message = format!(
                "The script in directory [{}] generated {} report(s):\n\n{}\n\n",
                script_dir, report_count, results
            );
            log::debug!("{}", log_message);
            if self.output_dir.is_some() {
                self.write_report(&results);
            }
        }
    }
}
