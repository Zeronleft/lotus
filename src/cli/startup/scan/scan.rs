use crate::cli::args::Opts;
use crate::cli::input::parse_requests::FullRequest;
use crate::cli::input::{get_stdin_input, get_target_hosts, get_target_paths};
use crate::lua::parsing::files::filename_to_string;
use crate::{Lotus, RequestOpts};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
use url::Url;

#[path = "input_handler.rs"]
mod input_handler;
use input_handler::custom_input_lua;

pub struct ScanArgs {
    pub target_data: TargetData,
    pub exit_after: i32,
    pub req_opts: RequestOpts,
    pub lotus_obj: Lotus,
    pub requests_limit: i32,
    pub delay: u64,
    pub fuzz_workers: usize,
    pub verbose: bool,
}

pub struct TargetData {
    pub urls: Vec<String>,
    pub hosts: Vec<String>,
    pub paths: Vec<String>,
    pub parse_requests: Vec<Value>,
    pub custom: Vec<Value>,
}

pub fn args_scan() -> ScanArgs {
    let (
        urls,
        hosts,
        paths,
        parse_requests,
        custom,
        exit_after,
        req_opts,
        lotus_obj,
        requests_limit,
        delay,
        fuzz_workers,
        verbose,
    ) = match Opts::from_args() {
        Opts::Scan(url_opts) => {
            // setup logger
            let req_opts = RequestOpts {
                headers: url_opts.headers,
                proxy: url_opts.proxy,
                timeout: url_opts.timeout,
                redirects: url_opts.redirects,
            };
            let lotus_obj = Lotus {
                script_path: url_opts.script_path,
                output: url_opts.output,
                workers: url_opts.workers,
                script_workers: url_opts.scripts_workers,
                stop_after: Arc::new(Mutex::new(1)),
                env_vars: url_opts.env_vars,
            };
            let input_data = if let Some(urls_file) = url_opts.urls {
                let read_file = filename_to_string(urls_file.to_str().unwrap());
                if let Err(..) = read_file {
                    log::error!("Cannot Read the urls file");
                    std::process::exit(1);
                }
                read_file
                    .unwrap()
                    .lines()
                    .map(|line| line.to_string())
                    .collect::<Vec<String>>()
            } else {
                match get_stdin_input() {
                    Ok(input_data) => input_data,
                    Err(..) => {
                        log::error!("No input in Stdin");
                        std::process::exit(1);
                    }
                }
            };
            let input_handler = if let Some(custom_input) = url_opts.input_handler {
                let lua_code = filename_to_string(custom_input.to_str().unwrap());
                if let Err(err) = lua_code {
                    log::error!(
                        "{}",
                        &format!("Unable to read custom input lua script: {}", err),
                    );
                    vec![]
                } else {
                    let lua_output = custom_input_lua(input_data.clone(), &lua_code.unwrap());
                    if let Ok(lua_output) = lua_output {
                        lua_output
                    } else {
                        log::error!("{}", &format!("{}", lua_output.unwrap_err()));
                        vec![]
                    }
                }
            } else {
                vec![]
            };
            let mut urls = vec![];
            let mut paths = vec![];
            let mut hosts = vec![];
            let mut parsed_request: Vec<Value> = vec![];
            if input_handler.is_empty() {
                let input_str = input_data.join("\n");
                let is_json = is_json_string(&input_str);
                log::debug!("input data is json: {} \n{}", is_json, &input_str);
                if is_json {
                    let parsed_json = match serde_json::from_str::<Vec<FullRequest>>(&input_str) {
                        Ok(parsed_request) => {
                            parsed_request.iter().for_each(|the_request| {
                                urls.push(the_request.url.clone());
                                urls.dedup();
                                urls.sort();
                            });
                            parsed_request
                        }
                        Err(err) => {
                            log::error!(
                                "{}",
                                &format!(
                                    "Not Valid JSON Data for Http Request parser: {}",
                                    err.to_string()
                                ),
                            );
                            std::process::exit(0);
                        }
                    };
                    log::debug!("JSON Data has benn Parsed successfully");
                    if urls.len() > 0 {
                        paths = match get_target_paths(urls.clone()) {
                            Ok(paths) => paths,
                            Err(err) => {
                                log::info!("{}", &format!("Failed to get target paths: {}", err),);
                                vec![]
                            }
                        };
                        hosts = get_target_hosts(urls.clone());
                    };
                    parsed_request = parsed_json
                        .iter()
                        .map(|req| serde_json::to_value(req).unwrap())
                        .collect();
                } else {
                    urls = input_data
                        .iter()
                        .filter_map(|target_url| Url::parse(target_url).ok())
                        .map(|url| url.to_string())
                        .collect();
                    paths = match get_target_paths(urls.clone()) {
                        Ok(paths) => paths,
                        Err(err) => {
                            log::error!("{}", &format!("Failed to get target paths: {}", err),);
                            vec![]
                        }
                    };
                    hosts = get_target_hosts(urls.clone());
                }
            }
            (
                urls,
                hosts,
                paths,
                parsed_request,
                input_handler,
                url_opts.exit_after,
                req_opts,
                lotus_obj,
                url_opts.requests_limit,
                url_opts.delay,
                url_opts.fuzz_workers,
                url_opts.verbose,
            )
        }
        _ => {
            std::process::exit(1);
        }
    };

    log::debug!("HOSTS: {}", hosts.len());
    log::debug!("HTTPMSGS: {}", parse_requests.len());
    log::debug!("URLS: {}", urls.len());
    log::debug!("PATHS: {}", paths.len());
    log::debug!("CUSTOM: {}", custom.len());
    ScanArgs {
        target_data: TargetData {
            urls,
            hosts,
            paths,
            custom,
            parse_requests,
        },
        exit_after,
        req_opts,
        lotus_obj,
        requests_limit,
        delay,
        fuzz_workers,
        verbose,
    }
}

fn is_json_string(json_str: &str) -> bool {
    match serde_json::from_str::<Value>(json_str) {
        Ok(_) => true,
        Err(_) => false,
    }
}
