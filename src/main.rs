use model::UpgradeStep;
use std::path::Path;
use std::{collections::HashMap, path::PathBuf, str::FromStr};
use clap::{Arg, Command};
use std::io::{self, Write};
use colored::*;
use std::env;
use regex_lite::Regex;

extern crate regex_lite;
extern crate clap;
use crate::model::Model;

mod model;
#[derive(Clone)]
struct ModelConfig<'a> {
    pub target_address: String,
    pub upgrade_steps: &'a Vec<UpgradeStep>,
    pub seed_to_key: fn(&[u8], u8) -> Vec<u8>,
}

fn seed_to_key_demo(seed: &[u8], level: u8) -> Vec<u8> {
    println!("demo seed: {:?} level: {}", seed, level);
    vec![0x00, 0x00, 0x00, 0x00]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upgrade_steps_demo = vec![UpgradeStep::DiagRqRawData(vec![0x10, 0x03]),
                                                        UpgradeStep::DiagRqRawData(vec![0x10, 0x02]),
                                                        UpgradeStep::PassSecurity(0x2),
                                                        UpgradeStep::TransferRequestWithCrypto,
                                                        UpgradeStep::TransferData,
                                                        UpgradeStep::DiagRqRawData(vec![0x37]),
                                                        UpgradeStep::VerifySign(vec![0x31, 0x01, 0xf0, 0x01]),
                                                        UpgradeStep::DiagRqRawData(vec![0x31, 0x01, 0xff, 0x01]),
                                                        // UpgradeStep::DiagRqRawData(vec![0x11, 0x01]),
                                                        ];

    let model_config: HashMap<&str, ModelConfig> = [
        ("demo", 
        ModelConfig {target_address: "0025".to_string(), 
                    upgrade_steps: &upgrade_steps_demo,
                    seed_to_key: seed_to_key_demo}),
    ].iter().cloned().collect();
    let model_help_msg = format!("lidar model like {}", "demo".green());
    let ip_help_msg = format!("lidar ip like: {}", "123.456.7.89".green());
    let sa_help_msg = format!("lidar source address like: {}", "0e80".green());
    let ta_help_msg = format!("lidar target address like: {}", "0025".green());
    let u_help_msg = format!("lidar upgrade {}({})", 
                                    Path::new("\\imageFile\\*.img").to_str().unwrap_or("").green(),
                                    "use -p or --path to sepcify the image path".blue());
    let path_help_msg = format!("lidar image absolute path like: {}",
                                    Path::new("F:\\uds_client_lite\\imageFile").to_str().unwrap_or("").green());
    let matches = Command::new("uds client lite rust")
        .version("1.0.0")
        .author("csh2077")
        .about("uds client lite rust")
        .arg(Arg::new("ip")
             .short('i')
             .long("ip")
             .help(ip_help_msg)
             .default_value("123.456.7.89"))
        .arg(Arg::new("model")
             .short('m')
             .long("model")
             .help(model_help_msg)
             .default_value("demo"))
        .arg(Arg::new("source_address")
             .short('s')
             .long("source_address")
             .help(sa_help_msg)
             .default_value("0e80"))
        .arg(Arg::new("target_address")
             .short('t')
             .long("target_address")
             .help(ta_help_msg))
        .arg(Arg::new("upgrade")
             .short('u')
             .long("upgrade")
             .action(clap::ArgAction::SetTrue)
             .help(u_help_msg))
        .arg(Arg::new("image_path")
             .short('p')
             .long("path")
             .help(path_help_msg))
            //  .default_value(""))
        .get_matches();
    println!("{}", "Use -h read helper".yellow());
    let ip_global:&str = matches.get_one::<String>("ip").expect("parse ip failed");
    println!("Using ip: {}", ip_global);

    let model_global:&str = matches.get_one::<String>("model").expect("parse model failed");
    println!("Using model: {}", model_global);

    let model_config_global =  model_config.get(model_global).expect("parse lidar model failed");

    let sa_global:&str = matches.get_one::<String>("source_address").expect("parse source_address failed");
    println!("Using source_address: {}", sa_global);

    let ta_global:&str = matches.get_one::<String>("target_address").unwrap_or(&(*model_config_global).target_address);
    println!("Using target_address: {}", ta_global);

    let upgrade_flag_global: bool = matches.get_flag("upgrade");
    let default_img_path: String = "".to_string();
    let image_path_global =  matches.get_one::<String>("image_path").unwrap_or(&default_img_path);

    let mut uds_client = Model::new(ip_global,
                                            (*model_config_global).upgrade_steps,
                                            ta_global,
                                            sa_global,
                                            (*model_config_global).seed_to_key);
    uds_client.create_connect().await?;
    println!("{}", "please input uds server like '22f195' and input 'q' to end".blue());
    println!("{} {}", "use 'upgrade' or 'u' to trigger uds upgrade".yellow(),
                    Path::new("\\imageFile\\*.img").to_str().unwrap_or("").green(),);
    println!("{} {}{}", "use 'upgrade/u -p/--path".yellow(),
                        Path::new("F:\\uds_client_lite\\imageFile").to_str().unwrap_or("").green(), 
                        "'to trigger uds upgrade with the image path".yellow());
    loop {
        let mut input = String::new();
        let mut input_path = String::new();
        if !upgrade_flag_global {
            print!("{}", "waitting for uds service data:\n".blue());
            io::stdout().flush().unwrap();
            io::stdin().read_line(&mut input).expect("read failed");
            input_path = input.clone();
            input = input.trim().to_lowercase();
            if input.contains(" -p ") || input.contains(" --path ") {
                let re_p = Regex::new(r"(?i) -p ").unwrap();
                let re_path = Regex::new(r"(?i) --path ").unwrap();
                input_path = re_p.replace_all(&input_path, " --path ").to_string();
                input_path = re_path.replace_all(&input_path, " --path ").to_string();
                let parts: Vec<&str> = input_path.split("--path").collect();
                input_path = parts[1].trim().to_string();
            } else {
                input_path = "".to_string();
            }
        }
        if input == "q" {
            break;
        }
        if upgrade_flag_global || input.starts_with("u ") || input.starts_with("upgrade ") {
            let mut image_path = PathBuf::new();
            let path_str:String;
            if upgrade_flag_global {
                path_str = image_path_global.trim().to_string();
            } else {
                path_str = input_path;
            }
            if path_str.is_empty() {
                match env::current_exe() {
                    Ok(exe_path) => {
                        if let Some(dir) = exe_path.parent() {
                            image_path =dir.join("imageFile");
                            println!("curr path: {}", dir.display());
                        } else {
                            eprintln!("can get curr path");
                        }
                    },
                    Err(e) => {
                        eprintln!("can get current exec path: {}", e);
                    }
                }
            } else {
                let err_msg = format!("parse {} path error", image_path_global);
                image_path = PathBuf::from_str(path_str.trim()).expect(&err_msg);
            }
            let _ = uds_client.upgrade(&image_path).await;
            break;
        }
        if input.len() < 2 || input.len() % 2 != 0 {
            println!("error: data is not even");
        } else if input == "3e80" {
            let _ = uds_client.start_keep_session().await;
        } else if input == "3eff" {
            uds_client.stop_keep_session().await?;
        } else {
            let hex_vec: Result<Vec<u8>, _> = (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
            .collect();
    
            match hex_vec {
                Ok(data) => {
                    if data[0] == 0x27 {
                        if let Some(level) = data.get(1) {
                            let level = (level+ 1) / 2;
                            uds_client.pass_security(level).await.unwrap_or_else(|e| {
                                println!("pass_security error occurred: {}", e);});
                        } else {
                            println!("{}", "27 is too short".red());
                        }
                    } else {
                        uds_client.diag_request_raw_data(data).await.unwrap_or_else(|e| {
                            println!("diag_request error occurred: {}", e);});
                    }},
                Err(e) => println!("parse data error: {:?}", e),
            }
        }
    }
    Ok(())
}