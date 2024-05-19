use colored::Colorize;
use std::path::Path;
use std::path::PathBuf;
use glob::glob;
use std::fs;
use std::path;
use crate::model::image_crypto::ImageCrypto;

use self::uds::Uds;
use std::sync::Arc;

mod uds;
mod image_crypto;
#[derive(Clone)]
pub enum UpgradeStep {
    PassSecurity(u8),
    TransferRequestWithCrypto,
    // TransferRequest,
    TransferData,
    VerifySign(Vec<u8>),
    DiagRqRawData(Vec<u8>),
}

pub struct Model<'a> {
    uds_: Arc<Uds>,
    upgrade_step_: &'a Vec<UpgradeStep>,
    seed_to_key_: fn(&[u8], u8) -> Vec<u8>,
}

impl<'a> Model<'a> {
    pub fn new(ip: &str, upgrade_step: &'a Vec<UpgradeStep>, ta: &str, sa: &str, 
                seed_to_key: fn(&[u8], u8) -> Vec<u8>) -> Self {
        let uds = Arc::new(Uds::new(ip, ta, sa));
        Model {
            uds_: uds,
            upgrade_step_: upgrade_step,
            seed_to_key_: seed_to_key,
        }
    }

    pub async fn create_connect(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.uds_.create_connect().await?;
        Ok(())
    }

    pub async fn upgrade(&mut self, image_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let len_max = self.upgrade_step_.len();
        let mut indices = 0;
        let mut image_path_ = PathBuf::new();
        loop {
            let step = self.upgrade_step_[indices].clone();
            match step {
                UpgradeStep::PassSecurity(level) => {
                    println!("{} {}", "enter level".green(), level);
                    if let Err(e) = self.pass_security(level).await {
                        println!("{}-{} {}", e, "error: Failed to enter level".red(), level);
                        break;
                    }},
                // UpgradeStep::TransferRequest => {
                //     println!("{} {}", "TransferReq".green(), image_path.display());
                //     if let Err(e) = self.file_transfer_request(image_path).await {
                //         println!("{}-{} {}", e, "error: Failed to TransferReq".red(), image_path.display());
                //         break;
                //     }},
                UpgradeStep::TransferRequestWithCrypto => {
                        println!("{} {}", "TransferRequestWithCrypto".green(), image_path.display());
                        image_path_ = image_path.to_path_buf();
                        for entry in glob(&(image_path.display().to_string() + "/*.img")).expect("Failed read image path") {
                            match entry {
                                Ok(path) => {
                                    image_path_ = path;
                                    break;},
                                Err(e) => println!("{:?}", e),
                            }
                        }
                        ImageCrypto::encrypt_aes_gcm(image_crypto::IMAGE_CRYPTO_INFO_DEMO.aes_hex_key,
                                                image_crypto::IMAGE_CRYPTO_INFO_DEMO.aes_hex_iv, &image_path_)
                                                .unwrap_or_else(|e| {println!("encrypt img failed {}", e);});
                        ImageCrypto::sign_rsa_pss(image_crypto::IMAGE_CRYPTO_INFO_DEMO.sign_private_key,
                                                                                             &image_path_)
                                                                .unwrap_or_else(|e| {println!("encrypt img failed {}", e);});
                        image_path_ = image_path.join("tmp");
                        if let Err(e) = self.file_transfer_request(&image_path_ ).await {
                            println!("{}-{} {}", e, "error: Failed to TransferReq".red(), image_path.display());
                            break;
                        }},
                UpgradeStep::TransferData => {
                    println!("{}", "TransferData".green());
                    if let Err(e) = self.file_transfer_data().await {
                        println!("{}-{}", e, "error: Failed to TransferData".red());
                        break;
                    }},
                UpgradeStep::VerifySign(data) => {
                    let data_str = data.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(" ");
                    println!("{} {}", "verify sign".green(), data_str);
                    if let Err(e) = self.verify_sign(data).await {
                        println!("{}-{} {}", e, "error: Failed to enter level".red(), data_str);
                        break;
                    }},
                UpgradeStep::DiagRqRawData(data) => {
                    let data_str = data.iter().map(|byte| format!("{:02x}", byte)).collect::<Vec<String>>().join(" ");
                    println!("{} {}", "diagRqRawData".green(), data_str);
                    if let Err(e) = self.diag_request_raw_data(data).await {
                        println!("{}-{} {}", e, "error: Failed to exec".red(), data_str);
                        break;
                    }},
            }
            indices = indices + 1;
            if indices >= len_max {
                break;
            }
        }
        if image_path_.display().to_string() != "" {
            match fs::remove_dir_all(path::Path::new(&image_path_)) {
                Ok(_) => println!("del {}", image_path_.display()),
                Err(e) => eprintln!("del {} failed {}", image_path_.display(), e),
            }
        }
        Ok(())
    }

    pub async fn start_keep_session(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.uds_.start_keep_session().await?;
        Uds::keep_session(self.uds_.clone()).await?;
        Ok(())
    }

    pub async fn stop_keep_session(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.uds_.stop_keep_session().await?;
        Ok(())
    }

    pub async fn verify_sign(&self, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.uds_.verify_sign(data).await?;
        Ok(())
    }

    pub async fn pass_security(&self, level: u8) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.uds_.pass_security(level, self.seed_to_key_).await?;
        Ok(())
    }

    pub async fn file_transfer_request(&self, image_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        self.uds_.file_transfer_request(image_path).await?;
        Ok(())
    }

    pub async fn file_transfer_data(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.uds_.file_transfer_data().await?;
        Ok(())
    }

    pub async fn diag_request_raw_data(&self, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        Uds::diag_request_raw_data(self.uds_.clone(), data).await?;
        Ok(())
    }
}