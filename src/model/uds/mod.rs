use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::io::Read;
use self::doip::Doip;
use std::sync::Arc;
use tokio::time;
use tokio::sync::Mutex as AsyncMutex;
use colored::Colorize;
use glob::glob;

mod doip;

struct ImageInfo_ {
    path: PathBuf,
    sig_path: PathBuf,
    simple_transfer_size_max: u32,
}

pub struct Uds {
    doip_: AsyncMutex<Doip>,
    image_info_: AsyncMutex<ImageInfo_>,
    keep_session_flag_: AsyncMutex<bool>,
}

impl Uds {
    pub fn new(ip: &str, ta: &str, sa: &str) -> Self {
        let doip = AsyncMutex::<Doip>::new(Doip::new(ip, 13400, ta, sa));
        let image_info = AsyncMutex::<ImageInfo_>::new(ImageInfo_ {
            path: PathBuf::new(),
            sig_path: PathBuf::new(),
            simple_transfer_size_max: 0x0000,
        });
        Uds {
            doip_: doip,
            image_info_: image_info,
            keep_session_flag_: AsyncMutex::<bool>::new(false),
        }
    }

    pub async fn create_connect(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut doip_ = self.doip_.lock().await;
        doip_.create_connect().await?;
        Ok(())
    }

    pub async fn start_keep_session(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut keep_session_flag_ = self.keep_session_flag_.lock().await;
        *keep_session_flag_ = true;
        Ok(())
    }
    
    pub async fn keep_session(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let _ = Uds::diag_request_raw_data(self_clone.clone(), vec![0x3e, 0x80]).await;
            }
        });

        Ok(())
    }

    pub async fn stop_keep_session(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut keep_session_flag_ = self.keep_session_flag_.lock().await;
        *keep_session_flag_ = false;
        Ok(())
    }

    pub async fn pass_security(&self, level: u8, seed_to_key: fn(&[u8], u8) -> Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let mut sid:Vec<u8> = vec![0x27];
        let mut doip_ = self.doip_.lock().await;
        let data = 2 * level - 1;
        sid.push(data);
        doip_.send_diagnostic_msg(&sid).await?;
        let mut res_data = Vec::<u8>::new();
        doip_.recv_diagnostic_msg(&mut res_data).await?;
        if res_data[0] != (sid[0] + 0x40) {
            let err_str = "diag_res is error".red();
            return Err(err_str.into());
        }
        let seed = &res_data[2..];

        let key = seed_to_key(seed, level);
        let mut sid:Vec<u8> = vec![0x27];
        let data = 2 * level;
        sid.push(data);
        sid.extend(key);
        doip_.send_diagnostic_msg(&sid).await?;
        let mut res_data = Vec::<u8>::new();
        doip_.recv_diagnostic_msg(&mut res_data).await?;
        if res_data[0] != (sid[0] + 0x40) {
            let err_str = "diag_res is error".red();
            return Err(err_str.into());
        }
        Ok(())
    }

    pub async fn file_transfer_request(&self, image_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut sid:Vec<u8> = vec![0x34];
        let mut doip_ = self.doip_.lock().await;
        let mut image_info_ = self.image_info_.lock().await;
        sid.extend(vec![0x00, 0x44, 0x00, 0x00, 0x00, 0x00]);
        for entry in glob(&(image_path.display().to_string() + "/*.img")).expect("Failed read image path") {
            match entry {
                Ok(path) => {
                    image_info_.path = path;
                    break;},
                Err(e) => println!("{:?}", e),
            }
        }
        for entry in glob(&(image_path.display().to_string() + "/*.sig")).expect("Failed read sig path") {
            match entry {
                Ok(path) => {
                    image_info_.sig_path = path;
                    break;},
                Err(e) => println!("{:?}", e),
            }
        }
        println!("image {} \nsig_path {}", image_info_.path.display(), image_info_.sig_path.display());
        let metadata = fs::metadata(&image_info_.path).expect("file size read err");
        let image_size: u32 = metadata.len() as u32;
        sid.push((image_size >> 24) as u8);
        sid.push((image_size >> 16) as u8);
        sid.push((image_size >> 8) as u8);
        sid.push(image_size as u8);
        println!("{} {:02x} ...", "Transfer data request".green(), sid[0]);
        doip_.send_diagnostic_msg(&sid).await?;
        let mut res_data = Vec::<u8>::new();
        doip_.recv_diagnostic_msg(&mut res_data).await?;
        if res_data[0] != (sid[0] + 0x40) {
            let err_str = "diag_res is error".red();
            return Err(err_str.into());
        }
        let max_size_len = (res_data[1] & 0xf0) >> 4;
        if res_data.len() < max_size_len as usize + 2 {
            let err_str = "34 response is short".red();
            return Err(err_str.into());
        }
        for i in 0..max_size_len {
            let index: usize = (i + 2).into();
            let tmp_value: u32 = (res_data[index] as u32)  << (8 * (max_size_len - 1 -i));
            image_info_.simple_transfer_size_max = image_info_.simple_transfer_size_max + tmp_value;
        }
        Ok(())
    }

    pub async fn file_transfer_data(&self) -> Result<(), Box<dyn std::error::Error>> {
        let sid:Vec<u8> = vec![0x36];
        let image_info_ = self.image_info_.lock().await;
        let mut file = File::open(&image_info_.path).expect("open image file failed");
        let mut image_hex = Vec::new();
        let mut doip_ = self.doip_.lock().await;
        file.read_to_end(&mut image_hex).expect("convert image to bin failed");
        let mut block_num: u8 = 0;
        println!("image size {}", image_hex.len());
        for chunk in image_hex.chunks((image_info_.simple_transfer_size_max - 6) as usize) {
            let mut image_data_slice = vec![0x36];
            block_num = block_num + 1;
            image_data_slice.push(block_num);
            println!("{} {:02x} {:02x} ...", "Transfer data".green(), image_data_slice[0], image_data_slice[1]);
            image_data_slice.extend(chunk);
            doip_.send_diagnostic_msg(&image_data_slice).await?;
            let mut res_data = Vec::<u8>::new();
            doip_.recv_diagnostic_msg(&mut res_data).await?;
            if res_data[0] != (sid[0] + 0x40) && res_data[1] != block_num {
                let err_str = "diag_res is error".red();
                return Err(err_str.into());
            }
        }
        Ok(())
    }

    pub async fn verify_sign(&self, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let image_info_ = self.image_info_.lock().await;
        let mut sign_str = fs::read_to_string(&image_info_.sig_path)?;
        sign_str = sign_str.replace("\n", "").replace("\t", "").replace(" ", "").replace("0x", "");
        let sign_hex_str:Vec<&str> = sign_str.split(",").collect();
        let hex_values:Vec<Result<u8, _>> = sign_hex_str.into_iter().filter(|s| !s.is_empty()).map(|s| u8::from_str_radix(s, 16)).collect();
        let mut sign_data = Vec::<u8>::new();

        for value in hex_values {
            match value {
                Ok(num) => {sign_data.push(num)},
                Err(e) => println!("Error: {}", e),
            }
        }
        let mut data:Vec<u8> = data.clone();
        data.extend(sign_data);

        let sid:Vec<u8> = vec![data[0]];
        let mut doip_ = self.doip_.lock().await;
        doip_.send_diagnostic_msg(&data).await?;
        let mut res_data = Vec::<u8>::new();
        doip_.recv_diagnostic_msg(&mut res_data).await?;
        if res_data[0] != (sid[0] + 0x40) {
            let err_str = "diag_res is error".red();
            return Err(err_str.into());
        }
        Ok(())
    }

    pub async fn diag_request_raw_data(self: Arc<Self>, data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let sid:Vec<u8> = vec![data[0]];
        let mut doip_ = self.doip_.lock().await;
        doip_.send_diagnostic_msg(&data).await?;
        let mut res_data = Vec::<u8>::new();
        doip_.recv_diagnostic_msg(&mut res_data).await?;
        if res_data[0] != (sid[0] + 0x40) {
            let err_str = "diag_res is error".red();
            return Err(err_str.into());
        }
        Ok(())
    }
}