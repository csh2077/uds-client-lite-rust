use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};
use colored::Colorize;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use rsa::pss::Pss;
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

pub struct ImageCryptoInfo<'a> {
    pub aes_hex_key: &'a str,
    pub aes_hex_iv: &'a str,
    pub sign_private_key: &'a str,
}

pub const IMAGE_CRYPTO_INFO_DEMO: ImageCryptoInfo = ImageCryptoInfo {
    aes_hex_key: "...",
    aes_hex_iv: "...",
    sign_private_key: r#"
...
-----END RSA PRIVATE KEY-----
"#,
};

pub struct ImageCrypto {

}

// key: &[u8; 32], iv: &[u8; 32], plaintext: &[u8]

impl ImageCrypto {
    pub fn encrypt_aes_gcm(key: &str, iv: &str, file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let key_hex_vec: Result<Vec<u8>, _> = (0..key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key[i..i + 2], 16))
        .collect();
        let key = key_hex_vec.unwrap_or_else(|e| {
            println!("{} {} {}", "aes key is error", key, e);
            vec![]
        });

        let iv_hex_vec: Result<Vec<u8>, _> = (0..iv.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&iv[i..i + 2], 16))
        .collect();
        let iv = iv_hex_vec.unwrap_or_else(|e| {
            println!("{} {} {}", "aes iv is error", iv, e);
            vec![]
        });

        let mut file = File::open(file_path).expect("open image file failed");
        let mut plaintext = Vec::new();
        file.read_to_end(&mut plaintext).expect("convert image to bin failed");
        
        let key = GenericArray::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let nonce = GenericArray::from_slice(&iv);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .expect("encryption failure!");

        let path = file_path.parent().unwrap_or_else(|| {println!("{} {}", "get parent path failed".red(), file_path.display()); Path::new("")});
        let tmp_path = path.join("tmp");
        ImageCrypto::write_data_to_file(&tmp_path, "tmp.img", &ciphertext);
        Ok(())
    }

    pub fn sign_rsa_pss(private_key: &str, file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut hasher = Sha256::new();
        let mut file = File::open(file_path).expect("open image file failed");
        let mut plaintext = Vec::new();
        file.read_to_end(&mut plaintext).expect("convert image to bin failed");
        hasher.update(plaintext);
        let hashed_data = hasher.finalize();
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::from_pkcs1_pem(private_key)?;
        let sign_data =  private_key.sign_with_rng(
            &mut rng,
            Pss::new::<Sha256>(),
            &hashed_data,
        ).expect("Failed to sign");
        let sign_data_str = sign_data.iter().map(|byte| format!("0x{:02x},", byte)).collect::<Vec<String>>().join(" ");
        // println!("sign data: {}", sign_data_str);

        let path = file_path.parent().unwrap_or_else(|| {println!("{} {}", "get parent path failed".red(), file_path.display()); Path::new("")});
        let tmp_path = path.join("tmp");
        ImageCrypto::write_data_to_file(&tmp_path, "tmp.sig", sign_data_str.as_bytes());
        Ok(())
    }

    fn write_data_to_file(file_dir_path: &Path, file_name: &str, data: &[u8]) {
        if !file_dir_path.exists() {
            fs::create_dir(&file_dir_path).unwrap_or_else(|e| {println!("{} {} {}", "create_dir failed".red(), e, file_dir_path.display())});
        }
        let file_path = file_dir_path.join(file_name);
        let mut file = match File::create(&file_path) {
            Ok(file) => file,
            Err(e) => panic!("create {} failed: {}", file_path.display(), e),
        };
        match file.write_all(data) {
            Ok(_) => {},
            Err(e) => println!("write data error: {}", e),
        }
    }
}

