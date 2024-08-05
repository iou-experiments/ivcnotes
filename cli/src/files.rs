use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::ChaCha20Poly1305;
use colored::Colorize;
use digest::Digest;
use ivcnotes::circuit::concrete::{Concrete, POSEIDON_CFG};
use ivcnotes::id::Auth;
use ivcnotes::FWrap;
use serde_derive::{Deserialize, Serialize};
use service::blocking::{BlockingHttpClient, HttpScheme};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

pub(crate) fn encrypt(cleartext: &[u8], key: &[u8]) -> Vec<u8> {
    let key = sha2::Sha256::digest(key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut encrypted = cipher.encrypt(&nonce, cleartext).unwrap();
    encrypted.splice(..0, nonce.iter().copied());
    encrypted
}

pub(crate) fn _decrypt(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let key = sha2::Sha256::digest(key);
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]));
    let (nonce, encrypted) = encrypted.split_at(NonceSize::to_usize());
    let nonce = GenericArray::from_slice(nonce);
    cipher.decrypt(nonce, encrypted).unwrap()
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Creds {
    pub(crate) username: String,
    pub(crate) address: String,
    pub(crate) auth: Vec<u8>,
    // to do, we need pubkey?
}

use crate::CreateArgs;

impl Creds {
    pub(crate) fn register(
        username: String,
        address: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = BlockingHttpClient::new(
            HttpScheme::Http,
            "167.172.25.99", // Replace with your actual host
            Some(80),        // Replace with your actual port
        );

        let address = ivcnotes::Address::<Concrete>::from_str(&address)
            .map_err(|_| "Failed to parse address")?;

        let register_msg = ivcnotes::service::msg::request::Register {
            username: username.clone(),
            address,
        };

        client.register(register_msg);

        println!("Successfully registered user: {}", username);
        Ok(())
    }

    pub(crate) fn generate(args: &CreateArgs) -> std::io::Result<()> {
        println!("{}", "> Generating new key...".blue());
        let auth = Auth::<Concrete>::generate(&POSEIDON_CFG, &mut OsRng).unwrap();
        let address = auth.address().short_hex();
        println!(
            "{} {}",
            "> Address:".blue(),
            auth.address().short_hex().yellow()
        );

        let auth = auth.to_bytes();
        let auth = encrypt(&auth, args.pass.as_bytes());
        let creds = Creds {
            username: args.username.clone(),
            auth,
            address: address.clone(),
        };
        FileMan::write_creds(&creds)?;
        FileMan::update_current_address(&address)?;
        Ok(())
    }
}

pub(crate) struct FileMan;

impl FileMan {
    const APP_DIR: &'static str = ".ivcnotes";
    const CRED_FILE: &'static str = "cred.json";
    const ANCHOR_FILE: &'static str = "anchor";
    // const PK_FILE: &'static str = "pk.g16";
    // const VK_FILE: &'static str = "vk.p16";
    // const PK_DIR: &'static str = "pk";
    // const VK_DIR: &'static str = "vk";

    fn dir_app() -> PathBuf {
        let mut dir = Self::dir_home();
        fs::create_dir_all(&dir).unwrap();
        dir.push(Self::APP_DIR);
        dir
    }

    fn dir_home() -> PathBuf {
        std::env::var("HOME")
            .expect("Failed to get HOME directory")
            .into()
    }

    fn path_cred(addr: String) -> PathBuf {
        let mut dir = Self::dir_app();
        dir.push(addr);
        fs::create_dir_all(&dir).unwrap();
        dir.push(Self::CRED_FILE);
        dir
    }

    fn path_anchor() -> PathBuf {
        let mut dir = Self::dir_app();
        dir.push(Self::ANCHOR_FILE);
        dir
    }

    // fn path_vk() -> PathBuf {
    //     let mut dir = Self::dir_app();
    //     dir.push(Self::VK_FILE);
    //     dir
    // }

    // fn path_pk() -> PathBuf {
    //     let mut dir = Self::dir_app();
    //     dir.push(Self::PK_FILE);
    //     dir
    // }

    pub(crate) fn update_current_address(address: &str) -> std::io::Result<()> {
        let file = FileMan::path_anchor();
        let mut file = File::create(file)?;
        file.write_all(address.as_bytes())?;
        Ok(())
    }

    pub(crate) fn read_current_address() -> std::io::Result<String> {
        let file = FileMan::path_anchor();
        let mut file = File::open(file)?;
        let mut addr = String::new();
        file.read_to_string(&mut addr)?;
        Ok(addr)
    }

    pub(crate) fn _read_creds() -> std::io::Result<Creds> {
        let addr = Self::read_current_address()?;
        let path = Self::path_cred(addr);
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(Into::into)
    }

    pub(crate) fn write_creds(creds: &Creds) -> std::io::Result<()> {
        let path = Self::path_cred(creds.address.clone());
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &creds).map_err(Into::into)
    }

    pub(crate) fn clear_contents() -> std::io::Result<()> {
        let dir = Self::dir_app();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }

        Ok(())
    }

    pub(crate) fn list_accounts() {
        match Self::read_current_address() {
            Ok(current) => {
                let path = Self::dir_app();
                for entry in fs::read_dir(path).unwrap() {
                    let entry = entry.unwrap();
                    let path = entry.path();
                    if path.is_dir() {
                        let address = path.file_name().unwrap().to_str().unwrap();
                        let current = if address == current { "current" } else { "" }.blue();
                        println!(
                            "{} {}",
                            path.file_name().unwrap().to_str().unwrap().yellow(),
                            current
                        )
                    }
                }
            }
            Err(_) => println!("{}", "No account.".blue()),
        }
    }

    // pub(crate) fn read_vk() -> std::io::Result {
    //     let path = Self::path_vk();
    //     let file = File::open(path)?;
    //     let pk_key_file = File::open("keys/pk.g16").unwrap();
    //     let _pk = Concrete::read_proving_key(pk_key_file).unwrap();
    // }
}
