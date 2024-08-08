use crate::address_book::AddressBook;
use crate::creds::Creds;
use crate::notebook::Notebook;
use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::ChaCha20Poly1305;
use digest::Digest;
use ivcnotes::circuit::concrete::Concrete;
use ivcnotes::circuit::{Prover, Verifier, IVC};
use ivcnotes::{Error, FWrap};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

pub(crate) fn encrypt(text: &[u8], key: &[u8]) -> Vec<u8> {
    let key = sha2::Sha256::digest(key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut encrypted = cipher.encrypt(&nonce, text).unwrap();
    encrypted.splice(..0, nonce.iter().copied());
    encrypted
}

pub(crate) fn decrypt(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let key = sha2::Sha256::digest(key);
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key[..]));
    let (nonce, encrypted) = encrypted.split_at(NonceSize::to_usize());
    let nonce = GenericArray::from_slice(nonce);
    cipher.decrypt(nonce, encrypted).unwrap()
}

pub(crate) struct FileMan;

#[derive(Debug)]
pub(crate) enum Storage {
    Creds { addr: String },
    Anchor,
    VK,
    PK,
    AddressBook,
    Notebook { addr: String },
}

impl FileMan {
    const APP_DIR: &'static str = ".ivcnotes";
    const CRED_FILE: &'static str = "cred.json";
    const ANCHOR_FILE: &'static str = "anchor";
    const ADDRESS_BOOK_FILE: &'static str = "address_book.json";
    const NOTEBOOK_FILE: &'static str = "notes.json";
    const PK_FILE: &'static str = "pk.g16";
    const VK_FILE: &'static str = "vk.p16";

    pub(crate) fn dir_app() -> PathBuf {
        let mut dir = Self::dir_home();
        fs::create_dir_all(&dir).unwrap();
        dir.push(Self::APP_DIR);
        dir
    }

    pub(crate) fn dir_home() -> PathBuf {
        std::env::var("HOME")
            .expect("Failed to get HOME directory")
            .into()
    }

    fn path(file: &Storage) -> PathBuf {
        let mut dir = Self::dir_app();
        match file {
            Storage::Notebook { addr } => {
                dir.push(addr);
                fs::create_dir_all(&dir).unwrap();
                dir.push(Self::NOTEBOOK_FILE);
            }
            Storage::Creds { addr } => {
                dir.push(addr);
                fs::create_dir_all(&dir).unwrap();
                dir.push(Self::CRED_FILE);
            }
            Storage::Anchor => dir.push(Self::ANCHOR_FILE),
            Storage::VK => dir.push(Self::VK_FILE),
            Storage::PK => dir.push(Self::PK_FILE),
            Storage::AddressBook => dir.push(Self::ADDRESS_BOOK_FILE),
        };
        dir
    }

    fn open(file: Storage) -> Result<File, Error> {
        let path = Self::path(&file);
        File::open(path).map_err(|_| Error::Data(format!("Failed to open {:?}", file)))
    }

    fn create(file: Storage) -> Result<File, Error> {
        let path = Self::path(&file);
        File::create(path).map_err(|_| Error::Data(format!("Failed to create {:?}", file)))
    }

    pub(crate) fn update_current_account(address: &str) -> Result<(), Error> {
        let mut file = FileMan::create(Storage::Anchor)?;
        file.write_all(address.as_bytes())
            .map_err(|_| Error::Data("Failed to write anchor file".into()))?;
        Ok(())
    }

    pub(crate) fn read_current_account() -> Result<String, Error> {
        let mut file = FileMan::open(Storage::Anchor)?;
        let mut addr = String::new();
        file.read_to_string(&mut addr)
            .map_err(|_| Error::Data("Failed to read anchor file".into()))?;
        Ok(addr)
    }

    pub(crate) fn read_creds() -> Result<Creds, Error> {
        let addr = Self::read_current_account()?;
        let file = FileMan::open(Storage::Creds { addr })?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(|_| Error::Data("Failed to read cred file".into()))
    }

    pub(crate) fn write_creds(creds: &Creds) -> Result<(), Error> {
        let file = FileMan::create(Storage::Creds {
            addr: creds.contact.address.short_hex(),
        })?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &creds)
            .map_err(|_| Error::Data("Failed to write cred file".into()))
    }

    pub(crate) fn read_verifier() -> Result<Verifier<Concrete>, Error> {
        let file = Self::open(Storage::VK)?;
        let vk = Concrete::read_verifying_key(file)?;
        Ok(Verifier::new(vk))
    }

    pub(crate) fn read_prover() -> Result<Prover<Concrete>, Error> {
        let file = Self::open(Storage::PK)?;
        let pk = Concrete::read_proving_key(file)?;
        Ok(Prover::new(pk))
    }

    pub(crate) fn read_address_book() -> Result<AddressBook, Error> {
        let book = FileMan::open(Storage::AddressBook)?;
        serde_json::from_reader(book).map_err(|_| Error::Data("Failed to read address book".into()))
    }

    pub(crate) fn write_address_book(address_book: &AddressBook) -> Result<(), Error> {
        let file = FileMan::create(Storage::AddressBook)?;
        serde_json::to_writer_pretty(file, address_book)
            .map_err(|_| Error::Data("Failed to write address book".into()))
    }

    pub(crate) fn read_notebook() -> Result<Notebook, Error> {
        let addr = Self::read_current_account()?;
        let book = FileMan::open(Storage::Notebook { addr })?;
        serde_json::from_reader(book).map_err(|_| Error::Data("Failed to read notebook".into()))
    }

    pub(crate) fn write_notebook(notebook: &Notebook) -> Result<(), Error> {
        let addr = Self::read_current_account()?;
        let file = FileMan::create(Storage::Notebook { addr })?;
        serde_json::to_writer_pretty(file, notebook)
            .map_err(|_| Error::Data("Failed to write notebook".into()))
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
}
