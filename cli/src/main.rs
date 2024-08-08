use address_book::AddressBook;
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use core::str;
use creds::Creds;
use files::FileMan;
use ivcnotes::note::EncryptedNoteHistory;
use ivcnotes::service::msg;
use ivcnotes::{
    asset::Terms,
    circuit::concrete::{Concrete, POSEIDON_CFG},
    service::{
        msg::{request::GetContact, response::Contact},
        Service,
    },
    wallet::Wallet,
    Error, FWrap,
};
use notebook::Notebook;
use rand_core::OsRng;
use service::blocking::{BlockingHttpClient, HttpScheme};
use std::fs;

pub(crate) mod address_book;
pub(crate) mod creds;
pub(crate) mod files;
pub(crate) mod notebook;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create(CreateArgs),
    Register(RegisterArgs),
    Issue(IssueArgs),
    Transfer(TransferArgs),
    Info,
    Reset,
}

#[derive(Args)]
struct CreateArgs {
    #[arg(short, long, default_value = "")]
    pass: String,
}

#[derive(Args)]
struct RegisterArgs {
    #[arg(short, long, default_value = "")]
    pass: String,
    #[arg(short, long = "user")]
    username: String,
}

#[derive(Args)]
struct IssueArgs {
    #[arg(short, long, default_value = "")]
    pass: String,
    receiver: String,
    value: u64,
}

#[derive(Args)]
struct TransferArgs {
    #[arg(short, long, default_value = "")]
    pass: String,
    index: usize,
    receiver: String,
    value: u64,
}

pub(crate) fn wallet(pass: &str) -> Result<Wallet<Concrete>, Error> {
    let creds = FileMan::read_creds()?;
    let auth = creds.auth(pass)?;
    let prover = FileMan::read_prover()?;
    let verifier = FileMan::read_verifier()?;

    Ok(Wallet::new(
        auth,
        &POSEIDON_CFG,
        prover,
        verifier,
        creds.contact.username,
    ))
}

fn main() {
    let cli = Cli::parse();
    let service = BlockingHttpClient::new(HttpScheme::Http, "localhost", None);
    match &cli.command {
        Commands::Create(args) => cli.create(args).unwrap(),
        Commands::Info => cli.list_accounts(),
        Commands::Register(args) => cli.register(args, &service).unwrap(),
        Commands::Issue(args) => cli.issue(args, &service).unwrap(),
        Commands::Transfer(args) => cli.transfer(args, &service).unwrap(),
        Commands::Reset => FileMan::clear_contents().unwrap(),
    }
}

impl Cli {
    pub(crate) fn get_contact<S: Service<Concrete>>(
        &self,
        username: String,
        service: &S,
    ) -> Result<Contact<Concrete>, Error> {
        let contact = AddressBook::get_contract(username.clone())?;
        match contact {
            Some(contact) => Ok(contact),
            None => {
                let msg = GetContact::Username(username.clone());
                let contact = service.get_contact(&msg)?;
                AddressBook::add_contact(username, &contact)?;
                Ok(contact)
            }
        }
    }

    pub(crate) fn register<S: Service<Concrete>>(
        &self,
        args: &RegisterArgs,
        s: &S,
    ) -> Result<(), Error> {
        let mut creds = FileMan::read_creds().unwrap();
        creds.contact.username = args.username.clone();
        s.register(&creds.contact)?;
        FileMan::write_creds(&creds)?;
        Ok(())
    }

    pub(crate) fn create(&self, args: &CreateArgs) -> Result<(), Error> {
        AddressBook::create()?;
        Notebook::create()?;
        let creds = Creds::generate(&args.pass);
        FileMan::write_creds(&creds)?;
        FileMan::update_current_account(&creds.contact.address.short_hex())
    }

    pub(crate) fn transfer<S: Service<Concrete>>(
        &self,
        args: &TransferArgs,
        service: &S,
    ) -> Result<(), Error> {
        let creds = FileMan::read_creds()?;
        let auth = creds.auth(&args.pass)?;

        let w = wallet(&args.pass)?;
        let receiver = self.get_contact(args.receiver.clone(), service)?;
        let notes = Notebook::get_notes()?;
        let note = notes[args.index].clone();
        let (note_0, note_1) = w.split(&mut OsRng, &auth, note, args.value, &receiver)?;

        let encrypted = auth.encrypt(&receiver.public_key, &note_1);
        let msg = msg::request::SendNote {
            note_history: EncryptedNoteHistory {
                encrypted,
                sender: creds.contact(),
            },
            receiver: receiver.address,
        };

        service.send_note(&msg)?;
        Notebook::update_note(args.index, note_0)?;
        Ok(())
    }

    pub(crate) fn issue<S: Service<Concrete>>(
        &self,
        args: &IssueArgs,
        service: &S,
    ) -> Result<(), Error> {
        let creds = FileMan::read_creds()?;
        let auth = creds.auth(&args.pass)?;

        let w = wallet(&args.pass)?;
        let receiver = self.get_contact(args.receiver.clone(), service)?;
        let terms = Terms::iou(0, ivcnotes::asset::Unit::USD);
        let note = w.issue(&mut OsRng, &auth, &terms, args.value, &receiver)?;
        let encrypted = auth.encrypt(&receiver.public_key, &note);

        let msg = msg::request::SendNote {
            note_history: EncryptedNoteHistory {
                encrypted,
                sender: creds.contact(),
            },
            receiver: receiver.address,
        };
        service.send_note(&msg)?;
        Notebook::add_note(note)?;
        Ok(())
    }

    pub(crate) fn list_accounts(&self) {
        match FileMan::read_current_account() {
            Ok(current) => {
                let path = FileMan::dir_app();
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
}
