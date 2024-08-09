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
    service::msg::response::Contact,
    wallet::Wallet,
    Error, FWrap,
};
use notebook::Notebook;
use rand_core::OsRng;
use service::blocking::{BlockingHttpClient, HttpScheme};
use std::fs::{self};
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
    Notes(ReadNotesArgs),
    Info,
    Reset,
}

#[derive(Args)]
struct CreateArgs {
    #[arg(short, long, default_value = "")]
    pass: String,
}

#[derive(Args)]
struct ReadNotesArgs {
    #[arg(short, long, default_value = "")]
    pass: String,
    username: String,
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
    #[arg(short, long = "from")]
    from: String,
    index: usize,
    receiver: String,
    value: u64,
}

pub(crate) fn wallet(pass: &str) -> Result<Wallet<Concrete>, Error> {
    let creds = FileMan::read_creds()?;
    let auth = creds.auth(pass)?;
    let prover = FileMan::read_prover()?;
    let verifier = FileMan::read_verifier()?;
    let _ = FileMan::read_notebook()?;

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
    let service = BlockingHttpClient::new(HttpScheme::Http, "167.172.25.99", Some(80));
    match &cli.command {
        Commands::Create(args) => cli.create(args).unwrap(),
        Commands::Info => cli.list_accounts(),
        Commands::Register(args) => cli.register(args, &service).unwrap(),
        Commands::Issue(args) => cli.issue(args, &service).unwrap(),
        Commands::Transfer(args) => cli.transfer(args, &service).unwrap(),
        Commands::Notes(args) => cli.get_notes(args, &service).unwrap(),
        Commands::Reset => FileMan::clear_contents().unwrap(),
    }
}

impl Cli {
    pub(crate) fn get_contact(
        &self,
        username: String,
        service: &BlockingHttpClient,
    ) -> Result<Contact<Concrete>, Error> {
        let contact = AddressBook::get_contract(username.clone())?;
        match contact {
            Some(contact) => Ok(contact),
            None => {
                let msg = service::schema::UserIdentifier::Username(username.clone());
                let contact = service.get_contact(msg).expect("couldnt get contact");
                AddressBook::add_contact(username, &contact)?;
                Ok(contact)
            }
        }
    }

    pub(crate) fn get_notes(
        &self,
        args: &ReadNotesArgs,
        service: &BlockingHttpClient,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut creds = FileMan::read_creds().unwrap();
        creds.contact.username = args.username.clone();
        let notes = service.get_notes(creds.contact.username.clone())?;
        println!("Successfully retrieved notes for user: {:#?}", notes);
        Ok(())
    }

    pub(crate) fn register(
        &self,
        args: &RegisterArgs,
        s: &BlockingHttpClient,
    ) -> Result<(), Error> {
        let mut creds = FileMan::read_creds().unwrap();
        creds.contact.username = args.username.clone();
        s.register(creds.contact.clone())
            .expect("failed to register user");
        FileMan::write_creds(&creds)?;
        Ok(())
    }

    pub(crate) fn create(&self, args: &CreateArgs) -> Result<(), Error> {
        let creds: Creds = Creds::generate(&args.pass);
        FileMan::write_creds(&creds)?;
        FileMan::update_current_account(&creds.contact.address.short_hex())?;
        AddressBook::create()?;
        Notebook::create()?;
        Ok(())
    }

    pub(crate) fn transfer(
        &self,
        args: &TransferArgs,
        service: &BlockingHttpClient,
    ) -> Result<(), Error> {
        let creds = FileMan::read_creds()?;
        let auth: ivcnotes::id::Auth<Concrete> = creds.auth(&args.pass)?;

        let w = wallet(&args.pass)?;
        let receiver = self.get_contact(args.receiver.clone(), service)?;
        let notes = Notebook::get_notes()?;
        let note = notes[args.index].clone();

        // store nullifier for verification.
        let (note_0, note_1, sealed) = w.split(&mut OsRng, &auth, note, args.value, &receiver)?;
        let note_0_str = format!(
            "Current Note: {:?}, Steps: {}",
            note_0.current_note,
            note_0.steps.len()
        );
        let note_1_str = format!(
            "Current Note: {:?}, Steps: {}",
            note_1.current_note,
            note_1.steps.len()
        );
        let nullifier_str = sealed.nullifier().to_string();
        // Combine the strings
        let combined_str = format!("{}{}", note_0_str, note_1_str);
        let _ = service
            .get_nullifier(nullifier_str.clone(), combined_str.clone())
            .expect("hm");
        let _ = service
            .store_nullifier(nullifier_str, combined_str, args.from.clone())
            .map_err(|e| (format!("Failed to store nullifier: {}", e)));

        let encrypted = auth.encrypt(&receiver.public_key, &note_1);
        let msg = msg::request::SendNote {
            note_history: EncryptedNoteHistory {
                encrypted,
                sender: creds.contact(),
            },
            receiver: receiver.address,
            receiver_username: args.receiver.clone(),
        };

        let _ = service
            .send_note(&msg)
            .map_err(|e| (format!("Failed to send note: {}", e)));
        Notebook::update_note(args.index, note_0)?;
        Ok(())
    }

    pub(crate) fn issue(
        &self,
        args: &IssueArgs,
        service: &BlockingHttpClient,
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
            receiver_username: args.receiver.clone(),
        };
        let _ = service
            .send_note(&msg)
            .map_err(|e| (format!("Failed to send note: {}", e)));

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
