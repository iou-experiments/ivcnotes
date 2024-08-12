use address_book::AddressBook;
use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use core::str;
use creds::Creds;
use files::FileMan;
use ivcnotes::note::EncryptedNoteHistory;
use ivcnotes::note::NoteHistory;
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
    Get(ReadNotesArgs),
    Info,
    Reset,
    Switch,
    List,
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
    #[arg(short, long = "to")]
    receiver: String,
    #[arg(short, long = "value")]
    value: u64,
}

#[derive(Args)]
struct TransferArgs {
    #[arg(short, long, default_value = "")]
    pass: String,
    #[arg(short, long = "index")]
    index: usize,
    #[arg(short, long = "to")]
    receiver: String,
    #[arg(short, long = "value")]
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
        Commands::Get(args) => cli.get_notes(args, &service).unwrap(),
        Commands::Reset => FileMan::clear_contents().unwrap(),
        Commands::Switch => cli.list_and_switch_accounts(),
        Commands::List => cli.list_all_notes().unwrap(),
    }
}

impl Cli {
    pub(crate) fn get_contact(
        &self,
        username: String,
        service: &BlockingHttpClient,
    ) -> Result<Contact<Concrete>, Error> {
        println!("Checking if contact is in your address book...");
        let contact = AddressBook::get_contract(username.clone())?;
        match contact {
            Some(contact) => Ok(contact),
            None => {
                println!(
                    "No contact found for {}, checking database...",
                    username.clone()
                );
                let msg = service::schema::UserIdentifier::Username(username.clone());
                let contact = service.get_contact(msg).expect("couldnt get contact");
                AddressBook::add_contact(username, &contact)?;
                println!("Found contact in database and saved to your address book!");
                Ok(contact)
            }
        }
    }

    pub(crate) fn get_notes(
        &self,
        args: &ReadNotesArgs,
        service: &BlockingHttpClient,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let creds = FileMan::read_creds().unwrap();
        println!(
            "preparing to fetch notes for {}...",
            creds.contact.username.clone()
        );
        let auth = creds.auth(&args.pass)?;

        let encrypted = service.get_notes(creds.contact.username.clone())?;
        println!("Fetched encrypted notes, preparing to decrypt...",);
        for (encrypted_note, sender) in encrypted {
            let msg = service::schema::UserIdentifier::Username(sender.username.clone());
            let contact = service.get_contact(msg).expect("couldn't get contact");

            // Decrypt the note using the public key from the contact
            let decrypted_note: NoteHistory<Concrete> = auth
                .decrypt(&contact.public_key, &encrypted_note.encrypted)
                .expect("couldn't decrypt");

            // Add the decrypted note to the notebook
            Notebook::add_note(decrypted_note)?;
            println!("Decrypted notes and saved in your notebook, use list command to view!");
        }

        Ok(())
    }

    pub(crate) fn list_all_notes(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Listing all notes in the notebook:");
        println!("----------------------------------");

        match Notebook::list_notes() {
            Ok(_) => println!("All notes listed successfully."),
            Err(e) => println!("Error listing notes: {:?}", e),
        }

        Ok(())
    }

    pub(crate) fn register(
        &self,
        args: &RegisterArgs,
        s: &BlockingHttpClient,
    ) -> Result<(), Error> {
        println!("Preparing for registeration...");
        let mut creds = FileMan::read_creds().unwrap();
        creds.contact.username = args.username.clone();
        println!("Checking if username can be registered...");
        s.register(creds.contact.clone())
            .expect("failed to register user");
        FileMan::write_creds(&creds)?;
        println!("Username, {} registered!", args.username.clone());
        Ok(())
    }

    pub(crate) fn create(&self, args: &CreateArgs) -> Result<(), Error> {
        println!("Creating your credentials...");
        let creds: Creds = Creds::generate(&args.pass);
        FileMan::write_creds(&creds)?;
        FileMan::update_current_account(&creds.contact.address.short_hex())?;
        AddressBook::create()?;
        Notebook::create()?;
        println!("Your credentials have been created and saved...");
        Ok(())
    }

    pub(crate) fn transfer(
        &self,
        args: &TransferArgs,
        service: &BlockingHttpClient,
    ) -> Result<(), Error> {
        println!("Preparing note for transfer...");
        let creds = FileMan::read_creds()?;
        let auth: ivcnotes::id::Auth<Concrete> = creds.auth(&args.pass)?;
        let w = wallet(&args.pass)?;
        let receiver = self.get_contact(args.receiver.clone(), service)?;
        let notes = Notebook::get_notes()?;
        let note = notes[args.index].clone();

        println!("Splitting note...");
        // store nullifier for verification.
        let (note_0, note_1, sealed) = w.split(&mut OsRng, &auth, note, args.value, &receiver)?;

        let nullifier_str = sealed.nullifier().to_string();
        let combined_str = format!(
            "Current Note: {:?}, Steps: {}Current Note: {:?}, Steps: {}",
            note_0.current_note,
            note_0.steps.len(),
            note_1.current_note,
            note_1.steps.len()
        );

        println!("Verifying transaction integrity...");
        service
            .get_nullifier(nullifier_str.clone(), combined_str.clone())
            .expect("Failed to verify the nullifier.");

        println!("Storing transaction record...");
        service
            .store_nullifier(nullifier_str, combined_str, creds.contact.username.clone())
            .expect("Failed to store the nullifier.");

        println!("Encrypting note for receiver...");
        let encrypted = auth.encrypt(&receiver.public_key, &note_1);

        println!("Sending note to receiver...");
        let msg = msg::request::SendNote {
            note_history: EncryptedNoteHistory {
                encrypted,
                receiver: receiver.clone(),
            },
            receiver: receiver.address,
            receiver_username: args.receiver.clone(),
            sender_username: creds.contact.username.clone(),
        };

        let _ = service
            .send_note(&msg)
            .map_err(|e| (format!("Failed to send note: {}", e)));

        println!("Updating notebook...");
        Notebook::update_note(args.index, note_0)?;

        println!("Transfer completed successfully!");
        Ok(())
    }

    pub(crate) fn issue(
        &self,
        args: &IssueArgs,
        service: &BlockingHttpClient,
    ) -> Result<(), Error> {
        let creds = FileMan::read_creds()?;
        println!(
            "Preparing to issue note with a value of {} to {}",
            args.value.clone(),
            args.receiver.clone()
        );
        let auth = creds.auth(&args.pass)?;

        let w = wallet(&args.pass)?;
        let receiver = self.get_contact(args.receiver.clone(), service)?;
        let terms = Terms::iou(0, ivcnotes::asset::Unit::USD);
        let note = w.issue(&mut OsRng, &auth, &terms, args.value, &receiver)?;
        println!("Encrypting note and preparing to transfer...");
        let encrypted = auth.encrypt(&receiver.public_key, &note);

        let msg = msg::request::SendNote {
            note_history: EncryptedNoteHistory {
                encrypted,
                receiver: receiver.clone(),
            },
            receiver: receiver.address,
            receiver_username: args.receiver.clone(),
            sender_username: creds.contact.username.clone(),
        };

        let _ = service
            .send_note(&msg)
            .map_err(|e| (format!("Failed to send note: {}", e)));
        println!("Issued note successfully.");
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

    pub(crate) fn list_and_switch_accounts(&self) {
        let current = FileMan::read_current_account().unwrap_or_else(|_| String::new());
        let path = FileMan::dir_app();
        let mut accounts = Vec::new();

        println!("Available accounts:");
        for entry in fs::read_dir(path).expect("1") {
            let path = entry.expect("2").path();
            if path.is_dir() {
                if let Some(address) = path.file_name() {
                    if let Some(address_str) = address.to_str() {
                        let is_current = address_str == current;
                        let current_indicator = if is_current {
                            " (current)".blue()
                        } else {
                            "".into()
                        };
                        println!("{}{}", address_str.yellow(), current_indicator);
                        accounts.push(address_str.to_string());
                    }
                }
            }
        }

        if accounts.is_empty() {
            println!("{}", "No accounts found.".blue());
        }

        print!("Enter the number of the account to switch to (or press Enter to cancel): ");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("3");

        let input = input.trim();
        if !input.is_empty() {
            if let Ok(selection) = input.parse::<usize>() {
                if selection > 0 && selection <= accounts.len() {
                    let selected_account = &accounts[selection - 1];
                    FileMan::update_current_account(selected_account).expect("4");
                    println!(
                        "{} {}",
                        "Switched to account:".green(),
                        selected_account.yellow()
                    );
                } else {
                    println!("{}", "Invalid selection.".red());
                }
            } else {
                println!("{}", "Invalid input.".red());
            }
        }
    }
}
