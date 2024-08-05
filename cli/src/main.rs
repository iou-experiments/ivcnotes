use clap::{Args, Parser, Subcommand};
use core::str;
use files::{Creds, FileMan};

pub(crate) mod files;

// pub(crate) type Field = <Concrete as IVC>::Field;
// pub(crate) type VerifyingKey = <Concrete as IVC>::Field;

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
    Info,
    Reset,
}

#[derive(Args)]
struct CreateArgs {
    #[arg(short, long = "user")]
    username: String,
    #[arg(short, long, default_value = "")]
    pass: String,
}
#[derive(Args)]
struct RegisterArgs {
    #[arg(short, long = "user")]
    username: String,
    #[arg(short, long)]
    address: String,
    public_key: String,
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Create(args) => Creds::generate(args).unwrap(),
        Commands::Info => FileMan::list_accounts(),
        Commands::Register(args) => {
            if let Err(e) = Creds::register(args.username.clone(), args.address.clone()) {
                eprintln!("Failed to register user: {:?}", e);
            }
        }
        Commands::Reset => FileMan::clear_contents().unwrap(),
    }
}
