use colored::Colorize;
use ivcnotes::{
    circuit::concrete::{Concrete, POSEIDON_CFG},
    id::Auth,
    wallet::Contact,
    Error, FWrap,
};
use rand_core::OsRng;
use serde_derive::{Deserialize, Serialize};

use crate::files::{decrypt, encrypt};

#[derive(Serialize, Deserialize)]
pub(crate) struct Creds {
    pub(crate) contact: Contact<Concrete>,
    pub(crate) auth: Vec<u8>,
}

impl Creds {
    pub(crate) fn generate(pass: &str) -> Self {
        println!("{}", "> Generating new key...".blue());
        let auth = Auth::<Concrete>::generate(&POSEIDON_CFG, &mut OsRng).unwrap();
        let address = auth.address();
        println!(
            "{} {}",
            "> Address:".blue(),
            auth.address().short_hex().yellow()
        );

        let public_key = auth.public_key();
        let auth = auth.to_bytes();
        let auth = encrypt(&auth, pass.as_bytes());
        let contact = Contact {
            username: String::new(),
            address: *address,
            public_key: public_key.clone(),
        };
        Creds { auth, contact }
    }

    // pub(crate) fn register() -> Result<(), Box<dyn std::error::Error>> {
    //     // Read credentials from file
    //     let creds = FileMan::_read_creds()?;

    //     let client = BlockingHttpClient::new(HttpScheme::Http, "167.172.25.99", Some(80));
    //     let register_msg = UserRegister {
    //         username: creds.username.clone(),
    //         address: creds.address,
    //         public_key: creds.pubkey,
    //     };
    //     let username = creds.username.clone();
    //     let (pk, vk) = circuit_setup();
    //     let h = POSEIDON_CFG.clone();
    //     let auth = ivcnotes::id::Auth::<ivcnotes::circuit::concrete::Concrete>::generate(
    //         &h,
    //         &mut rand::thread_rng(),
    //     )
    //     .unwrap();

    //     let prover = Prover::new(pk);
    //     let verifier = Verifier::new(vk);
    //     let wallet = CliWallet::new(auth, &h, prover, verifier, client, username);

    //     let _ = wallet.comm.register(register_msg);
    //     println!("Successfully registered user");
    //     Ok(())
    // }

    // pub(crate) fn get_user(username: String) -> Result<(), Box<dyn std::error::Error>> {
    //     let client = BlockingHttpClient::new(HttpScheme::Http, "167.172.25.99", Some(80));

    //     let user = client.get_user_from_db(service::schema::UserIdentifier::Username(username))?;

    //     println!("Successfully retrieved user: {:#?}", user);

    //     Ok(())
    // }

    // pub(crate) fn verify_nullifier(
    //     nullifier: String,
    //     state: String,
    // ) -> Result<(), Box<dyn std::error::Error>> {
    //     let client = BlockingHttpClient::new(HttpScheme::Http, "167.172.25.99", Some(80));
    //     let nullifier_res = client.get_nullifier(nullifier, state)?;

    //     println!("Successfully retrieved nullifier: {:#?}", nullifier_res);

    //     Ok(())
    // }

    // pub(crate) fn get_notes(username: String) -> Result<(), Box<dyn std::error::Error>> {
    //     let client = BlockingHttpClient::new(HttpScheme::Http, "167.172.25.99", Some(80));

    //     let notes = client.get_notes(username)?;

    //     println!("Successfully retrieved notes for user: {:#?}", notes);
    //     Ok(())
    // }

    pub(crate) fn auth(&self, pass: &str) -> Result<Auth<Concrete>, Error> {
        let auth = decrypt(&self.auth, pass.as_bytes());
        Auth::new(&POSEIDON_CFG, auth.try_into().unwrap())
    }

    pub(crate) fn contact(&self) -> Contact<Concrete> {
        self.contact.clone()
    }
}
