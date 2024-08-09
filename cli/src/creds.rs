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

    pub(crate) fn auth(&self, pass: &str) -> Result<Auth<Concrete>, Error> {
        let auth = decrypt(&self.auth, pass.as_bytes());
        Auth::new(&POSEIDON_CFG, auth.try_into().unwrap())
    }

    pub(crate) fn contact(&self) -> Contact<Concrete> {
        self.contact.clone()
    }
}
