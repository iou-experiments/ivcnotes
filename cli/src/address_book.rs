use ivcnotes::{circuit::concrete::Concrete, wallet::Contact, Error};
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::files::FileMan;

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct AddressBook(BTreeMap<String, Contact<Concrete>>);

impl AddressBook {
    pub(crate) fn create() -> Result<(), Error> {
        match FileMan::read_address_book() {
            Err(_) => FileMan::write_address_book(&AddressBook::default()),
            Ok(_) => Ok(()),
        }
    }

    pub(crate) fn get_contract(username: String) -> Result<Option<Contact<Concrete>>, Error> {
        let book = FileMan::read_address_book()?;
        Ok(book.0.get(&username).cloned())
    }

    pub(crate) fn add_contact(username: String, contact: &Contact<Concrete>) -> Result<(), Error> {
        let mut book = FileMan::read_address_book()?;
        book.0.insert(username, contact.clone());
        FileMan::write_address_book(&book)?;
        Ok(())
    }
}
