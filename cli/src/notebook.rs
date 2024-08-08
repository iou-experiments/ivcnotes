use crate::files::FileMan;
use ivcnotes::Error;
use ivcnotes::{circuit::concrete::Concrete, note::NoteHistory};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct Notebook(Vec<NoteHistory<Concrete>>);

impl Notebook {
    pub(crate) fn create() -> Result<(), Error> {
        match FileMan::read_address_book() {
            Err(_) => FileMan::write_notebook(&Notebook::default()),
            Ok(_) => Ok(()),
        }
    }

    pub(crate) fn get_notes() -> Result<Vec<NoteHistory<Concrete>>, Error> {
        Ok(FileMan::read_notebook()?.0)
    }

    pub(crate) fn add_note(note: NoteHistory<Concrete>) -> Result<(), Error> {
        let mut book = FileMan::read_notebook()?;
        book.0.push(note);
        FileMan::write_notebook(&book)?;
        Ok(())
    }

    pub(crate) fn update_note(idx: usize, note: NoteHistory<Concrete>) -> Result<(), Error> {
        let mut book = FileMan::read_notebook()?;
        book.0[idx] = note;
        FileMan::write_notebook(&book)?;
        Ok(())
    }
}
