use crate::{asset::Terms, circuit::IVC, wallet::Wallet, Error, FWrap};
use colored::Colorize;
use std::fmt::Display;

pub(crate) struct PrettyAsset {
    hash: String,
    issuer: String,
    _maturity: u64,
    unit: u64,
}

pub(crate) struct PrettyNote {
    senders: Vec<String>,
    asset: PrettyAsset,
    value: u64,
}

impl Display for PrettyNote {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        fn pad(s: &str) -> String {
            format!("{:<width$}", s, width = 10)
        }
        writeln!(f, "{}: {}", pad("asset id").blue(), self.asset.hash)?;
        writeln!(f, "{}: {}", pad("issuer").blue(), self.asset.issuer)?;
        writeln!(f, "{}: {}", pad("unit").blue(), self.asset.unit)?;
        writeln!(f, "{}: {}", pad("value").blue(), self.value)?;
        writeln!(f, "{}:", pad("senders").blue())?;
        for (i, sender) in self.senders.iter().enumerate() {
            writeln!(f, "{i}: {}", sender)?;
        }
        Ok(())
    }
}

impl<E: IVC> Wallet<E> {
    pub(crate) fn pretty_notes(&mut self) -> Result<Vec<PrettyNote>, Error> {
        let mut notes = vec![];
        for note in self.spendables.clone().into_iter() {
            let issuer = note.asset.issuer;
            let issuer = self.find_contact_by_address(&issuer)?;
            let terms = note.asset.terms;
            let asset = match terms {
                Terms::IOU { maturity, unit } => PrettyAsset {
                    hash: note.asset.hash().short_hex(),
                    issuer: format!("{}, {}", issuer.address.short_hex(), issuer.username)
                        .to_string(),
                    _maturity: maturity,
                    unit,
                },
            };
            let mut senders = vec![];
            for step in note.steps.iter() {
                let sender = self.find_contact_by_address(&step.sender)?;
                let sender =
                    format!("{}, {}", sender.address.short_hex(), sender.username).to_string();
                senders.push(sender);
            }
            let note = note.current_note;
            let pretty_note = PrettyNote {
                senders,
                asset,
                value: note.value,
            };
            notes.push(pretty_note);
        }
        Ok(notes)
    }
}
