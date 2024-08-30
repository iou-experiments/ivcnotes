use crate::{WasmAuth, WasmIVCNotes, WasmNoteHistory};
use ark_serialize::CanonicalSerialize;
use ivcnotes::circuit::concrete::{circuit_setup, ConcretePK, ConcreteVK};
use std::fmt::Debug;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct Asset {
    issuer: String,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct Tx {
    asset: Asset,
    sender: String,
    receiver: String,
    value: u32,
}

struct Wallet {
    // Can be constructed with prover and verifier key
    // Store those keys in binary format locally or in remote storage
    engine: WasmIVCNotes,
    // Has to be persisted locally or in remote storage
    spendables: Vec<WasmNoteHistory>,
    // Has to be persisted locally or in remote storage
    tx_in: Vec<Tx>,
    // Has to be persisted locally or in remote storage
    tx_out: Vec<Tx>,
    // Has to be persisted locally or in remote storage
    liabilities: Vec<WasmNoteHistory>,
    // Has to be persisted locally
    auth: WasmAuth,
}

impl Wallet {
    #[allow(dead_code)]
    fn new(pk: &[u8], vk: &[u8]) -> Result<Self, JsValue> {
        let auth = WasmIVCNotes::generate_auth()?;
        let engine = WasmIVCNotes::new(pk, vk)?;
        Ok(Self {
            engine,
            spendables: Vec::new(),
            tx_in: Vec::new(),
            tx_out: Vec::new(),
            liabilities: Vec::new(),
            auth,
        })
    }

    fn new_unchecked(pk: &[u8], vk: &[u8]) -> Result<Self, JsValue> {
        let auth = WasmIVCNotes::generate_auth()?;
        let engine = WasmIVCNotes::new_unchecked(pk, vk)?;
        Ok(Self {
            engine,
            spendables: Vec::new(),
            tx_in: Vec::new(),
            tx_out: Vec::new(),
            liabilities: Vec::new(),
            auth,
        })
    }

    fn issue(&mut self, receiver: &str, value: u32) -> Result<WasmNoteHistory, JsValue> {
        // * Create the note with ivc-notes engine
        // * Add the note to liabilities
        // * Add as outgoing transaction
        // * Return the note

        let note = self.engine.issue(&self.auth, receiver, value)?;
        let tx = Tx {
            asset: Asset {
                issuer: self.address(),
            },
            sender: self.address(),
            receiver: receiver.to_string(),
            value,
        };
        self.tx_out.push(tx);
        self.liabilities.push(note.clone());
        Ok(note)
    }

    fn transfer(
        &mut self,
        note_index: usize,
        receiver: &str,
        value: u32,
    ) -> Result<WasmNoteHistory, JsValue> {
        // * Get the note for the given index
        // * Split the note with ivc-notes engine
        // * Remove the **spent** note from spendables
        // * Add the **change** notes to spendables
        // * Add as outgoing transaction
        // * Return the **spent** note

        let note = self
            .spendables
            .get(note_index)
            .ok_or(JsValue::from("invalid spendable index"))?;
        let output = self.engine.transfer(&self.auth, note, receiver, value)?;
        let out0 = output.out0.clone();
        let out1 = output.out1.clone();
        let tx = Tx {
            asset: Asset {
                issuer: note.issuer(),
            },
            sender: self.address(),
            receiver: receiver.to_string(),
            value,
        };
        self.tx_out.push(tx);
        self.spendables.remove(note_index);
        self.spendables.push(out0.clone());
        Ok(out1)
    }

    fn address(&self) -> String {
        self.auth.address.clone()
    }

    fn exists(&self, note: &WasmNoteHistory) -> bool {
        self.spendables.contains(note)
    }

    fn verify(&mut self, note: &WasmNoteHistory) -> Result<(), JsValue> {
        // * Check if note is already verified
        // * If not:
        //      * Check if receiver is the owner of the wallet (self)
        //      * Verify note
        //      * Add note to spendables
        //      * Add as incoming transaction

        if !self.exists(note) {
            (note.owner() == self.address())
                .then_some(())
                .ok_or(JsValue::from("invalid owner"))?;

            self.engine.verify(note)?;
            self.spendables.push(note.clone());

            let tx = Tx {
                asset: Asset {
                    issuer: note.issuer(),
                },
                sender: note.sender(),
                receiver: self.address(),
                value: note.value(),
            };
            self.tx_in.push(tx);
        }
        Ok(())
    }
}

// Emulate the issue event
fn issue(sender: &mut Wallet, receiver: &mut Wallet, value: u32) -> Result<(), JsValue> {
    let note_history = sender.issue(&receiver.address(), value)?;

    // Assume communication happened just here:
    // Sender sends note_history to receiver

    receiver.verify(&note_history)?;
    Ok(())
}

// Emulate the transfer event
fn transfer(
    sender: &mut Wallet,
    receiver: &mut Wallet,
    note_index: usize,
    value: u32,
) -> Result<(), JsValue> {
    let note_history = sender.transfer(note_index, &receiver.address(), value)?;

    // Assume communication happened just here:
    // Sender sends note_history to receiver

    receiver.verify(&note_history)?;
    Ok(())
}

use lazy_static::lazy_static;
lazy_static! {
    pub static ref KEYS: (ConcretePK, ConcreteVK) = circuit_setup();
}

#[allow(dead_code)]
fn log<T: Debug>(s: &T) {
    use web_sys::console;
    let str = format!("{:#?}", s);
    console::log_1(&str.into());
}

#[wasm_bindgen_test]
fn test_auth_roundtrip() {
    let wasm_auth0 = WasmIVCNotes::generate_auth().unwrap();
    let js_auth = wasm_auth0.as_js().unwrap();
    let wasm_auth1 = WasmAuth::from_js(js_auth).unwrap();
    assert_eq!(wasm_auth0.addresss(), wasm_auth1.addresss())
}

#[wasm_bindgen_test]
fn test_wasm() {
    let mut pk_bytes = Vec::new();
    let mut vk_bytes = Vec::new();
    KEYS.0.serialize_uncompressed(&mut pk_bytes).unwrap();
    KEYS.1.serialize_uncompressed(&mut vk_bytes).unwrap();

    let w0 = &mut Wallet::new_unchecked(&pk_bytes, &vk_bytes).unwrap();
    let w1 = &mut Wallet::new_unchecked(&pk_bytes, &vk_bytes).unwrap();
    let w2 = &mut Wallet::new_unchecked(&pk_bytes, &vk_bytes).unwrap();
    let w3 = &mut Wallet::new_unchecked(&pk_bytes, &vk_bytes).unwrap();
    let w4 = &mut Wallet::new_unchecked(&pk_bytes, &vk_bytes).unwrap();
    let w5 = &mut Wallet::new_unchecked(&pk_bytes, &vk_bytes).unwrap();

    issue(w0, w1, 1000).unwrap();
    transfer(w1, w2, 0, 900).unwrap();
    transfer(w2, w3, 0, 800).unwrap();
    transfer(w3, w4, 0, 400).unwrap();
    transfer(w3, w5, 0, 300).unwrap();

    log(&w3.tx_in);
    log(&w3.tx_out);
}
