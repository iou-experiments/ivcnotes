use ivcnotes::asset::Terms;
use ivcnotes::circuit::{Verifier, IVC};
use ivcnotes::note::NoteHistory;
use ivcnotes::{
    circuit::{
        concrete::{Concrete, POSEIDON_CFG},
        Prover,
    },
    id::Auth,
    wallet::Wallet,
};
use ivcnotes::{Address, FWrap};
use rand_core::OsRng;
use serde_derive::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[cfg(test)]
mod test;

#[wasm_bindgen]
#[derive(Clone, Serialize, Deserialize)]
pub struct WasmAuth {
    secret: [u8; 32],
    address: String,
}

#[wasm_bindgen]
impl WasmAuth {
    pub fn as_js(&self) -> Result<JsValue, serde_wasm_bindgen::Error> {
        serde_wasm_bindgen::to_value(&self)
    }

    pub fn from_js(value: JsValue) -> Result<WasmNoteHistory, JsValue> {
        let inner: NoteHistory<Concrete> = serde_wasm_bindgen::from_value(value)?;
        Ok(WasmNoteHistory { inner })
    }

    pub fn addresss(&self) -> String {
        self.address.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq)]
pub struct WasmNoteHistory {
    inner: NoteHistory<Concrete>,
}

#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq)]
pub struct WasmAsset {
    issuer: String,
}

#[wasm_bindgen]
pub struct WasmTransferOutput {
    out0: WasmNoteHistory,
    out1: WasmNoteHistory,
}

#[wasm_bindgen]
impl WasmNoteHistory {
    pub fn hash(&self) -> Vec<u8> {
        self.inner.hash().to_vec()
    }

    pub fn issuer(&self) -> String {
        self.inner.asset().issuer().to_string()
    }

    pub fn as_js(&self) -> Result<JsValue, serde_wasm_bindgen::Error> {
        serde_wasm_bindgen::to_value(&self.inner)
    }

    pub fn from_js(value: JsValue) -> Result<WasmNoteHistory, JsValue> {
        let inner: NoteHistory<Concrete> = serde_wasm_bindgen::from_value(value)?;
        Ok(WasmNoteHistory { inner })
    }

    pub fn value(&self) -> u64 {
        self.inner.value()
    }

    pub fn owner(&self) -> String {
        self.inner.owner().to_string()
    }

    pub fn sender(&self) -> String {
        self.signers().last().unwrap().clone()
    }

    pub fn signers(&self) -> Vec<String> {
        let signers = self.inner.signers();
        signers.iter().map(|s| s.to_string()).collect()
    }
}

#[wasm_bindgen]
impl WasmTransferOutput {
    pub fn out0(&self) -> WasmNoteHistory {
        self.out0.clone()
    }

    pub fn out1(&self) -> WasmNoteHistory {
        self.out1.clone()
    }
}

#[wasm_bindgen]
pub struct WasmIVCNotes {
    inner: Wallet<Concrete>,
}

#[wasm_bindgen]
impl WasmIVCNotes {
    pub fn generate_auth() -> Result<WasmAuth, JsValue> {
        let auth: Auth<Concrete> = Auth::generate(&POSEIDON_CFG, &mut OsRng)
            .map_err(|_| JsValue::from("cannot generate auth object"))?;
        Ok(WasmAuth {
            secret: auth.to_bytes().try_into().unwrap(),
            address: auth.address().to_string(),
        })
    }

    pub fn new(pk: &[u8], vk: &[u8]) -> Result<WasmIVCNotes, JsValue> {
        let pk = Concrete::read_proving_key(pk).map_err(|_| JsValue::from("read_proving_key"))?;
        let prover = Prover::<Concrete>::new(pk);
        let vk =
            Concrete::read_verifying_key(vk).map_err(|_| JsValue::from("read_verifying_key"))?;
        let verifier = Verifier::new(vk);
        let inner = Wallet::new(&POSEIDON_CFG, prover, verifier);
        Ok(WasmIVCNotes { inner })
    }

    pub fn new_unchecked(pk: &[u8], vk: &[u8]) -> Result<WasmIVCNotes, JsValue> {
        let pk = Concrete::read_proving_key_unchecked(pk)
            .map_err(|_| JsValue::from("read_proving_key"))?;
        let prover = Prover::<Concrete>::new(pk);
        let vk = Concrete::read_verifying_key_unchecked(vk)
            .map_err(|_| JsValue::from("read_verifying_key"))?;
        let verifier = Verifier::new(vk);
        let inner = Wallet::new(&POSEIDON_CFG, prover, verifier);
        Ok(WasmIVCNotes { inner })
    }

    pub fn issue(
        &self,
        auth: &WasmAuth,
        receiver: &str,
        value: u64,
    ) -> Result<WasmNoteHistory, JsValue> {
        let rng = &mut OsRng;
        let auth = Auth::<Concrete>::new(&POSEIDON_CFG, auth.secret)
            .map_err(|_| JsValue::from("cannot generate auth object"))?;
        let receiver = Address::from_string(receiver.to_string())
            .map_err(|_| JsValue::from("invalid address"))?;
        let note_history = self
            .inner
            .issue(rng, &auth, &Terms::Open, value, &receiver)
            .map_err(|_| JsValue::from("prover error"))?;
        let note_history = WasmNoteHistory {
            inner: note_history,
        };
        Ok(note_history)
    }

    pub fn transfer(
        &self,
        auth: &WasmAuth,
        note_history: &WasmNoteHistory,
        receiver: &str,
        value: u64,
    ) -> Result<WasmTransferOutput, JsValue> {
        let rng = &mut OsRng;
        let auth = Auth::<Concrete>::new(&POSEIDON_CFG, auth.secret)
            .map_err(|_| JsValue::from("cannot generate auth object"))?;
        let receiver = Address::from_string(receiver.to_string())
            .map_err(|_| JsValue::from("invalid address"))?;
        let out = self
            .inner
            .split(rng, &auth, note_history.inner.clone(), value, &receiver)
            .map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let out = WasmTransferOutput {
            out0: WasmNoteHistory { inner: out.0 },
            out1: WasmNoteHistory { inner: out.1 },
        };
        Ok(out)
    }

    pub fn verify(&self, note_history: &WasmNoteHistory) -> Result<(), JsValue> {
        self.inner
            .verify(&note_history.inner)
            .map_err(|_| JsValue::from("verifier error"))
    }
}
