use crate::{
    asset::{Asset, Terms},
    circuit::{
        inputs::{AuxInputs, PublicInput},
        Prover, Verifier, IVC,
    },
    id::Auth,
    note::{IVCStep, Note, NoteHistory, NoteOutIndex},
    poseidon::PoseidonConfigs,
    tx::{IssueTx, SealedIssueTx, SealedSplitTx, SplitTx},
    Address, Blind, BlindNoteHash, FWrap,
};
use arkeddsa::PublicKey;
use rand::{CryptoRng, RngCore};
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]

pub struct Contact<E: IVC> {
    #[serde(with = "crate::ark_serde")]
    pub address: Address<E::Field>,
    pub username: String,
    #[serde(with = "crate::ark_serde")]
    pub public_key: PublicKey<E::TE>,
}

impl<E: IVC> PartialEq for Contact<E> {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
    }
}

impl<E: IVC> Eq for Contact<E> {}

impl<E: IVC> Ord for Contact<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.username.cmp(&other.username)
    }
}

impl<E: IVC> PartialOrd for Contact<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct Wallet<E: IVC> {
    // configs for poseidion hasher
    pub(crate) h: PoseidonConfigs<E::Field>,
    // ivc prover
    pub(crate) prover: Prover<E>,
    // ivc verifier
    pub(crate) verifier: Verifier<E>,
    // self contract
    pub(crate) contact: Contact<E>,
}

impl<E: IVC> Auth<E> {
    // sign issue transaction
    pub(crate) fn issue(
        &self,
        h: &PoseidonConfigs<E::Field>,
        tx: &IssueTx<E::Field>,
    ) -> Result<SealedIssueTx<E::TE>, crate::Error> {
        let (note_hash, _) = h.note(tx.note());
        let sighash = h.sighash(&Default::default(), &Default::default(), &note_hash);
        let signature = self.sign_tx(&sighash);
        Ok(tx.seal(signature))
    }

    // sign split transaction and generate the nullifier
    pub(crate) fn split(
        &self,
        h: &PoseidonConfigs<E::Field>,
        tx: &SplitTx<E::Field>,
    ) -> Result<SealedSplitTx<E::TE>, crate::Error> {
        let sighash = h.sighash_split_tx(tx);
        let signature = self.sign_tx(&sighash);
        let (note_in, _) = h.note(&tx.note_in);
        let nullifier = h.nullifier(&note_in, &self.nullifier_key());
        Ok(tx.seal(&signature, &nullifier))
    }
}

impl<E: IVC> Wallet<E> {
    pub fn new(
        auth: Auth<E>,
        poseidon: &PoseidonConfigs<E::Field>,
        prover: Prover<E>,
        verifier: Verifier<E>,
        username: String,
    ) -> Self {
        let contact = Contact {
            address: *auth.address(),
            username,
            public_key: auth.public_key().clone(),
        };
        Self {
            h: poseidon.clone(),
            prover,
            verifier,
            contact,
        }
    }

    pub fn address(&self) -> &Address<E::Field> {
        &self.contact.address
    }

    pub fn issue<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        auth: &Auth<E>,
        terms: &Terms,
        value: u64,
        receiver: &Contact<E>,
    ) -> Result<NoteHistory<E>, crate::Error> {
        // create asset from terms
        let asset = Asset::new(auth.address(), terms);
        let asset_hash = &asset.hash();
        // draw random blinding factor
        let blind = crate::Blind::<E::Field>::rand(rng);
        // create new note
        let note = Note::new(
            &asset.hash(),
            &receiver.address,
            value,
            0,
            &NoteOutIndex::Out1,
            &crate::BlindNoteHash::default(),
            blind,
        );

        // create the transaction
        let tx = IssueTx::new(self.address(), &note);
        // and sign
        let sealed = auth.issue(&self.h, &tx)?;

        // construct public inputs
        let state_in = &asset_hash.as_ref().into();
        let state_out = &self.h.state_out_from_issue_tx(sealed.tx());
        let sender = self.address();

        let public_inputs = PublicInput::new(
            asset_hash,
            sender,
            state_in,
            state_out,
            0,
            &Default::default(),
        );

        // construct aux inputs
        let public_key = auth.public_key();
        let signature = sealed.signature();
        let nullifier_key = auth.nullifier_key();
        let aux_inputs: AuxInputs<E> = AuxInputs::new(
            &receiver.address,
            public_key,
            signature,
            &nullifier_key,
            &Default::default(),
            &NoteOutIndex::Out1,
            0,
            value,
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &blind,
        );

        // crate proof
        let proof = self
            .prover
            .create_proof(&self.h, public_inputs, aux_inputs, rng)?;

        // create note history
        let step: IVCStep<E> = IVCStep::new(&proof, state_out, &Default::default(), self.address());
        let note_history = NoteHistory {
            asset,
            steps: vec![step],
            current_note: note,
            sibling: BlindNoteHash::default(),
        };

        Ok(note_history)
    }

    pub fn split<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        auth: &Auth<E>,
        mut note_history: NoteHistory<E>,
        value: u64,
        receiver: &Contact<E>,
    ) -> Result<(NoteHistory<E>, NoteHistory<E>), crate::Error> {
        let sender = auth.address();

        let note_in = note_history.current_note;
        let (_, blind_note_in) = self.h.note(&note_in);

        let step = note_history.steps.len() as u32;
        let asset_hash = &note_history.asset.hash();

        // find output values

        let value_out_0 = note_in
            .value
            .checked_sub(value)
            .ok_or(crate::Error::Custom("insufficient funds".into()))?;
        let value_out_1 = value;

        // create change note, output 0
        let note_out_0 = Note::new(
            asset_hash,
            sender,
            value_out_0,
            step,
            &NoteOutIndex::Out0,
            &blind_note_in,
            Blind::rand(rng),
        );

        // crate transfer note, output 1
        let note_out_1 = Note::new(
            asset_hash,
            &receiver.address,
            value_out_1,
            step,
            &NoteOutIndex::Out1,
            &blind_note_in,
            Blind::rand(rng),
        );

        // create the transaction
        let tx = SplitTx::new(&note_in, &note_out_0, &note_out_1);
        // and sign and generate the nullifier
        let sealed = auth.split(&self.h, &tx)?;

        // construct public inputs
        let state_in = &note_history.state(&self.h);
        let (_, blind_note_hash_0) = self.h.note(sealed.note_out_0());
        let (_, blind_note_hash_1) = self.h.note(sealed.note_out_1());
        let state_out = &self.h.state(&blind_note_hash_0, &blind_note_hash_1);

        let public_inputs = PublicInput::new(
            asset_hash,
            sender,
            state_in,
            state_out,
            step,
            &sealed.nullifier,
        );

        let public_key = auth.public_key();
        let signature = sealed.signature();
        let nullifier_key = auth.nullifier_key();
        let parent = &note_in.parent_note;
        let input_index = &note_in.out_index; // TODO: issue index is not good for first split tx?
        let value_in = note_in.value;
        let value_out = value_out_1;
        let sibling = &note_history.sibling;
        let aux_inputs: AuxInputs<E> = AuxInputs::new(
            &receiver.address,
            public_key,
            signature,
            &nullifier_key,
            parent,
            input_index,
            value_in,
            value_out,
            sibling,
            &note_in.blind,
            &note_out_0.blind,
            &note_out_1.blind,
        );

        // crate proof
        let proof = self
            .prover
            .create_proof(&self.h, public_inputs, aux_inputs, rng)?;

        // add the new step
        let step = IVCStep::new(&proof, state_out, sealed.nullifier(), sender);

        // and update note history
        note_history.steps.push(step);

        // 0. history to keep
        let mut note_history_0 = note_history.clone();
        note_history_0.current_note = note_out_0;
        note_history_0.sibling = blind_note_hash_1;

        // 1. history to send
        let mut note_history_1 = note_history.clone();
        note_history_1.current_note = note_out_1;
        note_history_1.sibling = blind_note_hash_0;

        Ok((note_history_0, note_history_1))
    }

    pub fn verify_incoming(&mut self, note_history: &NoteHistory<E>) -> Result<(), crate::Error> {
        let asset_hash = &note_history.asset.hash();
        let mut state_in = &asset_hash.as_ref().into();

        for (i, step) in note_history.steps.iter().enumerate() {
            let state_out = &step.state;
            let public_input = PublicInput::new(
                asset_hash,
                &step.sender,
                state_in,
                state_out,
                i as u32,
                &step.nullifier,
            );

            if i == note_history.steps.len() - 1 {
                (note_history.state(&self.h) == *state_out)
                    .then_some(())
                    .ok_or(crate::Error::Verify("bad current state".into()))?;
            }
            use ark_serialize::CanonicalSerialize;
            let mut bytes = Vec::new();
            step.proof.serialize_compressed(&mut bytes).unwrap();
            let verified = self.verifier.verify_proof(&step.proof, &public_input)?;
            if !verified {
                println!("not verified {}", i);
                return Err(crate::Error::Verify("not verified".into()));
            }
            state_in = state_out;
        }

        Ok(())
    }
}
