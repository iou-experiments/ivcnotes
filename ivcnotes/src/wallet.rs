use crate::{
    asset::Asset,
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

use rand::{CryptoRng, RngCore};

pub trait CommReceiver<E: IVC> {
    fn receive(&mut self, history: &NoteHistory<E>) -> Result<(), crate::Error>;
    fn address(&self) -> &Address<E::Field>;
}

pub struct Wallet<E: IVC> {
    // receivables are transferable notes
    spendables: Vec<NoteHistory<E>>,
    // auth object that holds private keys
    auth: Auth<E>,
    // configs for poseidion hasher
    h: PoseidonConfigs<E::Field>,
    // prover
    prover: Prover<E>,
    // verifier
    verifier: Verifier<E>,
}

impl<E: IVC> CommReceiver<E> for Wallet<E> {
    fn receive(&mut self, note_history: &NoteHistory<E>) -> Result<(), crate::Error> {
        (note_history.current_note.owner == *self.address())
            .then_some(())
            .ok_or(crate::Error::With("not me"))?;

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
                    .ok_or(crate::Error::With("bad current state"))?;
            }
            self.verifier
                .verify_proof(&step.proof, &public_input)
                .map_err(|_| crate::Error::With("verification failed"))?;
            state_in = state_out;
        }

        Ok(())
    }

    fn address(&self) -> &Address<E::Field> {
        self.auth.address()
    }
}

impl<E: IVC> Auth<E> {
    // sign issue transaction
    pub(crate) fn issue(
        &mut self,
        h: &PoseidonConfigs<E::Field>,
        tx: &IssueTx<E::Field>,
    ) -> Result<SealedIssueTx<E::TE>, crate::Error> {
        let (note_hash, _) = h.note(tx.note());
        let sighash = h.sighash(&Default::default(), &note_hash, &Default::default());
        let signature = self.sign(&sighash);
        Ok(tx.seal(signature))
    }

    // sign split transaction and generate the nullifier
    pub(crate) fn split(
        &self,
        h: &PoseidonConfigs<E::Field>,
        tx: &SplitTx<E::Field>,
    ) -> Result<SealedSplitTx<E::TE>, crate::Error> {
        let sighash = h.sighash_split_tx(tx);
        let signature = self.sign(&sighash);
        let (note_in, _) = h.note(&tx.note_in);
        let nullifier = h.nullifier(&note_in, self.nullifier_key());
        Ok(tx.seal(&signature, &nullifier))
    }
}

impl<E: IVC> Wallet<E> {
    pub fn new(
        auth: Auth<E>,
        poseidon: &PoseidonConfigs<E::Field>,
        prover: Prover<E>,
        verifier: Verifier<E>,
    ) -> Self {
        Self {
            spendables: vec![],
            auth,
            h: poseidon.clone(),
            prover,
            verifier,
        }
    }

    pub fn issue<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        comm_receiver: &mut impl CommReceiver<E>,
        asset: &Asset<E::Field>,
        value: u64,
    ) -> Result<(), crate::Error> {
        let asset_hash = &asset.hash();
        // draw random blinding factor
        let blind = Blind::<E::Field>::rand(rng);
        // create new note
        let note = Note::new(
            &asset.hash(),
            comm_receiver.address(),
            value,
            0,
            &NoteOutIndex::Issue,
            &crate::BlindNoteHash::default(),
            blind,
        );

        // create the transaction
        let tx = IssueTx::new(self.address(), &note);
        // and sign
        let sealed = self.auth.issue(&self.h, &tx)?;

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

        // contruct aux inputs
        let receiver = comm_receiver.address();
        let public_key = self.auth.public_key();
        let signature = sealed.signature();
        let nullifier_key = self.auth.nullifier_key();
        let aux_inputs: AuxInputs<E> = AuxInputs::new(
            receiver,
            public_key,
            signature,
            nullifier_key,
            &Default::default(),
            &NoteOutIndex::Issue,
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
        let step = IVCStep::new(&proof, state_out, &Default::default(), self.address());
        let note_history = NoteHistory {
            asset: *asset,
            steps: vec![step],
            current_note: note,
            sibling: BlindNoteHash::default(),
        };

        // send the new history to the receivers
        comm_receiver.receive(&note_history)?;

        Ok(())
    }

    pub fn split<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        comm_receiver: &mut impl CommReceiver<E>,
        spendable_index: usize,
        value: u64,
    ) -> Result<(), crate::Error> {
        let sender = *self.address();
        let note_history = self
            .spendables
            .get_mut(spendable_index)
            .ok_or(crate::Error::With("bad spendable index"))?;

        let note_in = note_history.current_note;
        let step = (note_history.steps.len() - 1) as u32;
        let asset_hash = &note_history.asset.hash();

        // find output values

        let value_out_0 = note_in
            .value
            .checked_sub(value)
            .ok_or(crate::Error::With("insufficient funds"))?;
        let value_out_1 = value;

        // create change note, output 0
        let note_out_0 = Note::new(
            asset_hash,
            &sender,
            value_out_0,
            step,
            &NoteOutIndex::Out0,
            &note_in.parent_note,
            Blind::rand(rng),
        );

        // crate transfer note, output 1
        let note_out_1 = Note::new(
            asset_hash,
            comm_receiver.address(),
            value_out_1,
            step,
            &NoteOutIndex::Out1,
            &note_in.parent_note,
            Blind::rand(rng),
        );

        // create the transaction
        let tx = SplitTx::new(&note_in, &note_out_0, &note_out_1);
        // and sign and generate the nullifier
        let sealed = self.auth.split(&self.h, &tx)?;

        // construct public inputs
        let state_in = &note_history.state(&self.h);
        let (_, blind_note_hash_0) = self.h.note(sealed.note_out_0());
        let (_, blind_note_hash_1) = self.h.note(sealed.note_out_1());
        let state_out = &self.h.state(&blind_note_hash_0, &blind_note_hash_1);

        let public_inputs = PublicInput::new(
            asset_hash,
            &sender,
            state_in,
            state_out,
            0,
            &Default::default(),
        );

        let receiver = comm_receiver.address();
        let public_key = self.auth.public_key();
        let signature = sealed.signature();
        let nullifier_key = self.auth.nullifier_key();
        let parent = &note_in.parent_note;
        let input_index = &note_in.out_index; // TODO: issue index is not good for first split tx?
        let value_in = note_in.value;
        let value_out = value_out_1;
        let sibling = &note_history.sibling;
        let aux_inputs: AuxInputs<E> = AuxInputs::new(
            receiver,
            public_key,
            signature,
            nullifier_key,
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

        // update note history

        // add the new step
        let step = IVCStep::new(&proof, state_out, sealed.nullifier(), &sender);

        note_history.steps.push(step);

        // update the leading notes

        // 0. history to keep
        let note_history_0 = note_history;
        note_history_0.current_note = note_out_0;
        note_history_0.sibling = blind_note_hash_1;

        // 1. history to send
        let mut note_history_1 = note_history_0.clone();
        note_history_1.current_note = note_out_1;
        note_history_1.sibling = blind_note_hash_0;
        comm_receiver.receive(&note_history_1)?;

        Ok(())
    }
}
