use crate::crypto::circuit::Witness;
use crate::crypto::circuit::SNARK;
use crate::id::Auth;
use crate::tx::IssueTx;
use crate::tx::{SealedIssueTx, SealedSplitTx, SplitTx};
use crate::Error;
use crate::{asset::Asset, id::Address, note::Blind};
use crate::{
    note::{BlindNoteHash, Note, NoteHistory, NoteOutIndex},
    FWrap,
};
use rand::RngCore;

pub trait CommReceiver<E: SNARK> {
    fn receive(&mut self, history: &NoteHistory<E>) -> Result<(), crate::Error>;
    fn address(&self) -> &Address<E::AppField>;
}

pub struct Wallet<E: SNARK> {
    // receivables are transferable notes
    receivables: Vec<NoteHistory<E>>,
    // auth object that holds private keys
    auth: Auth<E>,
    // pre configured hasher
    hasher: E::Hasher,
}

impl<E: SNARK> CommReceiver<E> for Wallet<E> {
    fn receive(&mut self, note_history: &NoteHistory<E>) -> Result<(), crate::Error> {
        note_history.verify(&self.hasher)?;
        self.receivables.push(note_history.clone());
        Ok(())
    }

    fn address(&self) -> &Address<E::AppField> {
        self.auth.address()
    }
}

impl<E: SNARK> Auth<E> {
    // sign issue transaction
    pub(crate) fn issue(
        &mut self,
        tx: &IssueTx<E::AppField>,
    ) -> Result<SealedIssueTx<E>, crate::Error> {
        let signature = self.sign(&tx.sig_hash);
        Ok(tx.seal(signature))
    }

    // sign split transaction and generate the nullifier
    pub(crate) fn split(
        &mut self,
        h: &E::Hasher,
        tx: &SplitTx<E::AppField>,
    ) -> Result<SealedSplitTx<E>, crate::Error> {
        let signature = self.sign(&tx.sig_hash);
        let nullifier = tx.nullifier(h, self.nullifier_key());
        Ok(tx.seal(&signature, &nullifier))
    }
}

impl<E: SNARK> Wallet<E> {
    pub fn new(h: &E::Hasher, auth: Auth<E>) -> Self {
        Self {
            hasher: h.clone(),
            receivables: vec![],
            auth,
        }
    }

    pub fn issue(
        &mut self,
        rng: &mut impl RngCore,
        receiver: &mut impl CommReceiver<E>,
        asset: &Asset<E::AppField>,
        value: u64,
    ) -> Result<(), crate::Error> {
        // draw random blinding factor
        let blind = Blind::<E::AppField>::rand(rng);
        // create new note
        let note = Note::new(
            &asset.hash(),
            receiver.address(),
            value,
            0,
            &NoteOutIndex::Issue,
            &BlindNoteHash::default(),
            blind,
        );

        // create the note and sign
        let tx = IssueTx::new(&self.hasher, &note);
        let tx = self.auth.issue(&tx)?;

        // create witness
        let witness =
            E::Witness::first_step_witness(&tx, self.auth.nullifier_key(), self.auth.public_key())?;

        // crate a fresh history with initial note
        let history = NoteHistory::new(asset, tx.note(), &witness);

        // post the history to the receiver
        receiver.receive(&history)?;

        Ok(())
    }

    pub fn split<Comm: CommReceiver<E>>(
        &mut self,
        rng: &mut impl RngCore,
        receiver: &mut impl CommReceiver<E>,
        note_history: &mut NoteHistory<E>,
        value: u64,
    ) -> Result<(), crate::Error> {
        let note_in = note_history.current_note;
        let step = (note_history.steps.len() - 1) as u32;
        let asset_hash = &note_history.asset.hash();

        // find output values
        let value_out_0 = value;
        let value_out_1 = note_in
            .value
            .checked_sub(value)
            .ok_or(Error::With("insufficient funds"))?;

        // create change note, output 0
        let note_out_0 = Note::new(
            asset_hash,
            self.address(),
            value_out_0,
            step,
            &NoteOutIndex::Out0,
            &note_in.parent_note_blind_hash,
            Blind::rand(rng),
        );

        // crate transfer note, output 1
        let note_out_1 = Note::new(
            asset_hash,
            receiver.address(),
            value_out_1,
            step,
            &NoteOutIndex::Out1,
            &note_in.parent_note_blind_hash,
            Blind::rand(rng),
        );

        let tx = SplitTx::new(&self.hasher, &note_in, &note_out_0, &note_out_1);
        let tx = self.auth.split(&self.hasher, &tx)?;

        // accumulate witness
        E::Witness::accumulate_witness(
            note_history,
            &tx,
            self.auth.nullifier_key(),
            self.auth.public_key(),
        )?;

        // send the updated history to the receiver
        receiver.receive(note_history)?;
        Ok(())
    }
}
