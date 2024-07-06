use crate::crypto::hasher::ToSponge;
use ark_crypto_primitives::sponge::Absorb;
use arkeddsa::signature::Signature;

use crate::{
    crypto::{
        circuit::{Nullifier, StateHash, SNARK},
        hasher::NtoOneHasher,
    },
    id::{NullifierKey, SigHash},
    note::{BlindNoteHash, Note, NoteOutIndex},
    FWrap,
};

#[derive(Debug, Clone, Copy)]
pub enum Tx<E: SNARK> {
    Issue(SealedIssueTx<E>),
    Split {
        tx: SealedSplitTx<E>,
        sibling: BlindNoteHash<E::AppField>,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IssueTx<F: ark_ff::PrimeField> {
    pub(crate) note: Note<F>,
    // signature hash calculated in the construction
    // `sig_hash = H(note_hash)`
    pub(crate) sig_hash: SigHash<F>,
    // output state calculated in the construction
    // `state_out = H(blinded_hash)`
    // pub(crate) state_out: StateHash<F>,
}

#[derive(Debug, Clone, Copy)]
pub struct SealedIssueTx<E: SNARK> {
    // wrap the transaction
    pub(crate) tx: IssueTx<E::AppField>,
    // additionally store the signature
    pub(crate) signature: Signature<E::Ed>,
}

impl<F: ark_ff::PrimeField + Absorb> IssueTx<F> {
    pub(crate) fn new<H: NtoOneHasher<F>>(h: &H, note: &Note<F>) -> Self {
        assert_eq!(note.out_index, NoteOutIndex::Issue);
        assert_eq!(note.step, 0);
        assert_eq!(note.parent_note_blind_hash, BlindNoteHash::<F>::default());

        let sig_hash = h.hash(note).into();
        // let state_out = note.blinded_hash(h).inner().into();

        IssueTx {
            note: *note,
            sig_hash,
            // state_out,
        }
    }

    pub(crate) fn note(&self) -> &Note<F> {
        &self.note
    }

    pub(crate) fn sig_hash(&self) -> &SigHash<F> {
        &self.sig_hash
    }

    pub(crate) fn seal<E: SNARK<AppField = F>>(self, sig: Signature<E::Ed>) -> SealedIssueTx<E> {
        SealedIssueTx::new(self, sig)
    }
}

impl<E: SNARK> SealedIssueTx<E> {
    pub(crate) fn new(tx: IssueTx<E::AppField>, signature: Signature<E::Ed>) -> Self {
        SealedIssueTx { tx, signature }
    }

    // pub(crate) fn state_out(&self) -> &StateHash<E::AppField> {
    //     &self.tx.state_out
    // }

    pub(crate) fn signature(&self) -> &Signature<E::Ed> {
        &self.signature
    }

    pub(crate) fn note(&self) -> &Note<E::AppField> {
        &self.tx.note
    }

    pub(crate) fn inner(&self) -> &IssueTx<E::AppField> {
        &self.tx
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SplitTx<F: ark_ff::PrimeField> {
    pub(crate) note_in: Note<F>,
    pub(crate) note_out_0: Note<F>,
    pub(crate) note_out_1: Note<F>,

    // signature hash calculated in the construction
    // `sig_hash = H(note_hash)`
    pub(crate) sig_hash: SigHash<F>,
    // output state calculated in the construction
    // `state_out = H(blinded_hash)`
    pub(crate) state_out: StateHash<F>,
}

#[derive(Debug, Clone, Copy)]
pub struct SealedSplitTx<E: SNARK> {
    // wrap the transaction
    pub(crate) tx: SplitTx<E::AppField>,
    // store the signature
    pub(crate) signature: Signature<E::Ed>,
    // and the nullifier
    pub(crate) nullifier: Nullifier<E::AppField>,
}

impl<F: ark_ff::PrimeField + Absorb> SplitTx<F> {
    pub fn new<H: NtoOneHasher<F>>(
        h: &H,
        note_in: &Note<F>,
        note_out_0: &Note<F>,
        note_out_1: &Note<F>,
    ) -> Self {
        let sig_hash = {
            let note_in = h.compress(&note_in.to_sponge());
            let note_out_0 = h.compress(&note_out_0.to_sponge());
            let note_out_1 = h.compress(&note_out_1.to_sponge());
            h.compress(&[note_in, note_out_1, note_out_0]).into()
        };

        let state_out = {
            let blind_note_out_0 = note_out_0.blinded_hash(h);
            let blind_note_out_1 = note_out_1.blinded_hash(h);
            h.compress(&[blind_note_out_0.inner(), blind_note_out_1.inner()])
                .into()
        };

        SplitTx {
            note_in: *note_in,
            note_out_0: *note_out_0,
            note_out_1: *note_out_1,

            sig_hash,
            state_out,
        }
    }

    pub fn sig_hash(&self) -> &SigHash<F> {
        &self.sig_hash
    }

    pub fn nullifier<H: NtoOneHasher<F>>(
        &self,
        h: &H,
        nullifier_key: &NullifierKey<F>,
    ) -> Nullifier<F> {
        self.note_in.nullifier(h, nullifier_key)
    }

    pub fn seal<E: SNARK<AppField = F>>(
        &self,
        sig: &Signature<E::Ed>,
        nullifier: &Nullifier<E::AppField>,
    ) -> SealedSplitTx<E> {
        SealedSplitTx::new(self, sig, nullifier)
    }
}

impl<E: SNARK> SealedSplitTx<E> {
    pub fn new(
        tx: &SplitTx<E::AppField>,
        signature: &Signature<E::Ed>,
        nullifier: &Nullifier<E::AppField>,
    ) -> Self {
        SealedSplitTx {
            tx: *tx,
            signature: *signature,
            nullifier: *nullifier,
        }
    }

    pub(crate) fn inner(&self) -> &SplitTx<E::AppField> {
        &self.tx
    }

    pub(crate) fn state_out(&self) -> &StateHash<E::AppField> {
        &self.tx.state_out
    }

    pub(crate) fn nullifier(&self) -> &Nullifier<E::AppField> {
        &self.nullifier
    }

    pub(crate) fn signature(&self) -> &Signature<E::Ed> {
        &self.signature
    }

    // pub(crate) fn note_in(&self) -> &Note<E::AppField> {
    //     &self.tx.note_in
    // }

    // pub(crate) fn note_out_0(&self) -> &Note<E::AppField> {
    //     &self.tx.note_out_0
    // }

    // pub(crate) fn note_out_1(&self) -> &Note<E::AppField> {
    //     &self.tx.note_out_1
    // }
}
