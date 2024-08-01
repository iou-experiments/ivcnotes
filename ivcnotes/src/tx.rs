use ark_crypto_primitives::sponge::Absorb;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::PrimeField;
use arkeddsa::signature::Signature;

use crate::{
    note::{Note, NoteOutIndex},
    Address, BlindNoteHash, Nullifier,
};

#[derive(Debug, Clone, Copy)]
pub struct IssueTx<F: PrimeField> {
    // the first note in the propagation
    pub(crate) note: Note<F>,
    // issuer address
    pub(crate) issuer: Address<F>,
}

#[derive(Debug, Clone)]
pub struct SealedIssueTx<TE: TECurveConfig + Clone>
where
    TE::BaseField: PrimeField + Absorb,
{
    // wrap the transaction
    pub(crate) tx: IssueTx<TE::BaseField>,
    // additionally store the signature
    pub(crate) signature: Signature<TE>,
}

impl<F: PrimeField + Absorb> IssueTx<F> {
    pub(crate) fn new(issuer: &Address<F>, note: &Note<F>) -> Self {
        assert_eq!(note.out_index, NoteOutIndex::Out1);
        assert_eq!(note.step, 0);
        assert_eq!(note.parent_note, BlindNoteHash::<F>::default());

        IssueTx {
            note: *note,
            issuer: *issuer,
        }
    }

    pub(crate) fn note(&self) -> &Note<F> {
        &self.note
    }

    pub(crate) fn seal<TE: TECurveConfig<BaseField = F> + Clone>(
        self,
        sig: Signature<TE>,
    ) -> SealedIssueTx<TE> {
        SealedIssueTx::new(self, sig)
    }
}

impl<TE: TECurveConfig + Clone> SealedIssueTx<TE>
where
    TE::BaseField: PrimeField + Absorb,
{
    pub(crate) fn new(tx: IssueTx<TE::BaseField>, signature: Signature<TE>) -> Self {
        SealedIssueTx { tx, signature }
    }

    pub(crate) fn tx(&self) -> &IssueTx<TE::BaseField> {
        &self.tx
    }

    pub(crate) fn signature(&self) -> &Signature<TE> {
        &self.signature
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SplitTx<F: PrimeField> {
    pub(crate) note_in: Note<F>,
    pub(crate) note_out_0: Note<F>,
    pub(crate) note_out_1: Note<F>,
}

#[derive(Debug, Clone)]
pub struct SealedSplitTx<TE: TECurveConfig + Clone>
where
    TE::BaseField: PrimeField + Absorb,
{
    // wrap the transaction
    pub(crate) tx: SplitTx<TE::BaseField>,
    // store the signature
    pub(crate) signature: Signature<TE>,
    // and the nullifier
    pub(crate) nullifier: Nullifier<TE::BaseField>,
}

impl<F: PrimeField + Absorb> SplitTx<F> {
    pub(crate) fn new(note_in: &Note<F>, note_out_0: &Note<F>, note_out_1: &Note<F>) -> Self {
        Self {
            note_in: *note_in,
            note_out_0: *note_out_0,
            note_out_1: *note_out_1,
        }
    }

    pub(crate) fn seal<TE: TECurveConfig<BaseField = F> + Clone>(
        &self,
        sig: &Signature<TE>,
        nullifier: &Nullifier<TE::BaseField>,
    ) -> SealedSplitTx<TE> {
        SealedSplitTx::new(self, sig, nullifier)
    }

    pub(crate) fn note_out_0(&self) -> &Note<F> {
        &self.note_out_0
    }

    pub(crate) fn note_out_1(&self) -> &Note<F> {
        &self.note_out_1
    }
}

impl<TE: TECurveConfig + Clone> SealedSplitTx<TE>
where
    TE::BaseField: PrimeField + Absorb,
{
    pub(crate) fn new(
        tx: &SplitTx<TE::BaseField>,
        signature: &Signature<TE>,
        nullifier: &Nullifier<TE::BaseField>,
    ) -> Self {
        SealedSplitTx {
            tx: *tx,
            signature: signature.clone(),
            nullifier: *nullifier,
        }
    }

    pub(crate) fn nullifier(&self) -> &Nullifier<TE::BaseField> {
        &self.nullifier
    }

    pub(crate) fn signature(&self) -> &Signature<TE> {
        &self.signature
    }

    pub(crate) fn note_out_0(&self) -> &Note<TE::BaseField> {
        self.tx.note_out_0()
    }

    pub(crate) fn note_out_1(&self) -> &Note<TE::BaseField> {
        self.tx.note_out_1()
    }
}
