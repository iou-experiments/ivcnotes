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
    // The first note in the propagation
    pub(crate) note: Note<F>,
    // Issuer address
    pub(crate) issuer: Address<F>,
}

#[derive(Debug, Clone)]
pub struct SealedIssueTx<TE: TECurveConfig + Clone>
where
    TE::BaseField: PrimeField + Absorb,
{
    // Wrapped transaction
    pub(crate) tx: IssueTx<TE::BaseField>,
    // Stored signature
    pub(crate) signature: Signature<TE>,
}

impl<F: PrimeField + Absorb> IssueTx<F> {
    // Create a new IssueTx
    pub(crate) fn new(issuer: &Address<F>, note: &Note<F>) -> Self {
        assert_eq!(note.out_index, NoteOutIndex::Out1);
        assert_eq!(note.step, 0);
        assert_eq!(note.parent_note, BlindNoteHash::<F>::default());

        IssueTx {
            note: *note,
            issuer: *issuer,
        }
    }

    // Get the note from IssueTx
    pub(crate) fn note(&self) -> &Note<F> {
        &self.note
    }

    // Seal the IssueTx with a signature
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
    // Create a new SealedIssueTx
    pub(crate) fn new(tx: IssueTx<TE::BaseField>, signature: Signature<TE>) -> Self {
        SealedIssueTx { tx, signature }
    }

    // Get the transaction from SealedIssueTx
    pub(crate) fn tx(&self) -> &IssueTx<TE::BaseField> {
        &self.tx
    }

    // Get the signature from SealedIssueTx
    pub(crate) fn signature(&self) -> &Signature<TE> {
        &self.signature
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SplitTx<F: PrimeField> {
    // Input note
    pub(crate) note_in: Note<F>,
    // Output note 0
    pub(crate) note_out_0: Note<F>,
    // Output note 1
    pub(crate) note_out_1: Note<F>,
}

#[derive(Debug, Clone)]
pub struct SealedSplitTx<TE: TECurveConfig + Clone>
where
    TE::BaseField: PrimeField + Absorb,
{
    // Wrapped transaction
    pub(crate) tx: SplitTx<TE::BaseField>,
    // Stored signature
    pub(crate) signature: Signature<TE>,
    // Stored nullifier
    pub(crate) nullifier: Nullifier<TE::BaseField>,
}

impl<F: PrimeField + Absorb> SplitTx<F> {
    // Create a new SplitTx
    pub(crate) fn new(note_in: &Note<F>, note_out_0: &Note<F>, note_out_1: &Note<F>) -> Self {
        Self {
            note_in: *note_in,
            note_out_0: *note_out_0,
            note_out_1: *note_out_1,
        }
    }

    // Seal the SplitTx with a signature and nullifier
    pub(crate) fn seal<TE: TECurveConfig<BaseField = F> + Clone>(
        &self,
        sig: &Signature<TE>,
        nullifier: &Nullifier<TE::BaseField>,
    ) -> SealedSplitTx<TE> {
        SealedSplitTx::new(self, sig, nullifier)
    }

    // Get the output note 0 from SplitTx
    pub(crate) fn note_out_0(&self) -> &Note<F> {
        &self.note_out_0
    }

    // Get the output note 1 from SplitTx
    pub(crate) fn note_out_1(&self) -> &Note<F> {
        &self.note_out_1
    }
}

impl<TE: TECurveConfig + Clone> SealedSplitTx<TE>
where
    TE::BaseField: PrimeField + Absorb,
{
    // Create a new SealedSplitTx
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

    // Get the nullifier from SealedSplitTx
    pub(crate) fn nullifier(&self) -> &Nullifier<TE::BaseField> {
        &self.nullifier
    }

    // Get the signature from SealedSplitTx
    pub(crate) fn signature(&self) -> &Signature<TE> {
        &self.signature
    }

    // Get the output note 0 from SealedSplitTx
    pub(crate) fn note_out_0(&self) -> &Note<TE::BaseField> {
        self.tx.note_out_0()
    }

    // Get the output note 1 from SealedSplitTx
    pub(crate) fn note_out_1(&self) -> &Note<TE::BaseField> {
        self.tx.note_out_1()
    }
}
