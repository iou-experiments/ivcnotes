use crate::{
    circuit::inputs::NoteVar,
    note::Note,
    tx::{IssueTx, SplitTx},
    Address, Blind, BlindNoteHash, FWrap, NoteHash, Nullifier, NullifierKey, SigHash, StateHash,
};
use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::CRHGadget, poseidon::constraints::CRHParametersVar, poseidon::CRH,
        CRHScheme, CRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, fields::fp::FpVar, groups::curves::twisted_edwards::AffineVar,
};
use ark_relations::r1cs::{Namespace, Result as CSResult};
use arkeddsa::PublicKey;

pub trait ToCRH<F: PrimeField> {
    type Output;
    fn to_crh(&self) -> Vec<Self::Output>;
}

impl<F: PrimeField + Absorb> ToCRH<F> for Note<F> {
    type Output = F;

    // serialize into field elements
    fn to_crh(&self) -> Vec<F> {
        let asset_hash = self.asset_hash.inner();
        let owner = self.owner.inner();
        let value = self.value.into();
        let step = self.step.into();
        let parent = self.parent_note.inner();
        let out_index = self.out_index.inner();
        vec![asset_hash, owner, value, step, parent, out_index]
    }
}

pub(crate) fn field_cast<'a, F1: PrimeField, F2: PrimeField>(
    x: &[F1],
    dest: &'a mut Vec<F2>,
) -> Option<&'a mut Vec<F2>> {
    if F1::characteristic() != F2::characteristic() {
        // "Trying to absorb non-native field elements."
        None
    } else {
        x.iter().for_each(|item| {
            let bytes = item.into_bigint().to_bytes_le();
            dest.push(F2::from_le_bytes_mod_order(&bytes))
        });
        Some(dest)
    }
}

impl<F: PrimeField + Absorb> Absorb for Note<F> {
    fn to_sponge_bytes(&self, _: &mut Vec<u8>) {
        unimplemented!();
    }

    fn to_sponge_field_elements<FF: PrimeField>(&self, dest: &mut Vec<FF>) {
        field_cast(&self.to_crh(), dest).unwrap();
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonConfigs<F: PrimeField + Absorb> {
    pub(crate) id: PoseidonConfig<F>,
    pub(crate) note: PoseidonConfig<F>,
    pub(crate) blind: PoseidonConfig<F>,
    pub(crate) state: PoseidonConfig<F>,
    pub(crate) nullifier: PoseidonConfig<F>,
    pub(crate) tx: PoseidonConfig<F>,
    pub(crate) eddsa: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> PoseidonConfigs<F> {
    pub fn id_commitment<TE: TECurveConfig<BaseField = F>>(
        &self,
        nullifier_key: &NullifierKey<F>,
        public_key: &PublicKey<TE>,
    ) -> Address<F> {
        let (x, y) = public_key.xy();
        let input = vec![nullifier_key.inner(), *x, *y];
        CRH::<F>::evaluate(&self.id, input).unwrap().into()
    }

    pub fn var_id_commitment<TE: TECurveConfig<BaseField = F>>(
        &self,
        cs: impl Into<Namespace<F>>,
        nullifier_key: &FpVar<F>,
        public_key: &AffineVar<TE, FpVar<F>>,
    ) -> CSResult<FpVar<F>> {
        let cs = cs.into();
        let (x, y) = (public_key.x.clone(), public_key.y.clone());
        let input = vec![nullifier_key.clone(), x, y];
        let params = CRHParametersVar::<F>::new_constant(cs.clone(), &self.id)?;
        CRHGadget::evaluate(&params, &input)
    }

    pub fn note(&self, note: &Note<F>) -> (NoteHash<F>, BlindNoteHash<F>) {
        let input = note.to_crh();
        let note_hash = CRH::<F>::evaluate(&self.note, input).unwrap().into();
        let blind = self.blind_note(&note_hash, &note.blind);
        (note_hash, blind)
    }

    pub fn blind_note(&self, note: &NoteHash<F>, blind: &Blind<F>) -> BlindNoteHash<F> {
        let input = vec![note.inner(), blind.inner()];
        CRH::<F>::evaluate(&self.blind, input).unwrap().into()
    }

    pub fn var_note(&self, cs: impl Into<Namespace<F>>, note: &NoteVar<F>) -> CSResult<FpVar<F>> {
        let cs = cs.into().cs();
        let input = note.to_crh();
        let params = CRHParametersVar::<F>::new_constant(cs.clone(), &self.note)?;
        CRHGadget::evaluate(&params, &input)
    }

    pub fn var_blind_note(
        &self,
        cs: impl Into<Namespace<F>>,
        note_hash: &FpVar<F>,
        blind: &FpVar<F>,
    ) -> CSResult<FpVar<F>> {
        let cs = cs.into().cs();
        let input = vec![note_hash.clone(), blind.clone()];
        let params = CRHParametersVar::<F>::new_constant(cs.clone(), &self.blind)?;
        CRHGadget::evaluate(&params, &input)
    }

    pub fn state_out_from_issue_tx(&self, tx: &IssueTx<F>) -> StateHash<F> {
        let (_, blind_note_hash) = self.note(tx.note());
        self.state(&Default::default(), &blind_note_hash)
    }

    pub fn state_out_from_split_tx(&self, tx: &SplitTx<F>) -> StateHash<F> {
        let (_, blind_note_hash_0) = self.note(tx.note_out_0());
        let (_, blind_note_hash_1) = self.note(tx.note_out_1());
        self.state(&blind_note_hash_0, &blind_note_hash_1)
    }

    pub fn state(&self, out0: &BlindNoteHash<F>, out1: &BlindNoteHash<F>) -> StateHash<F> {
        let input = vec![out0.inner(), out1.inner()];
        CRH::<F>::evaluate(&self.state, input).unwrap().into()
    }

    pub fn var_state(
        &self,
        cs: impl Into<Namespace<F>>,
        out0: &FpVar<F>,
        out1: &FpVar<F>,
    ) -> CSResult<FpVar<F>> {
        let cs = cs.into().cs();
        let input = vec![out0.clone(), out1.clone()];
        let params = CRHParametersVar::<F>::new_constant(cs.clone(), &self.state)?;
        CRHGadget::evaluate(&params, &input)
    }

    pub fn sighash_split_tx(&self, tx: &SplitTx<F>) -> SigHash<F> {
        let (note_in, _) = self.note(&tx.note_in);
        let (note_out_0, _) = self.note(&tx.note_out_0);
        let (note_out_1, _) = self.note(&tx.note_out_1);
        self.sighash(&note_in, &note_out_0, &note_out_1)
    }

    pub fn sighash_issue_tx(&self, tx: &Note<F>) -> SigHash<F> {
        let (note, _) = self.note(tx);
        self.sighash(&Default::default(), &note, &Default::default())
    }

    pub fn sighash(
        &self,
        input: &NoteHash<F>,
        out0: &NoteHash<F>,
        out1: &NoteHash<F>,
    ) -> SigHash<F> {
        let input = vec![input.inner(), out0.inner(), out1.inner()];
        CRH::<F>::evaluate(&self.tx, input).unwrap().into()
    }

    pub fn var_sighash(
        &self,
        cs: impl Into<Namespace<F>>,
        input: &FpVar<F>,
        out0: &FpVar<F>,
        out1: &FpVar<F>,
    ) -> CSResult<FpVar<F>> {
        let cs = cs.into().cs();
        let input = vec![input.clone(), out0.clone(), out1.clone()];
        let params = CRHParametersVar::<F>::new_constant(cs.clone(), &self.tx)?;
        CRHGadget::evaluate(&params, &input)
    }

    pub fn nullifier(&self, note_in: &NoteHash<F>, key: &NullifierKey<F>) -> Nullifier<F> {
        let input = vec![note_in.inner(), key.inner()];
        CRH::<F>::evaluate(&self.state, input).unwrap().into()
    }

    pub fn var_nullifier(
        &self,
        cs: impl Into<Namespace<F>>,
        note: &FpVar<F>,
        nullifier_key: &FpVar<F>,
    ) -> CSResult<FpVar<F>> {
        let cs = cs.into().cs();
        let input = vec![note.clone(), nullifier_key.clone()];
        let params = CRHParametersVar::<F>::new_constant(cs.clone(), &self.nullifier)?;
        CRHGadget::evaluate(&params, &input)
    }
}
