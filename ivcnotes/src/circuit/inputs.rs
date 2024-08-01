use super::IVC;
use crate::note::NoteOutIndex;
use crate::poseidon::ToCRH;
use crate::{Address, AssetHash, Blind, BlindNoteHash, FWrap, Nullifier, NullifierKey, StateHash};
use ark_ec::twisted_edwards::Affine;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{Namespace, Result as CSResult, SynthesisError};
use arkeddsa::signature::Signature;
use arkeddsa::PublicKey;
use std::borrow::Borrow;
use std::fmt::Debug;

pub(super) fn var_in<Z, F: PrimeField, V, Var: AllocVar<V, F>, T: Borrow<V> + Clone>(
    cs: impl Into<Namespace<F>>,
    st: Option<&Z>,
    access: impl FnOnce(&Z) -> T,
    mode: AllocationMode,
) -> CSResult<Var> {
    Var::new_variable(
        cs.into().cs(),
        || {
            st.map(|e| access(e).clone())
                .ok_or(SynthesisError::AssignmentMissing)
        },
        mode,
    )
}

pub(super) fn witness_in<Z, F: PrimeField, T: Borrow<F> + Clone>(
    cs: impl Into<Namespace<F>>,
    st: Option<&Z>,
    access: impl FnOnce(&Z) -> T,
) -> CSResult<FpVar<F>> {
    var_in::<_, _, _, _, _>(cs.into().cs(), st, access, AllocationMode::Witness)
}

pub(super) fn witness_point_in<Z, F: PrimeField, TE: TECurveConfig<BaseField = F> + Clone>(
    cs: impl Into<Namespace<F>>,
    st: Option<&Z>,
    access: impl FnOnce(&Z) -> Affine<TE>,
) -> CSResult<AffineVar<TE, FpVar<F>>> {
    var_in::<_, _, _, AffineVar<TE, FpVar<F>>, Affine<TE>>(
        cs.into().cs(),
        st,
        access,
        AllocationMode::Witness,
    )
}

impl<F: PrimeField> PublicInput<F> {
    pub(crate) fn new(
        asset_hash: &AssetHash<F>,
        sender: &Address<F>,
        state_in: &StateHash<F>,
        state_out: &StateHash<F>,
        step: u32,
        nullifier: &Nullifier<F>,
    ) -> Self {
        Self {
            asset_hash: *asset_hash,
            sender: *sender,
            state_in: *state_in,
            state_out: *state_out,
            step,
            nullifier: *nullifier,
        }
    }

    pub(crate) fn to_verifier(&self) -> Vec<F> {
        vec![
            self.asset_hash.inner(),
            self.sender.inner(),
            self.state_in.inner(),
            self.state_out.inner(),
            self.nullifier.inner(),
            F::from(self.step as u64),
        ]
    }
}

#[derive(Debug, Clone, Default)]
pub struct PublicInput<F: PrimeField> {
    // asset hash is part of notes
    pub(crate) asset_hash: AssetHash<F>,
    // sender of the note
    pub(crate) sender: Address<F>,
    // input state `state_in = hash(sibling, input_note)` or `state_in = hash(input_note, sibling)`
    pub(crate) state_in: StateHash<F>,
    // output state `state_out = hash(note_out_0, note_out_1)`
    pub(crate) state_out: StateHash<F>,
    // number of steps so far in the ivc propagation
    pub(crate) step: u32,
    // nullifier of the spent note
    pub(crate) nullifier: Nullifier<F>,
}

#[derive(Debug, Clone)]
pub struct PublicInputVar<F: PrimeField> {
    pub(crate) asset_hash: FpVar<F>,
    pub(crate) sender: FpVar<F>,
    pub(crate) state_in: FpVar<F>,
    pub(crate) state_out: FpVar<F>,
    pub(crate) step: FpVar<F>,
    pub(crate) nullifier: FpVar<F>,
}

impl<F: PrimeField> PublicInputVar<F> {
    fn input_in<Z, T: Borrow<F> + Clone>(
        cs: impl Into<Namespace<F>>,
        st: Option<&Z>,
        access: impl FnOnce(&Z) -> T,
    ) -> CSResult<FpVar<F>> {
        var_in(cs.into().cs(), st, access, AllocationMode::Input)
    }

    pub(crate) fn new(
        cs: impl Into<Namespace<F>>,
        pi: Option<&PublicInput<F>>,
    ) -> CSResult<PublicInputVar<F>> {
        let cs = cs.into().cs();
        let asset_hash = Self::input_in(cs.clone(), pi, |e| e.asset_hash)?;
        let sender = Self::input_in(cs.clone(), pi, |e| e.sender)?;
        let state_in = Self::input_in(cs.clone(), pi, |e| e.state_in)?;
        let state_out = Self::input_in(cs.clone(), pi, |e| e.state_out)?;
        let nullifier = Self::input_in(cs.clone(), pi, |e| e.nullifier)?;
        let step = Self::input_in(cs.clone(), pi, |e| F::from(e.step as u64))?;
        Ok(PublicInputVar {
            asset_hash,
            sender,
            state_in,
            state_out,
            step,
            nullifier,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuxInputs<E: IVC> {
    // receiver address
    pub(crate) receiver: Address<E::Field>,
    // public key of the signer (sender or issuer)
    pub(crate) public_key: PublicKey<E::TE>,
    // signature of sender or issuer
    pub(crate) signature: Signature<E::TE>,
    // nullifier key of the sender. remember that we will use nullifier key of the "issuer" only for id commitment recovery
    pub(crate) nullifier_key: NullifierKey<E::Field>,
    // asset hash defines context of the note tree
    pub(crate) parent: BlindNoteHash<E::Field>,
    // input index
    pub(crate) input_index: NoteOutIndex,
    // input value
    pub(crate) value_in: u64,
    // output value
    pub(crate) value_out: u64,
    // sibling note to recover the state
    pub(crate) sibling: BlindNoteHash<E::Field>,
    // input blind
    pub(crate) blind_in: Blind<E::Field>,
    // output blind of note 0
    pub(crate) blind_out_0: Blind<E::Field>,
    // output blind of note 1
    pub(crate) blind_out_1: Blind<E::Field>,
}

impl<E: IVC> AuxInputs<E> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        receiver: &Address<E::Field>,
        public_key: &PublicKey<E::TE>,
        signature: &Signature<E::TE>,
        nullifier_key: &NullifierKey<E::Field>,
        parent: &BlindNoteHash<E::Field>,
        input_index: &NoteOutIndex,
        value_in: u64,
        value_out: u64,
        sibling: &BlindNoteHash<E::Field>,
        blind_in: &Blind<E::Field>,
        blind_out_0: &Blind<E::Field>,
        blind_out_1: &Blind<E::Field>,
    ) -> Self {
        Self {
            receiver: *receiver,
            public_key: public_key.clone(),
            signature: signature.clone(),
            nullifier_key: *nullifier_key,
            parent: *parent,
            input_index: *input_index,
            value_in,
            value_out,
            sibling: *sibling,
            blind_in: *blind_in,
            blind_out_0: *blind_out_0,
            blind_out_1: *blind_out_1,
        }
    }
}

#[derive(Clone)]
pub struct NoteVar<F: PrimeField> {
    pub(crate) asset_hash: FpVar<F>,
    pub(crate) owner: FpVar<F>,
    pub(crate) value: FpVar<F>,
    pub(crate) step: FpVar<F>,
    pub(crate) parent_note: FpVar<F>,
    pub(crate) out_index: FpVar<F>,
}

impl<F: PrimeField> Debug for NoteVar<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoteVar")
            .field(
                "asset_hash",
                &self.asset_hash.value().map(|e| e.to_string()),
            )
            .field("owner", &self.owner.value().map(|e| e.to_string()))
            .field("value", &self.value.value().map(|e| e.to_string()))
            .field("step", &self.step.value().map(|e| e.to_string()))
            .field(
                "parent_note",
                &self.parent_note.value().map(|e| e.to_string()),
            )
            .field("out_index", &self.out_index.value().map(|e| e.to_string()))
            .finish()
    }
}

impl<F: PrimeField> ToCRH<F> for NoteVar<F> {
    // serialize into field elements
    type Output = FpVar<F>;
    fn to_crh(&self) -> Vec<FpVar<F>> {
        vec![
            self.asset_hash.clone(),
            self.owner.clone(),
            self.value.clone(),
            self.step.clone(),
            self.parent_note.clone(),
            self.out_index.clone(),
        ]
    }
}

impl<F: PrimeField> NoteVar<F> {
    pub fn new(
        asset_hash: &FpVar<F>,
        owner: &FpVar<F>,
        value: &FpVar<F>,
        step: &FpVar<F>,
        parent_note: &FpVar<F>,
        out_index: &FpVar<F>,
    ) -> Self {
        Self {
            asset_hash: asset_hash.clone(),
            owner: owner.clone(),
            value: value.clone(),
            step: step.clone(),
            parent_note: parent_note.clone(),
            out_index: out_index.clone(),
        }
    }
}
