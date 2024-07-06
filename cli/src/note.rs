use crate::crypto::circuit::Witness;
use crate::{
    asset::{Asset, AssetHash},
    crypto::{
        circuit::{Nullifier, PublicInputs, PublicStep, SNARK},
        hasher::{NtoOneHasher, ToSponge},
    },
    id::{Address, NullifierKey, SigHash},
    FWrap,
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

crate::field_wrap!(Blind);
crate::field_wrap!(NoteHash);
crate::field_wrap!(BlindNoteHash);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NoteOutIndex {
    // Original note hash the issue tag
    Issue,
    // Output with index 0 conventionally this is the refund note
    Out0,
    // Output with index 1 conventionally this is the sent note
    Out1,
    // TODO: is this necessary?
    #[default]
    NotApplicable,
}

impl NoteOutIndex {
    fn inner<F: ark_ff::Field>(&self) -> F {
        let u: u8 = self.into();
        u.into()
    }
}

impl From<&NoteOutIndex> for u8 {
    fn from(val: &NoteOutIndex) -> Self {
        match val {
            NoteOutIndex::Issue => 0,
            NoteOutIndex::Out0 => 1,
            NoteOutIndex::Out1 => 2,
            NoteOutIndex::NotApplicable => 0xff,
        }
    }
}

#[derive(Clone, Debug, Copy, Default)]
pub struct Note<F: ark_ff::PrimeField> {
    // asset hash defines context of the note tree
    pub(crate) asset_hash: AssetHash<F>,
    // spend authority
    pub(crate) owner: Address<F>,
    // numerical value of the note & asset
    pub(crate) value: u64,
    // depth in the ivc tree (note tree)
    pub(crate) step: u32,
    // previous note hash
    pub(crate) parent_note_blind_hash: BlindNoteHash<F>,
    // output index
    pub(crate) out_index: NoteOutIndex,
    // blinding factor
    pub(crate) blind: Blind<F>,
}

impl<F: PrimeField + Absorb> ToSponge<F> for Note<F> {
    // serialize into field elements
    fn to_sponge(&self) -> Vec<F> {
        let asset_hash = self.asset_hash.inner();
        let owner = self.owner.inner();
        let value = self.value.into();
        let step = self.step.into();
        let parent = self.parent_note_blind_hash.inner();
        let out_index = self.out_index.inner();
        vec![asset_hash, owner, value, step, parent, out_index]
    }
}

impl<F: PrimeField + Absorb> Note<F> {
    pub fn new(
        asset_hash: &AssetHash<F>,
        owner: &Address<F>,
        value: u64,
        step: u32,
        out_index: &NoteOutIndex,
        parent_note_blind_hash: &BlindNoteHash<F>,
        blind: Blind<F>,
    ) -> Self {
        Note {
            asset_hash: *asset_hash,
            owner: *owner,
            value,
            step,
            out_index: *out_index,
            parent_note_blind_hash: *parent_note_blind_hash,
            blind,
        }
    }

    pub fn hash<H: NtoOneHasher<F>>(&self, h: &H) -> SigHash<F> {
        h.hash(self).into()
    }

    // `blindded_hash = hash(hash(note), blind)`
    pub fn blinded_hash<H: NtoOneHasher<F>>(&self, h: &H) -> BlindNoteHash<F> {
        let hash = self.hash(h).inner();
        h.compress(&[hash, self.blind.inner()]).into()
    }

    // `nullifier = hash(hash(note), nullifier_key)`
    pub fn nullifier<H: NtoOneHasher<F>>(
        &self,
        h: &H,
        nullifier: &NullifierKey<F>,
    ) -> Nullifier<F> {
        let hash = self.hash(h).inner();
        h.compress(&[hash, nullifier.inner()]).into()
    }
}

#[derive(Debug, Clone)]
pub struct NoteHistory<E: SNARK> {
    // asset that defines the terms and issuer
    pub(crate) asset: Asset<E::AppField>,
    // accumulated witnesses
    pub(crate) witness: E::Witness,
    // part of intermediate public inputs
    pub(crate) steps: Vec<PublicStep<E::AppField>>,
    // unspent note
    pub(crate) current_note: Note<E::AppField>,
    // sibling of unspent note
    pub(crate) sibling: BlindNoteHash<E::AppField>,
}

impl<E: SNARK> NoteHistory<E> {
    pub fn new(asset: &Asset<E::AppField>, note: &Note<E::AppField>, witness: &E::Witness) -> Self {
        NoteHistory {
            witness: witness.clone(),
            asset: *asset,
            steps: Vec::new(),
            current_note: *note,
            sibling: BlindNoteHash::default(),
        }
    }

    pub fn owner(&self) -> &Address<E::AppField> {
        &self.current_note.owner
    }

    pub fn out_index(&self) -> &NoteOutIndex {
        &self.current_note.out_index
    }

    pub fn sibling(&self) -> &BlindNoteHash<E::AppField> {
        &self.sibling
    }

    pub fn verify(&self, h: &E::Hasher) -> Result<(), crate::Error> {
        let public_inputs = self.public_inputs();
        self.witness.verify(h, &public_inputs)
    }

    pub fn public_inputs(&self) -> Vec<PublicInputs<E::AppField>> {
        let asset_hash = self.asset.hash();
        let mut state_in = asset_hash.inner().into();
        self.steps
            .iter()
            .enumerate()
            .map(
                |(
                    step,
                    PublicStep {
                        state: state_out,
                        // sibling,
                        nullifier,
                        sender,
                        // out_index: _,
                    },
                )| {
                    let public_inputs = PublicInputs::new(
                        &asset_hash,
                        &sender,
                        &state_in,
                        &state_out,
                        step as u32,
                        &nullifier,
                    );
                    state_in = *state_out;
                    public_inputs
                },
            )
            .collect()
    }
}
