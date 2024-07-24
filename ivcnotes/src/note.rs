use crate::{
    asset::Asset, circuit::IVC, poseidon::PoseidonConfigs, tx::IssueTx, Address, AssetHash, Blind,
    BlindNoteHash, Nullifier, StateHash,
};
use ark_crypto_primitives::{snark::SNARK, sponge::Absorb};
use ark_ff::PrimeField;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteOutIndex {
    // Output with index 0 conventionally this is the refund note
    Out0,
    // Output with index 1 conventionally this is the sent note
    Out1,
}

impl NoteOutIndex {
    // Convert NoteOutIndex to a field element
    pub(crate) fn inner<F: ark_ff::Field>(&self) -> F {
        let u: u8 = self.into();
        u.into()
    }
}

impl From<&NoteOutIndex> for u8 {
    fn from(val: &NoteOutIndex) -> Self {
        match val {
            NoteOutIndex::Out0 => 1,
            NoteOutIndex::Out1 => 2,
        }
    }
}

#[derive(Clone, Debug, Copy)]
pub struct Note<F: PrimeField> {
    // asset hash defines context of the note tree
    pub(crate) asset_hash: AssetHash<F>,
    // spend authority
    pub(crate) owner: Address<F>,
    // numerical value of the note & asset
    pub(crate) value: u64,
    // depth in the ivc tree (note tree)
    pub(crate) step: u32,
    // previous note hash
    pub(crate) parent_note: BlindNoteHash<F>,
    // output index
    pub(crate) out_index: NoteOutIndex,
    // blinding factor
    pub(crate) blind: Blind<F>,
}

impl<F: PrimeField + Absorb> Note<F> {
    // Create a new Note
    pub fn new(
        asset_hash: &AssetHash<F>,
        owner: &Address<F>,
        value: u64,
        step: u32,
        out_index: &NoteOutIndex,
        parent_note: &BlindNoteHash<F>,
        blind: Blind<F>,
    ) -> Self {
        Note {
            asset_hash: *asset_hash,
            owner: *owner,
            value,
            step,
            out_index: *out_index,
            parent_note: *parent_note,
            blind,
        }
    }
}

#[derive(Clone)]
// part of intermediate public inputs
pub struct IVCStep<E: IVC> {
    // Proof of correctness
    pub(crate) proof: <<E as IVC>::Snark as SNARK<E::Field>>::Proof,
    // Output state hash
    pub(crate) state: StateHash<E::Field>,
    // Nullifier of spent note
    pub(crate) nullifier: Nullifier<E::Field>,
    // Previous owner, signer of the input note or issuer
    pub(crate) sender: Address<E::Field>,
}

impl<E: IVC> std::fmt::Debug for IVCStep<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IVCStep")
            .field("state", &self.state)
            .field("nullifier", &self.nullifier)
            .field("sender", &self.sender)
            .finish()
    }
}

impl<E: IVC> IVCStep<E> {
    // Create a new IVCStep
    pub fn new(
        proof: &<<E as IVC>::Snark as SNARK<E::Field>>::Proof,
        state: &StateHash<E::Field>,
        nullifier: &Nullifier<E::Field>,
        sender: &Address<E::Field>,
    ) -> Self {
        IVCStep {
            proof: proof.clone(),
            state: *state,
            nullifier: *nullifier,
            sender: *sender,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NoteHistory<E: IVC> {
    // Asset that defines the terms and issuer
    pub(crate) asset: Asset<E::Field>,
    // Part of intermediate public inputs
    pub(crate) steps: Vec<IVCStep<E>>,
    // Unspent note
    pub(crate) current_note: Note<E::Field>,
    // Sibling of unspent note
    pub(crate) sibling: BlindNoteHash<E::Field>,
}

impl<E: IVC> NoteHistory<E> {
    // Create a new NoteHistory
    pub fn new(
        h: &PoseidonConfigs<E::Field>,
        asset: &Asset<E::Field>,
        issue_tx: &IssueTx<E::Field>,
        proof: &<<E as IVC>::Snark as SNARK<E::Field>>::Proof,
    ) -> Self {
        let note = issue_tx.note;
        let state = h.state_out_from_issue_tx(issue_tx);
        let step = IVCStep::new(proof, &state, &Default::default(), &issue_tx.issuer);
        NoteHistory {
            asset: *asset,
            steps: vec![step],
            current_note: note,
            sibling: BlindNoteHash::default(),
        }
    }

    // Get the owner of the current note
    pub fn owner(&self) -> &Address<E::Field> {
        &self.current_note.owner
    }

    // Get the output index of the current note
    pub fn out_index(&self) -> &NoteOutIndex {
        &self.current_note.out_index
    }

    // Get the sibling of the current note
    pub fn sibling(&self) -> &BlindNoteHash<E::Field> {
        &self.sibling
    }

    // Compute the state hash
    pub fn state(&self, h: &PoseidonConfigs<E::Field>) -> StateHash<E::Field> {
        let (_, blind_note_hash) = h.note(&self.current_note);

        match self.current_note.out_index {
            NoteOutIndex::Out0 => h.state(&blind_note_hash, &self.sibling),
            NoteOutIndex::Out1 => h.state(&self.sibling, &blind_note_hash),
        }
    }
}
