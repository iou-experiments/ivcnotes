use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr};
use ark_ff::PrimeField;
use arkeddsa::{signature::Signature, PublicKey};

use crate::{
    asset::AssetHash,
    id::{id_commitment, Address, NullifierKey},
    note::{BlindNoteHash, NoteHistory, NoteOutIndex},
    tx::{IssueTx, SealedIssueTx, SealedSplitTx, SplitTx, Tx},
    Error, FWrap,
};

use super::hasher::NtoOneHasher;
crate::field_wrap!(StateHash);
crate::field_wrap!(Nullifier);

pub trait SNARK: Clone {
    // n to 1 in-circuit hash function
    type Hasher: NtoOneHasher<Self::AppField>;
    // proof system end
    type Witness: Witness<Self>;
    // (baby)jubjub curve config
    type EdConfig: TECurveConfig;
    // application field
    type AppField: PrimeField + Absorb;
    // proof system curve
    type App: AffineRepr<ScalarField = Self::AppField>;
    // (baby)jubjub curve
    type Ed: AffineRepr<BaseField = <Self::App as AffineRepr>::ScalarField, Config = Self::EdConfig>;
}

pub trait Witness<E: SNARK>: Default + Clone {
    fn verify(
        &self,
        h: &E::Hasher,
        public_inputs: &[PublicInputs<E::AppField>],
    ) -> Result<(), Error>;

    fn first_step_witness(
        tx: &SealedIssueTx<E>,
        nullifier_key: &NullifierKey<E::AppField>,
        public_key: &PublicKey<E::Ed>,
    ) -> Result<Self, Error>;

    fn accumulate_witness(
        note_history: &mut NoteHistory<E>,
        tx: &SealedSplitTx<E>,
        nullifier_key: &NullifierKey<E::AppField>,
        public_key: &PublicKey<E::Ed>,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
// part of intermediate public inputs
pub struct PublicStep<F: PrimeField> {
    // previous state hash
    pub(crate) state: StateHash<F>,
    // sibling note to recover the state
    // pub sibling_note_blind_hash: BlindNoteHash<F>,
    // nullifier of spent note
    pub(crate) nullifier: Nullifier<F>,
    // previous owner, signer of the note
    pub(crate) sender: Address<F>,
    // output index of the note
    // pub(crate) out_index: NoteOutIndex, // is this public?
}

impl<F: PrimeField> PublicStep<F> {
    fn new(
        state: &StateHash<F>,
        nullifier: &Nullifier<F>,
        sender: &Address<F>,
        // out_index: &NoteOutIndex,
    ) -> Self {
        Self {
            state: *state,
            nullifier: *nullifier,
            sender: *sender,
            // out_index: *out_index,
        }
    }
}

pub struct PublicInputs<F: PrimeField> {
    // asset hash is part of notes
    pub(crate) asset_hash: AssetHash<F>,
    // sender of the note
    pub(crate) sender: Address<F>,
    // input state
    // `state = hash(sibling, spent)`
    // or `state = hash(spent, sibling)`
    pub(crate) state_in: StateHash<F>,
    // output state
    // `state = hash(note_out_0, note_out_1)`
    pub(crate) state_out: StateHash<F>,
    // number of steps so far in the ivc propagation
    pub(crate) step: u32,
    // nullifier of the spent note
    pub(crate) nullifier: Nullifier<F>,
}

impl<F: PrimeField> PublicInputs<F> {
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
}

#[derive(Debug, Clone)]
// Auxilarry inputs ideally private for prover
pub struct AuxInputs<E: SNARK> {
    // public key of the signer (sender or issuer)
    pub(crate) public_key: PublicKey<E::Ed>,
    // nullifier key of the sender
    // note that we will only use nullifier key of the issuer for id commitment recovery
    pub(crate) nullifier_key: NullifierKey<E::AppField>,
    // signature of sender or issuer
    pub(crate) signature: Signature<E::Ed>,
    // enum that wraps both transaction type
    pub(crate) tx: Tx<E>,
}

#[derive(Debug, Clone)]
pub struct NaiveWitness<E: SNARK> {
    aux_inputs: Vec<AuxInputs<E>>,
}

impl<E: SNARK> Default for NaiveWitness<E> {
    fn default() -> Self {
        Self { aux_inputs: vec![] }
    }
}

impl<E: SNARK<Witness = Self>> Witness<E> for NaiveWitness<E> {
    fn first_step_witness(
        tx: &SealedIssueTx<E>,
        nullifier_key: &NullifierKey<E::AppField>,
        public_key: &PublicKey<E::Ed>,
    ) -> Result<Self, Error> {
        let aux_inputs = AuxInputs {
            public_key: *public_key,
            nullifier_key: *nullifier_key,
            signature: *tx.signature(),
            tx: Tx::Issue(tx.clone()),
        };
        let witness = Self {
            aux_inputs: vec![aux_inputs],
        };
        Ok(witness)
    }

    fn accumulate_witness(
        note_history_0: &mut NoteHistory<E>,
        tx: &SealedSplitTx<E>,
        nullifier_key: &NullifierKey<E::AppField>,
        public_key: &PublicKey<E::Ed>,
    ) -> Result<(), Error> {
        // append new ausx inputs
        let aux_inputs = AuxInputs {
            nullifier_key: *nullifier_key,
            public_key: *public_key,
            signature: *tx.signature(),
            tx: Tx::Split {
                tx: tx.clone(),
                sibling: *note_history_0.sibling(),
            },
        };
        note_history_0.witness.aux_inputs.push(aux_inputs);

        // append new step
        let state_out = tx.state_out();
        let nullifier = tx.nullifier();
        let step = PublicStep::new(
            state_out,
            nullifier,
            note_history_0.owner(),
            // note_history_0.out_index(),
        );
        note_history_0.steps.push(step);

        Ok(())
    }

    fn verify(
        &self,
        h: &E::Hasher,
        public_inputs: &[PublicInputs<E::AppField>],
    ) -> Result<(), Error> {
        self.aux_inputs
            .iter()
            .zip(public_inputs.iter())
            .try_for_each(|(aux, public)| verify_step::<E>(h, public, aux))
    }
}

fn verify_step<E: SNARK>(
    h: &E::Hasher,
    public: &PublicInputs<E::AppField>,
    aux: &AuxInputs<E>,
) -> Result<(), Error> {
    let (issue_tx, (split_tx, sibling_in)) = match &aux.tx {
        Tx::Issue(tx) => (*tx.inner(), (SplitTx::default(), BlindNoteHash::default())),
        Tx::Split { tx, sibling } => (IssueTx::default(), (*tx.inner(), *sibling)),
    };

    #[derive(Debug, Clone)]
    struct Enfoce(String);

    impl From<String> for Enfoce {
        fn from(s: String) -> Self {
            Self(s)
        }
    }

    impl From<&str> for Enfoce {
        fn from(s: &str) -> Self {
            Self(s.to_string())
        }
    }

    #[derive(Debug, Clone)]
    struct Sat {
        inner: Result<(), Enfoce>,
    }

    impl From<Result<(), Enfoce>> for Sat {
        fn from(inner: Result<(), Enfoce>) -> Self {
            Self { inner }
        }
    }

    impl From<()> for Sat {
        fn from(_: ()) -> Self {
            Self { inner: Ok(()) }
        }
    }

    impl From<Enfoce> for Sat {
        fn from(e: Enfoce) -> Self {
            Self { inner: Err(e) }
        }
    }

    impl Sat {
        fn new() -> Self {
            Self { inner: Ok(()) }
        }

        fn equal<T: Eq>(&mut self, lhs: T, rhs: T, msg: &'static str) {
            self.inner = self
                .inner
                .clone()
                .and((lhs == rhs).then_some(()).ok_or(msg.into()));
        }

        fn and(&mut self, t: &Self) {
            self.inner = self.inner.clone().and(t.inner.clone());
        }

        fn xor(&self, other: &Self) -> Self {
            match (&self.inner, &other.inner) {
                (Ok(_), Err(_)) => ().into(),
                (Err(_), Ok(_)) => ().into(),
                (Err(err0), Err(err1)) => Enfoce(format!("{} and {}", err0.0, err1.0)).into(),
                (Ok(_), Ok(_)) => Enfoce("both ok".into()).into(),
            }
        }

        fn result(&self) -> Result<(), crate::Error> {
            self.inner
                .clone()
                .map_err(|_| crate::Error::With("invalid witness"))
        }
    }

    fn select<T>(cond: bool, lhs: T, rhs: T) -> T {
        if cond {
            lhs
        } else {
            rhs
        }
    }

    // issue branch
    let (sat_issue, tx_hash_issue) = {
        let note = issue_tx.note();
        let mut sat = Sat::new();

        sat.equal(0, note.step, "issue: note step");
        sat.equal(NoteOutIndex::Issue, note.out_index, "issue: note dir");
        sat.equal(
            BlindNoteHash::default(),
            note.parent_note_blind_hash,
            "issue: parent",
        );
        sat.equal(public.asset_hash, note.asset_hash, "issue: asset hash");

        let tx_hash = issue_tx.sig_hash();
        (sat, tx_hash)
    };

    // split branch
    let (sat_split, tx_hash_split) = {
        let note_in = split_tx.note_in;
        let note_out_0 = split_tx.note_out_0;
        let note_out_1 = split_tx.note_out_1;
        let mut sat = Sat::new();

        //
        // input note integrity
        //

        sat.equal(
            public.asset_hash,
            note_in.asset_hash,
            "split-in: asset hash",
        );
        sat.equal(public.step, note_in.step, "split-in: step");
        sat.equal(public.sender, note_in.owner, "split-in: sender");

        let t_note_in_hash = h.hash(&note_in);
        let t_note_in_hash_blind: BlindNoteHash<_> =
            h.compress(&[t_note_in_hash, note_in.blind.inner()]).into();

        let t_state_in: StateHash<_> = match note_in.out_index {
            NoteOutIndex::Out0 => h
                .compress(&[t_note_in_hash_blind.inner(), sibling_in.inner()])
                .into(),
            NoteOutIndex::Out1 => h
                .compress(&[sibling_in.inner(), t_note_in_hash_blind.inner()])
                .into(),
            _ => unreachable!(),
        };

        sat.equal(public.state_in, t_state_in, "split-in: state");

        //
        // output note integrity
        //
        // TODO: note_out_1 recovered offcircuit?

        // step
        sat.equal(public.step + 1, note_out_0.step, "split-out0: step");
        sat.equal(public.step + 1, note_out_1.step, "split-out1: step");

        // asset
        sat.equal(
            public.asset_hash,
            note_out_0.asset_hash,
            "split-out0: asset hash",
        );
        sat.equal(
            public.asset_hash,
            note_out_1.asset_hash,
            "split-out1: asset hash",
        );

        // parent blinded hash
        sat.equal(
            t_note_in_hash_blind,
            note_out_0.parent_note_blind_hash,
            "split-out0: asset hash",
        );
        sat.equal(
            t_note_in_hash_blind,
            note_out_1.parent_note_blind_hash,
            "split-out1: asset hash",
        );

        // output index
        sat.equal(NoteOutIndex::Out0, note_out_0.out_index, "split-out0: dir");
        sat.equal(NoteOutIndex::Out1, note_out_1.out_index, "split-out1: dir");

        // state
        let t_state_out: StateHash<_> = h
            .compress(&[
                note_out_0.blinded_hash(h).inner(),
                note_out_1.blinded_hash(h).inner(),
            ])
            .into();
        sat.equal(public.state_out, t_state_out, "split-out: state");

        //
        // nullifier integrity
        //

        let t_nullifier: Nullifier<_> = h
            .compress(&[t_note_in_hash, aux.nullifier_key.inner()])
            .into();
        sat.equal(public.nullifier, t_nullifier, "nullifier");

        //
        // split rules, zero sum
        //

        sat.equal(
            note_in.value,
            note_out_0.value + note_out_1.value,
            "zero sum",
        );

        let tx_hash = split_tx.sig_hash();
        (sat, tx_hash)
    };

    let mut sat = sat_issue.xor(&sat_split);
    let t_id = id_commitment::<E>(h, &aux.nullifier_key, &aux.public_key);
    sat.equal(t_id, public.sender, "id commitment");

    let tx_hash = select(public.step == 0, tx_hash_issue, tx_hash_split);
    let sat_sig = aux
        .public_key
        .verify(
            &E::Hasher::eddsa_config(),
            &[tx_hash.inner()],
            &aux.signature,
        )
        .map_err(|_| Enfoce("signature".into()))
        .into();

    sat.and(&sat_sig);
    sat.result()
}
