use crate::{
    asset::Asset,
    circuit::{
        inputs::{AuxInputs, PublicInput},
        Prover, Verifier, IVC,
    },
    id::Auth,
    note::{IVCStep, Note, NoteHistory, NoteOutIndex},
    poseidon::PoseidonConfigs,
    service::Comm,
    tx::{IssueTx, SealedIssueTx, SealedSplitTx, SplitTx},
    Address, Blind, BlindNoteHash, FWrap,
};

use arkeddsa::PublicKey;
use rand::{CryptoRng, RngCore};
use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]

pub struct Contact<E: IVC> {
    #[serde(with = "crate::ark_serde")]
    pub(crate) address: Address<E::Field>,
    pub(crate) username: String,
    #[serde(with = "crate::ark_serde")]
    pub(crate) public_key: PublicKey<E::TE>,
}

impl<E: IVC> PartialEq for Contact<E> {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
    }
}

impl<E: IVC> Eq for Contact<E> {}

impl<E: IVC> Ord for Contact<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.username.cmp(&other.username)
    }
}

impl<E: IVC> PartialOrd for Contact<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone)]
pub struct AddressBook<E: IVC> {
    contacts: Vec<Contact<E>>,
}

impl<E: IVC> Default for AddressBook<E> {
    fn default() -> Self {
        Self { contacts: vec![] }
    }
}

impl<E: IVC> AddressBook<E> {
    pub fn find_address(&self, address: &Address<E::Field>) -> Option<&Contact<E>> {
        self.contacts.iter().find(|c| c.address == *address)
    }

    pub fn find_username(&self, username: &str) -> Option<&Contact<E>> {
        self.contacts.iter().find(|c| c.username == username)
    }

    pub fn new_contact(&mut self, contact: &Contact<E>) {
        self.contacts.push(contact.clone());
    }
}

pub struct Wallet<E: IVC> {
    // receivables are transferable notes
    pub(crate) spendables: Vec<NoteHistory<E>>,
    // auth object that holds private keys
    pub(crate) auth: Auth<E>,
    // configs for poseidion hasher
    pub(crate) h: PoseidonConfigs<E::Field>,
    // ivc prover
    pub(crate) prover: Prover<E>,
    // ivc verifier
    pub(crate) verifier: Verifier<E>,
    // known users/peers
    pub(crate) address_book: AddressBook<E>,
    // communications
    pub(crate) comm: Comm<E>,
    // username
    pub(crate) username: String,
}

impl<E: IVC> Auth<E> {
    // sign issue transaction
    pub(crate) fn issue(
        &mut self,
        h: &PoseidonConfigs<E::Field>,
        tx: &IssueTx<E::Field>,
    ) -> Result<SealedIssueTx<E::TE>, crate::Error> {
        let (note_hash, _) = h.note(tx.note());
        let sighash = h.sighash(&Default::default(), &Default::default(), &note_hash);
        let signature = self.sign_tx(&sighash);
        Ok(tx.seal(signature))
    }

    // sign split transaction and generate the nullifier
    pub(crate) fn split(
        &self,
        h: &PoseidonConfigs<E::Field>,
        tx: &SplitTx<E::Field>,
    ) -> Result<SealedSplitTx<E::TE>, crate::Error> {
        let sighash = h.sighash_split_tx(tx);
        let signature = self.sign_tx(&sighash);
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
        comm: Comm<E>,
        username: String,
    ) -> Self {
        Self {
            spendables: vec![],
            auth,
            h: poseidon.clone(),
            prover,
            verifier,
            comm,
            address_book: AddressBook::default(),
            username,
        }
    }

    pub fn address(&self) -> &Address<E::Field> {
        self.auth.address()
    }

    pub fn contact(&self) -> Contact<E> {
        let address = self.address();
        let username = self.username.as_str();
        let public_key = self.auth.public_key();
        Contact {
            address: *address,
            username: username.to_string(),
            public_key: public_key.clone(),
        }
    }

    pub fn issue<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        asset: &Asset<E::Field>,
        value: u64,
        receiver: &str,
    ) -> Result<(), crate::Error> {
        let receiver = self.find_contact_by_username(receiver)?;

        let asset_hash = &asset.hash();
        // draw random blinding factor
        let blind = crate::Blind::<E::Field>::rand(rng);
        // create new note
        let note = Note::new(
            &asset.hash(),
            &receiver.address,
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

        let public_key = self.auth.public_key();
        let signature = sealed.signature();
        let nullifier_key = self.auth.nullifier_key();
        let aux_inputs: AuxInputs<E> = AuxInputs::new(
            &receiver.address,
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

        // send the new history to the receiver
        self.send_note(&receiver, &note_history)?;

        // TODO: save the note as liability

        Ok(())
    }

    pub fn split<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        spendable_index: usize,
        value: u64,
        receiver: &str,
    ) -> Result<(), crate::Error> {
        let receiver = self.find_contact_by_username(receiver)?;

        let sender = *self.address();
        let note_history = self
            .spendables
            .get_mut(spendable_index)
            .ok_or(crate::Error::With("bad spendable index"))?;

        let note_in = note_history.current_note;
        let step = note_history.steps.len() as u32;
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
            &receiver.address,
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

        let public_key = self.auth.public_key();
        let signature = sealed.signature();
        let nullifier_key = self.auth.nullifier_key();
        let parent = &note_in.parent_note;
        let input_index = &note_in.out_index; // TODO: issue index is not good for first split tx?
        let value_in = note_in.value;
        let value_out = value_out_1;
        let sibling = &note_history.sibling;
        let aux_inputs: AuxInputs<E> = AuxInputs::new(
            &receiver.address,
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

        // send the new history to the receiver
        self.send_note(&receiver, &note_history_1)?;

        Ok(())
    }

    pub(crate) fn verify_incoming(
        &mut self,
        note_history: &NoteHistory<E>,
    ) -> Result<(), crate::Error> {
        let incoming_note = note_history.current_note;
        let exists = self
            .spendables
            .iter()
            .any(|nh| nh.current_note == incoming_note);

        if exists {
            return Ok(());
        }

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
        self.spendables.push(note_history.clone());

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {

    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        snark::SNARK,
        sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig},
    };
    use ark_ff::PrimeField;
    use rand_core::OsRng;

    use crate::{
        asset::{self, Asset},
        circuit::{
            test::{ConcreteIVC, MockSNARK},
            Circuit, Prover, Verifier,
        },
        id::Auth,
        poseidon::PoseidonConfigs,
        service::{test::SharedMockService, Comm},
    };

    use super::Wallet;

    pub(crate) fn poseidon_cfg() -> PoseidonConfigs<Fr> {
        let rate = 2;
        let full_rounds = 8;
        let partial_rounds = 55;
        let prime_bits = Fr::MODULUS_BIT_SIZE as u64;
        let (constants, mds) =
            find_poseidon_ark_and_mds::<Fr>(prime_bits, 2, full_rounds, partial_rounds, 0);
        let poseidon_cfg = PoseidonConfig::<Fr>::new(
            full_rounds as usize,
            partial_rounds as usize,
            5,
            mds.clone(),
            constants.clone(),
            rate,
            1,
        );

        PoseidonConfigs::<Fr> {
            id: poseidon_cfg.clone(),
            note: poseidon_cfg.clone(),
            blind: poseidon_cfg.clone(),
            state: poseidon_cfg.clone(),
            nullifier: poseidon_cfg.clone(),
            tx: poseidon_cfg.clone(),
            eddsa: poseidon_cfg.clone(),
        }
    }

    #[test]
    fn test_wallet() {
        type X = ConcreteIVC;

        let service = SharedMockService::new();
        let h = poseidon_cfg();
        let circuit = Circuit::<X>::empty(&h);
        let (pk, vk) = MockSNARK::circuit_specific_setup(circuit, &mut OsRng).unwrap();

        let new_wallet = |username: &str| -> Wallet<X> {
            let auth = Auth::<X>::generate(&h, &mut OsRng).unwrap();
            let prover = Prover::<X>::new(pk.clone());
            let verifier = Verifier::<X>::new(vk.clone());
            let comm = Comm::<X> {
                service: Box::new(service.clone()),
            };

            Wallet::<X>::new(auth, &h, prover, verifier, comm, username.to_string())
        };

        let mut w0 = new_wallet("user0");
        let mut w1 = new_wallet("user1");

        w0.register().unwrap();
        w1.register().unwrap();
        let res1 = w0.find_contact_by_username("user0");
        let res2 = w1.find_contact_by_username("user1");
        println!("{:#?}, {:#?}", res1, res2);
        service.log_contacts();

        let terms = &asset::Terms::iou(365, 1);
        let asset = Asset::new(w0.address(), terms);
        w0.issue(&mut OsRng, &asset, 1000, "user1").unwrap();
        // service.log_messages();
        // w1.get_notes().unwrap();
    }
}
