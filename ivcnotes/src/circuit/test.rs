#[cfg(test)]
mod test {
    use crate::{
        asset::{Asset, Terms},
        circuit::{Circuit, Prover, Verifier, IVC},
        id::Auth,
        poseidon::PoseidonConfigs,
        wallet::{CommReceiver, Wallet},
    };
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
    use ark_ff::PrimeField;
    use ark_groth16::Groth16;
    use ark_std::test_rng;
    use rand::rngs::StdRng;
    use rand_core::{RngCore, SeedableRng};

    type F = ark_bn254::Fr;

    #[derive(Clone, Debug)]
    pub struct Tester;

    impl IVC for Tester {
        type Snark = Groth16<Bn254>;
        type Field = ark_bn254::Fr;
        type TE = ark_ed_on_bn254::EdwardsConfig;
    }

    #[test]
    fn test_tx() {
        let prime_bits = F::MODULUS_BIT_SIZE as u64;
        let (ark, mds) = find_poseidon_ark_and_mds::<F>(prime_bits, 4, 8 as u64, 55 as u64, 0);
        let config = PoseidonConfig::new(8, 55, 5, mds, ark, 4, 1);
        let poseidon = PoseidonConfigs {
            id: config.clone(),
            note: config.clone(),
            blind: config.clone(),
            state: config.clone(),
            nullifier: config.clone(),
            tx: config.clone(),
            eddsa: config.clone(),
        };

        let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
        let auth_1 = Auth::<Tester>::generate(&poseidon.clone(), &mut rng.clone()).unwrap();
        let auth_2 = Auth::<Tester>::generate(&poseidon.clone(), &mut rng.clone()).unwrap();

        let circuit = Circuit::<Tester>::empty(&poseidon);
        let (pk, vk) = <Tester as IVC>::Snark::setup(circuit, &mut rng).unwrap();
        let prover = Prover { pk };
        let verifier = Verifier { vk };

        let mut wallet_1 =
            Wallet::<Tester>::new(auth_1, &poseidon, prover.clone(), verifier.clone());
        let mut wallet_2 = Wallet::<Tester>::new(auth_2, &poseidon, prover, verifier);

        let asset = Asset::new(wallet_1.address(), &Terms::iou(1, 1));

        wallet_1
            .issue(&mut rng, &mut wallet_1.clone(), &asset, 100)
            .unwrap();

        wallet_1.split(&mut rng, &mut wallet_2, 0, 10).unwrap();
    }
}
