use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ff::PrimeField;

// Circom compatible number of partial rounds
const N_PARTIAL_ROUNDS: [u64; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];

pub trait ToSponge<F: PrimeField + Absorb> {
    fn to_sponge(&self) -> Vec<F>;
}

pub trait NtoOneHasher<F: PrimeField + Absorb>: Clone {
    // creates a new hasher. hasher is stateless
    fn new() -> Self;
    // hashes a list of field elements into a single field element
    fn compress(&self, inputs: &[F]) -> F;
    // hashes field element representaion of T into a single field element
    fn hash<T: ToSponge<F>>(&self, input: &T) -> F {
        self.compress(&input.to_sponge())
    }
    // Eddsa specific hasher with t = 5
    fn eddsa_config() -> PoseidonConfig<F>;
}

#[derive(Debug, Clone)]
pub struct CircomPoseidon {
    configs: [PoseidonConfig<ark_bn254::Fr>; 16],
}

impl NtoOneHasher<ark_bn254::Fr> for CircomPoseidon {
    fn compress(&self, inputs: &[ark_bn254::Fr]) -> ark_bn254::Fr {
        let config = &self.configs[inputs.len() - 1];
        let mut poseidon = PoseidonSponge::new(config);
        inputs.iter().for_each(|input| poseidon.absorb(input));

        // Circom gets the first element of the state
        poseidon.state[0]
        // but conventionally we would do:
        // poseidon .squeeze_field_elements::<ark_bn254::Fr>(1) .first() .unwrap()
    }

    fn new() -> Self {
        const N_FULL_ROUNDS: u64 = 8;
        let mut configs: Vec<PoseidonConfig<ark_bn254::Fr>> = vec![];
        for input_len in 1..=16 {
            let rate = input_len;
            let partial_rounds = N_PARTIAL_ROUNDS[rate];
            let (ark, mds) = find_poseidon_ark_and_mds(
                ark_bn254::Fr::MODULUS_BIT_SIZE as u64,
                rate,
                N_FULL_ROUNDS,
                partial_rounds,
                0,
            );
            let config = PoseidonConfig::new(
                N_FULL_ROUNDS as usize,
                partial_rounds as usize,
                5,
                mds,
                ark,
                rate,
                1,
            );
            configs.push(config);
        }

        Self {
            configs: configs.try_into().unwrap(),
        }
    }

    fn eddsa_config() -> PoseidonConfig<ark_bn254::Fr> {
        let rate = 5;
        let full_rounds = 8;
        let partial_rounds = 60;

        let prime_bits = ark_bn254::Fr::MODULUS_BIT_SIZE as u64;
        let (ark, mds) = find_poseidon_ark_and_mds(
            prime_bits,
            rate,
            full_rounds as u64,
            partial_rounds as u64,
            0,
        );
        PoseidonConfig::new(full_rounds, partial_rounds, 5, mds, ark, rate, 1)
    }
}
