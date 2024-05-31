use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F, S,
};
use pasta_curves::Fq;
use serde_json::json;
use std::{collections::HashMap, env::current_dir, time::Instant};

pub fn fold(x: Fq, y: Fq) {
    // The cycle of curves we use, can be any cycle supported by Nova
    type G1 = pasta_curves::pallas::Point;
    type G2 = pasta_curves::vesta::Point;

    let iteration_count = 2;
    // First values that our circuit gets
    let start_public_input = [x, y, z];
    let root = current_dir().unwrap();
    let circuit_file = root.join("src/artifacts/iou.r1cs");
    let witness_generator_file = root.join("src/artifacts/iou_js/iou.wasm");

    // Loads R1CS from our circuit
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));

    // Creates public parameters
    let pp = create_public_params::<G1, G2>(r1cs.clone());

    let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        //TODO do priv inputs part
        private_input.insert("priv_inputs".to_string(), json!(0));
        private_inputs.push(private_input);
    }

    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file),
        r1cs,
        private_inputs,
        start_public_input.to_vec(),
        &pp,
    )
    .unwrap();

    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        &start_public_input.clone(),
        &[F::<G2>::zero()],
    );
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    let verifier_time = start.elapsed();
    assert!(res.is_ok());
}
