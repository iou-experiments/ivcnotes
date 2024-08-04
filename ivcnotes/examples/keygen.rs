use ark_serialize::CanonicalSerialize;
use ivcnotes::circuit::concrete::circuit_setup;
use std::fs::File;

fn main() {
    println!("circuit setup");
    let (pk, vk) = circuit_setup();
    std::fs::create_dir_all("keys").unwrap();
    let pk_key_file = File::create("keys/pk.g16").unwrap();
    pk.serialize_compressed(pk_key_file).unwrap();
    let vk_key_file = File::create("keys/vk.g16").unwrap();
    vk.serialize_compressed(vk_key_file).unwrap();
}
