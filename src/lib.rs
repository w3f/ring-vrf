mod merkle;
mod circuit;
mod generator;
mod prover;
mod verifier;

pub use crate::circuit::Ring;
pub use crate::merkle::{MerkleSelection, AuthPath, AuthRoot, AuthPathPoint, auth_hash};
pub use crate::generator::generate_crs;
pub use crate::prover::prove;
pub use crate::verifier::verify;

use zcash_primitives::jubjub::JubjubEngine;

/// Configuration parameters for the system.
pub struct Params<E: JubjubEngine> {
    /// Engine parameters.
    pub engine: E::Params,
    /// Authentication depth.
    pub auth_depth: usize,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::time::SystemTime;

    use ff::Field;
    use bellman::groth16::{prepare_verifying_key, Parameters};
    use zcash_primitives::jubjub::{JubjubBls12, JubjubParams, FixedGenerators, fs, edwards};
    use pairing::bls12_381::Bls12;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use super::*;

    #[test]
    fn test_completeness() {
        let params = Params::<Bls12> {
            engine: JubjubBls12::new(),
            auth_depth: 10,
        };

        let rng = &mut XorShiftRng::from_seed([
            0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d,
            0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
        ]);

        let crs = match File::open("crs") {
            Ok(f) => Parameters::<Bls12>::read(f, false).expect("can't read CRS"),
            Err(_) => {
                let f = File::create("crs").unwrap();
                let t = SystemTime::now();
                let c = generator::generate_crs(&params).expect("can't generate CRS");
                println!("generation = {}", t.elapsed().unwrap().as_secs());
                c.write(&f).unwrap();
                c
            },
        };

        // Jubjub generator point // TODO: prime or---
        let base_point = params.engine.generator(FixedGenerators::SpendingKeyGenerator);

        // validator's secret key, an element of Jubjub scalar field
        let sk = fs::Fs::random(rng);

        // validator's public key, a point on Jubjub
        let pk = base_point.mul(sk, &params.engine);

        // VRF base point
        let vrf_base = edwards::Point::rand(rng, &params.engine).mul_by_cofactor(&params.engine);
        let vrf_output = vrf_base.mul(sk, &params.engine);

        let auth_path = AuthPath::random(params.auth_depth, rng);
        let auth_root = AuthRoot::from_proof(&auth_path, &pk.to_xy().0, &params);

        let t = SystemTime::now();
        let proof = prover::prove::<Bls12>(&crs, sk, vrf_base.clone(), auth_path.clone(), &params);
        println!("proving = {}", t.elapsed().unwrap().as_millis());
        let proof = proof.unwrap();

        let t = SystemTime::now();
        let pvk = prepare_verifying_key::<Bls12>(&crs.vk);
        let valid = verifier::verify(&pvk, proof, vrf_base, vrf_output, auth_root);
        println!("verification = {}", t.elapsed().unwrap().as_millis());
        assert_eq!(valid.unwrap(), true);
    }
}
