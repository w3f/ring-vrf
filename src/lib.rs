mod merkle;
mod circuit;
mod generator;
mod prover;
mod verifier;

pub use crate::circuit::Ring;
pub use crate::merkle::{aggregated_pkx, PathDirection};
pub use crate::generator::generate_crs;
pub use crate::prover::prove;
pub use crate::verifier::verify;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::time::SystemTime;

    use ff::Field;
    use bellman::groth16::{prepare_verifying_key, Parameters};
    use zcash_primitives::jubjub::{JubjubBls12, JubjubParams, FixedGenerators, fs, edwards};
    use pairing::bls12_381::{Bls12, Fr};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use super::*;

    #[test]
    fn test_completeness() {
        let rng = &mut XorShiftRng::from_seed([
            0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
            0xe5,
        ]);

        let params = &JubjubBls12::new();

        let crs = match File::open("crs") {
            Ok(f) => Parameters::<Bls12>::read(f, false).expect("can't read CRS"),
            Err(_) => {
                let f = File::create("crs").unwrap();
                let t = SystemTime::now();
                let c = generator::generate_crs().expect("can't generate CRS");
                println!("generation = {}", t.elapsed().unwrap().as_secs());
                c.write(&f).unwrap();
                c
            },
        };

        // Jubjub generator point // TODO: prime or---
        let base_point = params.generator(FixedGenerators::SpendingKeyGenerator);

        // validator's secret key, an element of Jubjub scalar field
        let sk = fs::Fs::random(rng);

        // validator's public key, a point on Jubjub
        let pk = base_point.mul(sk, params);

        // VRF base point
        let vrf_base = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let vrf_output = vrf_base.mul(sk, params);

        let tree_depth = 10;
        let auth_path = vec![(Fr::random(rng), PathDirection::random(rng)); tree_depth];

        let apkx = aggregated_pkx::<Bls12>(params, pk.to_xy().0, &auth_path);

        let t = SystemTime::now();
        let proof = prover::prove(params, &crs, sk, vrf_base.clone(), auth_path.clone());
        println!("proving = {}", t.elapsed().unwrap().as_millis());
        let proof = proof.unwrap();

        let t = SystemTime::now();
        let pvk = prepare_verifying_key::<Bls12>(&crs.vk);
        let valid = verifier::verify(&pvk, proof, vrf_base, vrf_output, apkx);
        println!("verification = {}", t.elapsed().unwrap().as_millis());
        assert_eq!(valid.unwrap(), true);
    }
}
