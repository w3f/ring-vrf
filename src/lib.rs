// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>


//! ## Ring VRF

mod scalar;
mod keys;
pub mod context;
mod merkle;
mod circuit;
mod generator;
mod prover;
mod verifier;
mod vrf;

use crate::scalar::{Scalar,read_scalar,write_scalar};
pub use crate::keys::{SecretKey,PublicKey,Keypair};
pub use crate::context::{signing_context,SigningTranscript}; // SigningTranscript

pub use crate::circuit::RingVRF;
pub use crate::merkle::{MerkleSelection, AuthPath, AuthRoot, AuthPathPoint, auth_hash};
pub use crate::generator::generate_crs;
pub use crate::prover::prove;
pub use crate::verifier::{verify_unprepared, verify_prepared};
pub use vrf::{VRFInOut, VRFInput, VRFOutput};


// use ff::{Field, ScalarEngine};
use zcash_primitives::jubjub::{JubjubEngine, PrimeOrder, Unknown, edwards::Point};

#[macro_use]
extern crate bench_utils;

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

    use rand_core::{RngCore}; // CryptoRng

    use bellman::groth16::Parameters;
    use zcash_primitives::jubjub::JubjubBls12;
    use pairing::bls12_381::Bls12;
    // use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn test_completeness() {
        let params = Params::<Bls12> {
            engine: JubjubBls12::new(),
            auth_depth: 10,
        };

        // let mut rng = ::rand_chacha::ChaChaRng::from_seed([0u8; 32]);
        let mut rng = ::rand_core::OsRng;

        let crs = match File::open("crs") {
            Ok(f) => Parameters::<Bls12>::read(f, false).expect("can't read CRS"),
            Err(_) => {
                let f = File::create("crs").unwrap();
                let generation = start_timer!(|| "generation");
                let c = generator::generate_crs(&params).expect("can't generate CRS");
                end_timer!(generation);
                c.write(&f).unwrap();
                c
            },
        };

        let sk = SecretKey::<Bls12>::from_rng(&mut rng);
        let pk = sk.to_public(&params);

        let t = signing_context(b"Hello World!").bytes(&rng.next_u64().to_le_bytes()[..]);
        let vrf_input = VRFInput::<Bls12>::new_malleable(t, &params);

        let vrf_inout = vrf_input.to_inout(&sk, &params);

        let auth_path = AuthPath::random(params.auth_depth, &mut rng);
        let auth_root = AuthRoot::from_proof(&auth_path, &pk, &params);

        let proving = start_timer!(|| "proving");
        let proof = prover::prove::<Bls12>(&crs, sk, vrf_input.clone(), auth_path.clone(), &params);
        end_timer!(proving);
        let proof = proof.unwrap();

        let verification = start_timer!(|| "verification");
        let valid = verifier::verify_unprepared(&crs.vk, proof, vrf_inout, auth_root, &params);
        end_timer!(verification);
        assert_eq!(valid.unwrap(), true);
    }
}
