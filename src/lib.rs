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
pub use crate::context::{signing_context,SigningTranscript,VRFSigningTranscript}; // SigningTranscript

pub use crate::circuit::RingVRF;
pub use crate::merkle::{MerkleSelection, AuthPath, AuthRoot, AuthPathPoint, auth_hash};
pub use crate::generator::generate_crs;
pub use crate::prover::prove;
pub use crate::verifier::{verify_unprepared, verify_prepared};
pub use vrf::{VRFOutput};


// use ff::{Field, ScalarEngine};
use zcash_primitives::jubjub::{JubjubEngine, PrimeOrder, Unknown, edwards::Point};


/// Configuration parameters for the system.
pub struct Params<E: JubjubEngine> {
    /// Engine parameters.
    pub engine: E::Params,
    /// Authentication depth.
    pub auth_depth: usize,
}


/// VRF input.
#[derive(Debug, Clone)]
pub struct VRFInput<E: JubjubEngine>(pub Point<E, Unknown>);

impl<E: JubjubEngine> VRFInput<E> {
    /// Create a new random VRF input.
    pub fn random<R: rand_core::RngCore>(rng: &mut R, params: &Params<E>) -> Self {
        Self(Point::rand(rng, &params.engine).mul_by_cofactor(&params.engine).into())
    }

    /// Into VRF output.
    pub fn to_output(&self, sk: &SecretKey<E>, params: &Params<E>) -> VRFOutput<E> {
        VRFOutput( self.0.mul(sk.key.clone(), &params.engine) )
    }
}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::time::SystemTime;

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
                let t = SystemTime::now();
                let c = generator::generate_crs(&params).expect("can't generate CRS");
                println!("generation = {}", t.elapsed().unwrap().as_secs());
                c.write(&f).unwrap();
                c
            },
        };

        let sk = SecretKey::<Bls12>::from_rng(&mut rng);
        let pk = sk.to_public(&params);

        let vrf_input = VRFInput::<Bls12>::random(&mut rng, &params);
        let vrf_output = vrf_input.to_output(&sk, &params);

        let auth_path = AuthPath::random(params.auth_depth, &mut rng);
        let auth_root = AuthRoot::from_proof(&auth_path, &pk, &params);

        let t = SystemTime::now();
        let proof = prover::prove::<Bls12>(&crs, sk, vrf_input.clone(), auth_path.clone(), &params);
        println!("proving = {}", t.elapsed().unwrap().as_millis());
        let proof = proof.unwrap();

        let t = SystemTime::now();
        let valid = verifier::verify_unprepared(&crs.vk, proof, vrf_input, vrf_output, auth_root, &params);
        println!("verification = {}", t.elapsed().unwrap().as_millis());
        assert_eq!(valid.unwrap(), true);
    }
}
