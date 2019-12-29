mod merkle;
mod circuit;
mod generator;
mod prover;
mod verifier;

pub use crate::circuit::Ring;
pub use crate::merkle::{MerkleSelection, AuthPath, AuthRoot, AuthPathPoint, auth_hash};
pub use crate::generator::generate_crs;
pub use crate::prover::prove;
pub use crate::verifier::{verify, verify_prepared};

use ff::{Field, ScalarEngine};
use zcash_primitives::jubjub::{JubjubEngine, FixedGenerators, JubjubParams, PrimeOrder, edwards};

/// Configuration parameters for the system.
pub struct Params<E: JubjubEngine> {
    /// Engine parameters.
    pub engine: E::Params,
    /// Authentication depth.
    pub auth_depth: usize,
}

/// Private key.
#[derive(Debug, Clone)]
pub struct PrivateKey<E: JubjubEngine>(pub E::Fs);

impl<E: JubjubEngine> PrivateKey<E> {
    /// Random private key.
    pub fn random<R: rand_core::RngCore>(rng: &mut R) -> Self {
        Self(<E::Fs>::random(rng))
    }

    /// Into public key.
    pub fn into_public(&self, params: &Params<E>) -> PublicKey<E> {
        // Jubjub generator point. TODO: prime or ---
        let base_point = params.engine.generator(FixedGenerators::SpendingKeyGenerator);
        base_point.mul(self.0.clone(), &params.engine).to_xy().0
    }
}

/// Public key.
pub type PublicKey<E> = <E as ScalarEngine>::Fr;

/// VRF input.
#[derive(Debug, Clone)]
pub struct VRFInput<E: JubjubEngine>(pub edwards::Point<E, PrimeOrder>);

impl<E: JubjubEngine> VRFInput<E> {
    /// Create a new random VRF input.
    pub fn random<R: rand_core::RngCore>(rng: &mut R, params: &Params<E>) -> Self {
        Self(edwards::Point::rand(rng, &params.engine).mul_by_cofactor(&params.engine))
    }

    /// Into VRF output.
    pub fn into_output(&self, sk: &PrivateKey<E>, params: &Params<E>) -> VRFOutput<E> {
        self.0.mul(sk.0.clone(), &params.engine)
    }
}


/// VRF output.
pub type VRFOutput<E> = edwards::Point<E, PrimeOrder>;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::time::SystemTime;

    use bellman::groth16::Parameters;
    use zcash_primitives::jubjub::JubjubBls12;
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

        let sk = PrivateKey::<Bls12>::random(rng);
        let pk = sk.into_public(&params);

        let vrf_input = VRFInput::<Bls12>::random(rng, &params);
        let vrf_output = vrf_input.into_output(&sk, &params);

        let auth_path = AuthPath::random(params.auth_depth, rng);
        let auth_root = AuthRoot::from_proof(&auth_path, &pk, &params);

        let t = SystemTime::now();
        let proof = prover::prove::<Bls12>(&crs, sk, vrf_input.clone(), auth_path.clone(), &params);
        println!("proving = {}", t.elapsed().unwrap().as_millis());
        let proof = proof.unwrap();

        let t = SystemTime::now();
        let valid = verifier::verify(&crs, proof, vrf_input, vrf_output, auth_root);
        println!("verification = {}", t.elapsed().unwrap().as_millis());
        assert_eq!(valid.unwrap(), true);
    }
}
