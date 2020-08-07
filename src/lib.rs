// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>


//! ## Ring VRF


use rand_core::{RngCore,CryptoRng};

use zcash_primitives::jubjub::JubjubEngine;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate bench_utils;


mod misc;
mod keys;
pub mod context;
mod merkle;
mod circuit;
mod generator;
mod prover;
mod verifier;
pub mod vrf;
pub mod schnorr;
pub mod bls12_381;
mod insertion;

use crate::misc::{
    SignatureResult, signature_error, ReadWrite,
    Scalar, read_scalar, write_scalar,
    scalar_times_generator, scalar_times_blinding_generator
};
pub use crate::keys::{SecretKey, PublicKey, PublicKeyUnblinding};
pub use crate::context::{signing_context, SigningTranscript};

pub use crate::merkle::{RingSecretCopath, RingRoot, auth_hash};
pub use crate::generator::generate_crs;
pub use vrf::{VRFInOut, VRFInput, VRFPreOut, vrfs_merge};
use neptune::poseidon::PoseidonConstants;
use typenum::U2;


/// Ugly hack until we can unify error handling
pub type SynthesisResult<T> = Result<T, ::bellman::SynthesisError>;

fn rand_hack() -> impl RngCore+CryptoRng {
    ::rand_core::OsRng
}

/// Fix ZCash's curve paramater handling
pub trait JubjubEngineWithParams : JubjubEngine {
    fn params() -> &'static <Self as JubjubEngine>::Params;

    fn poseidon_params() -> &'static PoseidonConstants<Self::Fr, U2>;
}

/// RingVRF SRS consisting of the Merkle tree depth, our only runtime 
/// configuration parameters for the system, attached to an appropirate
/// `&'a Parameters<E>` or some other `P: groth16::ParameterSource<E>`.
#[derive(Clone,Copy)]
pub struct RingSRS<SRS> {
    pub srs: SRS,
    pub depth: u32,
}
/*
We could make it clone if SRS is Copy, but we'd rather make up for zcash's limited impls here.
impl<SRS: Copy+Clone> Copy for RingSRS<SRS> { }
impl<SRS: Copy+Clone> Clone for RingSRS<SRS> {
    fn clone(&self) -> RingSRS<SRS> {
        let RingSRS { srs, depth } = self;
        RingSRS { srs: *srs, depth: *depth }
    }
}
*/


#[cfg(test)]
mod tests {
    use std::fs::File;

    use rand_core::RngCore;

    use bellman::groth16;
    use pairing::bls12_381::Bls12;

    use super::*;

    #[test]
    fn test_completeness() {
        let depth = 10;

        // let mut rng = ::rand_chacha::ChaChaRng::from_seed([0u8; 32]);
        let mut rng = ::rand_core::OsRng;

        let filename = format!("srs{}.pk", depth);
        let srs = match File::open(&filename) {
            Ok(f) => groth16::Parameters::<Bls12>::read(f, false).expect("can't read SRS prover key"),
            Err(_) => {
                let f = File::create(filename).unwrap();
                let generation = start_timer!(|| "generation");
                let c = generator::generate_crs(depth).expect("can't generate SRS");
                end_timer!(generation);
                c.write(&f).unwrap();
                c
            },
        };
        let srs = RingSRS { srs: &srs, depth, };

        let filename = format!("srs{}.vk", depth);
        let vk = match File::open(&filename) {
            Ok(f) => groth16::VerifyingKey::<Bls12>::read(f).expect("can't read SRS verifier key"),
            Err(_) => {
                let f = File::create(filename).unwrap();
                srs.srs.vk.write(&f).unwrap();
                srs.srs.vk.clone()
            },
        };

        let sk = SecretKey::<Bls12>::from_rng(&mut rng);
        let pk = sk.to_public();

        let t = signing_context(b"Hello World!").bytes(&rng.next_u64().to_le_bytes()[..]);
        let vrf_input = VRFInput::<Bls12>::new_malleable(t.clone());

        let vrf_inout = vrf_input.to_inout(&sk);

        let copath = RingSecretCopath::random(depth, &mut rng);
        let auth_root = copath.to_root(&pk);

        let proving = start_timer!(|| "proving");
        let (vrf_preout, proof) = sk.ring_vrf_sign_checked(vrf_inout, vrf::no_extra(), copath.clone(), srs).unwrap();
        end_timer!(proving);

        let vrf_inout = vrf_preout.attach_input_malleable(t);
        let verification = start_timer!(|| "verification");
        let valid = auth_root.ring_vrf_verify_unprepared(vrf_inout, vrf::no_extra(), proof, &vk);
        end_timer!(verification);
        assert_eq!(valid.unwrap(), true);
    }
}
