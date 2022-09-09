// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>


//! ## Ring VRF


use rand_core::{RngCore,CryptoRng};

#[macro_use]
extern crate lazy_static;

// #[macro_use]
extern crate arrayref;


mod misc;
mod keys;
pub mod context;
mod merkle;
mod circuit;
mod generator;
mod prover;
mod verifier;
pub mod vrf;
pub mod dleq;
mod insertion;
mod copath;

use misc::{
    SignatureResult, SignatureError, ReadWrite,
    Scalar, read_scalar, write_scalar,
    scalar_times_generator, scalar_times_blinding_generator
};
pub use keys::{SecretKey, PublicKey, PublicKeyUnblinding};
pub use context::{signing_context, SigningTranscript};

pub use merkle::{RingSecretCopath, RingRoot, auth_hash};
pub use generator::generate_crs;
pub use vrf::{VRFInOut, VRFInput, VRFPreOut, no_extra};
pub use dleq::{VRFSignature,VRFProof};

use neptune::poseidon::PoseidonConstants;
use typenum::{U2, U4};


pub type RingProof = (dleq::PedersenDelta,bellman::groth16::Proof<bls12_381::Bls12>);


/// Ugly hack until we can unify error handling
pub type SynthesisResult<T> = Result<T, ::bellman::SynthesisError>;


fn rand_hack() -> impl RngCore+CryptoRng {
    ::rand_core::OsRng
}

pub trait PoseidonArity: neptune::Arity<bls12_381::Scalar> + Send + Sync + Clone + std::fmt::Debug {
    fn params() -> &'static PoseidonConstants<bls12_381::Scalar, Self>;
}

lazy_static! {
    static ref POSEIDON_CONSTANTS_2: PoseidonConstants::<bls12_381::Scalar, U2> = PoseidonConstants::new();
    static ref POSEIDON_CONSTANTS_4: PoseidonConstants::<bls12_381::Scalar, U4> = PoseidonConstants::new();
}

impl PoseidonArity for U2 {
    fn params() -> &'static PoseidonConstants<bls12_381::Scalar, Self> {
        &POSEIDON_CONSTANTS_2
    }
}

impl PoseidonArity for U4 {
    fn params() -> &'static PoseidonConstants<bls12_381::Scalar, Self> {
        &POSEIDON_CONSTANTS_4
    }
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

    use super::*;
    use ::bls12_381::Bls12;
    use crate::dleq::{Individual, PedersenDelta};

    use ark_std::{end_timer, start_timer, test_rng};

    #[test]
    fn test_completeness() {
        let rng = &mut test_rng();

        let depth = 5;

        let generation = start_timer!(|| "CRS generation");
        let srs = generator::generate_crs::<U4>(depth).expect("can't generate SRS");
        end_timer!(generation);

        let srs = RingSRS { srs: &srs, depth, };
        let pvk = groth16::prepare_verifying_key::<Bls12>(&srs.srs.vk);

        let sk = SecretKey::from_rng(rng);
        let pk = sk.to_public();
        let copath = RingSecretCopath::<U4>::random(depth, rng);
        let auth_root = copath.to_root(&pk);

        let input = signing_context(b"").bytes(&rng.next_u64().to_le_bytes()[..]);

        let (io,proof) = sk.ring_vrf_sign_unchecked(input.clone(), no_extra(), copath, srs).unwrap();
        // assert_eq!(
        //    io.make_bytes::<[u8;16]>(b""),
        //     sk.vrf_sign_unchecked(input.clone(), no_extra()).0.make_bytes::<[u8;16]>(b"")
        // );
        assert_eq!(
            io.make_bytes::<[u8;16]>(b""),
            proof.ring_vrf_verify(input.clone(), no_extra(), &auth_root, &pvk).unwrap().make_bytes::<[u8;16]>(b"")
        );

        /*
        let vrf_input = VRFInput::new_ring_malleable(t.clone(),&auth_root);

        let proving_schnorr = start_timer!(|| "proving Schnorr");
        let (vrf_in_out, vrf_proof, unblinding) = sk.vrf_sign_simple::<Individual, PedersenDelta>(vrf_input);
        end_timer!(proving_schnorr);

        let proving_snark = start_timer!(|| "proving snark");
        let ring_proof= prover::compute_ring_affinity_proof(unblinding, vrf_proof.publickey().clone(), vrf::no_extra(), copath.clone(), srs, rng).unwrap();
        end_timer!(proving_snark);

        let vrf_proof_decoded = vrf_proof.attach_input_ring_malleable(t.clone(),&auth_root);

        let verifying_schnorr = start_timer!(|| "verifying Schnorr");
        assert!(vrf_proof_decoded.vrf_verify_simple().is_ok());
        end_timer!(verifying_schnorr);

        let verifying_snark = start_timer!(|| "verifying snark");
        let valid = auth_root.verify_ring_affinity_proof(vrf_proof_decoded.publickey().clone(), vrf::no_extra(), ring_proof, &pvk);
        end_timer!(verifying_snark);

        assert!(valid.unwrap());
        */
    }
}
