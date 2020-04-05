// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK prover

use bellman::{
    SynthesisError,
    groth16, // {create_random_proof, ParameterSource, Parameters}
};
pub use groth16::Proof as RingVRFProof;

use zcash_primitives::jubjub::JubjubEngine;
use rand_core::{RngCore,CryptoRng};


use crate::{
    SynthesisResult, rand_hack, JubjubEngineWithParams,
    RingSRS, SigningTranscript, 
    SecretKey, RingSecretCopath, 
    VRFInput, VRFOutput, VRFInOut,
    vrf::{no_extra, VRFExtraMessage},
};


impl<E: JubjubEngineWithParams> SecretKey<E> {
    /// Create ring VRF signature using specified randomness source.
    pub fn ring_vrf_prove<T,R,P>(
        &self,
        vrf_input: VRFInput<E>,
        mut extra: T,
        copath: RingSecretCopath<E>,
        proving_key: RingSRS<P>,
        rng: &mut R,
    ) -> SynthesisResult<RingVRFProof<E>> 
    where
        T: SigningTranscript, 
        P: groth16::ParameterSource<E>, 
        R: RngCore+CryptoRng,
    {
        let instance = crate::circuit::RingVRF {
            depth: proving_key.depth,
            sk: Some(self.clone()),
            vrf_input: Some(vrf_input.0.mul_by_cofactor(E::params())),
            extra: Some(extra.challenge_scalar(b"extra-msg")),
            copath: Some(copath),
        };
        groth16::create_random_proof(instance, proving_key.srs, rng)
    } 



    /// Run our Schnorr VRF on one single input, producing the output
    /// and correspodning Schnorr proof.
    /// You must extract the `VRFOutput` from the `VRFInOut` returned.
    pub fn ring_vrf_sign_simple<P>(
        &self, 
        input: VRFInput<E>,
        copath: RingSecretCopath<E>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<(VRFInOut<E>, RingVRFProof<E>)>
    where P: groth16::ParameterSource<E>, 
    {
        self.ring_vrf_sign_first(input, no_extra(), copath, proving_key)
    }

    /// Run our Schnorr VRF on one single input and an extra message 
    /// transcript, producing the output and correspodning Schnorr proof.
    /// You must extract the `VRFOutput` from the `VRFInOut` returned.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use `vrf_sign_after_check` to gain access to
    /// the `VRFInOut` from `vrf_create_hash` first, and then avoid
    /// computing the proof whenever you do not win. 
    pub fn ring_vrf_sign_first<T,P>(
        &self,
        input: VRFInput<E>,
        extra: T,
        copath: RingSecretCopath<E>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<(VRFInOut<E>, RingVRFProof<E>)>
    where T: SigningTranscript,
          P: groth16::ParameterSource<E>, 
    {
        let inout = input.to_inout(self);
        let proof = self.ring_vrf_prove(input, extra, copath, proving_key, &mut rand_hack()) ?;
        Ok((inout, proof))
    }

    /// Run our Schnorr VRF on one single input, producing the output
    /// and correspodning Schnorr proof, but only if the result first
    /// passes some check, which itself returns either a `bool` or else
    /// an `Option` of an extra message transcript.
    pub fn ring_vrf_sign_after_check<F,O,P>(
        &self, 
        input: VRFInput<E>,
        mut check: F,
        copath: RingSecretCopath<E>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<Option<(VRFOutput<E>, RingVRFProof<E>)>>
    where F: FnOnce(&VRFInOut<E>) -> O,
          O: VRFExtraMessage,
          P: groth16::ParameterSource<E>, 
    {
        let inout = input.to_inout(self);
        let extra = if let Some(e) = check(&inout).extra() { e } else { return Ok(None) };
        Ok(Some(self.ring_vrf_sign_checked(inout, extra, copath, proving_key) ?))
    }

    /// Run our Schnorr VRF on the `VRFInOut` input-output pair,
    /// producing its output component and and correspodning Schnorr
    /// proof.
    pub fn ring_vrf_sign_checked<T,P>(
        &self, 
        inout: VRFInOut<E>, 
        extra: T,
        copath: RingSecretCopath<E>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<(VRFOutput<E>, RingVRFProof<E>)>
    where T: SigningTranscript,
          P: groth16::ParameterSource<E>, 
    {
        let VRFInOut { input, output } = inout;
        let proof = self.ring_vrf_prove(input, extra, copath, proving_key, &mut rand_hack()) ?;
        Ok((output, proof))
    }

    // TODO: VRFs methods
}

