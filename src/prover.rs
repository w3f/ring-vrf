// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK prover

use bellman::groth16;
pub use groth16::Proof as RingVRFProof;

use rand_core::{RngCore,CryptoRng};


use crate::{SynthesisResult, rand_hack, RingSRS, SigningTranscript, SecretKey, RingSecretCopath, VRFInput, VRFPreOut, VRFInOut, vrf::{no_extra, VRFExtraMessage}, PoseidonArity};
use bls12_381::Bls12;
use bellman::multiexp::SourceBuilder;
use pairing::Engine;


impl SecretKey {
    /// Create ring VRF signature using specified randomness source.
    pub fn ring_vrf_prove<T, R, P, A>(
        &self,
        vrf_input: VRFInput,
        mut extra: T,
        copath: RingSecretCopath<A>,
        proving_key: RingSRS<P>,
        rng: &mut R,
    ) -> SynthesisResult<RingVRFProof<Bls12>>
    where
        T: SigningTranscript,
        R: RngCore + CryptoRng,
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
        A: 'static + PoseidonArity,
    {
        let instance = crate::circuit::RingVRF {
            depth: proving_key.depth,
            sk: Some(self.clone()),
            vrf_input: Some(vrf_input.as_point().clone()),
            extra: Some(extra.challenge_scalar(b"extra-msg")),
            copath: copath,
        };
        groth16::create_random_proof(instance, proving_key.srs, rng)
    } 



    /// Run our Schnorr VRF on one single input, producing the output
    /// and correspodning Schnorr proof.
    /// You must extract the `VRFPreOut` from the `VRFInOut` returned.
    pub fn ring_vrf_sign_simple<P, A>(
        &self, 
        input: VRFInput,
        copath: RingSecretCopath<A>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<(VRFInOut, RingVRFProof<Bls12>)>
    where
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
        A: 'static + PoseidonArity,
    {
        self.ring_vrf_sign_first(input, no_extra(), copath, proving_key)
    }

    /// Run our Schnorr VRF on one single input and an extra message 
    /// transcript, producing the output and correspodning Schnorr proof.
    /// You must extract the `VRFPreOut` from the `VRFInOut` returned.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use `vrf_sign_after_check` to gain access to
    /// the `VRFInOut` from `vrf_create_hash` first, and then avoid
    /// computing the proof whenever you do not win. 
    pub fn ring_vrf_sign_first<T, P, A>(
        &self,
        input: VRFInput,
        extra: T,
        copath: RingSecretCopath<A>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<(VRFInOut, RingVRFProof<Bls12>)>
    where
        T: SigningTranscript,
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
        A: 'static + PoseidonArity,
    {
        let inout = input.to_inout(self);
        let proof = self.ring_vrf_prove(input, extra, copath, proving_key, &mut rand_hack()) ?;
        Ok((inout, proof))
    }

    /// Run our Schnorr VRF on one single input, producing the output
    /// and correspodning Schnorr proof, but only if the result first
    /// passes some check, which itself returns either a `bool` or else
    /// an `Option` of an extra message transcript.
    pub fn ring_vrf_sign_after_check<F, O, P, A>(
        &self, 
        input: VRFInput,
        check: F,
        copath: RingSecretCopath<A>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<Option<(VRFPreOut, RingVRFProof<Bls12>)>>
    where
        F: FnOnce(&VRFInOut) -> O,
        O: VRFExtraMessage,
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
        A: 'static + PoseidonArity,
    {
        let inout = input.to_inout(self);
        let extra = if let Some(e) = check(&inout).extra() { e } else { return Ok(None) };
        Ok(Some(self.ring_vrf_sign_checked(inout, extra, copath, proving_key) ?))
    }

    /// Run our Schnorr VRF on the `VRFInOut` input-output pair,
    /// producing its output component and and correspodning Schnorr
    /// proof.
    pub fn ring_vrf_sign_checked<T, P, A>(
        &self, 
        inout: VRFInOut,
        extra: T,
        copath: RingSecretCopath<A>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<(VRFPreOut, RingVRFProof<Bls12>)>
    where
        T: SigningTranscript,
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
        A: 'static + PoseidonArity,
    {
        let VRFInOut { input, output } = inout;
        let proof = self.ring_vrf_prove(input, extra, copath, proving_key, &mut rand_hack()) ?;
        Ok((output, proof))
    }

    // TODO: VRFs methods
}

