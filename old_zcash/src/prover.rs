// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK prover

use bellman::groth16;
pub use groth16::Proof as Groth16Proof;

use rand_core::{RngCore,CryptoRng};


use crate::{SignatureResult, SynthesisResult, rand_hack, RingSRS, SigningTranscript, SecretKey, RingSecretCopath, VRFInput, VRFPreOut, VRFInOut, vrf::{no_extra, VRFExtraMessage}, dleq::{VRFProof, NewChallengeOrWitness, PedersenDeltaOrPublicKey, PedersenDelta, Individual}, PoseidonArity, PublicKeyUnblinding, PublicKey, RingProof};
use bls12_381::Bls12;
use bellman::multiexp::SourceBuilder;
use pairing::Engine;

pub fn compute_ring_affinity_proof<A,P,RNG>(
    unblinding: PublicKeyUnblinding,
    pk_blinded: PublicKey,
    copath: RingSecretCopath<A>,
    proving_key: RingSRS<P>,
    rng: &mut RNG,
) -> SynthesisResult<Groth16Proof<Bls12>>
    where
        A: 'static + PoseidonArity,
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
        RNG: RngCore + CryptoRng,
{
    let instance = crate::circuit::RingVRF {
        depth: proving_key.depth,
        unblinding: Some(unblinding),
        pk_blinded: Some(pk_blinded),
        copath: copath,
    };
    groth16::create_random_proof(instance, proving_key.srs, rng)
}

impl SecretKey {
    /// Irrefutable non-anonyimized/non-ring Schnorr VRF signature.
    /// 
    /// Returns first the `VRFInOut` from which output can be extracted,
    /// and second the ring VRF signature.
    pub fn ring_vrf_sign_unchecked<TI,TE,A,P>(
        &self,
        input: TI,
        extra: TE,
        copath: RingSecretCopath<A>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<(VRFInOut, VRFProof<VRFPreOut,Individual,RingProof>)>
    where
        TI: SigningTranscript,
        TE: SigningTranscript,
        // CW: NewChallengeOrWitness,  
        A: 'static + PoseidonArity,
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
    {
        use crate::{vrf::VRFMalleability, dleq::PedersenDeltaOrPublicKey};
        let inout = copath.to_root(self.as_publickey()).vrf_input(input).to_inout(self);
        let (proof, unblinding): (VRFProof<VRFPreOut,Individual,PedersenDelta>, PublicKeyUnblinding)
          = self.dleq_proove(&inout, extra, rand_hack());
        let rap = compute_ring_affinity_proof(
            unblinding,
            proof.pd.publickey().clone(),
            copath,
            proving_key,
            &mut rand_hack()
        ) ?;
        Ok(( inout, proof.alter_pd( |pd: PedersenDelta| (pd,rap) ) ))
    }

    /// Refutable ring VRF signature.
    ///
    /// We check whether an output warrants producing a proof using the
    /// closure provided, which itself returns either a `bool` or else
    /// an `Option` of an extra message transcript.
    pub fn ring_vrf_sign_after_check<TI,F,O,A,P>(
        &self,
        input: TI,
        check: F,
        copath: RingSecretCopath<A>,
        proving_key: RingSRS<P>,
    ) -> SynthesisResult<Option<VRFProof<VRFPreOut,Individual,RingProof>>>
    where
        TI: SigningTranscript,
        // CW: NewChallengeOrWitness,
        F: FnOnce(&VRFInOut) -> O,
        O: VRFExtraMessage,
        A: 'static + PoseidonArity,
        P: groth16::ParameterSource<Bls12>,
        P::G1Builder: SourceBuilder<<Bls12 as Engine>::G1Affine>,
        P::G2Builder: SourceBuilder<<Bls12 as Engine>::G2Affine>,
    {
        use crate::{vrf::VRFMalleability, dleq::PedersenDeltaOrPublicKey};
        let inout = copath.to_root(self.as_publickey()).vrf_input(input).to_inout(self);
        let extra = if let Some(extra) = check(&inout).extra() { extra } else { return Ok(None) };
        let (proof, unblinding): (VRFProof<VRFPreOut,Individual,PedersenDelta>, PublicKeyUnblinding)
          = self.dleq_proove(&inout, extra, rand_hack());
        let rap = compute_ring_affinity_proof(
            unblinding,
            proof.pd.publickey().clone(),
            copath,
            proving_key,
            &mut rand_hack()
        ) ?;
        Ok(Some( proof.alter_pd( |pd: PedersenDelta| (pd,rap) ) ))
    }

    // TODO: VRFs methods
}

