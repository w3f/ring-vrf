// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Wei Tang <hi@that.world>
// - Sergey Vasilyev <swasilyev@gmail.com>
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Ring VRF zk SNARK verifier

use bellman::groth16; // Proof, verify_proof, prepare_verifying_key, PreparedVerifyingKey, VerifyingKey

use crate::{SignatureResult, SynthesisResult, SigningTranscript, RingRoot, VRFInOut, VRFPreOut, PublicKey, dleq::{VRFProof, PedersenDeltaOrPublicKey, PedersenDelta, Individual}, RingProof };
use bls12_381::Bls12;
use jubjub::ExtendedPoint;
use group::Curve;

pub fn verify_ring_affinity_proof(
    pk_blinded: &PublicKey,
    zkproof: &groth16::Proof<Bls12>,
    auth_root: &RingRoot,
    verifying_key: &groth16::PreparedVerifyingKey<Bls12>,
) -> SynthesisResult<bool>
{
    let pk_blinded = pk_blinded.0.to_affine();
    let public_input: [bls12_381::Scalar; 3] = [ pk_blinded.get_u(), pk_blinded.get_v(), auth_root.0.clone() ];
    Ok(groth16::verify_proof(verifying_key, zkproof, &public_input[..]).is_ok())
}

/// TODO!  UNPACK AND CHECK RING !!!  ANOTHER MODULE
impl VRFProof<VRFPreOut,Individual,RingProof> {
    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn ring_vrf_verify<TI,TE>(
        mut self, 
        input: TI, 
        extra: TE, 
        auth_root: &RingRoot, 
        verifying_key: &groth16::PreparedVerifyingKey<Bls12>
    ) -> SignatureResult<VRFInOut>
    where
        TI: SigningTranscript,
        TE: SigningTranscript,
    {
        let mut rp = None;
        let proof = self.alter_pd(|(pd,rap)| { rp=Some((pd.publickey().clone(), rap)); pd });
        let (pk_blinded,rap) = rp.unwrap();
        let (io,_) = proof.inner_ring_vrf_verify(input,extra,auth_root) ?;  // ??
        verify_ring_affinity_proof(&pk_blinded, &rap, auth_root, verifying_key) ?;
        Ok(io)
    }
}


