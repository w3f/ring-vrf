// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Non-anonymous VRF implementation with Schnorr DLEQ proof 
//!
//! We model the VRF on "Making NSEC5 Practical for DNSSEC" by
//! Dimitrios Papadopoulos, Duane Wessels, Shumon Huque, Moni Naor,
//! Jan Včelák, Leonid Rezyin, andd Sharon Goldberg.
//! https://eprint.iacr.org/2017/099.pdf
//! We note the V(X)EdDSA signature scheme by Trevor Perrin at
//! https://www.signal.org/docs/specifications/xeddsa/#vxeddsa
//! is almost identical to the NSEC5 construction, except that
//! V(X)Ed25519 fails to be a VRF by giving signers multiple
//! outputs per input.  There is another even later variant at
//! https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/
//!
//! We support individual signers merging numerous VRF outputs created
//! with the same keypair, which follows the "DLEQ Proofs" and "Batching
//! the Proofs" sections of "Privacy Pass - The Math" by Alex Davidson,
//! https://new.blog.cloudflare.com/privacy-pass-the-math/#dleqproofs
//! and "Privacy Pass: Bypassing Internet Challenges Anonymously"
//! by Alex Davidson, Ian Goldberg, Nick Sullivan, George Tankersley,
//! and Filippo Valsorda.
//! https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf
//!
//! As noted there, our merging technique's soundness appeals to
//! Theorem 3.17 on page 74 of Ryan Henry's PhD thesis
//! "Efficient Zero-Knowledge Proofs and Applications"
//! https://uwspace.uwaterloo.ca/bitstream/handle/10012/8621/Henry_Ryan.pdf
//! See also the attack on Peng and Bao’s batch proof protocol in
//! "Batch Proofs of Partial Knowledge" by Ryan Henry and Ian Goldberg
//! https://www.cypherpunks.ca/~iang/pubs/batchzkp-acns.pdf
//!
//! We might reasonably ask if the VRF signer's public key should
//! really be hashed when creating the scalars in `vrfs_merge*`.
//! After all, there is no similar requirement when the values being
//! hashed are BLS public keys in say
//! https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
//! In fact, we expect the public key could be dropped both in
//! Privacy Pass' case, due to using randomness in the messages,
//! and in the VRF case, provided the message depends upon shared
//! randomness created after the public key.  Yet, there are VRF
//! applications outside these two cases, and DLEQ proof applications
//! where the points are not even hashes.  At minimum, we expect
//! hashing the public key prevents malicious signers from choosing
//! their key to cancel out the blinding of a particular point,
//! which might become important in a some anonymity applications.
//! In any case, there is no cost to hashing the public key for VRF
//! applications, but important such an approach cannot yield a
//! verifiable shuffle.
//! TODO: Explain better!
//!
//! We also implement verifier side batching analogous to batched
//! verification of Schnorr signatures, but note this requires an
//! extra curve point, which enlarges the VRF proofs from 64 bytes
//! to 96 bytes.  We provide `shorten_*` methods to produce the
//! non-batchable proof from the batchable proof because doing so
//! is an inherent part of the batch verification anyways.
//! TODO: Security arguments!
//!
//! We do not provide DLEQ proofs optimized for the same signer using
//! multiple public keys because such constructions sound more the
//! domain of zero-knowledge proof libraries.

use std::io;

use core::borrow::Borrow;

// #[cfg(any(feature = "alloc", feature = "std"))]
// use core::iter::once;

// #[cfg(feature = "alloc")]
// use alloc::{boxed::Box, vec::Vec};
// #[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

use ff::{Field}; // PrimeField, PrimeFieldRepr, ScalarEngine 
use zcash_primitives::jubjub::{JubjubEngine, PrimeOrder, Unknown, edwards::Point};

use merlin::Transcript;

use rand_core::{RngCore,CryptoRng};

use crate::{SigningTranscript, SecretKey, PublicKey, Scalar, VRFInOut};  // Params


/// Short proof of correctness for associated VRF output,
/// for which no batched verification works.
#[derive(Debug, Clone)] // PartialEq, Eq // PartialOrd, Ord, Hash
pub struct VRFProof<E: JubjubEngine> {
    /// Challenge
    c: Scalar<E>,
    /// Schnorr proof
    s: Scalar<E>,
}

impl<E: JubjubEngine> VRFProof<E> {
    pub fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let c = crate::read_scalar::<E, &mut R>(reader) ?;
        let s = crate::read_scalar::<E, &mut R>(reader) ?;
        Ok(VRFProof { c, s, })
    }

    pub fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        crate::write_scalar::<E, &mut W>(&self.c, writer) ?;
        crate::write_scalar::<E, &mut W>(&self.s, writer) ?;
        Ok(())
    }

}

/// Longer proof of correctness for associated VRF output,
/// which supports batching.
#[derive(Debug, Clone)] // PartialEq, Eq // PartialOrd, Ord, Hash
#[allow(non_snake_case)]
pub struct VRFProofBatchable<E: JubjubEngine> {
    /// Our nonce R = r G to permit batching the first verification equation
    R: Point<E,Unknown>,
    /// Our input hashed and raised to r to permit batching the second verification equation
    Hr: Point<E,Unknown>,
    /// Schnorr proof
    s: Scalar<E>,
}

impl<E: JubjubEngine> VRFProofBatchable<E> {
    #[allow(non_snake_case)]
    pub fn read<R: io::Read>(mut reader: R, params: &E::Params) -> io::Result<Self> {
        let R = Point::read(&mut reader,params) ?;
        let Hr = Point::read(&mut reader,params) ?;
        let s = crate::read_scalar::<E, &mut R>(&mut reader) ?;
        Ok(VRFProofBatchable { R, Hr, s, })
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.R.write(&mut writer) ?;
        self.Hr.write(&mut writer) ?;
        crate::write_scalar::<E, &mut W>(&self.s, &mut writer) ?;
        Ok(())
    }

    /// Return the shortened `VRFProof` for retransmitting in not batched situations
    #[allow(non_snake_case)]
    pub fn shorten_dleq<T>(&self, mut t: T, public: &PublicKey<E>, p: &VRFInOut<E>) -> VRFProof<E>
    where T: SigningTranscript,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"vrf:g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"vrf:h", &p.input.0);
        t.commit_point(b"vrf:pk", &public.0);

        t.commit_point(b"vrf:R=g^r", &self.R);
        t.commit_point(b"vrf:h^r", &self.Hr);

        t.commit_point(b"vrf:h^sk", &p.output.0);

        VRFProof {
            c: t.challenge_scalar(b"prove"), // context, message, A/public_key, R=rG
            s: self.s,
        }
    }

    /// Return the shortened `VRFProof` for retransmitting in non-batched situations
    pub fn shorten_vrf<T>( &self, public: &PublicKey<E>, p: &VRFInOut<E>) -> VRFProof<E> {
        let t0 = Transcript::new(b"VRF");  // We have context in t and another hear confuses batching
        self.shorten_dleq(t0, public, &p)
    }
}


impl<E: JubjubEngine> SecretKey<E> {
    /// Produce Schnorr DLEQ proof.
    ///
    /// We assume the `VRFInOut` paramater has been computed correctly
    /// by multiplying every input point by `self.key`, like by
    /// using one of the `vrf_create_*` methods on `SecretKey`.
    /// If so, we produce a proof that this multiplication was done correctly.
    #[allow(non_snake_case)]
    pub fn dleq_proove<T,R>(&self, mut t: T, p: &VRFInOut<E>, rng: R, params: &E::Params)
     -> (VRFProof<E>, VRFProofBatchable<E>)
    where
        T: SigningTranscript,
        R: RngCore+CryptoRng,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"vrf:g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"vrf:h", &p.input.0);
        t.commit_point(b"vrf:pk", &self.public.0);

        // We compute R after adding pk and all h.
        let r : Scalar<E> = t.witness_scalar(b"proving\00",&[&self.nonce_seed], rng);
        // let R = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let R = crate::scalar_times_generator(&r,params).into();
        t.commit_point(b"vrf:R=g^r", &R);

        // let Hr = (&r * p.input.0).compress();
        let Hr = p.input.0.mul(r.clone(), params);
        t.commit_point(b"vrf:h^r", &Hr);

        // We add h^sk last to save an allocation if we ever need to hash multiple h together.
        t.commit_point(b"vrf:h^sk", &p.output.0);

        let c = t.challenge_scalar(b"prove"); // context, message, A/public_key, R=rG
        // let s = &r - &(&c * &self.key);
        let mut s = r;
        let mut tmp = self.key.clone();
        tmp.mul_assign(&c);
        s.sub_assign(&tmp);

        // ::zeroize::Zeroize::zeroize(&mut r);

        (VRFProof { c, s }, VRFProofBatchable { R, Hr, s })
    }

/*

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use vrf_sign_n_check to gain access to the
    /// `VRFInOut` from `vrf_create_hash` first, and then avoid computing
    /// the proof whenever you do not win. 
    pub fn vrf_sign<T>(&self, t: T, params: &E::Params)
     -> (VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E>)
    where T: VRFSigningTranscript,
    {
        self.vrf_sign_extra(t,Transcript::new(b"VRF"),params)
        // We have context in t and another hear confuses batching
    }

    /// Run VRF on one single input transcript and an extra message transcript, 
    /// producing the outpus and correspodning short proof.
    pub fn vrf_sign_extra<T,E>(&self, t: T, extra: E, params: &E::Params)
     -> (VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E>)
    where T: VRFSigningTranscript,
          E: SigningTranscript,
    {
        let p = self.vrf_create_hash(t);
        let (proof, proof_batchable) = self.dleq_proove(extra, &p, params);
        (p, proof, proof_batchable)
    }


    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof only if the result first passes
    /// some check.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you might use this function to short circuit computing the full
    /// proof.
    pub fn vrf_sign_after_check<T,F>(&self, t: T, mut check: F, params: &E::Params)
     -> Option<(VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E>)>
    where T: VRFSigningTranscript,
          F: FnMut(&VRFInOut<E>) -> bool,
    {
        let f = |io| if check(io) { Some(Transcript::new(b"VRF")) } else { None };
        self.vrf_sign_extra_after_check(t,f,params)
    }

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof only if the result first passes
    /// some check, which itself returns an extra message transcript.
    pub fn vrf_sign_extra_after_check<T,E,F>(&self, t: T, mut check: F, params: &E::Params)
     -> Option<(VRFInOut<E>, VRFProof, VRFProofBatchable)>
    where T: VRFSigningTranscript,
          E: SigningTranscript,
          F: FnMut(&VRFInOut<E>) -> Option<E>,
    {
        let p = self.vrf_create_hash(t);
        let extra = check(&p) ?;
        let (proof, proof_batchable) = self.dleq_proove(extra, &p, params);
        Some((p, proof, proof_batchable))
    }

    /// Run VRF on several input transcripts, producing their outputs
    /// and a common short proof.
    ///
    /// We merge the VRF outputs using variable time arithmetic, so
    /// if even the hash of the message being signed is sensitive then
    /// you might reimplement some constant time variant.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_sign<T, I>(&self, ts: I, params: &E::Params)
     -> (Box<[VRFInOut<E>]>, VRFProof<E>, VRFProofBatchable<E>)
    where
        T: VRFSigningTranscript,
        I: IntoIterator<Item = T>,
    {
        self.vrfs_sign_extra(ts, Transcript::new(b"VRF"), params)
    }

    /// Run VRF on several input transcripts and an extra message transcript,
    /// producing their outputs and a common short proof.
    ///
    /// We merge the VRF outputs using variable time arithmetic, so
    /// if even the hash of the message being signed is sensitive then
    /// you might reimplement some constant time variant.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_sign_extra<T,E,I>(&self, ts: I, extra: E, params: &E::Params)
     -> (Box<[VRFInOut<E>]>, VRFProof<E>, VRFProofBatchable<E>)
    where
        T: VRFSigningTranscript,
        E: SigningTranscript,
        I: IntoIterator<Item = T>,
    {
        let ps = ts.into_iter()
            .map(|t| self.vrf_create_hash(t))
            .collect::<Vec<VRFInOut<E>>>();
        let p = self.public.vrfs_merge(&ps,true);
        let (proof, proof_batchable) = self.dleq_proove(extra, &p, params);
        (ps.into_boxed_slice(), proof, proof_batchable)
    }

*/

}

impl<E: JubjubEngine> PublicKey<E> {
    /// Verify DLEQ proof that `p.output = s * p.input` where `self`
    /// `s` times the basepoint.
    ///
    /// We return an enlarged `VRFProofBatchable` instead of just true,
    /// so that verifiers can forward batchable proofs.
    ///
    /// In principle, one might provide "blindly verifiable" VRFs that
    /// avoid requiring `self` here, but naively such constructions
    /// risk the same flaws as DLEQ based blind signatures, and this
    /// version exploits the slightly faster basepoint arithmetic.
    #[allow(non_snake_case)]
    pub fn dleq_verify<T>(
        &self,
        mut t: T,
        p: &VRFInOut<E>,
        proof: &VRFProof<E>,
        params: &E::Params,
    ) -> io::Result<VRFProofBatchable<E>>
    where
        T: SigningTranscript,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"vrf:g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"vrf:h", &p.input.0);
        t.commit_point(b"vrf:pk", &self.0);

        // We recompute R aka u from the proof
        // let R = ( (&proof.c * &self.0) + (&proof.s * &constants::RISTRETTO_BASEPOINT_TABLE) ).compress();
        let R = self.0.clone().mul(proof.c,params)
            .add(& crate::scalar_times_generator(&proof.s,params).into(), params)
            .into();
        t.commit_point(b"vrf:R=g^r", &R);

        // We also recompute h^r aka u using the proof
        // let Hr = (&proof.c * &p.output.0) + (&proof.s * &p.input.0);
        // let Hr = Hr.compress();
        let Hr = p.output.0.clone().mul(proof.c,params)
             .add(& p.input.0.clone().mul(proof.s,params), params);
        t.commit_point(b"vrf:h^r", &Hr);

        // We add h^sk last to save an allocation if we ever need to hash multiple h together.
        t.commit_point(b"vrf:h^sk", &p.output.0);

        // We need not check that h^pk lies on the curve because Ristretto ensures this.
        let VRFProof { c, s } = *proof;
        if c == t.challenge_scalar(b"prove") {
            Ok(VRFProofBatchable { R, Hr, s }) // Scalar: Copy ?!?
        } else {
            // Err(SignatureError::EquationFalse)
            Err( io::Error::new(io::ErrorKind::InvalidInput, "VRF signature validation failed" ) )
        }
    }

    /*
    
    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn vrf_verify<T: VRFSigningTranscript>(
        &self,
        t: T,
        out: &VRFOutput<E>,
        proof: &VRFProof<E>,
    ) -> SignatureResult<(VRFInOut<E>, VRFProofBatchable<E>)> {
        self.vrf_verify_extra(t,out,proof,Transcript::new(b"VRF"))
    }

    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn vrf_verify_extra<T,E>(
        &self,
        t: T,
        out: &VRFOutput<E>,
        proof: &VRFProof<E>,
        extra: E,
    ) -> SignatureResult<(VRFInOut<E>, VRFProofBatchable<E>)> 
    where T: VRFSigningTranscript,
          E: SigningTranscript,
    {
        let p = out.attach_input_hash(self,t) ?;
        let proof_batchable = self.dleq_verify(extra, &p, proof) ?;
        Ok((p, proof_batchable))
    }

    /// Verify a common VRF short proof for several input transcripts and corresponding outputs.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_verify<T,I,O>(
        &self,
        transcripts: I,
        outs: &[O],
        proof: &VRFProof<E>,
    ) -> SignatureResult<(Box<[VRFInOut<E>]>, VRFProofBatchable<E>)>
    where
        T: VRFSigningTranscript,
        I: IntoIterator<Item = T>,
        O: Borrow<VRFOutput>,
    {
        self.vrfs_verify_extra(transcripts,outs,proof,Transcript::new(b"VRF"))
    }

    /// Verify a common VRF short proof for several input transcripts and corresponding outputs.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_verify_extra<T,E,I,O>(
        &self,
        transcripts: I,
        outs: &[O],
        proof: &VRFProof,
        extra: E,
    ) -> SignatureResult<(Box<[VRFInOut<E>]>, VRFProofBatchable<E>)>
    where
        T: VRFSigningTranscript,
        E: SigningTranscript,
        I: IntoIterator<Item = T>,
        O: Borrow<VRFOutput>,
    {
        let mut ts = transcripts.into_iter();
        let ps = ts.by_ref().zip(outs)
            .map(|(t, out)| out.borrow().attach_input_hash(self,t))
            .collect::<SignatureResult<Vec<VRFInOut<E>>>>() ?;
        assert!(ts.next().is_none(), "Too few VRF outputs for VRF inputs.");
        assert!(
            ps.len() == outs.len(),
            "Too few VRF inputs for VRF outputs."
        );
        let p = self.vrfs_merge(&ps[..],true);
        let proof_batchable = self.dleq_verify(extra, &p, proof) ?;
        Ok((ps.into_boxed_slice(), proof_batchable))
    }

*/
    
}

/*
/// Batch verify DLEQ proofs where the public keys were held by
/// different parties.
///
/// We first reconstruct the `c`s present in the `VRFProof`s but absent
/// in the `VRFProofBatchable`s, using `shorten_dleq`.  We then verify
/// the `R` and `Hr` components of the `VRFProofBatchable`s using the
/// two equations a normal verification uses to discover them.
/// We do this by delinearizing both verification equations with
/// random numbers.
///
/// TODO: Assess when the two verification equations should be
/// combined, presumably by benchmarking both forms.  At smaller batch
/// sizes then we should clearly benefit form the combined form, but
/// bany combination doubles the scalar by scalar multiplicications
/// and hashing, so large enough batch verifications should favor two
/// seperate calls.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn dleq_verify_batch(
    ps: &[VRFInOut<E>],
    proofs: &[VRFProofBatchable<E>],
    public_keys: &[PublicKey<E>],
) -> SignatureResult<()> {
    const ASSERT_MESSAGE: &'static str = "The number of messages/transcripts / input points, output points, proofs, and public keys must be equal.";
    assert!(ps.len() == proofs.len(), ASSERT_MESSAGE);
    assert!(proofs.len() == public_keys.len(), ASSERT_MESSAGE);

    // Use a random number generator keyed by the publidc keys, the
    // inout and putput points, and the system randomn number gnerator.
    let mut csprng = {
        let mut t = Transcript::new(b"VB-RNG");
        for (pk,p) in public_keys.iter().zip(ps) {
            t.commit_point(b"",pk.as_compressed());
            p.commit(&mut t);
        }
        t.build_rng().finalize(&mut rand_hack())
    };

    // Select a random 128-bit scalar for each signature.
    // We may represent these as scalars because we use
    // variable time 256 bit multiplication below.
    let rnd_128bit_scalar = |_| {
        let mut r = [0u8; 16];
        csprng.fill_bytes(&mut r);
        Scalar::from(u128::from_le_bytes(r))
    };
    let zz: Vec<Scalar> = proofs.iter().map(rnd_128bit_scalar).collect();

    let z_s: Vec<Scalar> = zz.iter().zip(proofs)
        .map(|(z, proof)| z * proof.s)
        .collect();

    // Compute the basepoint coefficient, ∑ s[i] z[i] (mod l)
    let B_coefficient: Scalar = z_s.iter().sum();

    let t0 = Transcript::new(b"VRF");
    let z_c: Vec<Scalar> = zz.iter().enumerate()
        .map( |(i, z)| z * proofs[i].shorten_dleq(t0.clone(), &public_keys[i], &ps[i]).c )
        .collect();

    // Compute (∑ z[i] s[i] (mod l)) B + ∑ (z[i] c[i] (mod l)) A[i] - ∑ z[i] R[i] = 0
    let mut b = RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c.iter().cloned())
            .chain(once(B_coefficient)),
        proofs.iter().map(|proof| proof.R.decompress())
            .chain(public_keys.iter().map(|pk| Some(*pk.as_point())))
            .chain(once(Some(constants::RISTRETTO_BASEPOINT_POINT))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    // Compute (∑ z[i] s[i] (mod l)) Input[i] + ∑ (z[i] c[i] (mod l)) Output[i] - ∑ z[i] Hr[i] = 0
    b &= RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c)
            .chain(z_s),
        proofs.iter().map(|proof| proof.Hr.decompress())
            .chain(ps.iter().map(|p| Some(*p.output.as_point())))
            .chain(ps.iter().map(|p| Some(*p.input.as_point()))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    if b { Ok(()) } else { Err(SignatureError::EquationFalse) }
}

/// Batch verify VRFs by different signers
///
///
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn vrf_verify_batch<T, I>(
    transcripts: I,
    outs: &[VRFOutput],
    proofs: &[VRFProofBatchable],
    publickeys: &[PublicKey],
) -> SignatureResult<Box<[VRFInOut<E>]>>
where
    T: VRFSigningTranscript,
    I: IntoIterator<Item = T>,
{
    let mut ts = transcripts.into_iter();
    let ps = ts.by_ref()
        .zip(publickeys)
        .zip(outs)
        .map(|((t, pk), out)| out.attach_input_hash(pk,t))
        .collect::<SignatureResult<Vec<VRFInOut<E>>>>() ?;
    assert!(ts.next().is_none(), "Too few VRF outputs for VRF inputs.");
    assert!(
        ps.len() == outs.len(),
        "Too few VRF inputs for VRF outputs."
    );
    if dleq_verify_batch(&ps[..], proofs, publickeys).is_ok() {
        Ok(ps.into_boxed_slice())
    } else {
        Err(SignatureError::EquationFalse)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;

    use super::*;

    #[test]
    fn vrf_single() {
        // #[cfg(feature = "getrandom")]
        let mut csprng = ::rand_core::OsRng;

        let keypair1 = Keypair::generate_with(&mut csprng);

        let ctx = signing_context(b"yo!");
        let msg = b"meow";
        let (io1, proof1, proof1batchable) = keypair1.vrf_sign(ctx.bytes(msg));
        let out1 = &io1.to_output();
        assert_eq!(
            proof1,
            proof1batchable
                .shorten_vrf(&keypair1.public, ctx.bytes(msg), &out1)
                .unwrap(),
            "Oops `shorten_vrf` failed"
        );
        let (io1too, proof1too) = keypair1.public.vrf_verify(ctx.bytes(msg), &out1, &proof1)
            .expect("Correct VRF verification failed!");
        assert_eq!(
            io1too, io1,
            "Output differs between signing and verification!"
        );
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        assert_eq!(
            keypair1.vrf_sign(ctx.bytes(msg)).0,
            io1,
            "Rerunning VRF gave different output"
        );

        assert!(
            keypair1.public.vrf_verify(ctx.bytes(b"not meow"), &out1, &proof1).is_err(),
            "VRF verification with incorrect message passed!"
        );

        let keypair2 = Keypair::generate_with(&mut csprng);
        assert!(
            keypair2.public.vrf_verify(ctx.bytes(msg), &out1, &proof1).is_err(),
            "VRF verification with incorrect signer passed!"
        );
    }

    #[test]
    fn vrf_malleable() {
        // #[cfg(feature = "getrandom")]
        let mut csprng = ::rand_core::OsRng;

        let keypair1 = Keypair::generate_with(&mut csprng);

        let ctx = signing_context(b"yo!");
        let msg = b"meow";
        let (io1, proof1, proof1batchable) = keypair1.vrf_sign(Malleable(ctx.bytes(msg)));
        let out1 = &io1.to_output();
        assert_eq!(
            proof1,
            proof1batchable.shorten_vrf(&keypair1.public, Malleable(ctx.bytes(msg)), &out1).unwrap(),
            "Oops `shorten_vrf` failed"
        );
        let (io1too, proof1too) = keypair1
            .public.vrf_verify(Malleable(ctx.bytes(msg)), &out1, &proof1)
            .expect("Correct VRF verification failed!");
        assert_eq!(
            io1too, io1,
            "Output differs between signing and verification!"
        );
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        assert_eq!(
            keypair1.vrf_sign(Malleable(ctx.bytes(msg))).0,
            io1,
            "Rerunning VRF gave different output"
        );
        assert!(
            keypair1.public.vrf_verify(Malleable(ctx.bytes(b"not meow")), &out1, &proof1).is_err(),
            "VRF verification with incorrect message passed!"
        );

        let keypair2 = Keypair::generate_with(&mut csprng);
        assert!(
            keypair2.public.vrf_verify(Malleable(ctx.bytes(msg)), &out1, &proof1).is_err(),
            "VRF verification with incorrect signer passed!"
        );
        let (io2, _proof2, _proof2batchable) = keypair2.vrf_sign(Malleable(ctx.bytes(msg)));
        let out2 = &io2.to_output();

        // Verified key exchange, aka sequential two party VRF.
        let t0 = Transcript::new(b"VRF");
        let io21 = keypair2.secret.vrf_create_from_compressed_point(out1).unwrap();
        let proofs21 = keypair2.dleq_proove(t0.clone(), &io21);
        let io12 = keypair1.secret.vrf_create_from_compressed_point(out2).unwrap();
        let proofs12 = keypair1.dleq_proove(t0.clone(), &io12);
        assert_eq!(io12.output, io21.output, "Sequential two-party VRF failed");
        assert_eq!(
            proofs21.0,
            proofs21.1.shorten_dleq(t0.clone(), &keypair2.public, &io21),
            "Oops `shorten_dleq` failed"
        );
        assert_eq!(
            proofs12.0,
            proofs12.1.shorten_dleq(t0.clone(), &keypair1.public, &io12),
            "Oops `shorten_dleq` failed"
        );
        assert!(keypair1
            .public
            .dleq_verify(t0.clone(), &io12, &proofs12.0)
            .is_ok());
        assert!(keypair2
            .public
            .dleq_verify(t0.clone(), &io21, &proofs21.0)
            .is_ok());
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn vrfs_merged_and_batched() {
        let mut csprng = ::rand_core::OsRng;
        let keypairs: Vec<Keypair> = (0..4)
            .map(|_| Keypair::generate_with(&mut csprng))
            .collect();

        let ctx = signing_context(b"yo!");
        let messages: [&[u8; 4]; 2] = [b"meow", b"woof"];
        let ts = || messages.iter().map(|m| ctx.bytes(*m));

        let ios_n_proofs = keypairs.iter().map(|k| k.vrfs_sign(ts())).collect::<Vec<(
            Box<[VRFInOut<E>]>,
            VRFProof,
            VRFProofBatchable,
        )>>();

        for (k, (ios, proof, proof_batchable)) in keypairs.iter().zip(&ios_n_proofs) {
            let outs = ios
                .iter()
                .map(|io| io.to_output())
                .collect::<Vec<VRFOutput>>();
            let (ios_too, proof_too) = k
                .public
                .vrfs_verify(ts(), &outs, &proof)
                .expect("Valid VRF output verification failed!");
            assert_eq!(
                ios_too, *ios,
                "Output differs between signing and verification!"
            );
            assert_eq!(
                proof_too, *proof_batchable,
                "Returning batchable proof failed!"
            );
        }
        for (k, (ios, proof, _proof_batchable)) in keypairs.iter().zip(&ios_n_proofs) {
            let outs = ios.iter()
                .rev()
                .map(|io| io.to_output())
                .collect::<Vec<VRFOutput<_>>>();
            assert!(
                k.public.vrfs_verify(ts(), &outs, &proof).is_err(),
                "Incorrect VRF output verification passed!"
            );
        }
        for (k, (ios, proof, _proof_batchable)) in keypairs.iter().rev().zip(&ios_n_proofs) {
            let outs = ios.iter()
                .map(|io| io.to_output())
                .collect::<Vec<VRFOutput<_>>>();
            assert!(
                k.public.vrfs_verify(ts(), &outs, &proof).is_err(),
                "VRF output verification by a different signer passed!"
            );
        }

        let mut ios = keypairs.iter().enumerate()
            .map(|(i, keypair)| keypair.public.vrfs_merge(&ios_n_proofs[i].0,true))
            .collect::<Vec<VRFInOut<_>>>();

        let mut proofs = ios_n_proofs.iter()
            .map(|(_ios, _proof, proof_batchable)| proof_batchable.clone())
            .collect::<Vec<VRFProofBatchable<_>>>();

        let mut public_keys = keypairs.iter()
            .map(|keypair| keypair.public.clone())
            .collect::<Vec<PublicKey<_>>>();

        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_ok(),
            "Batch verification failed!"
        );
        proofs.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect proofs passed!"
        );
        proofs.reverse();
        public_keys.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect public keys passed!"
        );
        public_keys.reverse();
        ios.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect points passed!"
        );
    }
}

*/