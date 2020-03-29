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

use ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine}; // ScalarEngine 
use zcash_primitives::jubjub::{JubjubEngine, PrimeOrder, Unknown, edwards::Point};

use merlin::Transcript;

use crate::{SigningTranscript, Params, Scalar, VRFInOut, PublicKey};  // use super::*;


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

