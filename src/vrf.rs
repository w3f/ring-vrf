// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### VRF Output routines
//!
//! *Warning*  We warn that our ring VRF construction needs malleable
//! outputs via the `*malleable*` methods.  These are insecure when
//! used in  conjunction with our HDKD provided in dervie.rs.
//! Attackers could translate malleable VRF outputs from one soft subkey 
//! to another soft subkey, gaining early knowledge of the VRF output.
//! We suggest using either non-malleable VRFs or using implicit
//! certificates instead of HDKD when using VRFs.

use std::io;
use std::ops::{Add, Mul};

use rand_core::{RngCore,CryptoRng,SeedableRng}; // OsRng

use merlin::Transcript;

use ff::PrimeField;
use group::{Group, GroupEncoding};

use crate::{ReadWrite, SigningTranscript, Scalar};  // use super::*;


/// VRF Malleability Type
pub trait VRFMalleability {
    /// True if suitable for use with anonymized aka ring VRFs.
    const ANONYMOUS : bool = true;

    /// Build `VRFInput` from input transcript.
    fn vrf_input<T>(&self, t: T) -> VRFInput
    where T: SigningTranscript;
}

/// Malleable VRF input transcript.
///
/// Avoid use with related keys, aka HDKD.
/// Acknoledge malleability by never making this default behavior.
pub struct Malleable;
impl VRFMalleability for Malleable {
    /// Build malleable VRF input transcript.  
    ///
    /// We caution that malleable VRF inputs often become insecure if used
    /// with related keys, like blockchain wallets produce via "soft" HDKD.
    /// Instead you want a session key layer in which machines create
    /// unrelated VRF keys, and then users' account keys certify them.
    ///
    /// TODO: Verify that Point::rand is stable or find a stable alternative.
    fn vrf_input<T>(&self, t: T) -> VRFInput
    where T: SigningTranscript
    {
        VRFInput::from_transcript(t)
    }
}

/// Non-malleable VRF transcript.  Unsuitable for ring VRFs.
impl VRFMalleability for crate::PublicKey {
    const ANONYMOUS : bool = false;

    /// Build non-malleable VRF transcript.
    ///
    /// Actually safe with user created related keys, aka HDKD, but
    /// incompatable with our ring VRF.  Avoids malleability within
    /// the small order subgroup here by multiplying by the cofactor.
    ///
    /// We expect full signer sets should be registered well in advance,
    /// so our removing the malleability here never creates more valid
    /// VRF outputs, but reconsider this if you've more dynamic key
    /// registration process.
    fn vrf_input<T>(&self, mut t: T) -> VRFInput
    where T: SigningTranscript
    {
        t.commit_point(b"vrf-nm-pk", &self.0.mul_by_cofactor());
        VRFInput::from_transcript(t)
    }
}

/// Ring-malleable VRF transcript for usage with ring VRFs
impl VRFMalleability for crate::merkle::RingRoot {
    /// Ring-malleable VRF transcript
    ///
    /// We caution that ring malleable VRF inputs could become insecure
    /// when the same ring contains related keys, like blockchain wallets
    /// produce via "soft" HDKD.  
    /// We strongly suggest some session key abstraction in which servers
    /// make unrelated VRF keys, which users' account keys then certify.
    ///
    /// In this, we need the ring to be fixed protocol wide in advance
    /// because if users choose their ring then they enjoy potentially 
    /// unlimited VRF output choices too.  If you do this then your VRF
    /// reduces to proof-of-work, making it worthless.
    /// Use `Malleable` instead if you must choice over the ring.  
    fn vrf_input<T>(&self, mut t: T) -> VRFInput
    where T: SigningTranscript
    {
        t.commit_bytes(b"vrf-nm-ar", self.0.to_repr().as_ref());
        VRFInput::from_transcript(t)
    }
}


/// VRF input, consisting of an elliptic curve point.  
///
/// Always created locally from a `SigningTranscript` using the
/// `VRFMalleability` trait, which makes developers acknoledge their
/// malleability choice.
///
/// Not necessarily in the prime order subgroup.
#[derive(Debug, Clone)] // PartialEq, Eq
pub struct VRFInput(jubjub::SubgroupPoint);

impl VRFInput {
    /// TODO: Should we provide a convenience method that invokes `mul_by_cofactor()`?
    pub(crate) fn as_point(&self) -> &jubjub::SubgroupPoint { &self.0 }

    /// Create a new VRF input from an `RngCore`.
    #[inline(always)]
    fn from_rng<R: RngCore+CryptoRng>(rng: R) -> Self {
        VRFInput(jubjub::SubgroupPoint::random(rng))
    }

    /// Create a new VRF input from an `[u8; 32]`.
    #[inline(always)]
    fn from_seed(seed: [u8; 32]) -> Self {
        VRFInput::from_rng(rand_chacha::ChaChaRng::from_seed(seed))
    }

    /// Create a new VRF input from an `[u8; 32]`.
    #[inline(always)]
    fn from_transcript<T: SigningTranscript>(mut t: T) -> Self {
        let mut seed = [0u8; 32]; // <ChaChaRng as rand_core::SeedableRng>::Seed::default();
        t.challenge_bytes(b"vrf-input", seed.as_mut());
        VRFInput::from_seed(seed)
    }


    /// Into VRF pre-output.
    pub fn to_preout(&self, sk: &crate::SecretKey) -> VRFPreOut {
        let p: jubjub::ExtendedPoint = self.0.clone().into();
        VRFPreOut( p.mul(sk.key.clone()) )
    }

    /// Into VRF pre-output paired with input.
    pub fn to_inout(&self, sk: &crate::SecretKey) -> VRFInOut {
        let preoutput = self.to_preout(sk);
        VRFInOut { input: self.clone(), preoutput }
    }
}


/// VRF pre-output, possibly unverified.
#[derive(Debug, Clone)] // Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VRFPreOut(jubjub::ExtendedPoint);

impl VRFPreOut {
    /// TODO: Should we provide a convenience method that invokes `mul_by_cofactor()`?
    pub(crate) fn as_point(&self) -> &jubjub::ExtendedPoint { &self.0 }

    /// Create `VRFInOut` by attaching to our pre-output the VRF input
    /// with given malleablity from the given transcript. 
    pub fn attach_input<M,T>(&self, malleability: &M, t: T) -> VRFInOut
    where M: VRFMalleability, T: SigningTranscript
    {
        let input = malleability.vrf_input(t);
        VRFInOut { input, preoutput: self.clone() }
    }
}


/// VRF input and pre-output paired together, possibly unverified.
///
/// Internally, we keep both `RistrettoPoint` and `CompressedRistretto`
/// forms using `RistrettoBoth`.
#[derive(Debug, Clone)] // PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VRFInOut {
    /// VRF input point
    pub input: VRFInput,
    /// VRF pre-output point
    pub preoutput: VRFPreOut,
}

impl From<VRFInOut> for VRFInput {
    fn from(x: VRFInOut) -> VRFInput { x.input }
}

impl VRFInOut {
    /// Write VRF pre-output
    pub fn write_preoutput<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.preoutput.write(writer)
    }

    /// Commit VRF input and pre-output to a transcript.
    ///
    /// We commit both the input and pre-output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendix C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    ///
    /// We use this construction both for the VRF usage methods
    /// `VRFInOut::make_*` as well as for signer side batching.
    pub fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_point(b"vrf-in", self.input.as_point().into()); // .mul_by_cofactor(&params);
        t.commit_point(b"vrf-out", &self.preoutput.as_point().mul_by_cofactor());
    }

    /// Raw bytes output from the VRF.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// If called with distinct contexts then outputs should be independent.
    ///
    /// We incorporate both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    pub fn make_bytes<B: Default + AsMut<[u8]>>(&self, context: &[u8]) -> B {
        let mut t = ::merlin::Transcript::new(b"VRFResult");
        t.append_message(b"",context);
        self.commit(&mut t);
        let mut seed = B::default();
        t.challenge_bytes(b"", seed.as_mut());
        seed
    }

    /// VRF output converted into any `SeedableRng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// We expect most users would prefer the less generic `VRFInOut::make_chacharng` method.
    pub fn make_rng<R: SeedableRng>(&self, context: &[u8]) -> R {
        R::from_seed(self.make_bytes::<R::Seed>(context))
    }

    /// VRF output converted into a `ChaChaRng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// If called with distinct contexts then outputs should be independent.
    /// Independent output streams are available via `ChaChaRng::set_stream` too.
    ///
    /// We incorporate both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    #[cfg(feature = "rand_chacha")]
    pub fn make_chacharng(&self, context: &[u8]) -> ::rand_chacha::ChaChaRng {
        self.make_rng::<::rand_chacha::ChaChaRng>(context)
    }

    /// VRF output converted into Merlin's Keccek based `Rng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// We think this might be marginally slower than `ChaChaRng`
    /// when considerable output is required, but it should reduce
    /// the final linked binary size slightly, and improves domain
    /// separation.
    #[inline(always)]
    pub fn make_merlin_rng(&self, context: &[u8]) -> ::merlin::TranscriptRng {
        // Very insecure hack except for our commit_witness_bytes below
        struct ZeroFakeRng;
        impl RngCore for ZeroFakeRng {
            fn next_u32(&mut self) -> u32 {  panic!()  }
            fn next_u64(&mut self) -> u64 {  panic!()  }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                for i in dest.iter_mut() {  *i = 0;  }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ::rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl CryptoRng for ZeroFakeRng {}

        let mut t = ::merlin::Transcript::new(b"VRFResult");
        t.append_message(b"",context);
        self.commit(&mut t);
        t.build_rng().finalize(&mut ZeroFakeRng)
    }
}

impl ReadWrite for VRFPreOut  {
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let p = jubjub::ExtendedPoint::from_bytes(&bytes);
        if p.is_none().into() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid VRF pre-output encoding"));
        }
        // ZCash has not method to check for a JubJub point being the identity,
        // but so long as the VRFInput can only be created by hashing, then this
        // sounds okay.
        // if p.is_identity() {
        //     return Err( io::Error::new(io::ErrorKind::InvalidInput, "Identity point provided as VRF pre-output" ) );
        // }
        Ok(VRFPreOut(p.unwrap()))
    }

    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }
}


/// Merge VRF input and pre-output pairs from the same signer,
/// probably using variable time arithmetic
///
/// We merge VRF input and pre-outputs pairs by a single signer using
/// the same technique as the "DLEQ Proofs" and "Batching the Proofs"
/// sections of "Privacy Pass - The Math" by Alex Davidson,
/// https://new.blog.cloudflare.com/privacy-pass-the-math/#dleqproofs
/// and "Privacy Pass: Bypassing Internet Challenges Anonymously"
/// by Alex Davidson, Ian Goldberg, Nick Sullivan, George Tankersley,
/// and Filippo Valsorda.
/// https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf
///
/// As noted there, our merging technique's soundness appeals to
/// Theorem 3.17 on page 74 of Ryan Henry's PhD thesis
/// "Efficient Zero-Knowledge Proofs and Applications"
/// https://uwspace.uwaterloo.ca/bitstream/handle/10012/8621/Henry_Ryan.pdf
/// See also the attack on Peng and Bao’s batch proof protocol in
/// "Batch Proofs of Partial Knowledge" by Ryan Henry and Ian Goldberg
/// https://www.cypherpunks.ca/~iang/pubs/batchzkp-acns.pdf
///
/// We could reasonably ask if the VRF signer's public key or the
/// ring's merkle root should be hashed when creating the scalars in
/// `vrfs_merge*`, as Privacy Pass does.  In principle, one could
/// dicover relationships among the delinearizing scalars using
/// k-sum attacks, but not among distinct VRF inputs because they're
/// hashed to the curve.  TODO: Cite Wagner.
/// We also note no such requirement when the values being hashed are
/// BLS public keys as in https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
pub fn vrfs_merge<E,B>(ps: &[B]) -> VRFInOut
where B: ::core::borrow::Borrow<VRFInOut>
{
    assert!( ps.len() > 0);
    let mut t = ::merlin::Transcript::new(b"MergeVRFs");
    for p in ps {  p.borrow().commit(&mut t);  }

    // We'd do accumulation here, but rust lacks polymorphic closures.
    let psz = || ps.iter().map( |p| { 
        let mut t0 = t.clone();
        let p = p.borrow();
        p.commit(&mut t0);

        // Sample a 128bit scalar
        let mut s = [0u8; 16];
        t0.challenge_bytes(b"", &mut s);
        let z: Scalar = crate::misc::scalar_from_u128(s);
        (p,z)
    } );

    let input = VRFInput( psz().fold(jubjub::SubgroupPoint::identity(), |acc,(p,z)| {
        acc.add(&p.input.as_point().mul(z))
    } ) );
    let preoutput = VRFPreOut( psz().fold(jubjub::ExtendedPoint::identity(), |acc,(p,z)| {
        acc.add(&p.preoutput.as_point().mul(z))
    } ) );
    VRFInOut { input, preoutput }
}


/// Almost all VRF methods support signing an extra message
/// alongside the VRF, so `no_extra` provides a convenient
/// default transcript when no extra message is desired.
pub fn no_extra() -> Transcript {
    Transcript::new(b"VRF")
}

/// We take closures like `F: FnMut(&VRFInOut<E>) -> impl VRFExtraMessage`
/// in `vrf_sign_after_check` to avoid needing both 
/// `-> bool` and `-> Option<Transcript>` versions.
pub trait VRFExtraMessage {
    type T: SigningTranscript;
    fn extra(self) -> Option<Self::T>;
}
impl<T: SigningTranscript> VRFExtraMessage for Option<T> {
    type T = T;
    fn extra(self) -> Option<T> { self }
}
impl VRFExtraMessage for bool {
    type T = Transcript;
    fn extra(self) -> Option<Transcript> {
        if self { Some(no_extra()) } else { None }
    }
}
impl VRFExtraMessage for Transcript {
    type T = Transcript;
    fn extra(self) -> Option<Transcript> { Some(self) }
}

pub fn no_check_no_extra(_: &VRFInOut) -> bool { true }



#[cfg(test)]
mod tests {
}

