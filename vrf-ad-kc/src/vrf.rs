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

use ark_ec::{AffineRepr,CurveGroup};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};

use rand_core::{RngCore,CryptoRng,SeedableRng}; // OsRng

use crate::{
    SigningTranscript, SecretKey,
    flavor::{Flavor},
};  // use super::*;


use std::borrow::{Borrow}; // BorrowMut


/// VRF Malleability Type
pub trait VrfMalleability {
    /// True if suitable for use with anonymized aka ring VRFs.
    /// Flase if suitable for use with soft key derivation.
    const ANONYMOUS : bool = true;

    /// Append malleability to transcript
    fn add_malleability<T: SigningTranscript>(&self, t: &mut T);
}


/// Malleable VRF input transcript.
///
/// Avoid use with related keys, aka HDKD.
/// Acknoledge malleability by never making this default behavior.
pub struct Malleable;
impl VrfMalleability for Malleable {
    /// Malleable VRF transcript.  
    ///
    /// We caution that malleable VRF inputs often become insecure if used
    /// with related keys, like blockchain wallets produce via "soft" HDKD.
    /// Instead you want a session key layer in which machines create
    /// unrelated VRF keys, and then users' account keys certify them.
    ///
    /// TODO: Verify that Point::rand is stable or find a stable alternative.
    fn add_malleability<T: SigningTranscript>(&self, _t: &mut T) { }
}

/// Non-malleable VRF transcript.  Unsuitable for ring VRFs.
impl<C: AffineRepr> VrfMalleability for crate::PublicKey<C> {
    const ANONYMOUS : bool = false;

    /// Non-malleable VRF transcript.
    ///
    /// Actually safe with user created related keys, aka HDKD, but
    /// incompatable with our ring VRF.  Avoids malleability within
    /// the small order subgroup here by multiplying by the cofactor.paramaters
    ///
    /// We expect full signer sets should be registered well in advance,
    /// so our removing the malleability here never creates more valid
    /// VRF outputs, but reconsider this if you've more dynamic key
    /// registration process.
    fn add_malleability<T: SigningTranscript>(&self, t: &mut T) {
        t.append(b"vrf-nm-pk", &self.0.mul_by_cofactor());
    }
}

/*
/// Ring-malleable VRF transcript for usage with ring VRFs
impl VrfMalleability for crate::merkle::RingRoot {
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
    fn add_malleability<T: SigningTranscript>(&self, t: &mut T) {
    {
        t.commit_bytes(b"vrf-nm-ar", self.0.to_repr().as_ref());
    }
}
*/


/// VRF input, consisting of an elliptic curve point.  
///
/// Always created locally from a `SigningTranscript` using the
/// `VrfMalleability` trait, which makes developers acknoledge their
/// malleability choice.
///
/// Not necessarily in the prime order subgroup.
#[derive(Debug,Clone,CanonicalSerialize)] // CanonicalDeserialize, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VrfInput<C: AffineRepr>(pub(crate) C);

impl<C: AffineRepr> VrfInput<C> {
    /// Create a new VRF input from a `Transcript`.
    /// 
    /// As the arkworks hash-to-curve infrastructure looks complex,
    /// we employ arkworks' simpler `UniformRand` here, which uses
    /// shitty try and increment.  We strongly recommend you construct
    /// `VrfInput`s directly using a better hash-to-curve.
    /// 
    /// TODO: Ask Syed to use the correct hash-to-curve
    #[inline(always)]
    pub fn from_transcript<T,M>(mut t: T, m: &M) -> Self
    where T: SigningTranscript, M: VrfMalleability+?Sized
    {
        m.add_malleability(&mut t);
        let p: <C as AffineRepr>::Group = t.challenge(b"vrf-input");
        VrfInput( p.into_affine() )
    }
}

impl<F: Flavor> SecretKey<F> {
    /// Compute VRF pre-output from secret key and input.
    pub fn vrf_preout(
        &self, input: &VrfInput<<F as Flavor>::PreOutAffine>
    ) -> VrfPreOut<<F as Flavor>::PreOutAffine> {
        let p: <<F as Flavor>::PreOutAffine as AffineRepr>::Group = input.0 * self.key;
        VrfPreOut( p.into_affine() )
    }

    /// Compute VRF pre-output paired with input from secret key and input point.
    pub fn vrf_inout(
        &self, input: VrfInput<<F as Flavor>::PreOutAffine>
    ) -> VrfInOut<<F as Flavor>::PreOutAffine>
    {
        let preoutput = self.vrf_preout(&input);
        VrfInOut { input, preoutput }
    }

    /// Compute VRF pre-output paired with input from secret key and input transcript.
    /// 
    /// As the arkworks hash-to-curve infrastructure looks complex,
    /// we employ arkworks' simpler `UniformRand` here, which uses
    /// shitty try and increment.  We strongly recommend you use a
    /// better hash-to-curve manually.
    pub fn vrf_inout_from_transcript<T,M>(&self, t: T, m: &M) -> VrfInOut<<F as Flavor>::PreOutAffine>
    where T: SigningTranscript, M: VrfMalleability+?Sized
    {
        let input = VrfInput::from_transcript(t,m);
        self.vrf_inout(input)
    }
}


/// VRF pre-output, possibly unverified.
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VrfPreOut<C: AffineRepr>(pub(crate) C);

impl<C: AffineRepr> VrfPreOut<C> {
    /// Create `VrfInOut` by attaching to our pre-output the VRF input
    /// with given malleablity from the given transcript. 
    /// 
    /// As the arkworks hash-to-curve infrastructure looks complex,
    /// we employ arkworks' simpler `UniformRand` here, which uses
    /// shitty try and increment.  We strongly recommend you use a
    /// better hash-to-curve manually.
    pub fn attach_input<T,M>(&self, malleability: &M, t: T) -> VrfInOut<C>
    where T: SigningTranscript, M: VrfMalleability
    {
        let input = VrfInput::from_transcript(t, malleability);
        VrfInOut { input, preoutput: self.clone() }
    }
}


/// VRF input and pre-output paired together, possibly unverified.
///
/// Internally, we keep both `RistrettoPoint` and `CompressedRistretto`
/// forms using `RistrettoBoth`.
#[derive(Debug,Clone,CanonicalSerialize)] // CanonicalDeserialize, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VrfInOut<C: AffineRepr> {
    /// VRF input point
    pub input: VrfInput<C>,
    /// VRF pre-output point
    pub preoutput: VrfPreOut<C>,
}

impl<C: AffineRepr> VrfInOut<C> {
    /// Append to transcript, 
    pub fn append<T: SigningTranscript>(&self, label: &'static [u8], t: &mut T) {
        if crate::small_cofactor::<C>() {
            let mut io = self.clone();
            io.preoutput.0 = io.preoutput.0.mul_by_cofactor();
            t.append(label,&io);
        } else {
            t.append(label,self);
        }
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
    pub fn vrf_output_bytes<B: Default + AsMut<[u8]>>(&self, context: &[u8]) -> B {
        let mut t = ::merlin::Transcript::new(b"VrfOutput");
        t.append(b"context",context);
        self.append(b"VrfInOut",&mut t);
        let mut seed = B::default();
        t.challenge_bytes(b"", seed.as_mut());
        seed
    }

    /// VRF output converted into any `SeedableRng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// We expect most users would prefer the less generic `VrfInOut::vrf_output_chacharng` method.
    pub fn vrf_output_rng<R: SeedableRng>(&self, context: &[u8]) -> R {
        R::from_seed(self.vrf_output_bytes::<R::Seed>(context))
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
    pub fn vrf_output_chacharng(&self, context: &[u8]) -> ::rand_chacha::ChaChaRng {
        self.vrf_output_rng::<::rand_chacha::ChaChaRng>(context)
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
    pub fn vrf_output_merlin_rng(&self, context: &[u8]) -> ::merlin::TranscriptRng {
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
        t.append(b"ctx",context);
        self.append(b"VrfInOut",&mut t);
        t.build_rng().finalize(&mut ZeroFakeRng)
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
/// We multiply every `VrfInOut` tuple here, which enables using faster
/// 128 bit scalars.  Amusingly, it turns out faster to do n 128 bit
/// scalar multiplicaitons here, rather than merge these delinearization
/// factors with the challenges used in signing and verifying.
/// 
/// ... 
/// 
/// We could reasonably ask if the VRF signer's public key or the
/// ring's merkle root should be hashed when creating the scalars in
/// `vrfs_merge*`, as Privacy Pass does.  In principle, one could
/// dicover relationships among the delinearizing scalars using
/// k-sum attacks, but not among distinct VRF inputs because they're
/// hashed to the curve.  TODO: Cite Wagner.
/// We also note no such requirement when the values being hashed are
/// BLS public keys as in https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
pub fn vrfs_merge<T,C,B>(t: &mut T, ps: &[B]) -> VrfInOut<C>
where
    T: SigningTranscript+Clone,
    C: AffineRepr,
    B: Borrow<VrfInOut<C>>,
{
    t.append_slice(b"VrfInOut", ps);
    vrfs_delinearize( t, ps.iter().map(|io| io.borrow()) )
}

/// Raw delinerazation step for merger of VRF input and pre-output
/// pairs from the same signer, probably using variable time arithmetic.
/// All pairs must be hashed into the transcript `t` before invoking,
/// as otherwise malicious signers could validate invalid pairs like
/// `[(x, (sk*a)*x, (x,(sk/a)*x)]`, breaking VRF & VUF security.
pub(crate) fn vrfs_delinearize<'a,T,C,I>(t: &T, ps: I) -> VrfInOut<C>
where
    T: SigningTranscript+Clone,
    C: AffineRepr,
    I: Iterator<Item=&'a VrfInOut<C>>
{
    use ark_std::Zero;

    let mut i = 0;
    let mut input = <C as AffineRepr>::Group::zero();
    let mut preoutput = <C as AffineRepr>::Group::zero();
    for p in ps {
        let mut t0 = t.clone();               // Keep t clean, but
        t0.append_u64(b"delinearize:i",i);    // distinguish the different outputs.
        let z: [u64; 2] = t0.challenge(b"");  // Sample a 128bit scalar.

        input += p.input.0.mul_bigint(z);
        preoutput += p.preoutput.0.mul_bigint(z);
        i += 1;
    }
    VrfInOut {
        input: VrfInput(input.into_affine()),
        preoutput: VrfPreOut(preoutput.into_affine())
    }
}


#[cfg(test)]
mod tests {
}

