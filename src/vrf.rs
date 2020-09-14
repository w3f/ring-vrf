// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### VRF Output routines
//!
//! *Warning*  We warn that our ring VRF construction need malleable
//! outputs via the `*malleable*` methods.  These are insecure when
//! used in  conjunction with our HDKD provided in dervie.rs.
//! Attackers could translate malleable VRF outputs from one soft subkey 
//! to another soft subkey, gaining early knowledge of the VRF output.
//! We suggest using either non-malleable VRFs or using implicit
//! certificates instead of HDKD when using VRFs.

use std::io;

use rand_core::{RngCore,CryptoRng,SeedableRng}; // OsRng

use merlin::Transcript;

use ff::PrimeField;

use crate::{JubjubEngineWithParams, ReadWrite, SigningTranscript, Scalar};  // use super::*;


/// VRF input, always created locally from a `SigningTranscript`.
///
/// All creation methods require the developer acknoledge their VRF output malleability.
#[derive(Debug, Clone)] // PartialEq, Eq
pub struct VRFInput<E: JubjubEngine>(jubjub::SubgroupPoint);

impl<E: JubjubEngineWithParams> VRFInput<E> {
    pub(crate) fn as_point(&self) -> &jubjub::SubgroupPoint { &self.0 }

    /// Create a new VRF input from an `RngCore`.
    #[inline(always)]
    fn from_rng<R: RngCore+CryptoRng>(mut rng: R) -> Self {
        VRFInput(jubjub::SubgroupPoint::random(rng))
    }

    /// Acknoledge VRF transcript malleablity
    ///
    /// TODO: Verify that Point::rand is stable or find a stable alternative.
    pub fn new_malleable<T>(mut t: T) -> VRFInput<E> 
    where T: SigningTranscript
    {
        let mut seed = [0u8; 32]; // <ChaChaRng as rand_core::SeedableRng>::Seed::default();
        t.challenge_bytes(b"vrf-input", seed.as_mut());
        let rng = ::rand_chacha::ChaChaRng::from_seed(seed);
        VRFInput::from_rng(rng)
    }

    /// Non-malleable VRF transcript.
    ///
    /// Incompatable with ring VRF however.  We avoid malleability within the
    /// small order subgroup here by multiplying by the cofactor.
    pub fn new_nonmalleable<T>(mut t: T, publickey: &crate::PublicKey<E>)
     -> VRFInput<E>
    where T: SigningTranscript
    {
        t.commit_point(b"vrf-nm-pk", &publickey.0.mul_by_cofactor());
        VRFInput::new_malleable(t)
    }

    /// Semi-malleable VRF transcript
    pub fn new_ring_malleable<T>(mut t: T, auth_root: &crate::merkle::RingRoot<E>)
     -> VRFInput<E>
    where T: SigningTranscript
    {
        t.commit_bytes(b"vrf-nm-ar", auth_root.0.to_repr().as_ref());
        VRFInput::new_malleable(t)
    }

    /// Into VRF output.
    pub fn to_preout(&self, sk: &crate::SecretKey<E>) -> VRFPreOut<E> {
        let p: jubjub::ExtendedPoint = self.0.clone().into();
        VRFPreOut( p.mul(sk.key.clone()) )
    }

    /// Into VRF output.
    pub fn to_inout(&self, sk: &crate::SecretKey<E>) -> VRFInOut<E> {
        let output = self.to_preout(sk);
        VRFInOut { input: self.clone(), output }
    }
}


/// VRF output, possibly unverified.
#[derive(Debug, Clone)] // Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VRFPreOut<E: JubjubEngine>(jubjub::ExtendedPoint);

impl<E: JubjubEngineWithParams> VRFPreOut<E> {
    pub(crate) fn as_point(&self) -> &jubjub::ExtendedPoint { &self.0 }

    /// Acknoledge VRF transcript malleablity
    ///
    /// TODO: Verify that Point::rand is stable or find a stable alternative.
    pub fn attach_input_malleable<T>(&self, t: T) -> VRFInOut<E>
    where T: SigningTranscript
    {
        let input = VRFInput::new_malleable(t);
        VRFInOut { input, output: self.clone() }
    }

    /// Non-malleable VRF transcript.
    ///
    /// Incompatable with ring VRF however.
    pub fn attach_input_nonmalleable<T>(&self, t: T, publickey: &crate::PublicKey<E>)
     -> VRFInOut<E>
    where T: SigningTranscript
    {
        let input = VRFInput::new_nonmalleable(t,publickey);
        VRFInOut { input, output: self.clone() }
    }

    /// Semi-malleable VRF transcript
    pub fn attach_input_ring_malleable<T>(&self, t: T, auth_root: &crate::merkle::RingRoot<E>)
     -> VRFInOut<E>
    where T: SigningTranscript
    {
        let input = VRFInput::new_ring_malleable(t,auth_root);
        VRFInOut { input, output: self.clone() }
    }
}


/// VRF input and output paired together, possibly unverified.
///
/// Internally, we keep both `RistrettoPoint` and `CompressedRistretto`
/// forms using `RistrettoBoth`.
#[derive(Debug, Clone)] // PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VRFInOut<E: JubjubEngine> {
    /// VRF input point
    pub input: VRFInput<E>,
    /// VRF output point
    pub output: VRFPreOut<E>,
}

impl<E: JubjubEngine> From<VRFInOut<E>> for VRFInput<E> {
    fn from(x: VRFInOut<E>) -> VRFInput<E> { x.input }
}

impl<E: JubjubEngineWithParams> VRFInOut<E> {
    /// Write VRF output
    pub fn write_output<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.output.write(writer)
    }

    /// Commit VRF input and output to a transcript.
    ///
    /// We commit both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendix C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    ///
    /// We use this construction both for the VRF usage methods
    /// `VRFInOut::make_*` as well as for signer side batching.
    pub fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_point(b"vrf-in", &self.input.as_point()); // .mul_by_cofactor(&params);
        t.commit_point(b"vrf-out", &self.output.as_point().mul_by_cofactor());
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

impl<E: JubjubEngineWithParams> ReadWrite for VRFPreOut<E>  {
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
        //     return Err( io::Error::new(io::ErrorKind::InvalidInput, "Identity point provided as VRF output" ) );
        // }
        Ok(VRFPreOut(p.unwrap()))
    }

    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }
}


/// Merge VRF input and output pairs from the same signer,
/// probably using variable time arithmetic
///
/// We merge VRF input-outputs pairs by a single signer using the same
/// technique as the "DLEQ Proofs" and "Batching the Proofs" sections
/// of "Privacy Pass - The Math" by Alex Davidson,
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
pub fn vrfs_merge<E,B>(ps: &[B]) -> VRFInOut<E>
where
    E: JubjubEngineWithParams,
    B: ::core::borrow::Borrow<VRFInOut<E>>,
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
        let z: Scalar = crate::misc::scalar_from_u128::<E>(s);
        (p,z)
    } );

    let input = VRFInput( psz().fold(jubjub::SubgroupPoint::identity(), |acc,(p,z)| {
        acc.add(&p.input.as_point().mul(z))
    } ) );
    let output = VRFPreOut( psz().fold(jubjub::ExtendedPoint::identity(), |acc,(p,z)| {
        acc.add(&p.output.as_point().mul(z))
    } ) );
    VRFInOut { input, output }
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

pub fn no_check_no_extra<E: JubjubEngineWithParams>(_: &VRFInOut<E>) -> bool { true }



#[cfg(test)]
mod tests {
}

