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

use rand_core::{RngCore,CryptoRng};

use ff::{Field, ScalarEngine}; // PrimeField, PrimeFieldRepr
use zcash_primitives::jubjub::{JubjubEngine, PrimeOrder, Unknown, edwards::Point};

use crate::{Params, Scalar};  // use super::*;
use crate::context::SigningTranscript;

/// VRF output, possibly unverified.
#[derive(Debug, Clone)] // Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct VRFOutput<E: JubjubEngine>(pub Point<E, Unknown>);

impl<E: JubjubEngine> VRFOutput<E> {
    pub fn read<R: io::Read>(reader: R, params: &E::Params) -> io::Result<Self> {
        Ok(VRFOutput( Point::read(reader,params)? ))
    }

    pub fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.0.write(writer)
    }
}

/*
    /// Pair a non-malleable VRF output with the hash of the given transcript.
    pub fn attach_input<T>(&self, t: T) -> SignatureResult<VRFInOut>
    where T: VRFSigningTranscript 
    {
        let input = public.vrf_hash(t);
        let output = RistrettoBoth::from_bytes_ser("VRFOutput", VRFOutput::DESCRIPTION, &self.0) ?;
        if output.as_point().is_identity() { return Err(SignatureError::PointDecompressionError); }
        Ok(VRFInOut { input, output })
    }
}



/// VRF input and output paired together, possibly unverified.
///
/// Internally, we keep both `RistrettoPoint` and `CompressedRistretto`
/// forms using `RistrettoBoth`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VRFInOut {
    /// VRF input point
    pub input: RistrettoBoth,
    /// VRF output point
    pub output: RistrettoBoth,
}

impl SecretKey {
    /// Evaluate the VRF-like multiplication on an uncompressed point,
    /// probably not useful in this form.
    pub fn vrf_create_from_point(&self, input: RistrettoBoth) -> VRFInOut {
        let output = RistrettoBoth::from_point(&self.key * input.as_point());
        VRFInOut { input, output }
    }

    /// Evaluate the VRF-like multiplication on a compressed point,
    /// useful for proving key exchanges, OPRFs, or sequential VRFs.
    ///
    /// We caution that such protocols could provide signing oracles
    /// and note that `vrf_create_from_point` cannot check for
    /// problematic inputs like `attach_input_hash` does.
    pub fn vrf_create_from_compressed_point(&self, input: &VRFOutput) -> SignatureResult<VRFInOut> {
        let input = RistrettoBoth::from_compressed(CompressedRistretto(input.0)) ?;
        Ok(self.vrf_create_from_point(input))
    }
}

impl Keypair {
    /// Evaluate the VRF on the given transcript.
    pub fn vrf_create_hash<T: VRFSigningTranscript>(&self, t: T) -> VRFInOut {
        self.secret.vrf_create_from_point(self.public.vrf_hash(t))
    }
}

impl VRFInOut {
    /// VRF output point bytes for serialization.
    pub fn as_output_bytes(&self) -> &[u8; 32] {
        self.output.as_compressed().as_bytes()
    }

    /// VRF output point bytes for serialization.
    pub fn to_output(&self) -> VRFOutput {
        VRFOutput(self.output.as_compressed().to_bytes())
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
        t.commit_point(b"vrf-in", self.input.as_compressed());
        t.commit_point(b"vrf-out", self.output.as_compressed());
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
        let mut t = Transcript::new(b"VRFResult");
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
    pub fn make_rng<R: ::rand_core::SeedableRng>(&self, context: &[u8]) -> R {
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
    pub fn make_merlin_rng(&self, context: &[u8]) -> merlin::TranscriptRng {
        // Very insecure hack except for our commit_witness_bytes below
        struct ZeroFakeRng;
        impl ::rand_core::RngCore for ZeroFakeRng {
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
        impl ::rand_core::CryptoRng for ZeroFakeRng {}

        let mut t = Transcript::new(b"VRFResult");
        t.append_message(b"",context);
        self.commit(&mut t);
        t.build_rng().finalize(&mut ZeroFakeRng)
    }
}

fn challenge_scalar_128<T: SigningTranscript>(mut t: T) -> Scalar {
    let mut s = [0u8; 16];
    t.challenge_bytes(b"", &mut s);
    Scalar::from(u128::from_le_bytes(s))
}

impl PublicKey {
    /// Merge VRF input and output pairs from the same signer,
    /// using variable time arithmetic
    ///
    /// You should use `vartime=true` when verifying VRF proofs batched
    /// by the singer.  You could usually use `vartime=true` even when
    /// producing proofs, provided the set being signed is not secret.
    ///
    /// There is sadly no constant time 128 bit multiplication in dalek,
    /// making `vartime=false` somewhat slower than necessary.  It should
    /// only impact signers in niche scenarios however, so the slower
    /// variant should normally be unnecessary.
    ///
    /// Panics if given an empty points list.
    ///
    /// TODO: Add constant time 128 bit batched multiplication to dalek.
    /// TODO: Is rand_chacha's `gen::<u128>()` standardizable enough to
    /// prefer it over merlin for the output?  
    pub fn vrfs_merge<B>(&self, ps: &[B], vartime: bool) -> VRFInOut
    where
        B: Borrow<VRFInOut>,
    {
        assert!( ps.len() > 0);
        let mut t = ::merlin::Transcript::new(b"MergeVRFs");
        t.commit_point(b"vrf:pk", self.as_compressed());
        for p in ps.iter() {
            p.borrow().commit(&mut t);
        }

        let zf = || ps.iter().map(|p| {
            let mut t0 = t.clone();
            p.borrow().commit(&mut t0);
            challenge_scalar_128(t0)
        });
        #[cfg(any(feature = "alloc", feature = "std"))]
        let zs: Vec<Scalar> = zf().collect();
        #[cfg(any(feature = "alloc", feature = "std"))]
        let zf = || zs.iter();

        // We need actual fns here because closures cannot easily take
        // closures as arguments, due to Rust lacking polymorphic
        // closures but giving all closures unique types.
        fn get_input(p: &VRFInOut) -> &RistrettoPoint { p.input.as_point() }
        fn get_output(p: &VRFInOut) -> &RistrettoPoint { p.output.as_point() }
        #[cfg(any(feature = "alloc", feature = "std"))]
        let go = |io: fn(p: &VRFInOut) -> &RistrettoPoint| {
            let ps = ps.iter().map( |p| io(p.borrow()) );
            RistrettoBoth::from_point(if vartime {
                RistrettoPoint::vartime_multiscalar_mul(zf(), ps)
            } else {
                RistrettoPoint::multiscalar_mul(zf(), ps)
            })
        };
        #[cfg(not(any(feature = "alloc", feature = "std")))]
        let go = |io: fn(p: &VRFInOut) -> &RistrettoPoint| {
            use curve25519_dalek::traits::Identity;
            let mut acc = RistrettoPoint::identity();
            for (z,p) in zf().zip(ps) {
                acc += z * io(p.borrow());
            }
            RistrettoBoth::from_point(acc)
        };

        let input = go( get_input );
        let output = go( get_output );
        VRFInOut { input, output }
    }
}

#[cfg(test)]
mod tests {
}

*/