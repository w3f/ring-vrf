// -*- mode: rust; -*-
//
// Copyright (c) 2019 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Arkworks friendly transcripts for Chaum-Pederson DLEQ proofs 

use core::borrow::Borrow;

// use ark_ff::{Field};
use ark_std::{UniformRand};  // Result
use ark_serialize::{CanonicalSerialize};

use rand_core::{RngCore,CryptoRng};


#[cfg(feature = "blake3")]
pub mod blake3;

// #[cfg(feature = "merlin")]
pub mod merlin;


/// Arkworks friendly transcripts for Chaum-Pederson DLEQ proofs
pub trait SigningTranscript {
    /// Extend transcript with a protocol name
    fn proto_name(&mut self, label: &'static [u8]);

    /// Append `u64` conveniently
    fn append_u64(&mut self, label: &'static [u8], v: u64) {
        let b: &[u8] = &v.to_le_bytes();
        self.append(label,b)
    }

    /// Append items seralizable by Arkworks
    fn append<T: CanonicalSerialize+?Sized>(&mut self, label: &'static [u8], itm: &T);

    fn append_slice<T,B>(&mut self, label: &'static [u8], itms: &[B])
    where T: CanonicalSerialize+?Sized, B: Borrow<T>, 
    {
        for itm in itms.iter() {
            self.append(label, itm.borrow());
        }
    }

    /// Extract challenges samplable by Arkworks
    fn challenge<T: UniformRand>(&mut self, label: &'static [u8]) -> T;

    /// Extract witnesses samplable by Arkworks
    fn witnesses_rng<T, R, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> [T; N]
    where  R: RngCore+CryptoRng, T: UniformRand;

    /// Extract witnesses samplable by Arkworks
    fn witnesses<T: UniformRand, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]]) -> [T; N] {
        self.witnesses_rng(label, nonce_seeds, getrandom_or_panic())
    }
}


/// Returns `OsRng` with `getrandom`, or a `CryptoRng` which panics without `getrandom`.
#[cfg(feature = "getrandom")] 
pub fn getrandom_or_panic() -> impl RngCore+CryptoRng {
    rand_core::OsRng
}

/// Returns `OsRng` with `getrandom`, or a `CryptoRng` which panics without `getrandom`.
#[cfg(not(feature = "getrandom"))]
pub fn getrandom_or_panic() -> impl RngCore+CryptoRng {
    const PRM: &'static str = "Attempted to use functionality that requires system randomness!!";

    // Should we panic when invoked or when used?

    struct PanicRng;
    impl rand_core::RngCore for PanicRng {
        fn next_u32(&mut self) -> u32 {  panic!("{}", PRM)  }
        fn next_u64(&mut self) -> u64 {  panic!("{}", PRM)  }
        fn fill_bytes(&mut self, _dest: &mut [u8]) {  panic!("{}", PRM)  }
        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
            Err(core::num::NonZeroU32::new(core::u32::MAX).unwrap().into())
        }
    }
    impl rand_core::CryptoRng for PanicRng {}

    PanicRng
}


/// Schnorr signing transcript with the default `OsRng` replaced
/// by an arbitrary `CryptoRng`.
/// 
/// We employ this primarily for test vectors via `attach_test_vector_rng`.
/// It's also helpful if your platform lacks `getrandom`.  Yet, we cannot
/// derandomize either user supplied blinding factors in `PedersenVrf` or
/// multi-signatures, so in production this should always use system randomness.
pub struct SigningTranscriptWithRng<T,R>
where T: SigningTranscript, R: RngCore+CryptoRng
{
    t: T,
    rng: core::cell::RefCell<R>,
}

impl<ST,RNG> SigningTranscript for SigningTranscriptWithRng<ST,RNG>
where ST: SigningTranscript, RNG: RngCore+CryptoRng
{
     fn proto_name(&mut self, label: &'static [u8])
      { self.t.proto_name(label) }

    fn append<T: CanonicalSerialize+?Sized>(&mut self, label: &'static [u8], itm: &T)
      { self.t.append(label,itm) }

    // Assumes default impl for append_u64 and append_slice so might
    // not work with all user supplied SigningTranscripts

    fn challenge<T: UniformRand>(&mut self, label: &'static [u8]) -> T
      { self.t.challenge(label) }

    fn witnesses_rng<T, R, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> [T; N]
    where R: RngCore+CryptoRng, T: UniformRand
      { self.t.witnesses_rng(label,nonce_seeds,rng) }

    fn witnesses<T: UniformRand, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]]) -> [T; N] {
        self.witnesses_rng(label, nonce_seeds, &mut *self.rng.borrow_mut())
    }
}


/// Attach a `CryptoRng` to a `SigningTranscript` to replace the default `OsRng`.
///
/// We employ this primarily for test vectors via `attach_test_vector_rng`.
/// It's also helpful if your platform lacks `getrandom`.  Yet, we cannot
/// derandomize either user supplied blinding factors in `PedersenVrf` or
/// multi-signatures, so in production this should always use system randomness.
pub fn attach_rng<T,R>(t: T, rng: R) -> SigningTranscriptWithRng<T,R>
where T: SigningTranscript, R: RngCore+CryptoRng
{
    SigningTranscriptWithRng { t, rng: core::cell::RefCell::new(rng) }
}


/// Insecure in production but provides test vectors.
#[cfg(test)]
pub fn attach_test_vector_rng<T>(t: T) -> SigningTranscriptWithRng<T,impl RngCore+CryptoRng>
where T: SigningTranscript
{     
    // Very insecure hack but fine for test vectors.
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
    attach_rng(t, ZeroFakeRng)
}

