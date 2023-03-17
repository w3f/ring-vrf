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
        self.witnesses_rng(label, nonce_seeds, crate::rand_hack())
    }
}

// Insecure transcript with zeros replacing system randomness,
// useful only for test vectors.
#[cfg(test)]
pub struct TestVectorTranscript<ST: SigningTranscript>(pub ST);

#[cfg(test)]
impl<ST: SigningTranscript> SigningTranscript for TestVectorTranscript<ST>
{
     fn proto_name(&mut self, label: &'static [u8])
      { self.0.proto_name(label) }

    fn append<T: CanonicalSerialize+?Sized>(&mut self, label: &'static [u8], itm: &T)
      { self.0.append(label,itm) }

    // Assumes default impl for append_u64 and append_slice so might
    // not work with all user supplied SigningTranscripts

    fn challenge<T: UniformRand>(&mut self, label: &'static [u8]) -> T
      { self.0.challenge(label) }

    fn witnesses_rng<T, R, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> [T; N]
    where  R: RngCore+CryptoRng, T: UniformRand
      { self.0.witnesses_rng(label,nonce_seeds,rng) }

    fn witnesses<T: UniformRand, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]]) -> [T; N] {
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

        self.witnesses_rng(label, nonce_seeds, ZeroFakeRng)
    }
}
