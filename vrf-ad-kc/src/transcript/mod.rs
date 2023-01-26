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
mod blake3;

#[cfg(feature = "merlin")]
mod merlin;


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
    fn witnesses<T, R, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> [T; N]
    where  R: RngCore+CryptoRng, T: UniformRand;
}

