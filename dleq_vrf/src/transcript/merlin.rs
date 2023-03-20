// -*- mode: rust; -*-
//
// Copyright (c) 2021 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Arkworks friendly Merlin transcripts

// use ark_ff::{Field};
use ark_std::{UniformRand, };  // Result

use merlin::Transcript;

use rand_core::{RngCore,CryptoRng};



/// Arkworks compatable Merlin Transcripts for Chaum-Pederson DLEQ proofs 
impl super::SigningTranscript for Transcript {
    fn append_bytes(&mut self, label: &'static [u8], message: &[u8]) {
        self.append_message(label,message)
    }

    /// Extract challenges samplable by Arkworks
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.challenge_bytes(label, dest)

    }

    fn witnesses_rng<T, R, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], mut rng: R) -> [T; N]
    where  R: RngCore+CryptoRng, T: UniformRand
    {
        use arrayvec::ArrayVec;

        let mut br = self.build_rng();
        for ns in nonce_seeds {
            br = br.rekey_with_witness_bytes(label, ns);
        }
        let mut rng = br.finalize(&mut rng);

        ::core::iter::repeat_with(|| <T as UniformRand>::rand(&mut rng))
        .take(N).collect::<ArrayVec<T,{N}>>()
        .into_inner().map_err(|_| ()).unwrap()
    }
}


