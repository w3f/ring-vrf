// -*- mode: rust; -*-
//
// Copyright (c) 2021 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Arkworks friendly Merlin transcripts

// use ark_ff::{Field};
use ark_std::{UniformRand, io::{self, Read, Write}};  // Result
use ark_serialize::{CanonicalSerialize};

use merlin::Transcript;

use rand_core::{RngCore,CryptoRng};

use std::borrow::{BorrowMut}; // Borrow


include!("inc_io.rs");


impl<T: BorrowMut<Transcript>> Write for TranscriptIO<T> {
    /// We treat a `TranscriptIO` as a Writer by appending the messages
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let b: &mut Transcript = self.t.borrow_mut();
        b.append_message(self.label, buf);
        Ok(buf.len())
    }

    /// We inherently flush in write, so this does nothing.
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<T: BorrowMut<Transcript>> Read for TranscriptIO<T> {
    /// We treat a `TranscriptIO` as a Reader by requesting challenges
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let b: &mut Transcript = self.t.borrow_mut();
        b.challenge_bytes(self.label, buf);
        Ok(buf.len())
    }
}

/// Arkworks compatable Merlin Transcripts for Chaum-Pederson DLEQ proofs 
impl super::SigningTranscript for Transcript {
    fn proto_name(&mut self, label: &'static [u8]) {
        self.append_message(b"proto-name", label);
    }

    fn append<T: CanonicalSerialize+?Sized>(&mut self, label: &'static [u8], itm: &T) {
        let mut t = TranscriptIO { label, t: self };
        itm.serialize_uncompressed(&mut t)
            .expect("merlin::Transcript infaillibly flushes");
    }

    fn challenge<T: UniformRand>(&mut self, label: &'static [u8]) -> T {
        let mut t = TranscriptIO { label, t: self };
        <T as UniformRand>::rand(&mut t)
    }

    fn witnesses<T, R, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], mut rng: R) -> [T; N]
    where  R: RngCore+CryptoRng, T: UniformRand
    {
        use arrayvec::ArrayVec;

        let mut br = self.build_rng();
        for ns in nonce_seeds {
            br = br.rekey_with_witness_bytes(label, ns);
        }
        let mut rng = br.finalize(&mut rng);

        ::core::iter::repeat_with(|| <T as UniformRand>::rand(&mut rng))
        .collect::<ArrayVec<T,{N}>>().into_inner().map_err(|_| ()).unwrap()
    }
}


