// -*- mode: rust; -*-
//
// Copyright (c) 2021 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Arkworks friendly blake3 transcripts
//!
//! We caution this blake3 usage strategy winds up suboptimial
//! due to how we maximize code overlap with merlin and the arkworks
//! trait interface.


// use ark_ff::{Field};
use ark_std::{UniformRand, io::{self, Read, Write}};  // Result
use ark_serialize::{CanonicalSerialize};

use blake3::{Hasher, OutputReader};

use rand_core::{RngCore,CryptoRng};

use std::borrow::{BorrowMut}; // Borrow


include!("inc_io.rs");


fn blake3_update_with_len(h: &mut Hasher, s: &[u8]) -> &mut Hasher {
    let l = s.len();
    if l == 0 {
        return h.update(&[0xFFu8]);
    }
    if l < 128 {
        h.update(&[s.len() as u8]);
    } else if l <= u8::MAX {
        h.update(&[0x80u8, l as u8]);
    } else if l <= u16::MAX {
        let l = u16::to_le_bytes(l as u16);
        h.update(&[0x80u8, l[0], l[1]]);
    } else if l <= u32::MAX {
        let l = u32::to_le_bytes(l as u32);
        h.update(&[0x81u8, l[0], l[1], l[2], l[3]]);
    } else { // if l <= u64::MAX {
        let l = u64::to_le_bytes(l as u64);
        h.update(&[0x82u8, l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7]]);
    }
    h.update(s)
}

fn blake3_update_labeled(h: &mut Hasher, label: &[u8], s: &[u8]) -> &mut Hasher {
    blake3_update_with_len(h, label)
    blake3_update_with_len(h, s)
}


impl<T: BorrowMut<Hasher>> Write for TranscriptIO<T> {
    /// We treat a `TranscriptIO` as a Writer by appending the messages
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        blake3_update_labeled(self.t.borrow_mut(), self.label, buf);
        Ok(buf.len())
    }

    /// We inherently flush in write, so this does nothing.
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<T: BorrowMut<Hasher>> Read for TranscriptIO<T> {
    /// We treat a `TranscriptIO` as a Reader by requesting challenges
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let h: &mut Hasher = self.t.borrow_mut();
        blake3_update_with_len(h, self.label);
        h.finalize_xof().fill(buf);
        Ok(buf.len())
    }
}


/// Arkworks compatable Merlin Transcripts for Chaum-Pederson DLEQ proofs 
impl super::SigningTranscript for Hasher {
    fn proto_name(&mut self, label: &'static [u8]) {
        blake3_update_labeled(self, b"proto-name", label);
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

        let mut br = self.clone();
        blake3_update_with_len(&mut br, label);
        for ns in nonce_seeds {
            blake3_update_with_len(&mut br, ns);
        }

        let mut randbytes = [0u8; 32];
        rng.fill_bytes(&mut randbytes);
        br.update(&randbytes);

        ::core::iter::repeat_with(|| <T as UniformRand>::rand(&mut br))
        .collect::<ArrayVec<T,{N}>>().into_inner().map_err(|_| ()).unwrap()
    }
}
