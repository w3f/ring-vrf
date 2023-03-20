// -*- mode: rust; -*-
//
// Copyright (c) 2019 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Arkworks friendly transcripts for Chaum-Pederson DLEQ proofs 

use core::borrow::Borrow;

// use ark_ff::{Field};
use ark_std::{UniformRand, io::{self, Read, Write}};  // Result
use ark_serialize::{CanonicalSerialize};

use rand_core::{RngCore,CryptoRng};


#[cfg(feature = "blake3")]
pub mod blake3;

// #[cfg(feature = "merlin")]
pub mod merlin;


/// Arkworks friendly transcripts for Chaum-Pederson DLEQ proofs
pub trait SigningTranscript: Sized {
    /// Append `u64` conveniently
    fn append_u64(&mut self, label: &'static [u8], v: u64) {
        self.append_bytes(label, &v.to_le_bytes())
    }

    fn append_bytes(&mut self, label: &'static [u8], bytes: &[u8]);

    /// Append items seralizable by Arkworks
    fn append<O: CanonicalSerialize+?Sized>(&mut self, label: &'static [u8], itm: &O) {
        let mut t = TranscriptIO { label, t: self };
        itm.serialize_uncompressed(&mut t)
            .expect("SigningTranscript should infaillibly flushed");
    }

    fn append_slice<O,B>(&mut self, label: &'static [u8], itms: &[B])
    where O: CanonicalSerialize+?Sized, B: Borrow<O>, 
    {
        for itm in itms.iter() {
            self.append(label, itm.borrow());
        }
    }

    /// Extract challenges samplable by Arkworks
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]);

    /// Extract challenges samplable by Arkworks
    fn challenge<T: UniformRand>(&mut self, label: &'static [u8]) -> T {
        let mut t = TranscriptIO { label, t: self };
        <T as UniformRand>::rand(&mut t)
    }

    /// Extract witnesses samplable by Arkworks
    fn witnesses_rng<T, R, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> [T; N]
    where  R: RngCore+CryptoRng, T: UniformRand;

    /// Extract witnesses samplable by Arkworks
    fn witnesses<T: UniformRand, const N: usize>(&self, label: &'static [u8], nonce_seeds: &[&[u8]]) -> [T; N] {
        self.witnesses_rng(label, nonce_seeds, getrandom_or_panic())
    }
}


/// Arkworks Reader & Writer used by SigningTranscript
///
/// We produce challenges in Chaum-Pederson DLEQ proofs using transcripts,
/// for which [merlin](https://merlin.cool/) provides a convenient tool.
/// Arkworks de/serializes conveniently but with compile-time length
/// information existing only locally, via its `io::{Read,Write}` traits.
/// `TranscriptIO` attaches the `label` required by merlin.
pub struct TranscriptIO<'a,T: ?Sized> {
    pub label: &'static [u8],
    pub t: &'a mut T,
}

impl<'a,T: SigningTranscript> Write for TranscriptIO<'a,T> {
    /// We treat a `TranscriptIO` as a Writer by appending the messages
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.t.append_bytes(self.label, buf);
        Ok(buf.len())
    }

    /// We inherently flush in write, so this does nothing.
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<'a,T: SigningTranscript> Read for TranscriptIO<'a,T> {
    /// We treat a `TranscriptIO` as a Reader by requesting challenges
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.t.challenge_bytes(self.label, buf);
        Ok(buf.len())
    }
}

/// Read bytes from the transcript
impl<'a,T> RngCore for TranscriptIO<'a,T> where TranscriptIO<'a,T>: Read {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.read(&mut b).expect("Infalable, qed");
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.read(&mut b).expect("Infalable, qed");
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.read(dest).expect("Infalable, qed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// impl<T: BorrowMut<Transcript>> CryptoRng for TranscriptIO<T> { }


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
    fn append_u64(&mut self, label: &'static [u8], v: u64)
      { self.append_u64(label,v) }

  fn append_bytes(&mut self, label: &'static [u8], bytes: &[u8])
      { self.t.append_bytes(label,bytes) }
  
    fn append<T: CanonicalSerialize+?Sized>(&mut self, label: &'static [u8], itm: &T)
      { self.t.append(label,itm) }

    // Assumes default impl for append_u64 and append_slice so might
    // not work with all user supplied SigningTranscripts

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8])
        { self.t.challenge_bytes(label,dest) }

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
