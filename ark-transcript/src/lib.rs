// -*- mode: rust; -*-
//
// Copyright (c) 2019 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]


use ark_std::{
    UniformRand,
    borrow::{Borrow,BorrowMut},
    io::{self, Read, Write}, // Result
    vec::Vec,
};
use ark_serialize::{CanonicalSerialize};
use ark_ff::{Field,PrimeField};

use rand_core::{RngCore,CryptoRng};

pub use sha3::{Shake128};
pub use digest;
use digest::{Update,XofReader,ExtendableOutput};

#[cfg(test)]
mod tests;

#[cfg(any(test, debug_assertions))]
pub mod debug;

/// Trascript labels.
/// 
/// We prefer if labels are `&'static [u8]` but of course
/// users might require labels provided by another langauge.
pub trait AsLabel {
    fn as_label(&self) -> &[u8];
}
impl AsLabel for &'static [u8] {
    fn as_label(&self) -> &[u8] { &self[..] }
}
impl<const N: usize> AsLabel for &'static [u8; N] {
    fn as_label(&self) -> &[u8] { &self[..] }
}

/// Identify a byte slice as a label, which requires this not be
/// user controlled data.
/// 
/// We use `Borrow<[u8]>` so that `IsLabel<[u8; N]>`, `IsLabel<&[u8]>`,
/// `IsLabel<[u8]>`, etc. all work correctly.  `AsRef` would permit the
/// `IsLabel<str>`, which maybe non-cannonical and cause breakage.
#[derive(Clone,Debug)]
pub struct IsLabel<T>(pub T);
impl<T: Borrow<[u8]>> AsLabel for IsLabel<T> {
    fn as_label(&self) -> &[u8] { self.0.borrow() }
}


/// All types interpretable as `Transcript`s, including primarily
/// `impl BorrowMut<Traanscript>` types like `Transcript` and
/// `&mut Transcript`.
/// 
/// We permit `&[u8]` and `AsLabel<T>` here too, but caution that
/// `&[u8]` needs internal applicaiton domain seperation. 
pub trait IntoTranscript {
    type Taken: BorrowMut<Transcript>;
    fn into_transcript(self) -> Self::Taken;
}
impl<B: BorrowMut<Transcript>> IntoTranscript for B {
    type Taken = B;
    fn into_transcript(self) -> B { self }
}
impl<T: Borrow<[u8]>> IntoTranscript for IsLabel<T> {
    type Taken = Transcript;
    fn into_transcript(self) -> Transcript {
        Transcript::new_labeled(self)
    }
}
impl<'a> IntoTranscript for &'a [u8] {
    type Taken = Transcript;
    fn into_transcript(self) -> Transcript {
        Transcript::from_accumulation(self)
    }
}
impl<'a, const N: usize> IntoTranscript for &'a [u8; N] {
    type Taken = Transcript;
    fn into_transcript(self) -> Transcript {
        Transcript::from_accumulation(self)
    }
}

/// Inner hasher or accumulator object.
/// 
/// We make this distinction at runtime instead of at compile-time
/// for simplicity elsewhere.
#[derive(Clone)]
enum Mode {
    /// Actual Shake128 hasher being written to.
    Hash(Shake128),
    /// Accumulate bytes instead of hashing them.
    Accumulate(Vec<u8>),
}

impl Mode {
    /// Abstracts over the writing modes
    fn raw_write(&mut self, bytes: &[u8]) {
        match self {
            Mode::Hash(hasher) => hasher.update(bytes),
            Mode::Accumulate(acc) => acc.extend_from_slice(bytes),
        }
    }

    /// Switch from writing to reading
    /// 
    /// Panics if called in accumulation mode
    fn raw_reader(self) -> Reader {
        #[cfg(feature = "debug-transcript")]
        println!("Shake128 {}transcript XoF reader",self.debug_name);
        match self {
            Mode::Hash(hasher) => Reader(hasher.clone().finalize_xof()),
            Mode::Accumulate(acc) => {
                let mut t = Transcript::from_accumulation(acc);
                t.seperate();
                t.mode.raw_reader()
            }
        }
    }
}

/// Shake128 transcript style hasher.
#[derive(Clone)]
pub struct Transcript {
    /// Length writen between `seperate()` calls.  Always less than 2^31.
    /// `None` means `write` was not yet invoked, so seperate() does nothing.
    /// We need this to distinguish zero length write calls.
    length: Option<u32>,
    /// Actual Shake128 hasher being written to, or maybe an accumulator
    mode: Mode,
    /// Is this a witness transcript?
    #[cfg(feature = "debug-transcript")]
    debug_name: &'static str,
}

impl Default for Transcript {
    /// Create a fresh empty `Transcript`.
    fn default() -> Transcript {
        Transcript::new_blank()
    }
}

impl Update for Transcript {
    fn update(&mut self, bytes: &[u8]) {
        self.write_bytes(bytes);
    }
}

impl Write for Transcript {
    // Always succeed fully
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_bytes(bytes);
        Ok(bytes.len())
    }

    // Always succeed immediately
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }    
}


impl Transcript {
    /// Create a `Transcript` from `Shake128`.
    pub fn from_shake128(hasher: Shake128) -> Transcript {
        Transcript {
            length: None,
            mode: Mode::Hash(hasher),
            #[cfg(feature = "debug-transcript")]
            debug_name: "",
        } 
    }

    /// Create a `Transcript` from previously accumulated bytes.
    /// 
    /// We do not domain seperate these initial bytes, but we domain
    /// seperate everything after this, making this safe.
    pub fn from_accumulation(acc: impl AsRef<[u8]>) -> Transcript {
        let mut hasher = Shake128::default();
        hasher.update(acc.as_ref());
        Transcript::from_shake128(hasher)
    }

    /// Create an empty `Transcript`.
    pub fn new_blank() -> Transcript {
        #[cfg(feature = "debug-transcript")]
        println!("Initial Shake128 transcript..");
        Transcript::from_accumulation(&[])
    }

    /// Create a fresh `Transcript` with an initial domain label.
    /// 
    /// We implicitly have an initial zero length user data write
    /// preceeding this first label.
    pub fn new_labeled(label: impl AsLabel) -> Transcript {
        let mut t = Transcript::new_blank();
        t.label(label);
        t
    }
    
    /// Create an empty `Transcript` in bytes accumulation mode.
    /// 
    /// You cannot create `Reader`s in accumulation mode, but 
    /// `accumulator_finalize` exports the accumulated `Vec<u8>`.
    /// You could then transport this elsewhere and start a
    /// real hasher using `from_accumulation`.
    pub fn new_blank_accumulator() -> Transcript {
        #[cfg(feature = "debug-transcript")]
        println!("Initial Shake128 transcript..");
        Transcript {
            length: None,
            mode: Mode::Accumulate(Vec::new()),
            #[cfg(feature = "debug-transcript")]
            debug_name: "",
        }
    }

    /// Avoid repeated allocations by reserving additional space when in accumulation mode.
    pub fn accumulator_reserve(&mut self, additional: usize) {
        match &mut self.mode {
            Mode::Accumulate(acc) => acc.reserve(additional),
            _ => {},
        }
    }

    /// Invokes `seperate` and exports the accumulated transcript bytes,
    /// which you later pass into `Transcript::from_accumulation`.
    pub fn accumulator_finalize(mut self) -> Vec<u8> {
        self.seperate();
        match self.mode {
            Mode::Hash(_) => panic!("Attempte to accumulator_finalize a hashing Transcript"),
            Mode::Accumulate(acc) => acc,
        }
    }

    /// Write basic unlabeled domain seperator into the hasher.
    /// 
    /// Implemented by writing in big endian the number of bytes
    /// written since the previous `seperate` call, aka I2OSP(len,4)
    /// from [rfc8017](https://www.rfc-editor.org/rfc/rfc8017.txt).
    /// 
    /// We do nothing unless `write_bytes` was called previously, aka
    /// after the previous `seperate` call.  Invoking `write_bytes(b"")`
    /// before `seperate` forces seperation, aka aligns multiple code
    /// paths with convergent hashing, but in which users supply zero
    /// length inputs.
    pub fn seperate(&mut self) {
        #[cfg(feature = "debug-transcript")]
        println!("Shake128 {}transcript seperator: {}",self.debug_name, self.length);
        if let Some(l) = self.length {
            self.mode.raw_write( & l.to_be_bytes() ); 
        }
        self.length = None;
    }

    /// Write bytes into the hasher, increasing doain separator counter.
    /// 
    /// We wrap each 2^31 bytes into a seperate domain, instead of
    /// producing an error.
    pub fn write_bytes(&mut self, mut bytes: &[u8]) {
        const HIGH: u32 = 0x80000000;
        loop {
            let length = self.length.get_or_insert(0);
            let l = ark_std::cmp::min( (HIGH - 1 - *length) as usize, bytes.len() );
            #[cfg(feature = "debug-transcript")]
            match ark_std::str::from_utf8(bytes) {
                Ok(s) => {
                    println!("Shake128 {}transcript write of {} bytes: b\"{}\"", self.debug_name, l, s);
                }
                Err(_) => {
                    println!("Shake128 {}transcript write of {} bytes out of {}", self.debug_name, l, bytes.len());
                }
            }
            self.mode.raw_write( &bytes[0..l] );
            bytes = &bytes[l..];
            if bytes.len() == 0 {
                *length += u32::try_from(l).unwrap();
                return;
            }
            *length |= HIGH;
            self.seperate();
        }
    }

    /*
    /// I2OSP(len,4) from [rfc8017](https://www.rfc-editor.org/rfc/rfc8017.txt)
    /// with our own domain seperation 
    fn append_u32(&mut self, v: u32) {
        self.seperate();
        self.write_bytes(&v.to_be_bytes());
        self.seperate();
    }
    */

    /// I2OSP(len,8) from [rfc8017](https://www.rfc-editor.org/rfc/rfc8017.txt)
    /// with our own domain seperation 
    pub fn append_u64(&mut self, v: u64) {
        self.seperate();
        self.write_bytes(&v.to_be_bytes());
        self.seperate();
    }

    /// Write into the hasher items seralizable by Arkworks.
    /// 
    /// We `ensure_seperated` from any previously supplied user data,
    /// so we therfore suggest `label` be called in between `append`
    /// and `write`s of possibly empty user data.
    /// See concerns on `ensure_seperated`.
    /// 
    /// We use uncompressed serialization here for performance. 
    pub fn append<O: CanonicalSerialize+?Sized>(&mut self, itm: &O) {
        self.seperate();
        itm.serialize_uncompressed(&mut *self)
        .expect("ArkTranscript should infaillibly flushed"); 
        self.seperate();
    }
    // In concrete terms, `t.append(itm);` yields `t.ensure_seperated(); itm.serialize_uncompressed(&t);`,
    // while `t.seperate(); t.append(itm);` yields `t.seperate(); itm.serialize_uncompressed(&t);`,
    // which differ if preceeded by a `t.write(user_data);` with empty `user_data`.

    /// Write into the hasher a slice of items seralizable by Arkworks,
    /// exactly like invoking `append` repeatedly.
    pub fn append_slice<O,B>(&mut self, itms: &[B])
    where O: CanonicalSerialize+?Sized, B: Borrow<O>, 
    {
        self.seperate();
        for itm in itms.iter() {
            itm.borrow()
            .serialize_uncompressed(&mut *self)
            .expect("ArkTranscript should infaillibly flushed");
            self.seperate();
        }
    }

    /// Write domain separation label into the hasher,
    /// after first ending the previous write phase.
    pub fn label(&mut self, label: impl AsLabel) {
        self.seperate();
        self.write_bytes(label.as_label());
        self.seperate();
    }

    /// Create a challenge reader.
    /// 
    /// Invoking `self.label(label)` has the same effect upon `self`,
    /// but the reader returnned cannot be obtained by any combinataion of other methods.
    pub fn challenge(&mut self, label: impl AsLabel) -> Reader {
        #[cfg(feature = "debug-transcript")]
        println!("Shake128 {}transcript challenge",self.debug_name);
        self.label(label);
        self.write_bytes(b"challenge");
        let reader = self.mode.clone().raw_reader();
        self.seperate();
        reader
    }

    /// Forks transcript to prepare a witness reader.
    /// 
    /// We `clone` the transcript and `label` this clone, but do not
    /// touch the original.  After forking, you should write any
    /// secret seeds into the transcript, and then invoke `witness`
    /// with system randomness.
    pub fn fork(&self, label: impl AsLabel) -> Transcript {
        let mut fork = self.clone();
        #[cfg(feature = "debug-transcript")]
        {
            fork.debug_name = "witness ";
            println!("Shake128 {}transcript forked", self.debug_name);
        }
        // Invoking label forces an extra `seperate` vs `challenge`
        fork.label(label);
        fork
    }
    // In fact, `clone` alone works fine instead here, assuming you
    // correctly supply secret seeds and system randomness.
 
    /// Set the `debug_name` if you're doing anything complex, using clone, etc.
    #[cfg(feature = "debug-transcript")]
    pub fn set_debug_name(&mut self, debug_name: &'static str) {
        self.debug_name = debug_name;
    }

    // #[cfg(not(feature = "debug-transcript"))]
    // pub fn set_debug_name(&mut self, debug_name: &'static str) {
    // }

    /// Create a witness reader from a forked transcript.
    /// 
    /// We expect `rng` to be system randomness when used in production,
    /// ala `&mut rng_core::OsRng` or maybe `&mut rand::thread_rng()`,
    /// as otherwise you incur risks from any weaknesses elsewhere.
    /// 
    /// You'll need a deterministic randomness for test vectors of ourse, 
    /// ala `&mut ark_transcript::debug::TestVectorFakeRng`.
    /// We suggest implementing this choice inside your secret key type,
    /// along side whatever supplies secret seeds.
    pub fn witness(mut self, rng: &mut (impl RngCore+CryptoRng)) -> Reader {
        self.seperate();
        let mut rand = [0u8; 32];
        rng.fill_bytes(&mut rand);
        self.write_bytes(&rand);
        self.mode.raw_reader()
    }
}


/// Shake128 transcript style XoF reader, used for both 
/// Fiat-Shamir challenges and witnesses.
#[repr(transparent)]
pub struct Reader(sha3::Shake128Reader);

impl Reader {
    /// Read bytes from the transcript into the buffer.
    pub fn read_bytes(&mut self, buf: &mut [u8]) {
        XofReader::read(&mut self.0, buf);
    }

    /// Read bytes from the transcript. Always succeed fully.
    pub fn read_byte_array<const N: usize>(&mut self) -> [u8; N] {
        let mut buf = [0u8; N];
        self.read_bytes(&mut buf);
        buf
    }

    /// Sample a `T` using `ark_std:::UniformRand`
    /// 
    /// Arkworks always does rejection sampling so far, so
    /// constant-time-ness depends the object being sampled.
    pub fn read_uniform<T: UniformRand>(&mut self) -> T {
        <T as UniformRand>::rand(self)
    }

    /// Sample a prime field element using reduction mod the order from
    /// a 128 bit larger array of random bytes.
    ///
    /// Identical to the [IETF hash-to-curve draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/)
    /// except we only supports prime fields here, making this 
    /// compatable with constant-time implementation.
    pub fn read_reduce<F: PrimeField>(&mut self) -> F {
        xof_read_reduced::<F,Self>(self)
    }
}

pub fn xof_read_reduced<F: PrimeField,R: XofReader>(xof: &mut R) -> F {
    // The final output of `hash_to_field` will be an array of field
    // elements from F::BaseField, each of size `len_per_elem`.
    let len_per_base_elem = get_len_per_elem::<F, 128>();
    if len_per_base_elem > 256 {
        panic!("PrimeField larger than 1913 bits!");
    }
    // Rust *still* lacks alloca, hence this ugly hack.
    let mut alloca = [0u8; 256];
    let alloca = &mut alloca[0..len_per_base_elem];
    xof.read(alloca);
    alloca.reverse();  // Need BE for IRTF draft but Arkworks' LE is faster
    F::from_le_bytes_mod_order(&alloca)
}

/// This function computes the length in bytes that a hash function should output
/// for hashing an element of type `Field`.
/// See section 5.1 and 5.3 of the
/// [IETF hash-to-curve standardization draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/)
const fn get_len_per_elem<F: Field, const SEC_PARAM: usize>() -> usize {
    // ceil(log(p))
    let base_field_size_in_bits = F::BasePrimeField::MODULUS_BIT_SIZE as usize;
    // ceil(log(p)) + security_parameter
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + SEC_PARAM;
    // ceil( (ceil(log(p)) + security_parameter) / 8)
    let bytes_per_base_field_elem =
        ((base_field_size_with_security_padding_in_bits + 7) / 8) as u64;
    bytes_per_base_field_elem as usize
}

impl XofReader for Reader {
    fn read(&mut self, dest: &mut [u8]) {
        self.read_bytes(dest);
    }
}

/// Read bytes from the transcript. Always succeed fully.
impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_bytes(buf);
        Ok(buf.len())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.read_bytes(buf);
        Ok(())
    }
}

/// Read bytes from the transcript. Always succeed fully
impl RngCore for Reader {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.read_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.read_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.read_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
// impl<T: BorrowMut<Transcript>> CryptoRng for TranscriptIO<T> { }

