// -*- mode: rust; -*-
//
// Copyright (c) 2019 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Schnorr signature contexts and configuration, adaptable to most Schnorr signature schemes.

use arrayvec::{Array,ArrayVec};

use rand_core::{RngCore,CryptoRng};

use ff::Field;
use group::GroupEncoding;

use merlin::Transcript;

use digest::{FixedOutput,ExtendableOutput,XofReader}; // Input
use digest::generic_array::typenum::{U32,U64};


// === Signing context as transcript === //

/// Schnorr signing transcript
///
/// We envision signatures being on messages, but if a signature occurs
/// inside a larger protocol then the signature scheme's internal
/// transcript may exist before or persist after signing.
///
/// In this trait, we provide an interface for Schnorr signature-like
/// constructions that is compatable with `merlin::Transcript`, but
/// abstract enough to support conventional hash functions as well.
///
/// We warn however that conventional hash functions do not provide
/// strong enough domain seperation for usage via `&mut` references.
///
/// We also abstract over owned and borrowed `merlin::Transcript`s,
/// so that simple use cases do not suffer from our support for.
pub trait SigningTranscript {
    /// Extend transcript with some bytes, shadowed by `merlin::Transcript`.
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]);

    /// Extend transcript with a protocol name
    fn proto_name(&mut self, label: &'static [u8]) {
        self.commit_bytes(b"proto-name", label);
    }

    /// Extend the transcript with a compressed Ristretto point
    fn commit_point(&mut self, label: &'static [u8], point: &jubjub::ExtendedPoint)
    {
        // ZCash Foundation way: https://github.com/zkcrypto/jubjub/blob/master/src/lib.rs#L397
        // ..

        // ZCash ECC's way using zcash_primitives::jubjub and https://docs.rs/ff/0.5.2/ff/trait.PrimeField.html
        self.commit_bytes(label, &point.to_bytes());
    }

    /// Produce some challenge bytes, shadowed by `merlin::Transcript`.
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]);

    /// Produce the public challenge scalar `e`.
    fn challenge_scalar<Fs>(&mut self, label: &'static [u8]) -> Fs 
    where Fs: Field // PrimeField
    {
        // ZCash Foundation way: https://github.com/zcash-hackworks/sapling-crypto/blob/master/src/jubjub/mod.rs
        // let mut buf = [0; 64];
        // self.challenge_bytes(label, &mut buf);
        // <Fs as ::jubjub::ToUniform>::to_uniform(buf)

        // Ugly hack for crates that only generate scalars from an Rng
        use rand_core::SeedableRng;
        let mut buf = [0; 32];
        self.challenge_bytes(label, &mut buf);
        let mut rng = ::rand_chacha::ChaChaRng::from_seed(buf);

        // Zexe way: https://github.com/scipr-lab/zexe/blob/master/algebra-core/src/rand.rs
        // rng.sample(::rand::distributions::Standard)

        // ZCash ECC's way using zcash_primitives::jubjub
        // What the fuck are they thinking?
        <Fs as Field>::random(&mut rng)
    }

    /// Produce a secret witness scalar `k`, aka nonce, from the protocol
    /// transcript and any "nonce seeds" kept with the secret keys.
    fn witness_scalars<R,Fs,B>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> B 
    where  R: RngCore+CryptoRng,  Fs: Field, B: Array<Item=Fs>;
    // similar to challenge_scalar using witness_bytes

    /*  ZCash Foundation way: https://github.com/zcash-hackworks/sapling-crypto/blob/master/src/jubjub/mod.rs
    
    /// Produce a secret witness scalar `k`, aka nonce, from the protocol
    /// transcript and any "nonce seeds" kept with the secret keys.
    fn witness_scalar<R,Fs>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> Fs 
    where  R: RngCore+CryptoRng,  Fs: Field
    {
        let mut buf = [0; 64];
        self.witness_bytes(label, &mut buf, nonce_seeds);
        <Fs as ::jubjub::ToUniform>::to_uniform(buf)
    }

    /// Produce secret witness bytes from the protocol transcript
    /// and any "nonce seeds" kept with the secret keys.
    fn witness_bytes<R>(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]], rng: R)
    where R: RngCore+CryptoRng;
    */
}


/// We delegates any mutable reference to its base type, like `&mut Rng`
/// or similar to `BorrowMut<..>` do, but doing so here simplifies
/// alternative implementations.
impl<T> SigningTranscript for &mut T
where T: SigningTranscript + ?Sized,
{
    #[inline(always)]
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8])
        {  (**self).commit_bytes(label,bytes)  }
    #[inline(always)]
    fn proto_name(&mut self, label: &'static [u8])
        {  (**self).proto_name(label)  }
    #[inline(always)]
    fn commit_point(&mut self, label: &'static [u8], point: &jubjub::ExtendedPoint)
        {  (**self).commit_point(label, point)  }
    #[inline(always)]
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8])
        {  (**self).challenge_bytes(label,dest)  }
    #[inline(always)]
    fn challenge_scalar<Fs>(&mut self, label: &'static [u8]) -> Fs
    where  Fs: Field
        {  (**self).challenge_scalar(label)  }
    #[inline(always)]
    fn witness_scalars<R,Fs,B>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], rng: R) -> B 
    where  R: RngCore+CryptoRng,  Fs: Field, B: Array<Item=Fs>   // PrimeField + SqrtField + ToUniform,
        {  (**self).witness_scalars(label,nonce_seeds,rng)  }

    // #[inline(always)]
    // fn witness_bytes<R>(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]], rng: R)
    // where R: RngCore+CryptoRng
    //     {  (**self).witness_bytes(label,dest,nonce_seeds,rng)  }
}

/// We delegate `SigningTranscript` methods to the corresponding
/// inherent methods of `merlin::Transcript` and implement two
/// witness methods to avoid abrtasting the `merlin::TranscriptRng`
/// machenry.
impl SigningTranscript for Transcript {
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        Transcript::append_message(self, label, bytes)
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        Transcript::challenge_bytes(self, label, dest)
    }

    fn witness_scalars<R,Fs,B>(&self, label: &'static [u8], nonce_seeds: &[&[u8]], mut rng: R) -> B 
    where
        R: RngCore+CryptoRng,
        Fs: Field,  // PrimeField + SqrtField + ToUniform,
        B: Array<Item=Fs>
    {
        let mut br = self.build_rng();
        for ns in nonce_seeds {
            br = br.rekey_with_witness_bytes(label, ns);
        }
        let mut rng = br.finalize(&mut rng);

        // Zexe way: https://github.com/scipr-lab/zexe/blob/master/algebra-core/src/rand.rs
        // rng.sample(::rand::distributions::Standard)

        // ZCash ECC's way using zcash_primitives::jubjub
        // What the fuck are they thinking?
        ::core::iter::repeat_with(|| <Fs as ::ff::Field>::random(&mut rng))
        .collect::<ArrayVec<B>>().into_inner().unwrap()
    }

    /*
    fn witness_bytes<R>(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]], mut rng: R)
    where R: RngCore+CryptoRng
    {
        let mut br = self.build_rng();
        for ns in nonce_seeds {
            br = br.rekey_with_witness_bytes(label, ns);
        }
        let mut r = br.finalize(&mut rng);
        r.fill_bytes(dest)
    }
    */
}


/// Schnorr signing context
///
/// We expect users to have seperate `SigningContext`s for each role 
/// that signature play in their protocol.  These `SigningContext`s
/// may be global `lazy_static!`s, or perhaps constants in future.
///
/// To sign a message, apply the appropriate inherent method to create
/// a signature transcript.
///
/// You should use `merlin::Transcript`s directly if you must do
/// anything more complex, like use signatures in larger zero-knoweldge
/// protocols or sign several components but only reveal one later.
///
/// We declare these methods `#[inline(always)]` because rustc does
/// not handle large returns as efficently as one might like.
/// https://github.com/rust-random/rand/issues/817
#[derive(Clone)] // Debug
pub struct SigningContext(Transcript);

/// Initialize a signing context from a static byte string that
/// identifies the signature's role in the larger protocol.
#[inline(always)]
pub fn signing_context(context : &[u8]) -> SigningContext {
    SigningContext::new(context)
}

impl SigningContext {
    /// Initialize a signing context from a static byte string that
    /// identifies the signature's role in the larger protocol.
    #[inline(always)]
    pub fn new(context : &[u8]) -> SigningContext {
        let mut t = Transcript::new(b"SigningContext");
        t.append_message(b"",context);
        SigningContext(t)
    }

    /// Initalize an owned signing transcript on a message provided as a byte array.
    ///
    /// Avoid this method when processing large slices because it
    /// calls `merlin::Transcript::append_message` directly and
    /// `merlin` is designed for domain seperation, not performance.
    #[inline(always)]
    pub fn bytes(&self, bytes: &[u8]) -> Transcript {
        let mut t = self.0.clone();
        t.append_message(b"sign-bytes", bytes);
        t
    }

    /// Initalize an owned signing transcript on a message provided
    /// as a hash function with extensible output mode (XOF) by
    /// finalizing the hash and extracting 32 bytes from XOF.
    #[inline(always)]
    pub fn xof<D: ExtendableOutput>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32];
        h.xof_result().read(&mut prehash);
        let mut t = self.0.clone();
        t.append_message(b"sign-XoF", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 256 bit output.
    #[inline(always)]
    pub fn hash256<D: FixedOutput<OutputSize=U32>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32];
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.append_message(b"sign-256", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 512 bit output, usually a gross over kill.
    #[inline(always)]
    pub fn hash512<D: FixedOutput<OutputSize=U64>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 64];
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.append_message(b"sign-256", &prehash);
        t
    }
}

/*
/// Very simple transcript construction from a modern hash fucntion.
///
/// We provide this transcript type to directly use conventional hash
/// functions with an extensible output mode, like Shake128 and
/// Blake2x.  
///
/// We recommend using `merlin::Transcript` instead because merlin
/// provides the transcript abstraction natively and might function
/// better in low memory enviroments.  We therefore do not provide
/// conveniences like `signing_context` for this.  
///
/// We note that merlin already uses Keccak, upon which Shak128 is based,
/// and that no rust implementation for Blake2x currently exists.  
///
/// We caution that our transcript abstractions cannot provide the 
/// protections agsint hash collisions that Ed25519 provides via
/// double hashing, but that prehashed Ed25519 variants loose.
/// As such, any hash function used here must be collision resistant.
/// We strongly recommend agsint building XOFs from weaker hash
/// functions like SHA1 with HKDF constructions or similar.
///
/// In `XoFTranscript` style, we never expose the hash function `H`
/// underlying this type, so that developers cannot circument the
/// domain seperartion provided by our methods.  We do this to make
/// `&mut XoFTranscript : SigningTranscript` safe.
pub struct XoFTranscript<H>(H)
where H: Input + ExtendableOutput + Clone;

fn input_bytes<H: Input>(h: &mut H, bytes: &[u8]) {
    let l = bytes.len() as u64;
    h.input(l.to_le_bytes());
    h.input(bytes);
}

impl<H> XoFTranscript<H>
where H: Input + ExtendableOutput + Clone
{
    /// Create a `XoFTranscript` from a conventional hash functions with an extensible output mode.
    ///
    /// We intentionally consume and never reexpose the hash function
    /// provided, so that our domain seperation works correctly even
    /// when using `&mut XoFTranscript : SigningTranscript`.
    #[inline(always)]
    pub fn new(h: H) -> XoFTranscript<H> { XoFTranscript(h) }
}

impl<H> From<H> for XoFTranscript<H>
where H: Input + ExtendableOutput + Clone
{
    #[inline(always)]
    fn from(h: H) -> XoFTranscript<H> { XoFTranscript(h) }
}

impl<H> SigningTranscript for XoFTranscript<H>
where H: Input + ExtendableOutput + Clone
{
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.0.input(b"co");
        input_bytes(&mut self.0, label);
        input_bytes(&mut self.0, bytes);
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.0.input(b"ch");
        input_bytes(&mut self.0, label);
        let l = dest.len() as u64;
        self.0.input(l.to_le_bytes());
        self.0.clone().chain(b"xof").xof_result().read(dest);
    }

    fn witness_bytes<R>(&self, label: &'static [u8], dest: &mut [u8], nonce_seeds: &[&[u8]], mut rng: R)
    where R: RngCore+CryptoRng
    {
        let mut h = self.0.clone().chain(b"wb");
        input_bytes(&mut h, label);
        for ns in nonce_seeds {
            input_bytes(&mut h, ns);
        }
        let l = dest.len() as u64;
        h.input(l.to_le_bytes());

        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        h.input(&r);
        h.xof_result().read(dest);
    }
}
*/

/*
#[cfg(test)]
mod test {
    use sha3::Shake128;
    use curve25519_dalek::digest::{Input};

}
*/
