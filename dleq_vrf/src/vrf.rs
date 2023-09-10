// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### VRF input and output handling
//!
//! We caution that ring VRFs based upon DLEQ proofs like ours require
//! malleable pre-outputs, which become insecure if used in conjunction
//! with "soft key derivation" ala BIP32.

use ark_ec::{AffineRepr, CurveGroup, hashing::{HashToCurve,HashToCurveError}};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use ark_std::{borrow::BorrowMut, iter::IntoIterator, vec::Vec};

use crate::{Transcript,IntoTranscript,transcript::AsLabel,SecretKey};


use core::borrow::{Borrow}; // BorrowMut

/// Create VRF input points
///
/// You select your own hash-to-curve by implementing this trait
/// upon your own wrapper type.
/// 
/// Instead of our method being polymorphic, we impose the type parameter
/// in the trait because doing so simplifies the type annotations.
pub trait IntoVrfInput<C: AffineRepr> {
    fn into_vrf_input(self) -> VrfInput<C>;
}

impl<C: AffineRepr> IntoVrfInput<C> for VrfInput<C> {
    #[inline(always)]
    fn into_vrf_input(self) -> VrfInput<C> { self }
}

/*
impl<T: IntoTranscript,C: AffineRepr> IntoVrfInput<C> for T {
    /// Create a new VRF input from a `Transcript`.
    /// 
    /// As the arkworks hash-to-curve infrastructure looks complex,
    /// we support arkworks' simpler `UniformRand` here, which uses
    /// shitty try and increment.  We strongly recommend you construct
    /// `VrfInput`s directly using a better hash-to-curve though.
    /// 
    /// TODO: Ask Syed to use the correct hash-to-curve
    #[inline(always)]
    fn into_vrf_input(self) -> VrfInput<C> {
        let mut t = self.into_transcript();
        let t = t.borrow_mut();
        let p: <C as AffineRepr>::Group = t.challenge(b"vrf-input").read_uniform();
        VrfInput( p.into_affine() )
    }
}
*/

pub fn ark_hash_to_curve<C,H2C>(domain: impl AsLabel, message: &[u8]) -> Result<VrfInput<C>,HashToCurveError>
where C: AffineRepr, H2C: HashToCurve<<C as AffineRepr>::Group>,
{
    Ok(VrfInput( H2C::new(domain.as_label())?.hash(message)? ))
}


/// Actual VRF input, consisting of an elliptic curve point.  
///
/// Always created locally, either by hash-to-cuve or ocasionally
/// some base point, never sent over the wire nor deserialized.
/// 
/// `VrfInput` should always be consructed inside the prime order
/// subgroup, as otherwise risks leaking secret key material.
/// 
/// We do not enforce that key material be hashed in hash-to-curve,
/// so our VRF pre-outputs and signatures reveal VRF outputs for
/// algebraically related secret keys.  We need this for ring VRFs
/// but this makes insecure the soft derivations in hierarchical
/// key derivation (HDKD) schemes.
/// 
/// As a defense in depth, we suggest thin VRF usages hash their
/// public, given some broken applications might do soft derivations
/// anyways.
#[derive(Debug,Copy,Clone,CanonicalSerialize)] // CanonicalDeserialize, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
#[repr(transparent)]
pub struct VrfInput<C: AffineRepr>(pub C);

impl<K: AffineRepr> SecretKey<K> {
    /// Compute VRF pre-output from secret key and input.
    pub fn vrf_preout<H>(&self, input: &VrfInput<H>) -> VrfPreOut<H> 
    where H: AffineRepr<ScalarField = K::ScalarField>,
    {
        // VrfPreOut( (&self.key * &input.0).into_affine() )
        crate::traits::EcVrfSecret::vrf_preout(self,input)
    }

    /// Compute VRF pre-output paired with input from secret key and
    /// some VRF input, like a `Transcript` or a `VrfInput`.
    /// 
    /// As the arkworks hash-to-curve infrastructure looks complex,
    /// we employ arkworks' simpler `UniformRand` here, which uses
    /// shitty try and increment.  We strongly recommend you use a
    /// better hash-to-curve manually.
    pub fn vrf_inout<I,H>(&self, input: I) -> VrfInOut<H>
    where I: IntoVrfInput<H>, H: AffineRepr<ScalarField = K::ScalarField>,
    {
        // let input = input.into_vrf_input();
        // let preoutput = self.vrf_preout(&input);
        // VrfInOut { input, preoutput }
        crate::traits::EcVrfSecret::vrf_inout(self,input)
    }
}


/// VRF pre-output, possibly unverified.
#[derive(Debug,Copy,Clone,PartialEq,Eq,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialOrd, Ord, Hash
#[repr(transparent)]
pub struct VrfPreOut<C: AffineRepr>(pub C);

impl<C: AffineRepr> VrfPreOut<C> {
    /// Create `VrfInOut` by attaching to our pre-output the VRF input
    /// with given malleablity from the given transcript. 
    /// 
    /// As the arkworks hash-to-curve infrastructure looks complex,
    /// we employ arkworks' simpler `UniformRand` here, which uses
    /// shitty try and increment.  We strongly recommend you use a
    /// better hash-to-curve manually.
    pub fn attach_input<I: IntoVrfInput<C>>(&self, input: I) -> VrfInOut<C> {
        VrfInOut { input: input.into_vrf_input(), preoutput: self.clone() }
    }
}

pub fn attach_inputs_array<const N:usize,C,I,II>(preoutputs: &[VrfPreOut<C>; N], inputs: II) -> [VrfInOut<C>; N]
where C: AffineRepr, I: IntoVrfInput<C>, II: IntoIterator<Item=I>,
{
    preoutputs.iter().zip(inputs).map(
        |(preoutput,input)| preoutput.attach_input(input)
    ).collect::<arrayvec::ArrayVec<VrfInOut<C>,{N}>>().into_inner().unwrap()
}

pub fn collect_preoutputs_array<const N:usize,C: AffineRepr>(ios: &[VrfInOut<C>]) -> [VrfPreOut<C>; N]
{
    ios.iter().map(
        |io| io.preoutput.clone()
    ).collect::<arrayvec::ArrayVec<VrfPreOut<C>,{N}>>().into_inner().unwrap()
}

pub fn attach_inputs_vec<C,I,O,II,IO>(preoutputs: IO, inputs: II) -> Vec<VrfInOut<C>>
where
    C: AffineRepr,
    I: IntoVrfInput<C>,
    O: Borrow<VrfPreOut<C>>,
    II: IntoIterator<Item=I>,
    IO: IntoIterator<Item=O>,
{
    preoutputs.into_iter().zip(inputs).map(
        |(preout,input)| preout.borrow().attach_input(input)
    ).collect::<Vec<VrfInOut<C>>>()
}

pub fn collect_preoutputs_vec<C: AffineRepr>(ios: &[VrfInOut<C>]) -> Vec<VrfPreOut<C>>
{
    ios.iter().map(
        |io| io.preoutput.clone()
    ).collect::<Vec<VrfPreOut<C>>>()
}


/// VRF input and pre-output paired together, possibly unverified.
///
/// 
#[derive(Debug,Copy,Clone,CanonicalSerialize)] // CanonicalDeserialize, PartialEq,Eq, PartialOrd, Ord, Hash
pub struct VrfInOut<C: AffineRepr> {
    /// VRF input point
    pub input: VrfInput<C>,
    /// VRF pre-output point
    pub preoutput: VrfPreOut<C>,
}

impl<C: AffineRepr> VrfInOut<C> {
    /// Append to VRF output transcript, suitable for producing VRF output.
    /// 
    /// We incorporate both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    /// 
    /// We employ this method instead of `Transcript::append` for
    /// output, becuase this multiplies the preoutput by the cofactor.
    pub fn vrf_output_append(&self, t: &mut Transcript)
    {
        if crate::small_cofactor_affine::<C>() {
            let mut io = self.clone();
            io.preoutput.0 = io.preoutput.0.mul_by_cofactor();
            t.append(&io);
        } else {
            t.append(self);
        }
    }

    /// VRF output reader via the supplied transcript.
    /// 
    /// You should domain seperate outputs using the transcript.
    pub fn vrf_output(&self, t: impl IntoTranscript) -> crate::transcript::Reader
    {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();
        t.label(b"VrfOutput");
        self.vrf_output_append(&mut *t);
        t.challenge(b"")        
    }

    /// VRF output bytes via the supplied transcript.
    /// 
    /// You should domain seperate outputs using the transcript.
    pub fn vrf_output_bytes<const N: usize>(&self, t: impl IntoTranscript) -> [u8; N] 
    {
        self.vrf_output(t).read_byte_array()
    }
}


/// Merge VRF input and pre-output pairs from the same signer,
/// probably using variable time arithmetic
///
/// We merge VRF input and pre-outputs pairs by a single signer using
/// the same technique as the "DLEQ Proofs" and "Batching the Proofs"
/// sections of "Privacy Pass - The Math" by Alex Davidson,
/// https://new.blog.cloudflare.com/privacy-pass-the-math/#dleqproofs
/// and "Privacy Pass: Bypassing Internet Challenges Anonymously"
/// by Alex Davidson, Ian Goldberg, Nick Sullivan, George Tankersley,
/// and Filippo Valsorda.
/// https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf
///
/// As noted there, our merging technique's soundness appeals to
/// Theorem 3.17 on page 74 of Ryan Henry's PhD thesis
/// "Efficient Zero-Knowledge Proofs and Applications"
/// https://uwspace.uwaterloo.ca/bitstream/handle/10012/8621/Henry_Ryan.pdf
/// See also the attack on Peng and Bao’s batch proof protocol in
/// "Batch Proofs of Partial Knowledge" by Ryan Henry and Ian Goldberg
/// https://www.cypherpunks.ca/~iang/pubs/batchzkp-acns.pdf
///
/// We multiply every `VrfInOut` tuple here, which enables using faster
/// 128 bit scalars.  Amusingly, it turns out faster to do n 128 bit
/// scalar multiplicaitons here, rather than merge these delinearization
/// factors with the challenges used in signing and verifying.
/// 
/// ... 
/// 
/// We could reasonably ask if the VRF signer's public key or the
/// ring's merkle root should be hashed when creating the scalars in
/// `vrfs_merge*`, as Privacy Pass does.  In principle, one could
/// dicover relationships among the delinearizing scalars using
/// k-sum attacks, but not among distinct VRF inputs because they're
/// hashed to the curve.  TODO: Cite Wagner.
/// We also note no such requirement when the values being hashed are
/// BLS public keys as in https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html
pub fn vrfs_merge<C,B>(t: &mut Transcript, ps: &[B]) -> VrfInOut<C>
where
    C: AffineRepr,
    B: Borrow<VrfInOut<C>>,
{
    t.label(b"VrfInOut");
    t.append_slice(ps);
    vrfs_delinearize( t, ps.iter().map(|io| io.borrow()) )
}

/// Raw delinerazation step for merger of VRF input and pre-output
/// pairs from the same signer, probably using variable time arithmetic.
/// All pairs must be hashed into the transcript `t` before invoking,
/// as otherwise malicious signers could validate invalid pairs like
/// `[(x, (sk*a)*x, (x,(sk/a)*x)]`, breaking VRF & VUF security.
pub(crate) fn vrfs_delinearize<'a,C,I>(t: &Transcript, ps: I) -> VrfInOut<C>
where
    C: AffineRepr,
    I: Iterator<Item=&'a VrfInOut<C>>
{
    use ark_std::Zero;

    let mut i = 0;
    let mut input = <C as AffineRepr>::Group::zero();
    let mut preoutput = <C as AffineRepr>::Group::zero();
    for p in ps {
        let mut t0 = t.fork(b"delinearize");   // Keep t clean, but
        t0.append_u64(i);                        // distinguish the different outputs.
        // Sample a 128bit scalar.  RngCore::next_u64 winds up being u64::from_le_bytes here.
        let z: [u64; 2] = t0.challenge(b"128 bits").read_uniform();

        input += p.input.0.mul_bigint(z);
        preoutput += p.preoutput.0.mul_bigint(z);
        i += 1;
    }
    // TODO: Benchmark
    // let v = <C as AffineRepr>::Group::normalize_batch(&[input,preouput]);
    VrfInOut {
        input: VrfInput(input.into_affine()),
        // input: VrfInput(v[0]),
        preoutput: VrfPreOut(preoutput.into_affine()),
        // preoutput: VrfPreOut(v[1]),
    }
}


#[cfg(test)]
mod tests {
}

