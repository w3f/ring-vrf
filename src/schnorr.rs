// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Non-anonymous VRF implementation with Schnorr DLEQ proof 
//!
//! We model the VRF on "Making NSEC5 Practical for DNSSEC" by
//! Dimitrios Papadopoulos, Duane Wessels, Shumon Huque, Moni Naor,
//! Jan Včelák, Leonid Rezyin, andd Sharon Goldberg.
//! https://eprint.iacr.org/2017/099.pdf
//! We note the V(X)EdDSA signature scheme by Trevor Perrin at
//! https://www.signal.org/docs/specifications/xeddsa/#vxeddsa
//! is almost identical to the NSEC5 construction.  
//! There is another even later variant at
//! https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/
//!
//! We also implement verifier side batching analogous to batched
//! verification of Schnorr signatures, but note this requires an
//! extra curve point, which enlarges the VRF proofs from 64 bytes
//! to 96 bytes.  We provide `shorten_*` methods to produce the
//! non-batchable proof from the batchable proof because doing so
//! is an inherent part of the batch verification anyways.
//! TODO: Security arguments!
//!
//! We do not provide DLEQ proofs optimized for the same signer using
//! multiple public keys because such constructions sound more the
//! domain of zero-knowledge proof libraries.


use std::io;
use core::borrow::Borrow;

use std::ops::{SubAssign, MulAssign, Mul, Add};

use rand_core::{RngCore, CryptoRng};

use merlin::Transcript;

use group::GroupEncoding;

use crate::{
    rand_hack, ReadWrite, SignatureResult, signature_error,
    SigningTranscript, Scalar,
    SecretKey, PublicKey, PublicKeyUnblinding,
    VRFInput, VRFPreOut, VRFInOut, 
    vrf::{no_extra, VRFExtraMessage},
};  // Params


/// Delta of Pederson commitments
#[derive(Debug, Clone)]
pub struct PedersenDelta {
    delta: Scalar,
    publickey: PublicKey,
}

impl ReadWrite for PedersenDelta {
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let delta = crate::read_scalar::<&mut R>(&mut reader) ?;
        let publickey = PublicKey::read(reader) ?;
        Ok(PedersenDelta { delta, publickey, })
    }

    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        crate::write_scalar::<&mut W>(&self.delta, &mut writer) ?;
        self.publickey.write(writer) ?;
        Ok(())
    }
}

/// Rough public key for verifier
/// TODO: make sealed trait
pub trait PedersenDeltaOrPublicKey {
    fn delta(&self) -> Scalar { Scalar::zero() }
    fn publickey(&self) -> &PublicKey;
}

impl<PD> PedersenDeltaOrPublicKey for PD
where PD: Borrow<PublicKey>
{
    fn publickey(&self) -> &PublicKey { self.borrow() }
}

impl PedersenDeltaOrPublicKey for PedersenDelta {
    fn delta(&self) -> Scalar { self.delta.clone() }
    fn publickey(&self) -> &PublicKey { &self.publickey }
}

/// Rough public key output by VRF signer, either the public key,
/// nothing if verifier supplied, or blinded use with the ring VRF prover.
/// TODO: make sealed trait
pub trait NewPedersenDeltaOrPublicKey : Sized+Clone {
    const BLINDED: bool = false;
    type Unblinding : Sized;
    fn new(pd: PedersenDelta, unblinding: PublicKeyUnblinding) -> (Self, Self::Unblinding);
}

impl NewPedersenDeltaOrPublicKey for () {
    type Unblinding = ();

    fn new(_pd: PedersenDelta, unblinding: PublicKeyUnblinding) -> (Self, Self::Unblinding) {
        assert!( !unblinding.is_blinded() );
        ((),())
    }
}

impl NewPedersenDeltaOrPublicKey for PublicKey {
    type Unblinding = ();

    fn new(pd: PedersenDelta, unblinding: PublicKeyUnblinding) -> (Self, Self::Unblinding) {
        assert!( !unblinding.is_blinded() );  (pd.publickey,())
    }
}

impl NewPedersenDeltaOrPublicKey for PedersenDelta {
    const BLINDED: bool = true;

    type Unblinding = PublicKeyUnblinding;

    fn new(pd: PedersenDelta, unblinding: PublicKeyUnblinding) -> (Self, Self::Unblinding) {
        assert!( unblinding.is_blinded() ); (pd,unblinding)
    }
}


/// The challenge or witness component of VRF signature,
/// for smaller or batchble signatures respectively.
pub trait NewChallengeOrWitness : Sized+Clone {
    #[allow(non_snake_case)]
    fn new(c: Scalar, R: jubjub::ExtendedPoint, Hr: jubjub::ExtendedPoint) -> Self;
}

/// Challenge for smaller non-batchable VRF signatures
#[derive(Debug, Clone)] // PartialEq, Eq // PartialOrd, Ord, Hash
pub struct Individual {
    /// Challenge
    c: Scalar,
}

impl NewChallengeOrWitness for Individual {
    #[allow(non_snake_case)]
    fn new(c: Scalar, _R: jubjub::ExtendedPoint, _Hr: jubjub::ExtendedPoint) -> Self {
        Individual { c }
    }
}

impl ReadWrite for Individual {
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        Ok(Individual { c: crate::read_scalar::<&mut R>(&mut reader) ?, })
    }

    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        crate::write_scalar::<&mut W>(&self.c, &mut writer) ?;
        Ok(())
    }
}

/// Witnesses for larger batchable VRF signatures.
#[derive(Debug, Clone)] // PartialEq, Eq // PartialOrd, Ord, Hash
#[allow(non_snake_case)]
pub struct Batchable {
    /// Our nonce R = r G to permit batching the first verification equation
    R: jubjub::ExtendedPoint,
    /// Our input hashed and raised to r to permit batching the second verification equation
    Hr: jubjub::ExtendedPoint,
}

impl NewChallengeOrWitness for Batchable {
    #[allow(non_snake_case)]
    fn new(_c: Scalar, R: jubjub::ExtendedPoint, Hr: jubjub::ExtendedPoint) -> Self {
        Batchable { R, Hr }
    }
}

impl ReadWrite for Batchable {
    #[allow(non_snake_case)]
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let R = jubjub::ExtendedPoint::from_bytes(&bytes);
        if R.is_none().into() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid 'R' encoding"));
        }
        reader.read_exact(&mut bytes)?;
        let Hr = jubjub::ExtendedPoint::from_bytes(&bytes);
        if Hr.is_none().into() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid 'Hr' encoding"));
        }
        Ok(Batchable {R: R.unwrap(), Hr: Hr.unwrap()})
    }
    // #[allow(non_snake_case)]
    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.R.to_bytes())?;
        writer.write_all(&self.Hr.to_bytes())
    }
}

impl NewChallengeOrWitness for (Individual, Batchable) {
    #[allow(non_snake_case)]
    fn new(c: Scalar, R: jubjub::ExtendedPoint, Hr: jubjub::ExtendedPoint) -> Self {
        (Individual { c }, Batchable { R, Hr })
    }
}
impl<IO: Clone,PD: Clone> VRFProof<IO,(Individual, Batchable),PD> {
#[inline(always)]
    pub fn seperate(self) -> (VRFProof<IO,Individual,PD>, VRFProof<IO,Batchable,PD>) {
        let VRFProof { io, cw, s, pd, } = self;
        (VRFProof { io: io.clone(), cw: cw.0, s, pd: pd.clone(), }, VRFProof { io, cw: cw.1, s, pd, })
    }
}


/// Short proof of correctness for associated VRF output,
/// for which no batched verification works.
#[derive(Debug, Clone)] // PartialEq, Eq // PartialOrd, Ord, Hash
#[allow(non_snake_case)]
pub struct VRFProof<P, CW, PD> {
    /// VRFPreOut or VRFInOut
    io: P,
    /// Challenge
    cw: CW,
    /// Schnorr proof
    s: Scalar,
    /// Either public key or else delta of Pederson commitments
    pd: PD,
}

impl<IO,CW,PD> VRFProof<IO,CW,PD>
where PD: PedersenDeltaOrPublicKey {
    #[inline(always)]
    pub fn publickey(&self) -> &PublicKey { self.pd.publickey().borrow() }
}

impl<IO,CW> VRFProof<IO,CW,()> {
    #[inline(always)]
    pub fn attach_publickey<B: Borrow<PublicKey>>(self, pd: B) -> VRFProof<IO,CW,B> {
        let VRFProof { io, cw, s, .. } = self;
        VRFProof { io, cw, s, pd }
    }
}

impl<IO,CW,PD> VRFProof<IO,CW,PD>
where CW: Clone, PD: Borrow<PublicKey>,
{
    #[inline(always)]
    pub fn remove_publickey(self) -> VRFProof<IO,CW,()> {
        let VRFProof { io, cw, s, .. } = self;
        VRFProof { io, cw, s, pd: () }
    }
    // pub fn check_publickey<B: Borrow<PublicKey<E>>>(self, pk: B) -> bool { pk.borrow() == &self.pd }
}

impl<IO,CW,PD> VRFProof<IO,CW,PD>
{
    #[inline(always)]
    pub fn remove_inout(self) -> VRFProof<(),CW,PD> {
        let VRFProof { cw, s, pd, .. } = self;
        VRFProof { io: (), cw, s, pd, }
    }
    #[inline(always)]
    pub fn as_inout(&self) -> &IO { &self.io }
}

impl<CW,PD> VRFProof<(),CW,PD>
{
    #[inline(always)]
    pub fn attach_inout(self, io: VRFInOut) -> VRFProof<VRFInOut,CW,PD> {
        let VRFProof { cw, s, pd, .. } = self;
        VRFProof { io, cw, s, pd, }
    }
}

impl<CW,PD> VRFProof<VRFPreOut,CW,PD>
where PD: Borrow<PublicKey>,
{
    #[inline(always)]
    pub fn attach_input_nonmalleable<T: SigningTranscript>(self, t: T) -> VRFProof<VRFInOut,CW,PD> {
        let VRFProof { io, cw, s, pd, } = self;
        let io = io.attach_input_nonmalleable(t,pd.borrow());
        VRFProof { io, cw, s, pd, }
    }
}

impl<CW> VRFProof<VRFPreOut,CW,PedersenDelta>
{
    #[inline(always)]
    pub fn attach_input_ring_malleable<T: SigningTranscript>(self, t: T, auth_root: &crate::merkle::RingRoot)
     -> VRFProof<VRFInOut,CW,PedersenDelta>
    {
        let VRFProof { io, cw, s, pd, } = self;
        let io = io.attach_input_ring_malleable(t,auth_root);
        VRFProof { io, cw, s, pd, }
    }
}

impl<IO,CW,PD> ReadWrite for VRFProof<IO,CW,PD>
where IO: ReadWrite, CW: ReadWrite, PD: ReadWrite
{
    fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let io = IO::read(&mut reader) ?;
        let cw = CW::read(&mut reader) ?;
        let s = crate::read_scalar::<&mut R>(&mut reader) ?;
        let pd = PD::read(reader) ?;
        Ok(VRFProof { io, cw, s, pd })
    }
    fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.io.write(&mut writer) ?;
        self.cw.write(&mut writer) ?;
        crate::write_scalar::<&mut W>(&self.s, &mut writer) ?;
        self.pd.write(writer) ?;
        Ok(())
    }
}


/// Short proof of correctness for associated VRF output,
/// for which no batched verification works.
pub type VRFSignature<PD> = VRFProof<VRFPreOut, Individual, PD>;


/// Longer proof of correctness for associated VRF output,
/// which supports batching.
pub type VRFSignatureBatchable<PD> = VRFProof<VRFPreOut, Batchable, PD>;


impl<PD> VRFProof<VRFInOut,Batchable,PD>
where PD: PedersenDeltaOrPublicKey+Clone
{
    /// Return the shortened `VRFProof` for retransmitting in not batched situations
    #[allow(non_snake_case)]
    pub fn shorten_dleq<T>(&self, mut t: T) -> VRFProof<VRFInOut,Individual,PD>
    where T: SigningTranscript,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"vrf:g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"vrf:h", self.io.input.as_point().into());
        t.commit_point(b"vrf:pk", &self.pd.publickey().0);

        t.commit_point(b"vrf:R=g^r", &self.cw.R);
        t.commit_point(b"vrf:h^r", &self.cw.Hr);

        t.commit_point(b"vrf:h^sk", self.io.preoutput.as_point());

        let c = t.challenge_scalar(b"prove");  // context, message, A/public_key, R=rG

        VRFProof {
            io: self.io.clone(),
            cw: Individual { c, }, 
            s: self.s,
            pd: self.pd.clone(),
        }
    }

    /// Return the shortened `VRFProof` for retransmitting in non-batched situations
    pub fn shorten_vrf<T>( &self) -> VRFProof<VRFInOut,Individual,PD> {
        let t0 = Transcript::new(b"VRF");  // We have context in t and another hear confuses batching
        self.shorten_dleq(t0)
    }
}


impl SecretKey {
    /// Produce Schnorr DLEQ proof.
    ///
    /// We assume the `VRFInOut` paramater has been computed correctly
    /// by multiplying every input point by `self.key`, like by
    /// using one of the `vrf_create_*` methods on `SecretKey`.
    /// If so, we produce a proof that this multiplication was done correctly.
    #[allow(non_snake_case)]
    pub fn dleq_proove<T,CW,PD,RNG>(&self, mut t: T, p: &VRFInOut, mut rng: RNG) // blinded: bool
     -> (VRFProof<VRFPreOut,CW,PD>, PD::Unblinding)
    where
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
        T: SigningTranscript,
        RNG: RngCore+CryptoRng,
    {
        t.proto_name(b"DLEQProof");
        // t.commit_point(b"vrf:g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"vrf:h", p.input.as_point().into());

        let mut publickey = self.to_public();
        let mut delta = Scalar::zero();
        let mut unblinding : PublicKeyUnblinding = PublicKeyUnblinding(Scalar::zero());
        if PD::BLINDED {
            // let R = crate::scalar_times_blinding_generator(&r).into();
            let [b_pk,b_R] : [Scalar;2]
              = t.witness_scalars(b"blinding\00",&[&self.nonce_seed], &mut rng);
            publickey.0 = publickey.0.add(& crate::scalar_times_blinding_generator(&b_pk));
            unblinding.0 = b_pk;
            delta = b_R;  // we subtract c * b_pk below
        }
        t.commit_point(b"vrf:pk", &publickey.0);

        // let R = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        // Compute R after adding publickey and all h.
        let [r] : [Scalar;1] = t.witness_scalars(b"proving\00",&[&self.nonce_seed], rng);
        let mut R: jubjub::ExtendedPoint = crate::scalar_times_generator(&r).into();
        if PD::BLINDED {
            // We abuse delta's mutability here
            *&mut R = R.add(& crate::scalar_times_blinding_generator(&delta));
        }
        t.commit_point(b"vrf:R=g^r", &R);

        // let Hr = (&r * p.input.as_point()).compress();
        let Hr = p.input.as_point().mul(r.clone()).into();
        t.commit_point(b"vrf:h^r", &Hr);

        // We add h^sk last to save an allocation if we ever need to hash multiple h together.
        t.commit_point(b"vrf:h^sk", p.preoutput.as_point());

        let c = t.challenge_scalar(b"prove"); // context, message, A/public_key, R=rG
        // let s = &r - &(&c * &self.key);
        let mut s = r;
        let mut tmp = self.key.clone();
        tmp.mul_assign(&c);
        s.sub_assign(&tmp);

        if PD::BLINDED {
            // let delta = b_R - c * b_pk;
            let mut tmp = unblinding.0.clone();
            tmp.mul_assign(&c);
            delta.sub_assign(&tmp);
        }

        // ::zeroize::Zeroize::zeroize(&mut r);

        let cw = CW::new(c,R,Hr);
        let io = p.preoutput.clone();
        let (pd,unblinding) = PD::new(PedersenDelta { delta, publickey, }, unblinding);
        (VRFProof { io, cw, s, pd, }, unblinding)
    }

    /// Run our Schnorr VRF on one single input, producing the output
    /// and correspodning Schnorr proof.
    /// You must extract the `VRFPreOut` from the `VRFInOut` returned.
    pub fn vrf_sign_simple<CW,PD>(&self, input: VRFInput)
     -> (VRFInOut, VRFProof<VRFPreOut,CW,PD>, PD::Unblinding)
    where
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
    {
        self.vrf_sign_first(input, no_extra())
    }

    /// Run our Schnorr VRF on one single input and an extra message 
    /// transcript, producing the output and correspodning Schnorr proof.
    /// You must extract the `VRFPreOut` from the `VRFInOut` returned.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use `vrf_sign_after_check` to gain access to
    /// the `VRFInOut` from `vrf_create_hash` first, and then avoid
    /// computing the proof whenever you do not win. 
    pub fn vrf_sign_first<T,CW,PD>(&self, input: VRFInput, extra: T)
     -> (VRFInOut, VRFProof<VRFPreOut,CW,PD>, PD::Unblinding)
    where
        T: SigningTranscript,
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
    {
        let inout = input.to_inout(self);
        let (proof, pd) = self.dleq_proove(extra, &inout, rand_hack());
        (inout, proof, pd)
    }

    /// Run our Schnorr VRF on one single input, producing the output
    /// and correspodning Schnorr proof, but only if the result first
    /// passes some check, which itself returns either a `bool` or else
    /// an `Option` of an extra message transcript.
    pub fn vrf_sign_after_check<CW,PD,F,O>(&self, input: VRFInput, check: F)
     -> Option<(VRFPreOut, VRFProof<VRFPreOut,CW,PD>, PD::Unblinding)>
    where
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
        F: FnOnce(&VRFInOut) -> O,
        O: VRFExtraMessage,
    {
        let inout = input.to_inout(self);
        let extra = check(&inout).extra() ?;
        Some(self.vrf_sign_checked(inout,extra))
    }

    /// Run our Schnorr VRF on the `VRFInOut` input-output pair,
    /// producing its output component and and correspodning Schnorr
    /// proof.
    pub fn vrf_sign_checked<T,CW,PD>(&self, inout: VRFInOut, extra: T)
     -> (VRFPreOut, VRFProof<VRFPreOut,CW,PD>, PD::Unblinding)
    where
        T: SigningTranscript,
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
    {
        let (proof, pd) = self.dleq_proove(extra, &inout, rand_hack());
        (inout.preoutput, proof, pd)
    }

    /*

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you should probably use vrf_sign_n_check to gain access to the
    /// `VRFInOut` from `vrf_create_hash` first, and then avoid computing
    /// the proof whenever you do not win. 
    pub fn vrf_sign(&self, input: VRFInput<E>)
     -> (VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)
    {
        self.vrf_sign_extra(input, Transcript::new(b"VRF"))
    }

    /// Run VRF on one single input transcript and an extra message transcript, 
    /// producing the outpus and correspodning short proof.
    pub fn vrf_sign_extra<T>(&self, input: VRFInput<E>, extra: T)
     -> (VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)
    where T: SigningTranscript,
    {
        let p = input.to_inout(self);
        let (proof, unblinding) = self.dleq_proove(extra, &p, rand_hack());
        (p, proof, unblinding)
    }

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof only if the result first passes
    /// some check.
    ///
    /// There are schemes like Ouroboros Praos in which nodes evaluate
    /// VRFs repeatedly until they win some contest.  In these case,
    /// you might use this function to short circuit computing the full
    /// proof.
    pub fn vrf_sign_after_check<F>(&self, input: VRFInput<E>, mut check: F)
     -> Option<(VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)>
    where F: FnMut(&VRFInOut<E>) -> bool,
    {
        self.vrf_sign_extra_after_check( input, |io| if check(io) { Some(Transcript::new(b"VRF")) } else { None })
    }

    /// Run VRF on one single input transcript, producing the outpus
    /// and correspodning short proof only if the result first passes
    /// some check, which itself returns an extra message transcript.
    pub fn vrf_sign_extra_after_check<T,F>(&self, input: VRFInput<E>, mut check: F)
     -> Option<(VRFInOut<E>, VRFProof<E>, VRFProofBatchable<E,PD>)>
    where T: SigningTranscript,
          F: FnMut(&VRFInOut<E>) -> Option<T>,
    {
        let p = input.to_inout(self);
        let extra = check(&p) ?;
        let (proof, unblinding) = self.dleq_proove(extra, &p, rand_hack());
        Some((p, proof, unblinding))
    }

    */

    /// Run VRF on several input transcripts, producing their outputs
    /// and a common short proof.
    ///
    /// We merge the VRF outputs using variable time arithmetic, so
    /// if even the hash of the message being signed is sensitive then
    /// you might reimplement some constant time variant.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_sign_simple<T,CW,PD,B,I>(&self, ts: I)
     -> (Box<[VRFInOut]>, VRFProof<(),CW,PD>, PD::Unblinding)
    where
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
        B: Borrow<VRFInput>,
        I: IntoIterator<Item=B>,
    {
        self.vrfs_sign_extra(ts, Transcript::new(b"VRF"))
    }

    /// Run VRF on several input transcripts and an extra message transcript,
    /// producing their outputs and a common short proof.
    ///
    /// We merge the VRF outputs using variable time arithmetic, so
    /// if even the hash of the message being signed is sensitive then
    /// you might reimplement some constant time variant.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_sign<T,I,CW,B>(&self, ts: I, extra: T)
     -> (Box<[VRFInOut]>, VRFProof<(),CW,PD>, PD::Unblinding)
    where
        T: SigningTranscript,
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
        B: Borrow<VRFInput>,
        I: IntoIterator<Item=B>,
    {
        let ps = ts.into_iter()
            .map(|t| t.to_inout(self))
            .collect::<Vec<VRFInOut<E>>>();
        let p = vrfs_merge(&ps);
        let (proof, unblinding) = self.dleq_proove(extra, &p, rand_hack());
        (ps.into_boxed_slice(), proof.remove_io(), unblinding)
    }
}


impl<PD> VRFProof<VRFInOut,Individual,PD>
where PD: PedersenDeltaOrPublicKey+Clone,
{
    /// Verify DLEQ proof that `p.preoutput = s * p.input` where `self`
    /// `s` times the basepoint.
    ///
    /// We return an enlarged `VRFProofBatchable` instead of just true,
    /// so that verifiers can forward batchable proofs.
    ///
    /// In principle, one might provide "blindly verifiable" VRFs that
    /// avoid requiring `self` here, but naively such constructions
    /// risk the same flaws as DLEQ based blind signatures, and this
    /// version exploits the slightly faster basepoint arithmetic.
    #[allow(non_snake_case)]
    pub fn dleq_verify<T>(&self, mut t: T)
     -> SignatureResult<VRFProof<VRFPreOut,Batchable,PD>>
    where
        T: SigningTranscript,
    {
        let VRFProof { io, cw: Individual { c }, s, pd } = self.clone();

        t.proto_name(b"DLEQProof");
        // t.commit_point(b"vrf:g",constants::RISTRETTO_BASEPOINT_TABLE.basepoint().compress());
        t.commit_point(b"vrf:h", io.input.as_point().into());
        t.commit_point(b"vrf:pk", &pd.publickey().0);

        // We recompute R aka u from the proof
        // let R = ( (&proof.c * &pk.0) + (&proof.s * &constants::RISTRETTO_BASEPOINT_TABLE) ).compress();
        let R: jubjub::ExtendedPoint = pd.publickey().0.mul(c)
            .add(& crate::scalar_times_generator(&s));
        let R: jubjub::ExtendedPoint = if pd.delta() == Scalar::zero() { R } else {
            R.add(& crate::scalar_times_blinding_generator(&pd.delta()))
        };
        t.commit_point(b"vrf:R=g^r", &R);

        // We also recompute h^r aka u using the proof
        // let Hr = (&proof.c * io.preoutput.as_point()) + (&proof.s * io.input.as_point().into());
        // let Hr = Hr.compress();
        let Hr = io.preoutput.as_point().clone().mul(c)
             .add(& io.input.as_point().clone().mul(s));
        t.commit_point(b"vrf:h^r", &Hr);

        // We add h^sk last to save an allocation if we ever need to hash multiple h together.
        t.commit_point(b"vrf:h^sk", io.preoutput.as_point());

        let cw = Batchable { R, Hr };
        // We need not check that h^pk lies on the curve
        if c == t.challenge_scalar(b"prove") {
            Ok(VRFProof { io: io.preoutput.clone(), cw, s, pd }) // Scalar: Copy ?!?
        } else {
            // Err(SignatureError::EquationFalse)
            Err( signature_error("VRF signature validation failed") )
        }
    }

    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn vrf_verify_simple(&self)
     -> SignatureResult<(VRFInOut,VRFProof<VRFPreOut,Batchable,PD>)>
    {
        self.vrf_verify(no_extra())
    }

    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn vrf_verify<T>(&self, extra: T)
     -> SignatureResult<(VRFInOut,VRFProof<VRFPreOut,Batchable,PD>)>
    where T: SigningTranscript,
    {
        let pb = self.dleq_verify(extra) ?;
        Ok((self.io.clone(),pb))
    }

    /// Verify a common VRF short proof for several input transcripts and corresponding outputs.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_verify_simple<T,O>(
        &self,
        inouts: &[O],
        proof: &VRFProof<PD>,
    ) -> SignatureResult<VRFProof<(),Batchable,PD>>
    where
        T: VRFSigningTranscript,
        O: Borrow<VRFInOut>,
    {
        self.vrfs_verify(inouts, proof, no_extra())
    }
}

impl<PD> VRFProof<(),Batchable,PD>
where PD: PedersenDeltaOrPublicKey+Clone,
{
    /// Verify a common VRF short proof for several input transcripts and corresponding outputs.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_verify<T,O>(
        &self,
        inouts: &[O],
        extra: T,
    ) -> SignatureResult<VRFProof<(),Batchable,PD>>
    where
        T: SigningTranscript,
        O: Borrow<VRFInOut>,
    {
        let p = self.vrfs_merge(&ps[..]);
        let proof_batchable = self.clone().attach_inout(p).dleq_verify(extra) ?;
        Ok( proof_batchable.remove_inout() )
    }    
}


/*
/// Batch verify DLEQ proofs where the public keys were held by
/// different parties.
///
/// We first reconstruct the `c`s present in the `VRFProof`s but absent
/// in the `VRFProofBatchable`s, using `shorten_dleq`.  We then verify
/// the `R` and `Hr` components of the `VRFProofBatchable`s using the
/// two equations a normal verification uses to discover them.
/// We do this by delinearizing both verification equations with
/// random numbers.
///
/// TODO: Assess when the two verification equations should be
/// combined, presumably by benchmarking both forms.  At smaller batch
/// sizes then we should clearly benefit form the combined form, but
/// bany combination doubles the scalar by scalar multiplicications
/// and hashing, so large enough batch verifications should favor two
/// seperate calls.
#[cfg(any(feature = "alloc", feature = "std"))]
#[allow(non_snake_case)]
pub fn vrf_verify_batch(
    inouts: &[VRFInOut<E>],
    proofs: &[VRFProofBatchable<E,PD>],
    public_keys: &[PublicKey<E>],
) -> SignatureResult<()> 
{
    const ASSERT_MESSAGE: &'static str = "The number of messages/transcripts / input points, output points, proofs, and public keys must be equal.";
    assert!(inouts.len() == proofs.len(), ASSERT_MESSAGE);
    assert!(proofs.len() == public_keys.len(), ASSERT_MESSAGE);

    // Use a random number generator keyed by the public keys, the
    // inout and output points, and the system randomn number gnerator.
    // TODO: Use proofs too?
    let mut csprng = {
        let mut t = Transcript::new(b"VB-RNG");
        for (pk,p) in public_keys.iter().zip(inouts) {
            t.commit_point(b"",&pk.0);
            p.commit(&mut t);
        }
        t.build_rng().finalize(&mut rand_hack())
    };

    // Select a random 128-bit scalar for each signature.
    // We may represent these as scalars because we use
    // variable time 256 bit multiplication below.
    let rnd_128bit_scalar = |_| {
        let mut r = [0u8; 16];
        csprng.fill_bytes(&mut r);
        let z: Scalar = crate::scalar::scalar_from_u128::<E>(r);
    };
    let zz: Vec<Scalar> = proofs.iter().map(rnd_128bit_scalar).collect();

    let z_s: Vec<Scalar> = zz.iter().zip(proofs)
        .map(|(z, proof)| z * proof.s)
        .collect();

    // Compute the basepoint coefficient, ∑ s[i] z[i] (mod l)
    let B_coefficient: Scalar = z_s.iter().sum();

    // TODO: Support extra messages and DLEQ proofs by handling this differently.
    let t0 = Transcript::new(b"VRF");
    let z_c: Vec<Scalar> = zz.iter().enumerate()
        .map( |(i, z)| z * proofs[i].shorten_dleq(t0.clone(), &public_keys[i], &ps[i]).c )
        .collect();

    // Compute (∑ z[i] s[i] (mod l)) B + ∑ (z[i] c[i] (mod l)) A[i] - ∑ z[i] R[i] = 0
    let mut b = RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c.iter().cloned())
            .chain(once(B_coefficient)),
        proofs.iter().map(|proof| proof.R.decompress())
            .chain(public_keys.iter().map(|pk| Some(*pk.as_point())))
            .chain(once(Some(constants::RISTRETTO_BASEPOINT_POINT))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    // Compute (∑ z[i] s[i] (mod l)) Input[i] + ∑ (z[i] c[i] (mod l)) Output[i] - ∑ z[i] Hr[i] = 0
    b &= RistrettoPoint::optional_multiscalar_mul(
        zz.iter().map(|z| -z)
            .chain(z_c)
            .chain(z_s),
        proofs.iter().map(|proof| proof.Hr.decompress())
            .chain(inouts.iter().map(|p| Some(*p.preoutput.as_point())))
            .chain(inouts.iter().map(|p| Some(*p.input.as_point()))),
    ).map(|id| id.is_identity()).unwrap_or(false);

    if b { Ok(()) } else {
        // Err(SignatureError::EquationFalse) 
        Err( signature_error("VRF signature validation failed") )
    }
}
*/

/*
/// Batch verify VRFs by different signers
///
///
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn vrf_verify_batch(
    inouts: &[VRFInOut<E>],
    proofs: &[VRFProofBatchable<E,PD>],
    publickeys: &[PublicKey<E>],
) -> SignatureResult<()>
{
    let mut ts = transcripts.into_iter();
    let ps = ts.by_ref()
        .zip(publickeys)
        .zip(outs)
        .map(|((t, pk), out)| out.attach_input_hash(pk,t))
        .collect::<SignatureResult<Vec<VRFInOut<E>>>>() ?;
    assert!(ts.next().is_none(), "Too few VRF pre-outputs for VRF inputs.");
    assert!(
        ps.len() == outs.len(),
        "Too few VRF inputs for VRF pre-outputs."
    );
    if dleq_verify_batch(&ps[..], proofs, publickeys).is_ok() {
        Ok(ps.into_boxed_slice())
    } else {
        Err(SignatureError::EquationFalse)
    }
}
*/


#[cfg(test)]
mod tests {
    /*
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use std::vec::Vec;
    */

    use crate::*;

    #[test]
    fn vrf_single() {
        // #[cfg(feature = "getrandom")]
        let mut csprng = ::rand_core::OsRng;

        let sk1 = SecretKey::from_rng(&mut csprng);

        let ctx = signing_context(b"yo!");
        let input1 = VRFInput::new_nonmalleable(ctx.bytes(b"meow"),&sk1.to_public());

        let (io1, proof1, ()) = sk1.vrf_sign_simple::<_,PublicKey>(input1.clone());
        let (proof1, _proof1batchable) = proof1.remove_publickey().seperate();
        let sk2 = SecretKey::from_rng(&mut csprng);
        let proof1bad = proof1.clone().attach_publickey(sk2.to_public());
        let proof1 = proof1.attach_publickey(sk1.to_public());
        /*
        TODO: Fix zcash's crapy lack of traits
        assert_eq!(
            proof1,
            proof1batchable
                .shorten_vrf(&sk1.public, &io1)
            "Oops `shorten_vrf` failed"
        );
        */
        let proof1too = proof1.clone().attach_input_nonmalleable(ctx.bytes(b"meow")).vrf_verify_simple()
            .expect("Correct VRF verification failed!");
        let io1v = io1.preoutput.attach_input_nonmalleable(ctx.bytes(b"meow"),&sk1.to_public());
        let proof1 = proof1.remove_inout().attach_inout(io1v.clone());
        let proof1tooo = proof1.vrf_verify_simple()
            .expect("Correct VRF verification failed!");
        /*
        TODO: Fix zcash's crapy lack of traits
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        */
        assert_eq!(
            sk1.vrf_sign_simple::<super::Individual,()>(input1).0.make_bytes::<[u8;16]>(b""),
            io1.make_bytes::<[u8;16]>(b""),
            "Rerunning VRF gave different pre-output"
        );

        let io2v = io1.preoutput.attach_input_nonmalleable(ctx.bytes(b"woof"),&sk1.to_public());
        let proof1 = proof1.remove_inout().attach_inout(io2v);
        assert!(
            proof1.vrf_verify_simple().is_err(),
            "VRF verification with incorrect message passed!"
        );
        assert!(
            proof1bad.attach_input_nonmalleable(ctx.bytes(b"meow"))
            .vrf_verify_simple().is_err(),
            "VRF verification with incorrect signer passed!"
        );
    }

    /*
    #[test]
    fn vrf_malleable() {
        // #[cfg(feature = "getrandom")]
        let mut csprng = ::rand_core::OsRng;

        let sk1 = SecretKey::<Bls12>::from_rng(&mut rng);

        let ctx = signing_context(b"yo!");
        let msg = b"meow";
        let input1 = VRFInput::new_malleable(ctx.bytes(msg));
        
        let (io1, proof1, proof1batchable) = sk1.vrf_sign_first(Malleable(ctx.bytes(msg)));
        let out1 = &io1.to_preout();
        assert_eq!(
            proof1,
            proof1batchable.shorten_vrf(&sk1.public, Malleable(ctx.bytes(msg)), &out1).unwrap(),
            "Oops `shorten_vrf` failed"
        );
        let (io1too, proof1too) = sk1
            .public.vrf_verify(Malleable(ctx.bytes(msg)), &out1, &proof1)
            .expect("Correct VRF verification failed!");
        assert_eq!(
            io1too, io1,
            "Output differs between signing and verification!"
        );
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        assert_eq!(
            sk1.vrf_sign_first(Malleable(ctx.bytes(msg))).0,
            io1,
            "Rerunning VRF gave different output"
        );
        assert!(
            sk1.public.vrf_verify(Malleable(ctx.bytes(b"not meow")), &out1, &proof1).is_err(),
            "VRF verification with incorrect message passed!"
        );

        let sk2 = SecretKey::<Bls12>::from_rng(&mut rng, &params.engine);
        assert!(
            sk2.public.vrf_verify(Malleable(ctx.bytes(msg)), &out1, &proof1).is_err(),
            "VRF verification with incorrect signer passed!"
        );
        let (io2, _proof2, _proof2batchable) = sk2.vrf_sign_first(Malleable(ctx.bytes(msg)));
        let out2 = &io2.to_preout();

        // Verified key exchange, aka sequential two party VRF.
        let t0 = Transcript::new(b"VRF");
        let io21 = sk2.secret.vrf_create_from_compressed_point(out1).unwrap();
        let proofs21 = sk2.dleq_proove(t0.clone(), &io21);
        let io12 = sk1.secret.vrf_create_from_compressed_point(out2).unwrap();
        let proofs12 = sk1.dleq_proove(t0.clone(), &io12);
        assert_eq!(io12.preoutput, io21.preoutput, "Sequential two-party VRF failed");
        assert_eq!(
            proofs21.0,
            proofs21.1.shorten_dleq(t0.clone(), &sk2.public, &io21),
            "Oops `shorten_dleq` failed"
        );
        assert_eq!(
            proofs12.0,
            proofs12.1.shorten_dleq(t0.clone(), &sk1.public, &io12),
            "Oops `shorten_dleq` failed"
        );
        assert!(sk1
            .public
            .dleq_verify(t0.clone(), &io12, &proofs12.0)
            .is_ok());
        assert!(sk2
            .public
            .dleq_verify(t0.clone(), &io21, &proofs21.0)
            .is_ok());
    }
    */

    /*
    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn vrfs_merged_and_batched() {
        let mut csprng = ::rand_core::OsRng;
        let keypairs: Vec<Keypair> = (0..4)
            .map(|_| Keypair::generate_with(&mut csprng))
            .collect();

        let ctx = signing_context(b"yo!");
        let messages: [&[u8; 4]; 2] = [b"meow", b"woof"];
        let ts = || messages.iter().map(|m| ctx.bytes(*m));

        let ios_n_proofs = keypairs.iter().map(|k| k.vrfs_sign(ts())).collect::<Vec<(
            Box<[VRFInOut<E>]>,
            VRFProof,
            VRFProofBatchable,
        )>>();

        for (k, (ios, proof, proof_batchable)) in keypairs.iter().zip(&ios_n_proofs) {
            let outs = ios
                .iter()
                .map(|io| io.to_preout())
                .collect::<Vec<VRFPreOut>>();
            let (ios_too, proof_too) = k
                .public
                .vrfs_verify(ts(), &outs, &proof)
                .expect("Valid VRF output verification failed!");
            assert_eq!(
                ios_too, *ios,
                "Output differs between signing and verification!"
            );
            assert_eq!(
                proof_too, *proof_batchable,
                "Returning batchable proof failed!"
            );
        }
        for (k, (ios, proof, _proof_batchable)) in keypairs.iter().zip(&ios_n_proofs) {
            let outs = ios.iter()
                .rev()
                .map(|io| io.to_preout())
                .collect::<Vec<VRFPreOut<_>>>();
            assert!(
                k.public.vrfs_verify(ts(), &outs, &proof).is_err(),
                "Incorrect VRF output verification passed!"
            );
        }
        for (k, (ios, proof, _proof_batchable)) in keypairs.iter().rev().zip(&ios_n_proofs) {
            let outs = ios.iter()
                .map(|io| io.to_preout())
                .collect::<Vec<VRFPreOut<_>>>();
            assert!(
                k.public.vrfs_verify(ts(), &outs, &proof).is_err(),
                "VRF output verification by a different signer passed!"
            );
        }

        let mut ios = keypairs.iter().enumerate()
            .map(|(i, keypair)| keypair.public.vrfs_merge(&ios_n_proofs[i].0,true))
            .collect::<Vec<VRFInOut<_>>>();

        let mut proofs = ios_n_proofs.iter()
            .map(|(_ios, _proof, proof_batchable)| proof_batchable.clone())
            .collect::<Vec<VRFProofBatchable<_>>>();

        let mut public_keys = keypairs.iter()
            .map(|keypair| keypair.public.clone())
            .collect::<Vec<PublicKey<_>>>();

        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_ok(),
            "Batch verification failed!"
        );
        proofs.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect proofs passed!"
        );
        proofs.reverse();
        public_keys.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect public keys passed!"
        );
        public_keys.reverse();
        ios.reverse();
        assert!(
            dleq_verify_batch(&ios, &proofs, &public_keys).is_err(),
            "Batch verification with incorrect points passed!"
        );
    }
    */
}

