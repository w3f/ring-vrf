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
    rand_hack, ReadWrite, SignatureResult,
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


// At present, we create public key blinding factors inside `dleq_prove`,
// which hedges agsint poor randomness by hashing the transcript when
// creating the blinding factor.  As a result, we return the unblinding
// factor from `dleq_prove`, which creates an unusual interface in which
// returns define behavior.  Interestingly, only the public key blinding
// being secret binds the SNARK to the specific DLEQ proof. 
// 
// We explored a trait `MakePedersenDeltaOrPublicKey` similar to
// our `NewPedersenDeltaOrPublicKey` but with an associated type for
// `PublicKey` or `PedersenDelta` as well as both
// `impl MakePedersenDeltaOrPublicKey for () { .. }` and
// `impl MakePedersenDeltaOrPublicKey for PublicKeyUnblinding { .. }`.
//
// In this way, we could pass an argument containing the public key
// blinding factor into `dleq_prove`, so that either the our gapped
// signer aka HSM or the SNARK prover produces blinding factors.
// We dislike this primarily because it expands the interface surface
// with functions for blinding factors.
//
// We foresee three plausible advantages to this argument form however:
// Frist, we envision this improves robustness against leaked the public
// key blindings, such as by improperly written cloud signers.
// Second, it reduces latency if the gapped signer runs in a parallel with
// the SNARK prover, although this sounds pointless in sassafras where
// gapped signers choose how many unlinkable VRF signatures they produce.
// Third, the gapped signer only returns data which one safely outputs,
// retducing miss-use opertunities.  
//
// As advanced users often require `dleq_prove` directly, we select the
// return based interface that imposes a smaller surface and simplifies
// hard initial protocol development work.  We view gapped signers and
// HSMs as a niche longer term concern, and cloud signers remain innane.  


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
    fn new(_pd: PedersenDelta, unblinding: PublicKeyUnblinding) -> (Self, Self::Unblinding)
        {  assert!( !unblinding.is_blinded() );  ((),())  }
}
impl NewPedersenDeltaOrPublicKey for PublicKey {
    type Unblinding = ();
    fn new(pd: PedersenDelta, unblinding: PublicKeyUnblinding) -> (Self, Self::Unblinding)
        {  assert!( !unblinding.is_blinded() );  (pd.publickey,())  }
}
impl NewPedersenDeltaOrPublicKey for PedersenDelta {
    const BLINDED: bool = true;
    type Unblinding = PublicKeyUnblinding;
    fn new(pd: PedersenDelta, unblinding: PublicKeyUnblinding) -> (Self, Self::Unblinding)
        {  assert!( unblinding.is_blinded() );  (pd,unblinding)  }
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
    /// Either public key or else delta of Pederson commitments, and later also the RingVRFProof
    pub(crate) pd: PD,
}

impl<IO,CW,PD> VRFProof<IO,CW,PD>
where PD: PedersenDeltaOrPublicKey {
    #[inline(always)]
    pub fn publickey(&self) -> &PublicKey { self.pd.publickey().borrow() }
}

impl<IO,CW,PD> VRFProof<IO,CW,PD> {
    #[inline(always)]
    pub(crate) fn alter_pd<N,F: FnOnce(PD) -> N>(self, f: F) -> VRFProof<IO,CW,N> {
        let VRFProof { io, cw, s, pd } = self;
        let pd = f(pd);
        VRFProof { io, cw, s, pd }
    }
}

impl<IO,CW> VRFProof<IO,CW,()> {
    #[inline(always)]
    pub fn attach_publickey<B: Borrow<PublicKey>>(self, pd: B) -> VRFProof<IO,CW,B> {
        self.alter_pd(|_| pd)
    }
}

impl<IO,CW,PD> VRFProof<IO,CW,PD>
where CW: Clone, PD: Borrow<PublicKey>,
{
    #[inline(always)]
    pub fn remove_publickey(self) -> VRFProof<IO,CW,()> {
        self.alter_pd(|_| ())
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
    pub fn attach_input<T: SigningTranscript>(self, t: T) -> VRFProof<VRFInOut,CW,PD> {
        let VRFProof { io, cw, s, pd, } = self;
        let io = io.attach_input(pd.borrow(),t);
        VRFProof { io, cw, s, pd, }
    }
}

impl<CW> VRFProof<VRFPreOut,CW,PedersenDelta> {
    #[inline(always)]
    pub fn attach_input<T: SigningTranscript>(self, t: T, auth_root: &crate::merkle::RingRoot)
     -> VRFProof<VRFInOut,CW,PedersenDelta>
    {
        let VRFProof { io, cw, s, pd, } = self;
        let io = io.attach_input(auth_root,t);
        VRFProof { io, cw, s, pd, }
    }
}

impl<CW,PD> VRFProof<VRFPreOut,CW,PD> {
    #[inline(always)]
    pub fn attach_input_malleable<T: SigningTranscript>(self, t: T, auth_root: &crate::merkle::RingRoot)
     -> VRFProof<VRFInOut,CW,PD>
    {
        let VRFProof { io, cw, s, pd, } = self;
        let io = io.attach_input(&crate::vrf::Malleable,t);
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

    /*
    /// Return the shortened `VRFProof` for retransmitting in non-batched situations
    pub fn shorten_vrf<T>( &self) -> VRFProof<VRFInOut,Individual,PD> {
        let t0 = Transcript::new(b"VRF");  // We have context in t and another hear confuses batching
        self.shorten_dleq(t0)
    }
    */
}


impl SecretKey {
    /// Produce Schnorr DLEQ proof.
    ///
    /// We assume the `VRFInOut` paramater has been computed correctly
    /// by multiplying every input point by `self.key`, like by
    /// using one of the `vrf_create_*` methods on `SecretKey`.
    /// If so, we produce a proof that this multiplication was done correctly.
    #[allow(non_snake_case)]
    pub fn dleq_proove<T,CW,PD,RNG>(&self, p: &VRFInOut, mut t: T, mut rng: RNG)
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
        // Include the real publickey when creating nonces, so nearer the transcript being done.
        let [b_pk,b_R,r] : [Scalar;3] =
            t.witness_scalars(b"proving\00",&[&self.nonce_seed,&publickey.0.to_bytes()], &mut rng);

        let b_pk = PublicKeyUnblinding(
            if PD::BLINDED {
                publickey.0 = publickey.0.add(& crate::scalar_times_blinding_generator(&b_pk));
                b_pk
            } else { Scalar::zero() }
        );
        t.commit_point(b"vrf:pk", &publickey.0);

        let mut R: jubjub::ExtendedPoint = crate::scalar_times_generator(&r).into();
        if PD::BLINDED {
            // We abuse delta's mutability here
            *&mut R = R.add(& crate::scalar_times_blinding_generator(&b_R));
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

        // let delta = b_R - c * b_pk;
        let mut delta = b_R;
        if PD::BLINDED {
            let mut tmp = b_pk.0.clone();
            tmp.mul_assign(&c);
            delta.sub_assign(&tmp);
        }
        let (pd,unblinding) = PD::new(PedersenDelta { delta, publickey, }, b_pk);

        // ::zeroize::Zeroize::zeroize(&mut r);

        let cw = CW::new(c,R,Hr);
        let io = p.preoutput.clone();
        (VRFProof { io, cw, s, pd, }, unblinding)
    }

    /// Irrefutable non-anonyimized/non-ring Schnorr VRF signature.
    /// 
    /// Returns first the `VRFInOut` from which output can be extracted,
    /// and second the VRF signature.
    pub fn vrf_sign_unchecked<TI,TE>(&self, input: TI, extra: TE)
     -> (VRFInOut, VRFProof<VRFPreOut,Individual,PublicKey>)
    where
        TI: SigningTranscript,
        TE: SigningTranscript,
        // CW: NewChallengeOrWitness,
    {
        use crate::vrf::VRFMalleability;
        let inout = self.as_publickey().vrf_input(input).to_inout(self);
        let (proof, _) = self.dleq_proove(&inout, extra, rand_hack());
        (inout, proof)
        // let mut inout = None;
        // let proof = vrf_sign_after_check(input, |io| { inout = io; Some(extra) })
        // (inout.unwrap(), proof)
    }

    /// Refutable non-anonyimized/non-ring Schnorr VRF signature.
    ///
    /// We check whether an output warrants producing a proof using the
    /// closure provided, which itself returns either a `bool` or else
    /// an `Option` of an extra message transcript.
    pub fn vrf_sign_after_check<T,F,O>(&self, input: T, check: F)
     -> Option<VRFProof<VRFPreOut,Individual,PublicKey>>
    where
        T: SigningTranscript,
        // CW: NewChallengeOrWitness,
        F: FnOnce(&VRFInOut) -> O,
        O: VRFExtraMessage,
    {
        use crate::vrf::VRFMalleability;
        let inout = self.as_publickey().vrf_input(input).to_inout(self);
        let extra = check(&inout).extra() ?;
        Some(self.dleq_proove(&inout,extra,rand_hack()).0)
    }

    /// Run VRF on several input transcripts and an extra message transcript,
    /// producing their outputs and a common short proof.
    ///
    /// We merge the VRF outputs using variable time arithmetic, so
    /// if even the hash of the message being signed is sensitive then
    /// you might reimplement some constant time variant.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn dleqs_prove<T,I,CW,B>(&self, inouts: I, extra: T)
     -> (Box<[VRFInOut]>, VRFProof<(),CW,PD>, PD::Unblinding)
    where
        T: SigningTranscript,
        CW: NewChallengeOrWitness,
        PD: NewPedersenDeltaOrPublicKey,
        B: Borrow<VRFInput>,
        I: IntoIterator<Item=B>,
    {
        let ps = inouts.into_iter().collect::<Vec<VRFInOut>>();
        let p = vrfs_merge(&ps);
        let (proof, unblinding) = self.dleq_proove(&p, extra, rand_hack());
        (ps.into_boxed_slice(), proof.remove_io(), unblinding)
    }
}


impl<PD> VRFProof<VRFInOut,Individual,PD>
where PD: PedersenDeltaOrPublicKey,  // +Clone
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
    pub fn dleq_verify<T>(self, mut t: T)
     -> SignatureResult<VRFProof<VRFPreOut,Batchable,PD>>
    where
        T: SigningTranscript,
    {
        let VRFProof { io, cw: Individual { c }, s, pd } = self;  // <VRFProof<_,_,_> as Clone>::clone(self);

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
        if c == t.challenge_scalar::<Scalar>(b"prove") {
            Ok(VRFProof { io: io.preoutput.clone(), cw, s, pd }) // Scalar: Copy ?!?
        } else {
            // Err(SignatureError::EquationFalse)
            Err( crate::SignatureError::VRFProofInvalid )
        }
    }
}

impl<PD> VRFProof<VRFPreOut,Individual,PD>
where PD: Borrow<PublicKey>, // +Clone
{
    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn vrf_verify<TI,TE>(self, input: TI, extra: TE)
     -> SignatureResult<(VRFInOut,VRFProof<VRFPreOut,Batchable,PD>)>
    where
        TI: SigningTranscript,
        TE: SigningTranscript,
    {
        let proof = self.attach_input(input);
        let io = proof.io.clone();
        let pb = proof.dleq_verify(extra) ?;
        Ok((io,pb))
    }
}


/// TODO!  UNPACK AND CHECK RING !!!  ANOTHER MODULE
impl VRFProof<VRFPreOut,Individual,PedersenDelta> {
    /// Verify VRF proof for one single input transcript and corresponding output.
    pub fn inner_ring_vrf_verify<TI,TE>(self, input: TI, extra: TE, auth_root: &crate::merkle::RingRoot)
     -> SignatureResult<(VRFInOut,VRFProof<VRFPreOut,Batchable,PedersenDelta>)>
    where
        TI: SigningTranscript,
        TE: SigningTranscript,
    {
        let proof = self.attach_input(input,auth_root);
        let io = proof.io.clone();
        let pb = proof.dleq_verify(extra) ?;
        Ok((io,pb))
    }
}

impl<PD> VRFProof<(),Batchable,PD>
where PD: PedersenDeltaOrPublicKey+Clone,
{
    /// Verify a common VRF short proof for several input transcripts and corresponding outputs.
    #[cfg(any(feature = "alloc", feature = "std"))]
    pub fn vrfs_verify_checked<T,O>(
        &self,
        inouts: &[O],
        extra: T,
    ) -> SignatureResult<()>
    where
        T: SigningTranscript,
        O: Borrow<VRFInOut>,
    {
        let p = self.vrfs_merge(&ps[..]);
        let _ = self.clone().attach_inout(p).dleq_verify(extra) ?;
        Ok(())
    }
}



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
        let ctx = signing_context(b"yo!");

        // #[cfg(feature = "getrandom")]
        let mut csprng = ::rand_core::OsRng;

        let input1 = ctx.bytes(b"meow");
        let input2 = ctx.bytes(b"woof");
        let sk1 = SecretKey::from_rng(&mut csprng);

        let (io1,sig1) = sk1.vrf_sign_unchecked(input1.clone(), no_extra());
        assert!( sig1.clone().vrf_verify(input1.clone(), no_extra()).is_ok() );
        assert!( sig1.clone().vrf_verify(input2.clone(), no_extra()).unwrap_err().is_invalid_proof() );
        assert!( sig1.clone().vrf_verify(input1.clone(), input1.clone()).unwrap_err().is_invalid_proof() );

        assert_ne!(
            io1.make_bytes::<[u8;16]>(b""),
            sk1.vrf_sign_unchecked(input2.clone(), no_extra()).0.make_bytes::<[u8;16]>(b""),
            "VRF input ignored"
        );

        let sig2 = sk1.vrf_sign_after_check(input1.clone(), |io2| {
            assert_eq!(
                io1.make_bytes::<[u8;16]>(b""),
                io2.make_bytes::<[u8;16]>(b""),
                "Rerunning VRF gave different pre-output"
            );
            no_extra() 
        }).unwrap();
        assert!( sig2.clone().vrf_verify(input1.clone(), no_extra()).is_ok() );
        assert!( sig2.clone().vrf_verify(input2.clone(), no_extra()).unwrap_err().is_invalid_proof() );
        assert!( sig2.clone().vrf_verify(input1.clone(), input1.clone()).unwrap_err().is_invalid_proof() );
        
        let sk2 = SecretKey::from_rng(&mut csprng);
        let (io2,sig2) = sk2.vrf_sign_unchecked(input1.clone(), no_extra());
        assert_ne!(
            io1.make_bytes::<[u8;16]>(b""),
            io2.make_bytes::<[u8;16]>(b""),
            "VRF key ignored"
        );

        /*
        TODO: Fix zcash's crapy lack of traits
        assert_eq!(
            proof1,
            proof1batchable
                .shorten_vrf(&sk1.public, &io1)
            "Oops `shorten_vrf` failed"
        );
        assert_eq!(
            proof1batchable, proof1too,
            "VRF verification yielded incorrect batchable proof"
        );
        */
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
        let proofs21 = sk2.dleq_proove(&io21, t0.clone());
        let io12 = sk1.secret.vrf_create_from_compressed_point(out2).unwrap();
        let proofs12 = sk1.dleq_proove(&io12, t0.clone());
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

