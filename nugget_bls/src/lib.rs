// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

use zeroize::Zeroize;

use ark_std::{
    borrow::{Borrow,BorrowMut}, 
    // io::{Read, Write},
    hash::Hasher, vec::Vec, Zero,
};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};  // SerializationError

use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::{Pairing, prepare_g2, PairingOutput},
};

pub use dleq_vrf::{
    Transcript, IntoTranscript, transcript,
    error::{SignatureResult, SignatureError},
    vrf::{IntoVrfInput},
};
use dleq_vrf::vrf::{VrfInput, VrfInOut}; // VrfPreOut
use transcript::digest::Update;


#[cfg(feature = "scale")]
pub mod scale;

#[cfg(test)]
mod tests;


#[cfg(feature = "bls12_381")]
pub mod bls12_381 {
    pub use ark_bls12_381::{self as curve, Bls12_381};
    pub type P = Bls12_381;    
    include!("inc_bls12.rs");
}

#[cfg(feature = "bls12_377")]
pub mod bls12_377 {
    pub use ark_bls12_377::{self as curve, Bls12_377};
    pub type P = Bls12_377;    
    include!("inc_bls12.rs");
}


type ThinVrf<P> = dleq_vrf::ThinVrf<<P as Pairing>::G1Affine>;
type PedersenVrf<P> = dleq_vrf::PedersenVrf<<P as Pairing>::G1Affine,<P as Pairing>::G2Affine,0>;


// TODO:  All of thin_vrf, pedersen_vrf, pk_in, g2_minus_generator and
// other fns should all become const fn once const traits lands, but
// right now they hit errors like:
//  the trait `~const Neg` is not implemented for `<P as Pairing>::G2`
// 
// https://github.com/rust-lang/rust/issues/60551 https://github.com/arkworks-rs/algebra/issues/480
// https://github.com/rust-lang/rust/issues/67792 https://github.com/arkworks-rs/algebra/issues/481
// https://github.com/arkworks-rs/algebra/issues/485

/// Then VRF configured by the G1 generator for signatures.
pub fn thin_vrf<P: Pairing>() -> ThinVrf<P> {
    dleq_vrf::ThinVrf::default()  // keying_base: <P as Pairing>::G1Affine::generator()
}

/// Pedersen VRF configured by the G1 generator for public key certs.
pub fn pedersen_vrf<P: Pairing>() -> PedersenVrf<P> {
    thin_vrf::<P>().pedersen_vrf([])
}

/// VrfInput from the G2 generator for public key certs.
fn pk_in<P: Pairing>() -> VrfInput<<P as Pairing>::G2Affine> {
    VrfInput( <P as Pairing>::G2Affine::generator() )
}


#[derive(Clone,Zeroize)]
pub struct SecretKey<P: Pairing>(dleq_vrf::SecretKey<<P as Pairing>::G1Affine>);

impl<P: Pairing> SecretKey<P> {
    pub fn to_g1_publickey(&self) -> PublicKeyG1<P> {
        PublicKeyG1( self.0.as_publickey().0 )
    }
    
    /// Generate an "unbiased" `SecretKey` from a user supplied `XofReader`.
    pub fn from_xof(xof: impl transcript::digest::XofReader) -> Self {
        SecretKey( dleq_vrf::SecretKey::from_xof( xof ))
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SecretKey( dleq_vrf::SecretKey::from_seed( seed ))
    }

    /// Generate an ephemeral `SecretKey` with system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral() -> Self {
        use rand_core::{RngCore,OsRng};
        let mut seed: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SecretKey::from_seed(&seed)
    }

    pub fn create_public_cert(&self, t: impl IntoTranscript) -> AggregationKey<P> {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();
        t.label(b"NuggetPublic");
        let pedersen = pedersen_vrf::<P>();
        let g2_io = self.0.vrf_inout(pk_in::<P>());
        let g2 = g2_io.preoutput.clone();
        let sig = pedersen.sign_non_batchable_pedersen_vrf(t, &[g2_io], None, &self.0).0;
        AggregationKey { g2, sig, } // g1: self.as_publickey().clone(),
    }

    pub fn create_nugget_public(&self) -> AggregationKey<P> {
        self.create_public_cert(b"")
    }

    pub fn sign_nugget_bls<M>(&self, t: impl IntoTranscript, input: M) -> Signature<P> 
    where M: IntoVrfInput<<P as Pairing>::G1Affine>,
    {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();
        t.label(b"NuggetBLS");
        let io = self.0.vrf_inout(input);
        let preoutput = io.preoutput.clone();
        let signature = self.0.sign_thin_vrf_detached(t, &[io]);
        Signature { preoutput, signature }
    }
}

/// Incomplete public key living only on G1, not useful for either 
/// aggregation or classical stand alone BLS verificatoin, but useful
/// for end verifiers of nugget BLS' `AggregateSignature`s. 
#[derive(Debug,Clone,Hash,PartialEq,Eq,CanonicalSerialize,CanonicalDeserialize,Zeroize)]
#[repr(transparent)]
pub struct PublicKeyG1<P: ark_ec::pairing::Pairing>(<P as Pairing>::G1Affine);

impl<P: Pairing> PublicKeyG1<P> {
    pub fn as_g1_point(&self) -> &<P as Pairing>::G1Affine {
        &self.0
    }

    pub fn verify_nugget_bls<M>(&self, t: impl IntoTranscript, input: M, signature: &Signature<P>) -> SignatureResult<()>
    where M: IntoVrfInput<<P as Pairing>::G1Affine>,
    {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();
        t.label(b"NuggetBLS");
        let io = signature.preoutput.attach_input(input);
        let public = dleq_vrf::PublicKey(self.0);
        thin_vrf::<P>()
        .verify_thin_vrf(t, &[io], &public, &signature.signature )
        .map(|_| ())
    }

    pub fn update_digest(&self, h: &mut impl Update) {
        dleq_vrf::PublicKey(self.0).update_digest(h)
    }
}

/// Actual nugget BLS signature including faster correctness proof
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialEq, Eq, PartialOrd, Ord, Hash, 
pub struct Signature<P: Pairing> {
    /// Actual BLS signature
    preoutput: dleq_vrf::VrfPreOut<<P as Pairing>::G1Affine>,
    /// DLEQ proof of correctness for BLS signature
    signature: dleq_vrf::Batchable<ThinVrf<P>>,
}

#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialOrd, Ord, 
pub struct AggregationKey<P: Pairing> {
    /// Our public key on G2
    g2: dleq_vrf::VrfPreOut<<P as Pairing>::G2Affine>,
    /// Both our public key on G1 as well as a DLEQ proof for g2.
    /// 
    /// Inclusion of public keys inside signatures makes sense for
    /// the PdersenVrf, but only an odd artifact here.
    sig: dleq_vrf::NonBatchable<PedersenVrf<P>>,
}

impl<P: Pairing> core::cmp::PartialEq<Self> for AggregationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.g2 == other.g2 && self.sig.as_key_commitment() == other.sig.as_key_commitment()
    }
}
impl<P: Pairing> core::cmp::Eq for AggregationKey<P> {}

impl<P: Pairing> core::hash::Hash for AggregationKey<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // self.g2.0.hash(state); // removed to hash exactly like PublicKeyG1
        self.sig.as_key_commitment().0.hash(state);
    }
}

impl<P: Pairing> AggregationKey<P> {
    pub fn as_g1_point(&self) -> &<P as Pairing>::G1Affine {
        &self.sig.as_key_commitment().0
    }

    pub fn to_g1_publickey(&self) -> PublicKeyG1<P> {
        PublicKeyG1( self.sig.to_publickey().0 )
    }

    pub fn update_digest(&self, h: &mut impl Update) {
        self.to_g1_publickey().update_digest(h);
    }

    pub fn validate_public_cert(&self, t: impl IntoTranscript) -> SignatureResult<()> 
    {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();
        t.label(b"NuggetPublic");
        let g2_io = VrfInOut { input: pk_in::<P>(), preoutput: self.g2.clone(), };
        pedersen_vrf::<P>()
        .verify_non_batchable_pedersen_vrf(t, &[g2_io], &self.sig )
        .map(|_| ())
    }

    pub fn validate_nugget_public(&self) -> SignatureResult<()> {
        self.validate_public_cert(b"")
    }

    pub fn verify_nugget_bls<M>(&self, t: impl IntoTranscript, input: M, signature: &Signature<P>) -> SignatureResult<()>
    where M: IntoVrfInput<<P as Pairing>::G1Affine>,
    {
        self.to_g1_publickey().verify_nugget_bls(t,input,signature)
    }
}

#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialEq, Eq, PartialOrd, Ord, Hash, 
pub struct AggregateSignature<P: Pairing> {
    agg_sig: <P as Pairing>::G1Affine,
    agg_pk_g2: <P as Pairing>::G2Affine,
}

// TODO:  We could precomute g2_minus_generator using lazy_static and
// the AnyLinkedList trick in nugget_bls/any_tools/src, but const fn
// should work eventually, so likely overkill now.

fn g2_minus_generator<P: Pairing>() -> <P as Pairing>::G2Prepared {
    prepare_g2::<P>(- pk_in::<P>().0.into_group())
}

impl<P: Pairing> AggregateSignature<P> {
    /// Aggregate single nugget BLS signatures and their public keys
    /// into one aggregate nugget BLS signature.
    pub fn create<BP,BS>(publickeys: &[BP], signatures: &[BS]) -> AggregateSignature<P> 
    where BP: Borrow<AggregationKey<P>>, BS: Borrow<Signature<P>>,
    {
        assert_eq!( publickeys.len(), signatures.len() );
        let mut agg_sig = <<P as Pairing>::G1Affine as AffineRepr>::zero().into_group();
        for sig in signatures { agg_sig += sig.borrow().preoutput.0; }
        let mut agg_pk_g2 = <<P as Pairing>::G2Affine as AffineRepr>::zero().into_group();
        for pk in publickeys { agg_pk_g2 += pk.borrow().g2.0; }
        AggregateSignature {
            agg_sig: agg_sig.into_affine(),
            agg_pk_g2: agg_pk_g2.into_affine(),
        }
    }

    pub fn verify_by_aggregated(
        &self,
        input: impl IntoVrfInput<<P as Pairing>::G1Affine>,
        agg_pk_g1: <P as Pairing>::G1Affine
    ) -> SignatureResult<()> {
        let mut t = Transcript::from_accumulation(b"NuggetAggregate");
        t.label(b"g2+sig");
        t.append(self);
        t.label(b"g1");
        t.append(&agg_pk_g1);
        let r: <P as Pairing>::ScalarField = t.challenge(b"r").read_uniform();

        // e(msg + r * g1_gen, agg_pk_g2) == e(agg_sig + r * agg_pk_g1, -g2_gen)
        let g1s: [_; 2] = [
            input.into_vrf_input().0 + thin_vrf::<P>().keying_base * r,
            self.agg_sig + agg_pk_g1 * r,
        ];
        let g2s: [_;2] = [
            prepare_g2::<P>(self.agg_pk_g2),
            g2_minus_generator::<P>(),
        ];
        let z: _ = P::final_exponentiation( P::multi_miller_loop(g1s,g2s) );
        if z == Some(PairingOutput::<P>::zero()) { //zero is the target_field::one !!
            Ok(())
        } else {
            Err(SignatureError::Invalid)
        }
    }

    pub fn verify_by_pks<M,B,I>(&self, input: M, publickeys: I) -> SignatureResult<()>
    where
        M: IntoVrfInput<<P as Pairing>::G1Affine>,
        B: Borrow<PublicKeyG1<P>>,
        I: IntoIterator<Item=B>
    {
        let mut agg_pk_g1 = <<P as Pairing>::G1Affine as AffineRepr>::zero().into_group();
        for pk in publickeys { agg_pk_g1 += pk.borrow().0; }
        self.verify_by_aggregated(input, agg_pk_g1.into_affine())
    }
}

