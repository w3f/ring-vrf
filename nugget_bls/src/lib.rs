// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::borrow::Borrow;

use rand_core::{CryptoRng, RngCore};

use ark_ec::{
    AffineRepr, CurveGroup,
    pairing::{Pairing, prepare_g2, PairingOutput},
};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};  // SerializationError
use ark_std::{ Zero, vec::Vec, };   // io::{Read, Write}

pub use dleq_vrf::{
    SigningTranscript, 
    error::{SignatureResult, SignatureError},
    vrf::{IntoVrfInput},
};
use dleq_vrf::vrf::{VrfInput, VrfInOut}; // VrfPreOut


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

pub struct Message<'a> {
    pub domain: &'a [u8],
    pub message: &'a [u8],
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
    dleq_vrf::ThinVrf { keying_base: <P as Pairing>::G1Affine::generator(), }
}

/// Pedersen VRF configured by the G1 generator for public key certs.
pub fn pedersen_vrf<P: Pairing>() -> PedersenVrf<P> {
    dleq_vrf::PedersenVrf::new( <P as Pairing>::G1Affine::generator(), [] )
}

/// VrfInput from the G2 generator for public key certs.
fn pk_in<P: Pairing>() -> VrfInput<<P as Pairing>::G2Affine> {
    VrfInput( <P as Pairing>::G2Affine::generator() )
}


#[cfg(feature = "getrandom")]
#[derive(Clone)]  // Zeroize
pub struct SecretKey<P: Pairing>(dleq_vrf::SecretKey<<P as Pairing>::G1Affine>);

#[cfg(feature = "getrandom")]
impl<P: Pairing> SecretKey<P> {
    pub fn as_g1_publickey(&self) -> &PublicKeyG1<P> {
        self.0.as_publickey()
    }
    
    /// Generate an "unbiased" `SecretKey` directly from a user
    /// suplied `csprng` uniformly, bypassing the `MiniSecretKey`
    /// layer.
    pub fn from_rng<R>(rng: &mut R) -> Self
    where R: CryptoRng + RngCore,
    {
        SecretKey( dleq_vrf::SecretKey::from_rng( thin_vrf::<P>(), rng ))
    }

    /// Generate a `SecretKey` from a 32 byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SecretKey( dleq_vrf::SecretKey::from_seed( thin_vrf::<P>(), seed ))
    }

    /// Generate an ephemeral `SecretKey` with system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral() -> Self {
        SecretKey::from_rng(&mut ::rand_core::OsRng)
    }

    pub fn create_public_cert<T: SigningTranscript+Clone>(&mut self, t: T) -> PublicKey<P> {
        let pedersen = pedersen_vrf::<P>();
        let g2_io = self.0.vrf_inout(pk_in::<P>());
        let g2 = g2_io.preoutput.clone();
        let sig = pedersen.sign_non_batchable_pedersen_vrf(t, &[g2_io], None, &mut self.0).0;
        PublicKey { g2, sig, } // g1: self.as_publickey().clone(),
    }

    pub fn create_nugget_public(&mut self) -> PublicKey<P> {
        self.create_public_cert(::merlin::Transcript::new(b"NuggetPublic"))
    }

    pub fn sign_nugget_bls<T,M>(&mut self, t: T, input: M) -> Signature<P> 
    where T: SigningTranscript+Clone, M: IntoVrfInput<<P as Pairing>::G1Affine>,
    {
        let io = self.0.vrf_inout(input);
        let preoutput = io.preoutput.clone();
        let signature = self.0.sign_thin_vrf(t, &[io]);
        Signature { preoutput, signature }
    }
}

#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialOrd, Ord, 
pub struct PublicKey<P: Pairing> {
    /// Our public key on G2
    g2: dleq_vrf::VrfPreOut<<P as Pairing>::G2Affine>,
    /// Both our public key on G1 as well as a DLEQ proof for g2.
    /// 
    /// Inclusion of public keys inside signatures makes sense for
    /// the PdersenVrf, but only an odd artifact here.
    sig: dleq_vrf::NonBatchableSignature<PedersenVrf<P>>,
}

impl<P: Pairing> core::cmp::PartialEq<Self> for PublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.g2 == other.g2 && self.sig.as_key_commitment() == other.sig.as_key_commitment()
    }
}
impl<P: Pairing> core::cmp::Eq for PublicKey<P> {}

use core::hash::Hasher;
impl<P: Pairing> core::hash::Hash for PublicKey<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.g2.0.hash(state);
        self.sig.as_key_commitment().0.hash(state);
    }
}


/// Actual nugget BLS signature including faster correctness proof
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialEq, Eq, PartialOrd, Ord, Hash, 
pub struct Signature<P: Pairing> {
    /// Actual BLS signature
    preoutput: dleq_vrf::VrfPreOut<<P as Pairing>::G1Affine>,
    /// DLEQ proof of correctness for BLS signature
    signature: dleq_vrf::Signature<ThinVrf<P>>,
}    

/// Incomplete public key living only on G1, not useful for aggregation
/// but useful for end verifiers. 
pub type PublicKeyG1<P> = dleq_vrf::PublicKey<<P as Pairing>::G1Affine>;

impl<P: Pairing> PublicKey<P> {
    pub fn as_g1_point(&self) -> &<P as Pairing>::G1Affine {
        &self.sig.as_key_commitment().0
    }

    pub fn to_g1_publickey(&self) -> PublicKeyG1<P> {
        self.sig.to_publickey()
    }

    pub fn validate_public_cert<T>(&self, t: T) -> SignatureResult<()> 
    where T: SigningTranscript+Clone
    {
        let g2_io = VrfInOut { input: pk_in::<P>(), preoutput: self.g2.clone(), };
        pedersen_vrf::<P>()
        .verify_non_batchable_pedersen_vrf(t, &[g2_io], &self.sig )
        .map(|_| ())
    }

    pub fn validate_nugget_public(&self) -> SignatureResult<()> {
        self.validate_public_cert(::merlin::Transcript::new(b"NuggetPublic"))
    }

    pub fn verify_nugget_bls<T,M>(&self, t: T, input: M, signature: &Signature<P>) -> SignatureResult<()>
    where T: SigningTranscript+Clone, M: IntoVrfInput<<P as Pairing>::G1Affine>,
    {
        let io = signature.preoutput.attach_input(input);
        thin_vrf::<P>()
        .verify_thin_vrf(t, &[io], &self.to_g1_publickey(), &signature.signature )
        .map(|_| ())
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
    where BP: Borrow<PublicKey<P>>, BS: Borrow<Signature<P>>,
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
        let mut t = ::merlin::Transcript::new(b"NuggetAggregate");
        t.append(b"g2+sig",self);
        t.append(b"g1",&agg_pk_g1);
        let r: <P as Pairing>::ScalarField = t.challenge(b"r");

        // e(msg + r * g1_gen, agg_pk_g2) == e(agg_sig + r * agg_pk_g1, -g2_gen)
        let g1s: [_; 2] = [
            input.into_vrf_input().0 + thin_vrf::<P>().keying_base * r,
            self.agg_sig + agg_pk_g1 * r,
        ];
        let g2s: [_;2] = [
            prepare_g2::<P>(self.agg_pk_g2),
            g2_minus_generator::<P>(),
        ];
        let r: _ = P::final_exponentiation( P::multi_miller_loop(g1s,g2s) );
        if r == Some(PairingOutput::<P>::zero()) { //zero is the target_field::one !!
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

