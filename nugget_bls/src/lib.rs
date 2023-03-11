// Copyright (c) 2022-2023 Web 3 Foundation

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc = include_str!("../README.md")]

use ark_ec::{ AffineRepr, CurveGroup, pairing::{Pairing, prepare_g2, PairingOutput}, };
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};  // SerializationError
use ark_std::{ Zero, vec::Vec, };   // io::{Read, Write}

pub use dleq_vrf::{SigningTranscript, Flavor, vrf::{VrfInput, VrfPreOut, VrfInOut}};


#[cfg(test)]
mod tests;


type ThinVrf<P> = dleq_vrf::ThinVrf<<P as Pairing>::G1Affine>;
type PedersenVrf<P> = dleq_vrf::PedersenVrf<<P as Pairing>::G1Affine,<P as Pairing>::G2Affine,0>;

pub fn thin_vrf<P: Pairing>() -> ThinVrf<P> {
    dleq_vrf::ThinVrf { keying_base: <P as Pairing>::G1Affine::generator(), }
}

pub fn pedersen_vrf<P: Pairing>() -> PedersenVrf<P> {
    dleq_vrf::PedersenVrf::new( <P as Pairing>::G1Affine::generator(), [] )
}

pub struct BlsMessage<P: Pairing>(<P as Pairing>::G1Affine);

impl<P: Pairing> From<&[u8]> for BlsMessage<P> {
    fn from(msg: &[u8]) -> BlsMessage<P> {
        unimplemented!()
    }
}

#[derive(Clone)]  // Zeroize
pub struct SecretKey<P: Pairing>(dleq_vrf::SecretKey<<P as Pairing>::G1Affine>);

fn pk_in<P: Pairing>() -> VrfInput<<P as Pairing>::G2Affine> {
    VrfInput( <P as Pairing>::G2Affine::generator() )
}

impl<P: Pairing> SecretKey<P> {
    pub fn create_nugget_public(&self) -> PublicKey<P> {
        let pedersen = pedersen_vrf::<P>();
        let g2_io = self.0.vrf_inout(pk_in::<P>());
        let g2 = g2_io.preoutput.clone();
        let t = ::merlin::Transcript::new(b"NuggetPublic");
        let sig = pedersen.sign_non_batchable_pedersen_vrf(t, &[g2_io], None, &self.0, &mut rand_core::OsRng ).0;
        PublicKey { g2, sig, } // g1: self.as_publickey().clone(),
    }

    pub fn sign_nugget_bls<T: SigningTranscript+Clone>(&self, t: T, msg: impl Into<BlsMessage<P>>) -> Signature<P> {
        let msg: BlsMessage<P> = msg.into();
        let io = self.0.vrf_inout(VrfInput( msg.0 ));
        let preoutput = io.preoutput.clone();
        let signature = self.0.sign_thin_vrf(t, &[io], &mut rand_core::OsRng);
        Signature { preoutput, signature }
    }
}

#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialEq, Eq, PartialOrd, Ord, Hash, 
pub struct PublicKey<P: Pairing> {
    /// Our public key on G2
    g2: dleq_vrf::VrfPreOut<<P as Pairing>::G2Affine>,
    /// Both our public key on G1 as well as a DLEQ proof for g2.
    /// 
    /// Inclusion of public keys inside signatures makes sense for
    /// the PdersenVrf, but only an odd artifact here.
    sig: dleq_vrf::NonBatchableSignature<PedersenVrf<P>>,
}

/// Actual nugget BLS signature including faster correctness proof
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialEq, Eq, PartialOrd, Ord, Hash, 
pub struct Signature<P: Pairing> {
    /// Actual BLS signature
    preoutput: dleq_vrf::VrfPreOut<<P as Pairing>::G1Affine>,
    /// DLEQ proof of correctness for BLS signature
    signature: dleq_vrf::Signature<ThinVrf<P>>,
}    

impl<P: Pairing> PublicKey<P> {
    pub fn as_g1_point(&self) -> &<P as Pairing>::G1Affine {
        &self.sig.as_key_commitment().0
    }

    fn to_vrf_publickey(&self) -> dleq_vrf::PublicKey<<P as Pairing>::G1Affine> {
        self.sig.to_publickey()
    }

    pub fn validate_nugget_public(&self) -> bool {
        let pedersen = pedersen_vrf::<P>();
        let g2_io = VrfInOut { input: pk_in::<P>(), preoutput: self.g2.clone(), };
        let t = ::merlin::Transcript::new(b"NuggetPublic");
        pedersen.verify_non_batchable_pedersen_vrf(t, &[g2_io], &self.sig ).is_ok()
    }

    pub fn verify_nugget_bls<T: SigningTranscript+Clone>(&self, t: T, msg: impl Into<BlsMessage<P>>, signature: &Signature<P>) -> bool {
        let msg: BlsMessage<P> = msg.into();
        let io = VrfInOut {
            input: VrfInput( msg.0 ),
            preoutput: signature.preoutput.clone(),
        };
        thin_vrf::<P>().verify_thin_vrf(t, &[io], &self.to_vrf_publickey(), &signature.signature ).is_ok()
    }
}

#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, PartialEq, Eq, PartialOrd, Ord, Hash, 
pub struct AggregateSignature<P: Pairing> {
    agg_sig: <P as Pairing>::G1Affine,
    agg_pk_g2: <P as Pairing>::G2Affine,
}

// Ideally we'd make this const fn but we've this error right now:
// the trait `~const Neg` is not implemented for `<P as Pairing>::G2`
fn g2_minus_generator<P: Pairing>() -> <P as Pairing>::G2Prepared {
    prepare_g2::<P>(- <P as Pairing>::G2Affine::generator().into_group())
}

impl<P: Pairing> AggregateSignature<P> {
    /// Aggregate single nugget BLS signatures and their public keys
    /// into one aggregate nugget BLS signature.
    pub fn create(publickeys: &[PublicKey<P>], signatures: &[Signature<P>]) -> AggregateSignature<P> {
        assert_eq!( publickeys.len(), signatures.len() );
        let mut agg_sig = <<P as Pairing>::G1Affine as AffineRepr>::zero().into_group();
        for sig in signatures { agg_sig += sig.preoutput.0; }
        let mut agg_pk_g2 = <<P as Pairing>::G2Affine as AffineRepr>::zero().into_group();
        for pk in publickeys { agg_pk_g2 += pk.g2.0; }
        AggregateSignature {
            agg_sig: agg_sig.into_affine(),
            agg_pk_g2: agg_pk_g2.into_affine(),
        }
    }

    pub fn verify(&self, msg: impl Into<BlsMessage<P>>, agg_pk_g1: <P as Pairing>::G1Affine) -> bool {
        let msg: BlsMessage<P> = msg.into();
        let mut t = ::merlin::Transcript::new(b"NuggetAggregate");
        t.append(b"g2+sig",self);
        t.append(b"g1",&agg_pk_g1);
        let r: <P as Pairing>::ScalarField = t.challenge(b"r");

        // e(msg + r * g1_gen, agg_pk_g2) == e(agg_sig + r * agg_pk_g1, -g2_gen)
        let g1s: [_; 2] = [
            self.agg_sig + agg_pk_g1 * r,
            msg.0 + thin_vrf::<P>().keying_base * r
        ];
        let g2s: [_;2] = [
            prepare_g2::<P>(self.agg_pk_g2),
            g2_minus_generator::<P>(),
        ];
        P::final_exponentiation( P::multi_miller_loop(g1s,g2s) )
         == Some(PairingOutput::<P>::zero()) //zero is the target_field::one !!
    }
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}