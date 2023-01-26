// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Pedersen VRF routines

use ark_std::{ io::{Read, Write} };
use ark_ff::{PrimeField, SquareRootField};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,SerializationError};

use rand_core::{RngCore,CryptoRng};

use zeroize::Zeroize;

use crate::{
    SigningTranscript,
    flavor::{Flavor},
    keys::{PublicKey, SecretKey},
    error::{SignatureResult, SignatureError},
    vrf::{self, VrfInput, VrfInOut},
};

use core::borrow::{BorrowMut};


pub trait PedersenVrfPair : Clone {
    type ScalarField: PrimeField + SquareRootField;
    type KeyCurve: AffineCurve<ScalarField = Self::ScalarField>;
    type PreOutCurve: AffineCurve<ScalarField = Self::ScalarField>;
}

/// Pederson commitment openning for a public key, consisting of a scalar
/// that reveals the difference ebtween two public keys.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct SecretBlinding<P: PedersenVrfPair>(pub(crate) <P as PedersenVrfPair>::ScalarField);

impl<P: PedersenVrfPair> Zeroize for SecretBlinding<P> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<P: PedersenVrfPair> Drop for SecretBlinding<P> {
    fn drop(&mut self) { self.zeroize() }
}

/*
impl<P: PedersenVrfPair> SecretBlinding<P> {
    pub fn is_blinded(&self) -> bool {
        use ark_ff::Zero;
        self.0.is_zero() // != <<C as AffineCurve>::ScalarField as Zero>::zero()
    }

    pub fn verify(&self, blinded: PublicKey<<P as PedersenVrfPair>::KeyCurve>, unblinded: PublicKey<<P as PedersenVrfPair>::KeyCurve>) -> bool {
        let mut b = C::blinding_base_affine().mul(self.0);
        b.add_assign_mixed(& unblinded.0);
        crate::eq_mod_small_cofactor_projective(b, blinded.into_projective())
    }
}
*/


/// Pedersen VRF flavor
#[derive(Clone)]
pub struct PedersenVrf<P: PedersenVrfPair> {
    pub keying_base: <P as PedersenVrfPair>::KeyCurve,
    pub blinding_base:  <P as PedersenVrfPair>::KeyCurve,
}

impl<P: PedersenVrfPair> PedersenVrf<P> {
    pub fn compute_blinded_publickey(
        &self,
        public: &PublicKey<<P as PedersenVrfPair>::KeyCurve>, 
        secret_blinding: &SecretBlinding<P>
    ) -> KeyCommitment<P> {
        let mut b = self.blinding_base.mul(secret_blinding.0);
        b.add_assign_mixed(& public.0);
        KeyCommitment(b.into_affine())
    }
}

#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct KeyCommitment<P: PedersenVrfPair>(pub(crate) <P as PedersenVrfPair>::KeyCurve);

impl<P: PedersenVrfPair> Zeroize for KeyCommitment<P> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<P: PedersenVrfPair> Drop for KeyCommitment<P> {
    fn drop(&mut self) { self.zeroize() }
}


#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct Scalars<P: PedersenVrfPair> {
    pub(crate) keying:   <P as PedersenVrfPair>::ScalarField,
    pub(crate) blinding: <P as PedersenVrfPair>::ScalarField,
}

impl<P: PedersenVrfPair> Zeroize for Scalars<P> {
    fn zeroize(&mut self) {
        self.keying.zeroize();
        self.blinding.zeroize();
    }
}

#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct Affines<P: PedersenVrfPair> {
    pub(crate) keyish:  <P as PedersenVrfPair>::KeyCurve,
    pub(crate) preoutish: <P as PedersenVrfPair>::PreOutCurve,
}

impl<P: PedersenVrfPair> Flavor for PedersenVrf<P> {
    type ScalarField = <P as PedersenVrfPair>::ScalarField;
    type KeyAffine = <P as PedersenVrfPair>::KeyCurve;
    type PreOutAffine = <P as PedersenVrfPair>::PreOutCurve;

    fn keying_base(&self) -> &<P as PedersenVrfPair>::KeyCurve { &self.keying_base }

    type Scalars = Scalars<P>;   // [<C as AffineCurve>::ScalarField; 2];
    type Affines = Affines<P>;
}


// --- Sign --- //

impl<P: PedersenVrfPair> SecretKey<PedersenVrf<P>> {
    pub(crate) fn new_pedersen_witness<T,R>(
        &self,
        t: &T,
        input: &VrfInput<<P as PedersenVrfPair>::PreOutCurve>,
        rng: R
    ) -> Witness<P>
    where T: SigningTranscript, R: RngCore+CryptoRng
    {
        let k: [<P as PedersenVrfPair>::ScalarField; 2]
         = t.witnesses(b"MakeWitness", &[&self.nonce_seed], rng);
        let k = Scalars { keying: k[0], blinding: k[1], }; 
        let r = Affines {
            keyish: (
                    self.flavor.keying_base.mul(k.keying)
                    + self.flavor.blinding_base.mul(k.blinding)
                ).into_affine(),
            preoutish: input.0.mul(k.keying).into_affine(),
        };
        Witness { r, k }
    }

    pub fn new_secret_blinding<T,R>(&self, t: &T, rng: &mut R) -> SecretBlinding<P>
    where T: SigningTranscript+Clone, R: RngCore+CryptoRng
    {
        let [secret_blinding]: [<P as PedersenVrfPair>::ScalarField; 1]
         = t.witnesses(b"MakeSecretBlinding", &[&self.nonce_seed], rng);
        SecretBlinding(secret_blinding)
    }

    /// Sign Pedersen VRF signature
    pub fn sign_pedersen_vrf<T,B,R>(
        &self,
        mut t: B,
        ios: &[VrfInOut<<P as PedersenVrfPair>::PreOutCurve>],
        rng: &mut R
    ) -> (PedersenVrfSignature<P>, SecretBlinding<P>)
    where T: SigningTranscript+Clone, B: BorrowMut<T>, R: RngCore+CryptoRng
    {
        let t = t.borrow_mut();
        let io = vrf::vrfs_merge(t, ios);

        // Allow derandomization by constructing secret_blinding and witness as late as possible.
        let secret_blinding = self.new_secret_blinding(t,rng);
        let compk = self.flavor.compute_blinded_publickey(self.as_publickey(), &secret_blinding);
        t.append(b"KeyCommitment",&compk);

        let w = self.new_pedersen_witness(t,&io.input,rng);
        ( w.sign_final(t,&secret_blinding,self,compk), secret_blinding )
    }
}

/// Secret and public nonce/witness for doing one thin VRF signature,
/// obvoiusly usable only once ever.
pub(crate) struct Witness<P: PedersenVrfPair> {
    k: Scalars<P>,
    r: Affines<P>,
}

impl<P: PedersenVrfPair> Witness<P> {
    /// Complete Pedersen VRF signature.
    /// 
    /// Assumes we already hashed public key, `VrfInOut`s, etc.
    /// and passes the key commitment unchanged.
    pub(crate) fn sign_final<T: SigningTranscript>(
        self,
        t: &mut T,
        secret_blinding: &SecretBlinding<P>,
        secret: &SecretKey<PedersenVrf<P>>,
        compk: KeyCommitment<P>,
    ) -> PedersenVrfSignature<P> {
        let Witness { r, k } = self;
        t.append(b"Witness", &r);
        let c: <P as PedersenVrfPair>::ScalarField = t.challenge(b"PedersenVrfChallenge");
        let s = Scalars {
            keying: k.keying + c * secret.key,
            blinding: k.blinding + c * secret_blinding.0,
        };
        // k.zeroize();
        PedersenVrfSignature { compk, r, s }
    }
}

/// Pedersen VRF signature
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct PedersenVrfSignature<P: PedersenVrfPair> {
    compk: KeyCommitment<P>,
    r: Affines<P>,
    s: Scalars<P>,
}

impl<P: PedersenVrfPair> PedersenVrfSignature<P> {
    pub fn as_key_commitment(&self) -> &KeyCommitment<P> { &self.compk }
}

/*
impl<F: Flavor> Valid for PedersenVrfSignature<F> {
    fn check(&self) -> Result<(), SerializationError> {
        if self.is_on_curve() && self.is_in_correct_subgroup_assuming_on_curve() {
            Ok(())
        } else {
            Err(SerializationError::InvalidData)
        }
    }
}
*/


// --- Verify --- //

impl<P: PedersenVrfPair> PedersenVrf<P> {
    /// Verify Pedersen VRF signature 
    pub fn verify_pedersen_vrf<'a,T,B>(
        &self,
        mut t: B,
        ios: &'a [VrfInOut<<P as PedersenVrfPair>::PreOutCurve>],
        signature: &PedersenVrfSignature<P>,
    ) -> SignatureResult<&'a [VrfInOut<<P as PedersenVrfPair>::PreOutCurve>]>
    where T: SigningTranscript+Clone, B: BorrowMut<T>
    {
        let t = t.borrow_mut();
        let io = vrf::vrfs_merge(t, ios);
        t.append(b"KeyCommitment",&signature.compk);

        // verify_final
        t.append(b"Witness", &signature.r);
        let c: <P as PedersenVrfPair>::ScalarField = t.challenge(b"PedersenVrfChallenge");

        let lhs = io.input.0.mul(signature.s.keying);
        let rhs = signature.r.preoutish.into_projective() + io.preoutput.0.mul(c);
        if ! crate::eq_mod_small_cofactor_projective(&lhs, &rhs) {
            return Err(SignatureError::Invalid);
        }
        let lhs = self.keying_base.mul(signature.s.keying)
                  + self.blinding_base.mul(signature.s.blinding);
        let rhs = signature.r.keyish.into_projective() + signature.compk.0.mul(c);
        if ! crate::eq_mod_small_cofactor_projective(&lhs, &rhs) {
            return Err(SignatureError::Invalid);
        }
        Ok(ios)
    }
}


