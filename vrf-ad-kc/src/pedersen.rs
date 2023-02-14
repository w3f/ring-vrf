// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Pedersen VRF routines
//! 
//! 

use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};

use rand_core::{RngCore,CryptoRng};

use zeroize::Zeroize;

use crate::{
    SigningTranscript,
    flavor::{Flavor, InnerFlavor, Witness, Signature},
    keys::{PublicKey, SecretKey},
    error::{SignatureResult, SignatureError},
    vrf::{self, VrfInput, VrfInOut},
};

use core::borrow::{BorrowMut};


/// Pedersen VRF flavor
#[derive(Clone)]
pub struct PedersenVrf<K,H=K> 
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    // keying_base: K,
    thin: crate::ThinVrf<K>,
    blinding_base: K,
    _pd: core::marker::PhantomData<H>,
}

impl<K,H> core::ops::Deref for PedersenVrf<K,H> 
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    type Target = crate::ThinVrf<K>;
    fn deref(&self) -> &crate::ThinVrf<K> { &self.thin }
}

impl<K,H> Flavor for PedersenVrf<K,H>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>
{
    type ScalarField = K::ScalarField;
    type KeyAffine = K;
    type PreOutAffine = H;

    fn keying_base(&self) -> &K { &self.keying_base }
}

impl<K,H> InnerFlavor for PedersenVrf<K,H>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>
{
    type KeyCommitment = KeyCommitment<K>;
    type Scalars = Scalars<PedersenVrf<K,H>>;
    type Affines = Affines<PedersenVrf<K,H>>;
}

/// Pederson commitment openning for a public key, consisting of a scalar
/// that reveals the difference ebtween two public keys.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct SecretBlinding<C: AffineRepr>(pub(crate) <C as AffineRepr>::ScalarField);

impl<C: AffineRepr> Zeroize for SecretBlinding<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<C: AffineRepr> Drop for SecretBlinding<C> {
    fn drop(&mut self) { self.zeroize() }
}

/*
impl<C: AffineRepr> SecretBlinding<C> {
    pub fn is_blinded(&self) -> bool {
        use ark_ff::Zero;
        self.0.is_zero() // != <<C as AffineRepr>::ScalarField as Zero>::zero()
    }
}

impl<K,H> PedersenVrf<K,H>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub fn verify(&self, blinded: PublicKey<K>, unblinded: PublicKey<K>) -> bool {
        let mut b = self.blinding_base.mul(self.0);  // FIX !!
        b.add_assign_mixed(& unblinded.0);
        crate::eq_mod_small_cofactor_projective(b, blinded.into_group())
    }
}
*/

impl<K,H> PedersenVrf<K,H>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub fn new(keying_base: K, blinding_base: K) -> PedersenVrf<K,H> {
        let thin = crate::ThinVrf { keying_base };
        PedersenVrf { thin, blinding_base, _pd: core::marker::PhantomData, }
    }

    pub fn compute_blinded_publickey(
        &self,
        public: &PublicKey<K>, 
        secret_blinding: &SecretBlinding<K>
    ) -> KeyCommitment<K> {
        let mut b = self.blinding_base * secret_blinding.0;
        b += public.0;
        KeyCommitment(b.into_affine())
    }
}

#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct KeyCommitment<C: AffineRepr>(pub(crate) C);

impl<C: AffineRepr> Zeroize for KeyCommitment<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
// impl<C: AffineRepr> Drop for KeyCommitment<C> {
//     fn drop(&mut self) { self.zeroize() }
// }


#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct Scalars<F: Flavor> {
    pub(crate) keying:   <F as Flavor>::ScalarField,
    pub(crate) blinding: <F as Flavor>::ScalarField,
}

impl<F: Flavor> Zeroize for Scalars<F> {
    fn zeroize(&mut self) {
        self.keying.zeroize();
        self.blinding.zeroize();
    }
}
 
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct Affines<P: Flavor> {
    pub(crate) keyish:  <P as Flavor>::KeyAffine,
    pub(crate) preoutish: <P as Flavor>::PreOutAffine,
}


// --- Sign --- //

impl<K,H> SecretKey<PedersenVrf<K,H>>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub(crate) fn new_pedersen_witness<T,R>(
        &self,
        t: &T,
        input: &VrfInput<H>,
        rng: R
    ) -> Witness<PedersenVrf<K,H>>
    where T: SigningTranscript, R: RngCore+CryptoRng
    {
        let k: [<PedersenVrf<K,H> as Flavor>::ScalarField; 2]
         = t.witnesses(b"MakeWitness", &[&self.nonce_seed], rng);
        let k = Scalars { keying: k[0], blinding: k[1], };
        let keyish: <K as AffineRepr>::Group = 
            self.flavor.keying_base * k.keying
            + self.flavor.blinding_base * k.blinding;
        let preoutish: <H as AffineRepr>::Group = input.0 * k.keying;
        let r = Affines {
            keyish: keyish.into_affine(),
            preoutish: preoutish.into_affine(),
        };
        Witness { r, k }
    }

    pub fn new_secret_blinding<T,R>(&self, t: &T, rng: &mut R) -> SecretBlinding<K>
    where T: SigningTranscript+Clone, R: RngCore+CryptoRng
    {
        let [secret_blinding]: [<K as AffineRepr>::ScalarField; 1]
         = t.witnesses(b"MakeSecretBlinding", &[&self.nonce_seed], rng);
        SecretBlinding(secret_blinding)
    }

    /// Sign Pedersen VRF signature
    pub fn sign_pedersen_vrf<T,B,R>(
        &self,
        mut t: B,
        ios: &[VrfInOut<H>],
        rng: &mut R
    ) -> (Signature<PedersenVrf<K,H>>, SecretBlinding<K>)
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

    /// Sign Pedersen VRF signature, wtih a user supplied secret blinding.
    pub fn sign_pedersen_vrf_with_secret_blinding<T,B,R>(
        &self,
        mut t: B,
        ios: &[VrfInOut<H>],
        secret_blinding: SecretBlinding<K>,
        rng: &mut R
    ) -> Signature<PedersenVrf<K,H>>
    where T: SigningTranscript+Clone, B: BorrowMut<T>, R: RngCore+CryptoRng
    {
        let t = t.borrow_mut();
        let io = vrf::vrfs_merge(t, ios);

        // Allow derandomization by constructing secret_blinding and witness as late as possible.
        let compk = self.flavor.compute_blinded_publickey(self.as_publickey(), &secret_blinding);
        t.append(b"KeyCommitment",&compk);

        self.new_pedersen_witness(t,&io.input,rng)
        .sign_final(t,&secret_blinding,self,compk)
    }
}

impl<K,H> Witness<PedersenVrf<K,H>>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    /// Complete Pedersen VRF signature.
    /// 
    /// Assumes we already hashed public key, `VrfInOut`s, etc.
    /// and passes the key commitment unchanged.
    pub(crate) fn sign_final<T: SigningTranscript>(
        self,
        t: &mut T,
        secret_blinding: &SecretBlinding<K>,
        secret: &SecretKey<PedersenVrf<K,H>>,
        compk: KeyCommitment<K>,
    ) -> Signature<PedersenVrf<K,H>> {
        let Witness { r, k } = self;
        t.append(b"Witness", &r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"PedersenVrfChallenge");
        let s = Scalars {
            keying: k.keying + c * secret.key,
            blinding: k.blinding + c * secret_blinding.0,
        };
        // k.zeroize();
        Signature { compk, r, s }
    }
}


// --- Verify --- //

impl<K,H> PedersenVrf<K,H>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    /// Verify Pedersen VRF signature 
    pub fn verify_pedersen_vrf<'a,T,B>(
        &self,
        mut t: B,
        ios: &'a [VrfInOut<H>],
        signature: &Signature<PedersenVrf<K,H>>,
    ) -> SignatureResult<&'a [VrfInOut<H>]>
    where T: SigningTranscript+Clone, B: BorrowMut<T>
    {
        let t = t.borrow_mut();
        let io = vrf::vrfs_merge(t, ios);
        t.append(b"KeyCommitment",&signature.compk);

        // verify_final
        t.append(b"Witness", &signature.r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"PedersenVrfChallenge");

        let lhs = io.input.0 * signature.s.keying;
        let rhs = signature.r.preoutish.into_group() + io.preoutput.0 * c;
        if ! crate::eq_mod_small_cofactor_projective(&lhs, &rhs) {
            return Err(SignatureError::Invalid);
        }
        let lhs = self.keying_base.mul(signature.s.keying)
                  + self.blinding_base.mul(signature.s.blinding);
        let rhs = signature.r.keyish.into_group() + signature.compk.0 * c;
        if ! crate::eq_mod_small_cofactor_projective(&lhs, &rhs) {
            return Err(SignatureError::Invalid);
        }
        Ok(ios)
    }
}


