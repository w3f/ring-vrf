// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Pedersen VRF routines
//! 
//! 

use ark_ff::{PrimeField};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use ark_std::{vec::Vec};

use zeroize::Zeroize;

use crate::{
    SigningTranscript,
    flavor::{Flavor, InnerFlavor, Witness, Signature, NonBatchableSignature},
    keys::{PublicKey, SecretKey},
    error::{SignatureResult, SignatureError},
    vrf::{self, VrfInput, VrfInOut},
};

use core::borrow::{BorrowMut};


/// Pedersen VRF flavor
#[derive(Debug,Clone)]
pub struct PedersenVrf<K, H=K, const B: usize=1> 
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    // keying_base: K,
    thin: crate::ThinVrf<K>,
    blinding_bases: [K; B],
    _pd: core::marker::PhantomData<H>,
}

impl<K,H,const B: usize> core::ops::Deref for PedersenVrf<K,H,B> 
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    type Target = crate::ThinVrf<K>;
    fn deref(&self) -> &crate::ThinVrf<K> { &self.thin }
}

impl<K,H,const B: usize> Flavor for PedersenVrf<K,H,B>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>
{
    type ScalarField = K::ScalarField;
    type KeyAffine = K;
    type PreOutAffine = H;

    fn keying_base(&self) -> &K { &self.keying_base }
}

impl<K,H,const B: usize> InnerFlavor for PedersenVrf<K,H,B>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>
{
    type KeyCommitment = KeyCommitment<K>;
    type Scalars = Scalars<K::ScalarField,B>;
    type Affines = Affines<K,H>;
}

/// Pederson commitment openning for a public key, consisting of a scalar
/// that reveals the difference ebtween two public keys.
#[derive(Clone,CanonicalSerialize,CanonicalDeserialize)] // Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash
pub struct SecretBlinding<C: AffineRepr,const B: usize>(
    pub(crate) [<C as AffineRepr>::ScalarField; B]
);

impl<C: AffineRepr,const B: usize> Zeroize for SecretBlinding<C,B> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<C: AffineRepr,const B: usize> Drop for SecretBlinding<C,B> {
    fn drop(&mut self) { self.zeroize() }
}

/*
impl<C: AffineRepr,const B: usize> Drop for SecretBlinding<C,B> {
    pub fn is_blinded(&self) -> bool {
        use ark_ff::Zero;
        TODO: loop
        self.0.is_zero() // != <<C as AffineRepr>::ScalarField as Zero>::zero()
    }
}

impl<K,H,const B: usize> PedersenVrf<K,H,B>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub fn verify(&self, blinded: PublicKey<K>, unblinded: PublicKey<K>) -> bool {
        TODO: loop
        let mut b = self.blinding_base.mul(self.0);  // FIX !!
        b.add_assign_mixed(& unblinded.0);
        crate::eq_mod_small_cofactor_projective(b, blinded.into_group())
    }
}
*/

impl<K,H,const B: usize> PedersenVrf<K,H,B>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub fn new(keying_base: K, blinding_bases: [K; B],) -> PedersenVrf<K,H,B> {
        let thin = crate::ThinVrf { keying_base };
        PedersenVrf { thin, blinding_bases, _pd: core::marker::PhantomData, }
    }

    pub fn compute_blinded_publickey(
        &self,
        public: &PublicKey<K>, 
        secret_blindings: &SecretBlinding<K,B>
    ) -> KeyCommitment<K> {
        let mut b = public.0.into();
        for i in 0..B {
            b += self.blinding_bases[i] * secret_blindings.0[i];
        }
        KeyCommitment(b.into_affine())
    }
}

#[derive(Debug,Clone,PartialEq,Eq,Hash,CanonicalSerialize,CanonicalDeserialize)]
pub struct KeyCommitment<C: AffineRepr>(pub C);

impl<C: AffineRepr> Zeroize for KeyCommitment<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
// impl<C: AffineRepr> Drop for KeyCommitment<C> {
//     fn drop(&mut self) { self.zeroize() }
// }

impl<K,H> Signature<PedersenVrf<K,H,0>>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub fn to_publickey(&self) -> PublicKey<K> {
        PublicKey( self.compk.0.clone() )
    }
}

impl<K,H> NonBatchableSignature<PedersenVrf<K,H,0>>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub fn to_publickey(&self) -> PublicKey<K> {
        PublicKey( self.compk.0.clone() )
    }
}


#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct Scalars<SF: PrimeField,const B: usize> {
    pub(crate) keying:   SF,
    pub(crate) blindings: [SF; B],
}

impl<SF: PrimeField,const B: usize> Zeroize for Scalars<SF,B> {
    fn zeroize(&mut self) {
        self.keying.zeroize();
        for mut b in self.blindings {
            b.zeroize();
        }
    }
}
 
#[derive(Debug,Clone,CanonicalSerialize,CanonicalDeserialize)]
pub struct Affines<K,H> 
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub(crate) keyish:  K, // <P as Flavor>::KeyAffine,
    pub(crate) preoutish: H, // <P as Flavor>::PreOutAffine,
}


// --- Sign --- //

impl<K: AffineRepr> SecretKey<K> {
    pub fn new_secret_blinding<T, const B: usize>(&self, t: &T) -> SecretBlinding<K,B>
    where T: SigningTranscript+Clone
    {
        // Accessed system randomness using rand_hack(), which helps test vectors,
        // but clearly insecure otherwise. 
        let secret_blinding: [<K as AffineRepr>::ScalarField; B]
         = t.witnesses(b"MakeSecretBlinding", &[&self.nonce_seed]);
        SecretBlinding(secret_blinding)
    }
}

impl<K,H,const B: usize> PedersenVrf<K,H,B>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    pub(crate) fn new_pedersen_witness<T>(
        &self,
        t: &T,
        input: &VrfInput<H>,
        secret: &SecretKey<K>,
    ) -> Witness<PedersenVrf<K,H,B>>
    where T: SigningTranscript,
    {
        let flavor = self;
        assert_eq!(flavor.keying_base(), secret.thin.keying_base(), 
            "Internal error, incompatable keying basepoints used.");

        // We'll need two calls here until const generics lands 
         let keying: [K::ScalarField; 1]
         = t.witnesses(b"WitnessH", &[&secret.nonce_seed]);
         let blindings: [K::ScalarField; B]
         = t.witnesses(b"WitnessB", &[&secret.nonce_seed]);
        let k = Scalars { keying: keying[0], blindings, };

        let mut keyish: <K as AffineRepr>::Group = flavor.keying_base * k.keying;
        for i in 0..B {
            keyish += flavor.blinding_bases[i] * k.blindings[i];
        }
        let preoutish: <H as AffineRepr>::Group = input.0 * k.keying;
        let r = Affines {
            keyish: keyish.into_affine(),
            preoutish: preoutish.into_affine(),
        };
        Witness { r, k }
    }

    /// Sign Pedersen VRF signature
    /// 
    /// We create the secret blinding unless the user supplies one.
    pub fn sign_pedersen_vrf<T,BT>(
        &self,
        mut t: BT,
        ios: &[VrfInOut<H>],
        secret_blinding: Option<SecretBlinding<K,B>>,
        secret: &SecretKey<K>,
    ) -> (Signature<PedersenVrf<K,H,B>>, SecretBlinding<K,B>)
    where T: SigningTranscript+Clone, BT: BorrowMut<T>
    {
        let flavor = self;
        let t = t.borrow_mut();
        let io = vrf::vrfs_merge(t, ios);

        // Allow derandomization by constructing secret_blinding and
        // witness as late as possible.
        let secret_blinding = secret_blinding.unwrap_or_else( || secret.new_secret_blinding(t) );
        let compk = flavor.compute_blinded_publickey(secret.as_publickey(), &secret_blinding);
        t.append(b"KeyCommitment",&compk);

        // In principle our new secret blinding should be derandomizable
        // if the user supplied none. 
        let w = flavor.new_pedersen_witness(t,&io.input,secret);
        let signature = w.sign_final(t,&secret_blinding,secret,compk).0;
        ( signature, secret_blinding )
    }

    /// Sign a non-batchable Pedersen VRF signature
    /// 
    /// Non-batchable Pedersen VRF signatures resemble EC VRF,
    /// especially if `B=1`, except they contain the public key.
    /// We suggest thin VRF instead though for the EC VRF case when
    /// `H=K` and `B=1`.
    /// 
    /// We envision non-batchable VRF signatures being useful for
    /// proofs that public keys agree aross curves match, so when
    /// `H != K` but `B=1`.
    /// 
    /// We create the secret blinding unless the user supplies one.
    pub fn sign_non_batchable_pedersen_vrf<T,BT>(
        &self,
        mut t: BT,
        ios: &[VrfInOut<H>],
        secret_blinding: Option<SecretBlinding<K,B>>,
        secret: &SecretKey<K>,
    ) -> (NonBatchableSignature<PedersenVrf<K,H,B>>, SecretBlinding<K,B>)
    where T: SigningTranscript+Clone, BT: BorrowMut<T>
    {
        let flavor = self;
        let t = t.borrow_mut();
        let io = vrf::vrfs_merge(t, ios);

        // Allow derandomization by constructing secret_blinding and witness as late as possible.
        let secret_blinding = secret_blinding.unwrap_or_else( || secret.new_secret_blinding(t) );
        let compk = flavor.compute_blinded_publickey(secret.as_publickey(), &secret_blinding);
        t.append(b"KeyCommitment",&compk);

        let w = flavor.new_pedersen_witness(t,&io.input,secret);
        let signature = w.sign_final(t,&secret_blinding,secret,compk).1;
        ( signature, secret_blinding )
    }
}

impl<K,H,const B: usize> Witness<PedersenVrf<K,H,B>>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    /// Complete Pedersen VRF signature.
    /// 
    /// Assumes we already hashed public key, `VrfInOut`s, etc.
    /// and passes the key commitment unchanged.
    pub(crate) fn sign_final<T: SigningTranscript>(
        self,
        t: &mut T,
        secret_blindings: &SecretBlinding<K,B>,
        secret: &SecretKey<K>,
        compk: KeyCommitment<K>,
    ) -> (Signature<PedersenVrf<K,H,B>>,NonBatchableSignature<PedersenVrf<K,H,B>>) {
        let Witness { r, k } = self;
        t.append(b"Witness", &r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"PedersenVrfChallenge");
        let mut blindings = arrayvec::ArrayVec::<K::ScalarField,B>::new();
        for i in 0..B {
            blindings.push( k.blindings[i] + c * secret_blindings.0[i] );
        }
        let s = Scalars {
            keying: k.keying + secret.key.mul_by_challenge(&c),
            blindings: blindings.into_inner().unwrap(),
        };
        // k.zeroize();
        (Signature { compk: compk.clone(), r, s: s.clone() }, NonBatchableSignature { compk, c, s })
    }
}


// --- Verify --- //

impl<K,H,const B: usize> PedersenVrf<K,H,B>
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    /// Verify Pedersen VRF signature 
    pub fn verify_pedersen_vrf<'a,T,BT>(
        &self,
        mut t: BT,
        ios: &'a [VrfInOut<H>],
        signature: &Signature<PedersenVrf<K,H,B>>,
    ) -> SignatureResult<&'a [VrfInOut<H>]>
    where T: SigningTranscript+Clone, BT: BorrowMut<T>
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
        // TODO: Use an MSM here
        let mut lhs = self.keying_base.mul(signature.s.keying);
        for i in 0..B {
            lhs += self.blinding_bases[i].mul(signature.s.blindings[i]);
        }
        // TODO: Try an MSM here
        let rhs = signature.r.keyish.into_group() + signature.compk.0 * c;
        if ! crate::eq_mod_small_cofactor_projective(&lhs, &rhs) {
            return Err(SignatureError::Invalid);
        }
        Ok(ios)
    }

    /// Verify Pedersen VRF signature 
    pub fn verify_non_batchable_pedersen_vrf<'a,T,BT>(
        &self,
        mut t: BT,
        ios: &'a [VrfInOut<H>],
        signature: &NonBatchableSignature<PedersenVrf<K,H,B>>,
    ) -> SignatureResult<&'a [VrfInOut<H>]>
    where T: SigningTranscript+Clone, BT: BorrowMut<T>
    {
        let t = t.borrow_mut();
        let io = vrf::vrfs_merge(t, ios);
        t.append(b"KeyCommitment",&signature.compk);

        // Recompute Witness, but cofactors not a concern this way..
        // TODO: Use an MSM here
        let preoutish = io.input.0 * signature.s.keying - io.preoutput.0 * signature.c;
        // TODO: Try an MSM here
        let mut keyish = self.keying_base.mul(signature.s.keying);
        for i in 0..B {
            keyish += self.blinding_bases[i].mul(signature.s.blindings[i]);
        }
        keyish -= signature.compk.0 * signature.c;
        let r: Affines <K,H> = Affines {
            keyish: keyish.into_affine(),
            preoutish: preoutish.into_affine(),
        };

        t.append(b"Witness", &r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"PedersenVrfChallenge");
        if c == signature.c {
            Ok(ios)
        } else {
            return Err(SignatureError::Invalid);
        }
    }
}


