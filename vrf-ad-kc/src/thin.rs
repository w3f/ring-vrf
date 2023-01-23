// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Thin VRF routines

use ark_ec::{AffineCurve, ProjectiveCurve};

use rand_core::{RngCore,CryptoRng};

use crate::{
    SigningTranscript,
    keys::{PublicKey, SecretKey, VrfAffineCurve},
    error::{SignatureResult, SignatureError},
    vrf::{self, VrfInput, VrfPreOut, VrfInOut},
};

use core::borrow::{Borrow,BorrowMut};


impl<C: VrfAffineCurve> VrfInput<C> {
    pub(crate) fn flexi_witness<T,R>(self, t: &T, secret: &SecretKey<C>, rng: R) -> ThinVrfSecretNonce<C>
    where T: SigningTranscript, R: RngCore+CryptoRng
    {
        let k: [<C as AffineCurve>::ScalarField; 1] = t.witnesses(b"ThinVrfSecretNoncees", &[&secret.nonce_seed], rng);
        let k = k[0];
        let r = self.0.mul(k).into_affine();
        ThinVrfSecretNonce { r, k }
    }
}

/// Secret and public nonce/witness for doing one thin VRF signature,
/// obvoiusly usable only once ever.
pub(crate) struct ThinVrfSecretNonce<C: VrfAffineCurve> {
    pub(crate) r: C,
    pub(crate) k: <C as AffineCurve>::ScalarField,
}

impl<C: VrfAffineCurve> ThinVrfSecretNonce<C> {
    /// Complete Schnorr-like signature.
    /// 
    /// Assumes we already hashed public key, `VrfInOut`s, etc.
    pub(crate) fn sign_final<T: SigningTranscript>(
        self, t: &mut T, secret: &SecretKey<C>
    ) -> ThinVrfSignature<C> { 
        let ThinVrfSecretNonce { r, k } = self;
        t.append(b"Witness", &r);
        let c: <C as AffineCurve>::ScalarField = t.challenge(b"Challenge");
        ThinVrfSignature { r, s: k + c * secret.key }
    }
}

impl<C: VrfAffineCurve> VrfInOut<C> {
    /// Verify Schnorr-like signature 
    /// 
    /// Assumes we already hashed public key, `VrfInOut`s, etc.
    /// 
    // TODO:  We'll likely merge `verify_final` with `verify_thin_vrf`
    // but right now lets see if anything else comes up.
    pub(crate) fn verify_final<T: SigningTranscript>(
        &self, t: &mut T, signature: &ThinVrfSignature<C>
    ) -> SignatureResult<()> {
        t.append(b"ThinVrfSecretNonce", &signature.r);
        let c: <C as AffineCurve>::ScalarField = t.challenge(b"ThinVrfChallenge");
        let lhs = self.input.0.mul(signature.s);
        let rhs = signature.r.into_projective() + self.preoutput.0.mul(c);
        if lhs == rhs { // TODO: Apply .mul(<<C as AffineCurve>::Projective as ProjectiveCurve>::COFACTOR)
            Ok(())
        } else {
            Err(SignatureError::Invalid)
        }
    }
}

/// Thin VRF signature
pub struct ThinVrfSignature<C: VrfAffineCurve> {
    pub(crate) r: C,
    pub(crate) s: <C as AffineCurve>::ScalarField,
}

impl<C: VrfAffineCurve> PublicKey<C> {
    /// Attach a public key to its base point.
    fn schnorr_io(&self) -> VrfInOut<C> {
        VrfInOut {
            input: VrfInput( C::publickey_base_affine() ),
            preoutput: VrfPreOut( self.0.clone() ),
        }
    }

    /// Merge VRF operation which incorporates the public key.
    fn thin_vrf_merge<T,B>(&self, t: &mut T, ios: &[B]) -> VrfInOut<C> 
    where T: SigningTranscript+Clone, B: Borrow<VrfInOut<C>>,
    {
        let io = self.schnorr_io();
        // Append base too since we're being so polymorphic.
        t.append(b"PublicKey",&io);
        if ios.len() == 0 { return io }
        t.append_u64(b"IOs",ios.len() as u64); 
        t.append_slice(b"VrfInOut", ios);
        vrf::vrfs_delinearize( t, ios.iter().map(|io| io.borrow()).chain([ &io ]) )
    }
}

impl<C: VrfAffineCurve> SecretKey<C> {
    /// Sign thin VRF signature
    /// 
    /// If `ios = &[]` this reduces to a Schnorr signature.
    pub fn sign_thin_vrf<T,B,R>(&self, mut t: B, ios: &[VrfInOut<C>], rng: R) -> ThinVrfSignature<C>
    where T: SigningTranscript+Clone, B: BorrowMut<T>, R: RngCore+CryptoRng
    {
        let t = t.borrow_mut();
        let io = self.as_publickey().thin_vrf_merge(t, ios);
        // Allow derandomization by constructing witness late.
        let w = io.input.flexi_witness(t,&self,rng);
        w.sign_final(t,self)
    }
}

impl<C: VrfAffineCurve> ThinVrfSignature<C> {
    /// Verify thin VRF signature 
    /// 
    /// If `ios = &[]` this reduces to a Schnorr signature.
    pub fn verify_thin_vrf<'a,T,B>(&self, mut t: B, ios: &'a [VrfInOut<C>], public: &PublicKey<C>) -> SignatureResult<&'a [VrfInOut<C>]>
    where T: SigningTranscript+Clone, B: BorrowMut<T>
    {
        let t = t.borrow_mut();
        public.thin_vrf_merge(t, ios).verify_final(t,self).map(|()| ios)
    }

}


