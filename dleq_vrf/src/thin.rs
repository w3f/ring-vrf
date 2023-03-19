// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Thin VRF routines

use ark_ec::{AffineRepr, CurveGroup};

use crate::{
    SigningTranscript, 
    flavor::{Flavor, InnerFlavor, Witness, Signature},
    keys::{PublicKey, SecretKey, SecretPair},
    error::{SignatureResult, SignatureError},
    vrf::{self, VrfInput, VrfInOut},
};

use core::borrow::{Borrow,BorrowMut};


/// Thin VRF flavor
#[derive(Debug,Clone)]
pub struct ThinVrf<C: AffineRepr> {
    pub keying_base: C,
}


impl<C: AffineRepr> Flavor for ThinVrf<C> {
    type ScalarField = <C as AffineRepr>::ScalarField;
    type KeyAffine = C;
    type PreOutAffine = C;

    fn keying_base(&self) -> &C { &self.keying_base }
}

impl<C: AffineRepr> InnerFlavor for ThinVrf<C> {
    type KeyCommitment = ();
    type Scalars = <C as AffineRepr>::ScalarField;
    type Affines = C;
}


impl<C: AffineRepr> ThinVrf<C> {
    /// Attach a public key to its base point.
    fn schnorr_io(&self, public: &PublicKey<C>) -> VrfInOut<C> {
        VrfInOut {
            input: VrfInput( self.keying_base.clone() ),
            preoutput: vrf::VrfPreOut( public.0.clone() ),
        }
    }

    /// Merge VRF operation which incorporates the public key.
    fn thin_vrf_merge<T,B>(&self, t: &mut T, public: &PublicKey<C>, ios: &[B]) -> VrfInOut<C> 
    where T: SigningTranscript+Clone, B: Borrow<VrfInOut<C>>,
    {
        let io = self.schnorr_io(public);
        // Append base too since we're being so polymorphic.
        t.append(b"PublicKey",&io);
        if ios.len() == 0 { return io }
        t.append_u64(b"IOs",ios.len() as u64); 
        t.append_slice(b"VrfInOut", ios);
        vrf::vrfs_delinearize( t, ios.iter().map(|io| io.borrow()).chain([ &io ]) )
    }
}


// --- Sign --- //

impl<K: AffineRepr> SecretKey<K> {
    pub(crate) fn new_thin_witness<T>(&self, t: &T, input: &VrfInput<K>) -> Witness<ThinVrf<K>>
    where T: SigningTranscript
    {
        let k: [<K as AffineRepr>::ScalarField; 1]
         = t.witnesses(b"WitnessK", &[&self.nonce_seed]);
        let k = k[0];
        let r = input.0.mul(k).into_affine();
        Witness { r, k }
    }

    /// Sign thin VRF signature
    /// 
    /// If `ios = &[]` this reduces to a Schnorr signature.
    pub fn sign_thin_vrf<T,B>(&self, mut t: B, ios: &[VrfInOut<K>]) -> Signature<ThinVrf<K>>
    where T: SigningTranscript+Clone, B: BorrowMut<T>
    {
        let t = t.borrow_mut();
        let io = self.thin.thin_vrf_merge(t, self.as_publickey(), ios);
        // Allow derandomization by constructing witness late.
        self.new_thin_witness(t,&io.input).sign_final(t,self)
    }
}

impl<K: AffineRepr> Witness<ThinVrf<K>> {
    /// Complete Schnorr-like signature.
    /// 
    /// Assumes we already hashed public key, `VrfInOut`s, etc.
    pub(crate) fn sign_final<T: SigningTranscript>(
        self, t: &mut T, secret: &SecretKey<K>
    ) -> Signature<ThinVrf<K>> {
        let Witness { r, k } = self;
        t.append(b"Witness", &r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"ThinVrfChallenge");
        let s = k + secret.key.mul_by_challenge(&c);
        // k.zeroize();
        Signature { compk: (), r, s }
    }
}

/*
impl<C: AffineRepr> Valid for Signature<ThinVrf<C>> {
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

impl<K: AffineRepr> ThinVrf<K> {
    pub(crate) fn make_public(&self, secret: &mut SecretPair<<K as AffineRepr>::ScalarField>) -> PublicKey<K> {
        PublicKey( (secret * self.keying_base()).into_affine() )
    }

    /// Verify thin VRF signature 
    /// 
    /// If `ios = &[]` this reduces to a Schnorr signature.
    pub fn verify_thin_vrf<'a,T,B>(
        &self,
        mut t: B,
        ios: &'a [VrfInOut<K>],
        public: &PublicKey<K>,
        signature: &Signature<ThinVrf<K>>,
    ) -> SignatureResult<&'a [VrfInOut<K>]>
    where T: SigningTranscript+Clone, B: BorrowMut<T>
    {
        let t = t.borrow_mut();
        // A priori, one expects thin_vrf_merge's msm could be merged
        // into the multiplication by c below, except thin_vrf_merge
        // only needs 128 bit scalar multiplications, so doing this
        // should only boosts performance when ios.len() = 2.
        let io = self.thin_vrf_merge(t, public, ios);

        // verify_final
        t.append(b"Witness", &signature.r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"ThinVrfChallenge");

        let lhs = io.input.0.mul(signature.s);
        let rhs = signature.r.into_group() + io.preoutput.0.mul(c);
        if crate::eq_mod_small_cofactor_projective(&lhs, &rhs) {
            Ok(ios)
        } else {
            Err(SignatureError::Invalid)
        }
    }
}

