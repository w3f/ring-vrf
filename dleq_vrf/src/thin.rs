// Copyright (c) 2019-2020 Web 3 Foundation
//
// Authors:
// - Jeffrey Burdges <jeff@web3.foundation>

//! ### Thin VRF routines

use ark_std::{borrow::{Borrow,BorrowMut}, vec::Vec};
use ark_ec::{AffineRepr, CurveGroup};

use crate::{
    Transcript, IntoTranscript,
    flavor::{Flavor, InnerFlavor, Witness, Batchable},
    keys::{PublicKey, SecretKey},
    error::{SignatureResult, SignatureError},
    vrf::{self, IntoVrfInput, VrfInput, VrfInOut},
    EcVrfVerifier,EcVrfSigner,
};


/// Thin VRF flavor
#[derive(Debug,Clone,Eq,PartialEq)]
pub struct ThinVrf<C: AffineRepr> {
    pub keying_base: C,
}

impl<C: AffineRepr> Default for ThinVrf<C> {
    fn default() -> Self {
        ThinVrf { keying_base: C::generator(), }
    }
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
    fn thin_vrf_merge<B>(&self, t: &mut Transcript, public: &PublicKey<C>, ios: &[B]) -> VrfInOut<C> 
    where B: Borrow<VrfInOut<C>>,
    {
        let io = self.schnorr_io(public);
        // Append base too since we're being so polymorphic.
        t.label(b"PublicKey");
        t.append(&io);
        if ios.len() == 0 { return io }
        t.label(b"VrfInOuts");
        t.append_u64(ios.len() as u64); 
        t.append_slice(ios);
        vrf::vrfs_delinearize( t, ios.iter().map(|io| io.borrow()).chain([ &io ]) )
    }
}


// --- Sign --- //

impl<K: AffineRepr> SecretKey<K> {
    pub(crate) fn new_thin_witness(&self, t: &Transcript, input: &VrfInput<K>) -> Witness<ThinVrf<K>>
    {
        let mut reader = self.witness(t,b"thin keying only");
        let k: <K as AffineRepr>::ScalarField = reader.read_reduce();
        let r = input.0.mul(k).into_affine();
        Witness { r, k }
    }

    /// Sign thin VRF signature
    /// 
    /// If `ios = &[]` this reduces to a Schnorr signature.
    pub fn sign_thin_vrf_detached(&self, t: impl IntoTranscript, ios: &[VrfInOut<K>]) -> ThinVrfProof<K>
    {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();
        t.label(b"ThinVRF");
        let io = self.thin.thin_vrf_merge(t, self.as_publickey(), ios);
        // Allow derandomization by constructing witness late.
        self.new_thin_witness(t,&io.input).sign_final(t,self)
    }
}

impl<K: AffineRepr> Witness<ThinVrf<K>> {
    /// Complete Schnorr-like signature.
    /// 
    /// Assumes we already hashed public key, `VrfInOut`s, etc.
    pub(crate) fn sign_final(
        self, t: &mut Transcript, secret: &SecretKey<K>
    ) -> Batchable<ThinVrf<K>> {
        use zeroize::Zeroize;
        let Witness { r, mut k } = self;
        t.label(b"Thin R");
        t.append(&r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"ThinVrfChallenge").read_reduce();
        let s = k + secret.key.mul_by_challenge(&c);
        k.zeroize();  
        Batchable { compk: (), r, s }
        // TODO: Add some verify_final for additional rowhammer defenses?
        // We already hash the public key though, so no issues like Ed25519.
        // Against secret key corruption verify_final might still help, or
        // maybe our key splitting already handles this, or some new one?
        // Adjust Witness<PedersenVrf>::sign_final too if required.
    }
}


// --- Verify --- //

/*
impl<C: AffineRepr> Valid for Batchable<ThinVrf<C>> {
    fn check(&self) -> Result<(), SerializationError> {
        if self.is_on_curve() && self.is_in_correct_subgroup_assuming_on_curve() {
            Ok(())
        } else {
            Err(SerializationError::InvalidData)
        }
    }
}
*/

impl<K: AffineRepr> ThinVrf<K> {
    pub(crate) fn make_public(
        &self,
        secret: &ark_secret_scalar::SecretScalar<<K as AffineRepr>::ScalarField>
    ) -> PublicKey<K> {
        // #[cfg(feature = "getrandom")]
        let p = secret * self.keying_base();
        // #[cfg(not(feature = "getrandom"))]
        // let p = self.keying_base().mul(secret.0[0]) + self.keying_base().mul(secret.0[1]) ;
        PublicKey(p.into_affine())
    }

    /// Verify thin VRF signature 
    /// 
    /// If `ios = &[]` this reduces to a Schnorr signature.
    pub fn verify_thin_vrf<'a>(
        &self,
        t: impl IntoTranscript,
        ios: &'a [VrfInOut<K>],
        public: &PublicKey<K>,
        signature: &Batchable<ThinVrf<K>>,
    ) -> SignatureResult<&'a [VrfInOut<K>]>
    {
        let mut t = t.into_transcript();
        let t = t.borrow_mut();
        t.label(b"ThinVRF");
        // A priori, one expects thin_vrf_merge's msm could be merged
        // into the multiplication by c below, except thin_vrf_merge
        // only needs 128 bit scalar multiplications, so doing this
        // should harm performance, even when ios.len() = 1.
        let io = self.thin_vrf_merge(t, public, ios);

        // verify_final
        t.label(b"Thin R");
        t.append(&signature.r);
        let c: <K as AffineRepr>::ScalarField = t.challenge(b"ThinVrfChallenge").read_reduce();

        // TODO: Benchmark
        // let z = ark_ec::scalar_mul::variable_base::VariableBaseMSM::msm_bigint(
        //     &[io.input, io.preoutput],
        //     &[-signature.s, c],
        // ) + signature.r.into_group();
        let z = signature.r.into_group() + io.preoutput.0.mul(c) - io.input.0.mul(signature.s);
        if crate::zero_mod_small_cofactor(z) {
            Ok(ios)
        } else {
            Err(SignatureError::Invalid)
        }
    }
}


// Implement traits interface //

/// Thin VRF proof component
pub type ThinVrfProof<K> = Batchable<ThinVrf<K>>;

impl<K: AffineRepr> crate::EcVrfProof for Batchable<ThinVrf<K>> {
    type H = K;
}

impl<K: AffineRepr> EcVrfVerifier for (&ThinVrf<K>,&PublicKey<K>) {
    type Proof = ThinVrfProof<K>;
    type Error = SignatureError;
    fn vrf_verify_detached<'a>(
        &self,
        t: impl IntoTranscript,
        ios: &'a [VrfInOut<K>],
        signature: &Self::Proof,
    ) -> Result<&'a [VrfInOut<K>],SignatureError>
    {
        self.0.verify_thin_vrf(t,ios,self.1,signature)
    }
}

impl<K: AffineRepr> EcVrfVerifier for PublicKey<K> {
    type Proof = ThinVrfProof<K>;
    type Error = SignatureError;
    fn vrf_verify_detached<'a>(
        &self,
        t: impl IntoTranscript,
        ios: &'a [VrfInOut<K>],
        signature: &Self::Proof,
    ) -> Result<&'a [VrfInOut<K>],SignatureError>
    {
        crate::ThinVrf::default().verify_thin_vrf(t,ios,self,signature)
    }
}

impl<K: AffineRepr> PublicKey<K> {
    pub fn verify_thin_vrf<const N: usize>(
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<K>>,
        signature: &crate::VrfSignature<ThinVrfProof<K>,N>,
    ) -> Result<[VrfInOut<K>; N],SignatureError>
    {
        self.vrf_verify(t,inputs,signature)
    }

    pub fn verify_thin_vrf_vec(
        &self,
        t: impl IntoTranscript,
        inputs: impl IntoIterator<Item = impl IntoVrfInput<K>>,
        signature: &crate::VrfSignatureVec<ThinVrfProof<K>>,
    ) -> Result<Vec<VrfInOut<K>>,SignatureError>
    {
        self.vrf_verify_vec(t,inputs,signature)
    }
}

impl<K: AffineRepr> EcVrfSigner for SecretKey<K> {
    type Proof = ThinVrfProof<K>;
    type Error = ();
    type Secret = Self;
    fn vrf_sign_detached(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<K>]
    ) -> Result<Self::Proof,()>
    {
        Ok(self.sign_thin_vrf_detached(t,ios))
    }
}

impl<K: AffineRepr> SecretKey<K> {
    pub fn sign_thin_vrf<const N: usize>(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<K>; N]
    ) -> crate::VrfSignature<ThinVrfProof<K>,N>
    {
        self.vrf_sign(t,ios).unwrap() // "Infalible"
    }

    pub fn sign_thin_vrf_one<I,T,F>(&self, input: I, check: F)
     -> Result<crate::VrfSignature<ThinVrfProof<K>,1>,()>
    where
        I: IntoVrfInput<K>,
        T: IntoTranscript,
        F: FnMut(&VrfInOut<K>) -> Result<T,()>,
    {
        self.vrf_sign_one(input,check)
    }

    pub fn sign_thin_vrf_vec(
        &self,
        t: impl IntoTranscript,
        ios: &[VrfInOut<K>]
    ) -> crate::VrfSignatureVec<ThinVrfProof<K>>
    {
        self.vrf_sign_vec(t,ios).unwrap() // "Infalible"
    }
}
