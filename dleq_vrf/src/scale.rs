
use ark_std::vec::Vec;
use ark_serialize::{CanonicalSerialize}; 
use ark_ec::AffineRepr;

// #[macro_use]
pub use ark_scale::{
    ArkScale,ArkScaleRef,
    ArkScaleMaxEncodedLen,MaxEncodedLen,
    impl_decode_via_ark,
    impl_encode_via_ark,
    scale::{Encode,Decode,EncodeLike}
};

use crate::{
    VrfPreOut,PublicKey,
    pedersen::KeyCommitment,
    // ThinVrf,PedersenVrf,
    flavor::{Flavor, InnerFlavor},
    traits::{VrfSignature, VrfSignatureVec, EcVrfProofBound},
};


macro_rules! impl_point_wrapper {
    ($t:ident) => {

impl<C: AffineRepr> Decode for $t<C> {
    impl_decode_via_ark!();
}

impl<C: AffineRepr> Encode for $t<C> {
    impl_encode_via_ark!();
}

impl<C: AffineRepr> EncodeLike for $t<C> {}

impl<C: AffineRepr> MaxEncodedLen for $t<C> {
    #[inline]
    fn max_encoded_len() -> usize {
        <C as AffineRepr>::zero().compressed_size()
    }
}

impl<C: AffineRepr> ArkScaleMaxEncodedLen for $t<C> {
    #[inline]
    fn max_encoded_len() -> usize {
        <C as AffineRepr>::zero().compressed_size()
    }
}

    }
} // macro_rules! impl_point_wrapper

impl_point_wrapper!(PublicKey);
impl_point_wrapper!(VrfPreOut);
impl_point_wrapper!(KeyCommitment);


impl<P: EcVrfProofBound, H: AffineRepr, const N: usize> Decode for VrfSignature<P, H, N> {
    impl_decode_via_ark!();
}

impl<P: EcVrfProofBound, H: AffineRepr, const N: usize> Encode for VrfSignature<P, H, N> {
    impl_encode_via_ark!();
}

impl<P: EcVrfProofBound, H: AffineRepr, const N: usize> EncodeLike for VrfSignature<P, H, N> {}


impl<P: EcVrfProofBound, H: AffineRepr> Decode for VrfSignatureVec<P, H> {
    impl_decode_via_ark!();
}

impl<P: EcVrfProofBound, H: AffineRepr> Encode for VrfSignatureVec<P, H> {
    impl_encode_via_ark!();
}

impl<P: EcVrfProofBound, H: AffineRepr> EncodeLike for VrfSignatureVec<P, H> {}


impl<P: EcVrfProofBound + ArkScaleMaxEncodedLen, H: AffineRepr, const N: usize> MaxEncodedLen for VrfSignature<P, H, N>  {
    fn max_encoded_len() -> usize {
        let o = H::zero().compressed_size();
        N * o + <P as ArkScaleMaxEncodedLen>::max_encoded_len()
    }
}

impl<SF: ark_ff::PrimeField,const B: usize> ArkScaleMaxEncodedLen for crate::pedersen::Scalars<SF,B> {
    fn max_encoded_len() -> usize {
        B * <SF as ark_ff::Zero>::zero().compressed_size()
    }
}

impl<K,H> ArkScaleMaxEncodedLen for crate::pedersen::Affines<K,H> 
where K: AffineRepr, H: AffineRepr<ScalarField = K::ScalarField>,
{
    fn max_encoded_len() -> usize {
        <K as AffineRepr>::zero().compressed_size()
        + <H as AffineRepr>::zero().compressed_size()
    }
}


impl<F: Flavor> ArkScaleMaxEncodedLen for crate::Batchable<F>
where
    <F as InnerFlavor>::KeyCommitment: ArkScaleMaxEncodedLen,
    // <F as InnerFlavor>::Scalars: ArkScaleMaxEncodedLen,
    <F as InnerFlavor>::Affines: ArkScaleMaxEncodedLen,
{
    fn max_encoded_len() -> usize {
        <<F as InnerFlavor>::KeyCommitment as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <F as InnerFlavor>::Scalars::default().compressed_size()
        // + <<F as InnerFlavor>::Scalars as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <<F as InnerFlavor>::Affines as ArkScaleMaxEncodedLen>::max_encoded_len()
    }
}

impl<F: Flavor> ArkScaleMaxEncodedLen for crate::NonBatchable<F>
where
    <F as InnerFlavor>::KeyCommitment: ArkScaleMaxEncodedLen,
    // <F as InnerFlavor>::Scalars: ArkScaleMaxEncodedLen,
{
    fn max_encoded_len() -> usize {
        <<F as InnerFlavor>::KeyCommitment as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <F as InnerFlavor>::Scalars::default().compressed_size()
        // + <<F as InnerFlavor>::Scalars as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <<F as Flavor>::ScalarField as ark_ff::Zero>::zero().compressed_size()
    }
}



