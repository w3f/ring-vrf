
use ark_std::vec::Vec;
use ark_serialize::{CanonicalSerialize}; 
use ark_ec::AffineRepr;

// #[macro_use]
use ark_scale::{
    ArkScaleMaxEncodedLen,MaxEncodedLen,
    impl_decode_via_ark,
    impl_encode_via_ark,
    impl_body_max_encode_len,
    scale::{Encode,Decode,EncodeLike}
};

use crate::{
    VrfPreOut,PublicKey,
    pedersen::KeyCommitment,
    // ThinVrf,PedersenVrf,
    flavor::{Flavor,InnerFlavor},
    traits::{EcVrfVerifier,VrfSignature,VrfSignatureVec},
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


impl<V: EcVrfVerifier+?Sized> Decode for VrfSignatureVec<V> {
    impl_decode_via_ark!();
}

impl<V: EcVrfVerifier+?Sized> Encode for VrfSignatureVec<V> {
    impl_encode_via_ark!();
}

impl<V: EcVrfVerifier+?Sized> EncodeLike for VrfSignatureVec<V> {}


impl<V: EcVrfVerifier+?Sized, const N: usize> Decode for VrfSignature<V,N> {
    impl_decode_via_ark!();
}

impl<V: EcVrfVerifier+?Sized, const N: usize> Encode for VrfSignature<V,N> {
    impl_encode_via_ark!();
}

impl<V: EcVrfVerifier+?Sized, const N: usize> EncodeLike for VrfSignature<V,N> {}

impl<V: EcVrfVerifier+?Sized, const N: usize> MaxEncodedLen for VrfSignature<V,N> 
where <V as EcVrfVerifier>::VrfProof: ArkScaleMaxEncodedLen
{
    fn max_encoded_len() -> usize {
        let o = <<V as EcVrfVerifier>::H as AffineRepr>::zero().compressed_size();
        N * o + <<V as EcVrfVerifier>::VrfProof as ArkScaleMaxEncodedLen>::max_encoded_len()
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


impl<F: Flavor> ArkScaleMaxEncodedLen for crate::Signature<F>
where
    <F as InnerFlavor>::KeyCommitment: ArkScaleMaxEncodedLen,
    <F as InnerFlavor>::Scalars: ArkScaleMaxEncodedLen,
    <F as InnerFlavor>::Affines: ArkScaleMaxEncodedLen,
{
    fn max_encoded_len() -> usize {
        <<F as InnerFlavor>::KeyCommitment as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <<F as InnerFlavor>::Scalars as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <<F as InnerFlavor>::Affines as ArkScaleMaxEncodedLen>::max_encoded_len()
    }
}

impl<F: Flavor> ArkScaleMaxEncodedLen for crate::NonBatchable<F>
where
    <F as InnerFlavor>::KeyCommitment: ArkScaleMaxEncodedLen,
    <F as InnerFlavor>::Scalars: ArkScaleMaxEncodedLen,
{
    fn max_encoded_len() -> usize {
        <<F as InnerFlavor>::KeyCommitment as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <<F as InnerFlavor>::Scalars as ArkScaleMaxEncodedLen>::max_encoded_len()
        + <<F as Flavor>::ScalarField as ark_ff::Zero>::zero().compressed_size()
    }
}



