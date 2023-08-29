
use ark_std::vec::Vec;
use ark_serialize::{CanonicalSerialize}; 
use ark_ec::{AffineRepr,pairing::Pairing};

// #[macro_use]
use ark_scale::{
    ArkScaleMaxEncodedLen,MaxEncodedLen,
    impl_decode_via_ark,
    impl_encode_via_ark,
    scale::{Encode,Decode,EncodeLike}
};

use crate::{
    PublicKeyG1,
    Signature,
    AggregationKey,
    AggregateSignature,
    ThinVrf,PedersenVrf,
};



impl<P: Pairing> Decode for PublicKeyG1<P> {
    impl_decode_via_ark!();
}

impl<P: Pairing> Encode for PublicKeyG1<P> {
    impl_encode_via_ark!();
}

impl<P: Pairing> EncodeLike for PublicKeyG1<P> {}

impl<P: Pairing> MaxEncodedLen for PublicKeyG1<P> {
    #[inline]
    fn max_encoded_len() -> usize {
        <<P as Pairing>::G1Affine as AffineRepr>::zero().compressed_size()
    }
}


impl<P: Pairing> Decode for Signature<P> {
    impl_decode_via_ark!();
}

impl<P: Pairing> Encode for Signature<P> {
    impl_encode_via_ark!();
}

impl<P: Pairing> EncodeLike for Signature<P> {}

impl<P: Pairing> MaxEncodedLen for Signature<P> 
where <P as Pairing>::ScalarField: ArkScaleMaxEncodedLen
{
    #[inline]
    fn max_encoded_len() -> usize {
        <<P as Pairing>::G1Affine as AffineRepr>::zero().compressed_size()
        + <dleq_vrf::NonBatchable<ThinVrf<P>> as ArkScaleMaxEncodedLen>::max_encoded_len()
    }
}


impl<P: Pairing> Decode for AggregationKey<P> {
    impl_decode_via_ark!();
}

impl<P: Pairing> Encode for AggregationKey<P> {
    impl_encode_via_ark!();
}

impl<P: Pairing> EncodeLike for AggregationKey<P> {}

impl<P: Pairing> MaxEncodedLen for AggregationKey<P> {
    #[inline]
    fn max_encoded_len() -> usize {
        <<P as Pairing>::G2Affine as AffineRepr>::zero().compressed_size()
        + <dleq_vrf::NonBatchable<PedersenVrf<P>> as ArkScaleMaxEncodedLen>::max_encoded_len()
    }
}


impl<P: Pairing> Decode for AggregateSignature<P> {
    impl_decode_via_ark!();
}

impl<P: Pairing> Encode for AggregateSignature<P> {
    impl_encode_via_ark!();
}

impl<P: Pairing> EncodeLike for AggregateSignature<P> {}

impl<P: Pairing> MaxEncodedLen for AggregateSignature<P> {
    #[inline]
    fn max_encoded_len() -> usize {
        <<P as Pairing>::G1Affine as AffineRepr>::zero().compressed_size()
        + <<P as Pairing>::G2Affine as AffineRepr>::zero().compressed_size()
    }
}

