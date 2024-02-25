//! Definition of `SWCurveConfig` for compact points serialization.
//!
//! Our serialization technique works for any point in the curve excluded for `p = (x = 0, y)`.
//!
//! The point `p = (x = 0, y)` is a point in the curve but not in the prime order subgroup.
//! Such a point is not considered valid by the arkworks decoding procedures when `Validate::Yes`.

use ark_ff::MontFp;
use ark_ec::{short_weierstrass::{self, SWCurveConfig, SWFlags}, CurveConfig};
use ark_serialize::{Compress, Read, SerializationError, Validate, Write};
use ark_std::vec::Vec;
use crate::bandersnatch::{BandersnatchConfig as BandersnatchConfigBase, SWAffine as AffineBase, SWProjective as ProjectiveBase};

pub const COMPRESSED_POINT_SIZE: usize = 32;

pub type BandersnatchAffine = short_weierstrass::Affine<BandersnatchConfig>;
pub type BandersnatchProjective = short_weierstrass::Projective<BandersnatchConfig>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct BandersnatchConfig;

const SW_GENERATOR_X: <BandersnatchConfig as CurveConfig>::BaseField =
    MontFp!("30900340493481298850216505686589334086208278925799850409469406976849338430199");

const SW_GENERATOR_Y: <BandersnatchConfig as CurveConfig>::BaseField =
    MontFp!("12663882780877899054958035777720958383845500985908634476792678820121468453298");

impl CurveConfig for BandersnatchConfig {
    type BaseField = <BandersnatchConfigBase as CurveConfig>::BaseField;
    type ScalarField = <BandersnatchConfigBase as CurveConfig>::ScalarField;

    const COFACTOR: &'static [u64] = <BandersnatchConfigBase as CurveConfig>::COFACTOR;
    const COFACTOR_INV: Self::ScalarField = <BandersnatchConfigBase as CurveConfig>::COFACTOR_INV;
}

impl SWCurveConfig for BandersnatchConfig {
    const COEFF_A: Self::BaseField = <BandersnatchConfigBase as SWCurveConfig>::COEFF_A;
    const COEFF_B: Self::BaseField = <BandersnatchConfigBase as SWCurveConfig>::COEFF_B;
    const GENERATOR: BandersnatchAffine = BandersnatchAffine::new_unchecked(SW_GENERATOR_X, SW_GENERATOR_Y);
    
    #[inline(always)]
    fn msm(bases: &[BandersnatchAffine], scalars: &[Self::ScalarField]) -> Result<BandersnatchProjective, usize> {
        let bases: Vec<_> = bases.into_iter().map(|b| {
            AffineBase { x: b.x, y: b.y, infinity: b.infinity }
        }).collect();
        BandersnatchConfigBase::msm(&bases, scalars).map(|p| {
            BandersnatchProjective { x: p.x, y: p.y, z: p.z }
        })
    }

    #[inline(always)]
    fn mul_projective(base: &BandersnatchProjective, scalar: &[u64]) -> BandersnatchProjective {
        let base = ProjectiveBase { x: base.x, y: base.y, z: base.z };
        let res = BandersnatchConfigBase::mul_projective(&base, scalar);
        BandersnatchProjective { x: res.x, y: res.y, z: res.z }
    }

    fn serialize_with_mode<W: Write>(
        item: &BandersnatchAffine,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        let base = AffineBase { x: item.x, y: item.y, infinity: item.infinity };
        match compress {
            Compress::Yes => {
                let mut buf = [0_u8; 33];
                BandersnatchConfigBase::serialize_with_mode(&base, buf.as_mut_slice(), compress)?;
            	buf[31] |= buf[32] & SWFlags::YIsNegative as u8;
                writer.write_all(&buf[..32]).map_err(|_| SerializationError::InvalidData)
            }
            Compress::No => {
                BandersnatchConfigBase::serialize_with_mode(&base, writer, compress)
            }
        }
    }

    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<BandersnatchAffine, SerializationError> {
        let base = match compress {
            Compress::Yes => {
                let mut buf = [0_u8; 33];
                reader.read_exact(&mut buf[..32])?;
	            if buf.iter().all(|&b| b == 0) {
		            buf[32] |= SWFlags::PointAtInfinity as u8;
            	} else if buf[31] & SWFlags::YIsNegative as u8 != 0 {
            		buf[32] |= SWFlags::YIsNegative as u8;
            	}
            	buf[31] &= 0x7f;
                BandersnatchConfigBase::deserialize_with_mode(buf.as_slice(), compress, validate)
            }
            Compress::No => {
                BandersnatchConfigBase::deserialize_with_mode(reader, compress, validate)
            }
        }?;
        Ok(BandersnatchAffine { x: base.x, y: base.y, infinity: base.infinity })
    }

    #[inline(always)]
    fn serialized_size(compress: Compress) -> usize {
        match compress {
            Compress::Yes => 32,
            Compress::No => BandersnatchConfigBase::serialized_size(compress),
        }
    }
}

#[cfg(all(test, feature = "getrandom"))]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use rand_core;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid};

    // We assume that the point encoded with all zeros is the point at infinity.
    //
    // The point `p = (x = 0, y != 0)` is a valid point on the curve but it is not considered
    // valid (`p.check()` fails) as it has an order not equal to `BandersnatchConfig::ScalarField`.
    // 
    // Assess the backend assumptions (i.e. `BandersnatchConfig` which ships with arkworks).
    #[test]
    fn assumptions_check() {
        let mut buf = [0_u8; 33];

        // Positive y
        let err = BandersnatchConfigBase::deserialize_with_mode(buf.as_slice(), Compress::Yes, Validate::Yes).unwrap_err();
        assert!(matches!(err, SerializationError::InvalidData));
        let p = BandersnatchConfigBase::deserialize_with_mode(buf.as_slice(), Compress::Yes, Validate::No).unwrap();
        assert!(matches!(p.check().unwrap_err(), SerializationError::InvalidData));
        assert!(p.is_on_curve());
        // Checks that `p = (0, y)` is NOT in the subgroup with order defined by `BandersnatchConfig::ScalarField`.
        assert!(!p.is_in_correct_subgroup_assuming_on_curve());
        let p = p.clear_cofactor();
        assert!(p.check().is_ok());

        // Negative y
        buf[32] |= SWFlags::YIsNegative as u8;
        let err = BandersnatchConfigBase::deserialize_with_mode(buf.as_slice(), Compress::Yes, Validate::Yes).unwrap_err();
        assert!(matches!(err, SerializationError::InvalidData));
        let p = BandersnatchConfigBase::deserialize_with_mode(buf.as_slice(), Compress::Yes, Validate::No).unwrap();
        assert!(matches!(p.check().unwrap_err(), SerializationError::InvalidData));
        assert!(p.is_on_curve());
        // Checks that `p = (0, y)` is NOT in the subgroup with order defined by `BandersnatchConfig::ScalarField`.
        assert!(!p.is_in_correct_subgroup_assuming_on_curve());
        let p = p.clear_cofactor();
        assert!(p.check().is_ok());       
    }

    #[test]
    fn serialization_works() {
        let mut rng = rand_core::OsRng;
        let mut buf = [0u8; 32];

        let e = BandersnatchAffine::identity();
        e.serialize_compressed(buf.as_mut_slice()).unwrap();
        assert_eq!(buf, [0; 32]);
        let e2 = BandersnatchAffine::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(e, e2);
        assert!(e2.is_zero());
        
        let mut p = BandersnatchAffine::rand(&mut rng);
        assert_eq!(p.compressed_size(), COMPRESSED_POINT_SIZE);
        p.serialize_compressed(buf.as_mut_slice()).unwrap();
        let expected = if p.y <= -p.y { SWFlags::YIsPositive } else { SWFlags::YIsNegative };
        assert_eq!(expected as u8, buf[31] & SWFlags::YIsNegative as u8 );
        let p2 = BandersnatchAffine::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(p, p2);

        p.y = -p.y;
        p.serialize_compressed(buf.as_mut_slice()).unwrap();
        let expected = if p.y <= -p.y { SWFlags::YIsPositive } else { SWFlags::YIsNegative };
        assert_eq!(expected as u8, buf[31] & SWFlags::YIsNegative as u8 );
        let p2 = BandersnatchAffine::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(p, p2);
    }
}
