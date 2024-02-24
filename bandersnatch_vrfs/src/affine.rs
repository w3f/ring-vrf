use ark_ff::MontFp;
use ark_ec::{short_weierstrass::{self, SWCurveConfig, SWFlags}, CurveConfig};
use ark_serialize::{Compress, Read, SerializationError, Validate, Write};
use crate::bandersnatch::{BandersnatchConfig as BandersnatchConfigBase, SWAffine as AffineBase};

pub const COMPRESSED_POINT_SIZE: usize = 32;

pub type BandersnatchAffine = short_weierstrass::Affine<BandersnatchConfig>;

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

    fn serialize_with_mode<W: Write>(
        item: &BandersnatchAffine,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        let base = AffineBase::new_unchecked(item.x, item.y);
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
        Ok(BandersnatchAffine::new(base.x, base.y))
    }

    #[inline(always)]
    fn serialized_size(compress: Compress) -> usize {
        match compress {
            Compress::Yes => 32,
            Compress::No => BandersnatchConfigBase::serialized_size(compress),
        }
    }
}
