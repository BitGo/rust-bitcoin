// SPDX-License-Identifier: CC0-1.0

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used by Bitcoin that can be roundtrip (de)serialized.

use core::str::FromStr;
use core::{fmt, iter};

use hex::FromHex;
use internals::write_err;
use io::Write;

use crate::prelude::*;
use crate::script::PushBytes;
use crate::sighash::{EcdsaSighashType, NonStandardSighashTypeError};

const MAX_SIG_LEN: usize = 73;

/// An ECDSA signature with the corresponding hash type.
///
/// The `sighash_type` is stored as a raw `u32` to support non-standard sighash types
/// such as Bitcoin Cash's SIGHASH_FORKID (0x40). Use [`ecdsa_hash_ty`](Self::ecdsa_hash_ty)
/// to extract the standard [`EcdsaSighashType`] when needed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Signature {
    /// The underlying ECDSA Signature.
    pub signature: secp256k1::ecdsa::Signature,
    /// The corresponding hash type (raw value, may include non-standard flags like FORKID).
    pub sighash_type: u32,
}

impl Signature {
    /// Constructs an ECDSA Bitcoin signature for [`EcdsaSighashType::All`].
    pub fn sighash_all(signature: secp256k1::ecdsa::Signature) -> Signature {
        Signature { signature, sighash_type: EcdsaSighashType::All as u32 }
    }

    /// Deserializes from slice, accepting any sighash type (including non-standard values like FORKID).
    ///
    /// This accepts non-standard sighash types to support Bitcoin Cash's SIGHASH_FORKID.
    /// Use [`ecdsa_hash_ty`](Self::ecdsa_hash_ty) to extract the standard type when needed.
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        let (sighash_byte, sig) = sl.split_last().ok_or(Error::EmptySignature)?;
        let signature = secp256k1::ecdsa::Signature::from_der(sig).map_err(Error::Secp256k1)?;
        Ok(Signature { signature, sighash_type: *sighash_byte as u32 })
    }

    /// Returns the base ECDSA sighash type, stripping non-standard flags like FORKID.
    ///
    /// This extracts the standard [`EcdsaSighashType`] by masking out FORKID (0x40)
    /// and other non-standard bits, keeping only the base type (0x1f) and ANYONECANPAY (0x80).
    ///
    /// # Errors
    ///
    /// Returns an error if the base type (after masking flags) is not a standard type.
    pub fn ecdsa_hash_ty(&self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        // Strip FORKID (0x40) and keep only base type (0x1f) + ANYONECANPAY (0x80)
        let base = self.sighash_type & 0x1f;
        let anyonecanpay = (self.sighash_type & 0x80) != 0;

        use EcdsaSighashType::*;
        let base_type = match base {
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            _ => return Err(NonStandardSighashTypeError(self.sighash_type)),
        };

        Ok(if anyonecanpay {
            match base_type {
                All => AllPlusAnyoneCanPay,
                None => NonePlusAnyoneCanPay,
                Single => SinglePlusAnyoneCanPay,
                _ => unreachable!(),
            }
        } else {
            base_type
        })
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format).
    ///
    /// This does **not** perform extra heap allocation.
    pub fn serialize(&self) -> SerializedSignature {
        let mut buf = [0u8; MAX_SIG_LEN];
        let signature = self.signature.serialize_der();
        buf[..signature.len()].copy_from_slice(&signature);
        buf[signature.len()] = self.sighash_type as u8;
        SerializedSignature { data: buf, len: signature.len() + 1 }
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format) into `Vec`.
    ///
    /// Note: this performs an extra heap allocation, you might prefer the
    /// [`serialize`](Self::serialize) method instead.
    pub fn to_vec(self) -> Vec<u8> {
        self.signature
            .serialize_der()
            .iter()
            .copied()
            .chain(iter::once(self.sighash_type as u8))
            .collect()
    }

    /// Serializes an ECDSA signature (inner secp256k1 signature in DER format) to a `writer`.
    #[inline]
    pub fn serialize_to_writer<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        let sig = self.serialize();
        sig.write_to(writer)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.signature.serialize_der().as_hex(), f)?;
        fmt::LowerHex::fmt(&[self.sighash_type as u8].as_hex(), f)
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::from_hex(s)?;
        let (sighash_byte, signature) = bytes.split_last().ok_or(Error::EmptySignature)?;
        Ok(Signature {
            signature: secp256k1::ecdsa::Signature::from_der(signature)?,
            sighash_type: *sighash_byte as u32,
        })
    }
}

/// Holds signature serialized in-line (not in `Vec`).
///
/// This avoids allocation and allows proving maximum size of the signature (73 bytes).
/// The type can be used largely as a byte slice. It implements all standard traits one would
/// expect and has familiar methods.
/// However, the usual use case is to push it into a script. This can be done directly passing it
/// into [`push_slice`](crate::script::ScriptBuf::push_slice).
#[derive(Copy, Clone)]
pub struct SerializedSignature {
    data: [u8; MAX_SIG_LEN],
    len: usize,
}

impl SerializedSignature {
    /// Returns an iterator over bytes of the signature.
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, u8> { self.into_iter() }

    /// Writes this serialized signature to a `writer`.
    #[inline]
    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(self)
    }
}

impl core::ops::Deref for SerializedSignature {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target { &self.data[..self.len] }
}

impl core::ops::DerefMut for SerializedSignature {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.data[..self.len] }
}

impl AsRef<[u8]> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] { self }
}

impl AsMut<[u8]> for SerializedSignature {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] { self }
}

impl AsRef<PushBytes> for SerializedSignature {
    #[inline]
    fn as_ref(&self) -> &PushBytes { &<&PushBytes>::from(&self.data)[..self.len()] }
}

impl core::borrow::Borrow<[u8]> for SerializedSignature {
    #[inline]
    fn borrow(&self) -> &[u8] { self }
}

impl core::borrow::BorrowMut<[u8]> for SerializedSignature {
    #[inline]
    fn borrow_mut(&mut self) -> &mut [u8] { self }
}

impl fmt::Debug for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl fmt::Display for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl fmt::LowerHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&(**self).as_hex(), f)
    }
}

impl fmt::UpperHex for SerializedSignature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&(**self).as_hex(), f)
    }
}

impl PartialEq for SerializedSignature {
    #[inline]
    fn eq(&self, other: &SerializedSignature) -> bool { **self == **other }
}

impl Eq for SerializedSignature {}

impl core::hash::Hash for SerializedSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { core::hash::Hash::hash(&**self, state) }
}

impl<'a> IntoIterator for &'a SerializedSignature {
    type IntoIter = core::slice::Iter<'a, u8>;
    type Item = &'a u8;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { (*self).iter() }
}

/// An ECDSA signature-related error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Hex decoding error.
    Hex(hex::HexToBytesError),
    /// Non-standard sighash type.
    SighashType(NonStandardSighashTypeError),
    /// Signature was empty.
    EmptySignature,
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Hex(ref e) => write_err!(f, "signature hex decoding error"; e),
            SighashType(ref e) => write_err!(f, "non-standard signature hash type"; e),
            EmptySignature => write!(f, "empty ECDSA signature"),
            Secp256k1(ref e) => write_err!(f, "secp256k1"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Hex(ref e) => Some(e),
            Secp256k1(ref e) => Some(e),
            SighashType(ref e) => Some(e),
            EmptySignature => None,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self { Self::Secp256k1(e) }
}

impl From<NonStandardSighashTypeError> for Error {
    fn from(e: NonStandardSighashTypeError) -> Self { Self::SighashType(e) }
}

impl From<hex::HexToBytesError> for Error {
    fn from(e: hex::HexToBytesError) -> Self { Self::Hex(e) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_serialized_signature() {
        let hex = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
        let sig = Signature {
            signature: secp256k1::ecdsa::Signature::from_str(hex).unwrap(),
            sighash_type: EcdsaSighashType::All as u32,
        };

        let mut buf = vec![];
        sig.serialize_to_writer(&mut buf).expect("write failed");

        assert_eq!(sig.to_vec(), buf)
    }

    #[test]
    fn ecdsa_hash_ty_standard() {
        // Test standard sighash types
        for (raw, expected) in [
            (0x01, EcdsaSighashType::All),
            (0x02, EcdsaSighashType::None),
            (0x03, EcdsaSighashType::Single),
            (0x81, EcdsaSighashType::AllPlusAnyoneCanPay),
            (0x82, EcdsaSighashType::NonePlusAnyoneCanPay),
            (0x83, EcdsaSighashType::SinglePlusAnyoneCanPay),
        ] {
            let sig = Signature {
                signature: secp256k1::ecdsa::Signature::from_str(
                    "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45"
                ).unwrap(),
                sighash_type: raw,
            };
            assert_eq!(sig.ecdsa_hash_ty().unwrap(), expected);
        }
    }

    #[test]
    fn ecdsa_hash_ty_forkid() {
        // Test FORKID sighash types (Bitcoin Cash)
        const SIGHASH_FORKID: u32 = 0x40;

        for (raw, expected) in [
            (0x01 | SIGHASH_FORKID, EcdsaSighashType::All), // 0x41
            (0x02 | SIGHASH_FORKID, EcdsaSighashType::None), // 0x42
            (0x03 | SIGHASH_FORKID, EcdsaSighashType::Single), // 0x43
            (0x81 | SIGHASH_FORKID, EcdsaSighashType::AllPlusAnyoneCanPay), // 0xc1
            (0x82 | SIGHASH_FORKID, EcdsaSighashType::NonePlusAnyoneCanPay), // 0xc2
            (0x83 | SIGHASH_FORKID, EcdsaSighashType::SinglePlusAnyoneCanPay), // 0xc3
        ] {
            let sig = Signature {
                signature: secp256k1::ecdsa::Signature::from_str(
                    "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45"
                ).unwrap(),
                sighash_type: raw,
            };
            assert_eq!(sig.ecdsa_hash_ty().unwrap(), expected, "raw=0x{:02x}", raw);
        }
    }

    #[test]
    fn from_slice_accepts_forkid() {
        // Signature with SIGHASH_ALL | SIGHASH_FORKID (0x41)
        let sig_bytes = Vec::from_hex(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab4541"
        ).unwrap();
        let sig = Signature::from_slice(&sig_bytes).expect("should accept FORKID");
        assert_eq!(sig.sighash_type, 0x41);
        assert_eq!(sig.ecdsa_hash_ty().unwrap(), EcdsaSighashType::All);
    }
}
