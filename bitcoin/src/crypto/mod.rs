// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.
//!

pub mod ecdsa;
pub mod key;
pub mod sighash;
pub mod sighash_zcash;
// Contents re-exported in `bitcoin::taproot`.
pub(crate) mod taproot;
