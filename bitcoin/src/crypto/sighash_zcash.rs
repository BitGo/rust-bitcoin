// SPDX-License-Identifier: CC0-1.0

//! ZIP-243 Zcash Sighash Implementation
//!
//! This module provides signature hash computation for Zcash transparent inputs
//! according to [ZIP-243](https://zips.z.cash/zip-0243).
//!
//! The implementation uses BLAKE2b-256 with personalization strings as specified
//! by the Zcash protocol.

use core::borrow::Borrow;
use core::fmt;

use blake2::digest::core_api::{Buffer, UpdateCore};
use blake2::digest::Output;
use blake2::Blake2bVarCore;

// Import SighashCache from the sibling sighash module
use super::sighash::SighashCache;
use crate::consensus::encode::{Encodable, VarInt};
use crate::prelude::*;
use crate::{transaction, Amount, Script, Transaction};

/// Hash of a transaction according to ZIP-243 (Zcash Sapling) signature algorithm.
/// Uses BLAKE2b-256 with personalization "ZcashSigHash" || consensus_branch_id
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZcashSighash([u8; 32]);

impl ZcashSighash {
    /// Creates a `ZcashSighash` from a 32-byte array.
    pub fn from_byte_array(bytes: [u8; 32]) -> Self { Self(bytes) }

    /// Returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; 32] { self.0 }

    /// Returns a reference to the underlying byte array.
    pub fn as_byte_array(&self) -> &[u8; 32] { &self.0 }
}

impl From<ZcashSighash> for secp256k1::Message {
    fn from(hash: ZcashSighash) -> secp256k1::Message {
        secp256k1::Message::from_digest(hash.to_byte_array())
    }
}

impl fmt::Debug for ZcashSighash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZcashSighash({:?})", &self.0[..])
    }
}

impl fmt::Display for ZcashSighash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Extension trait that adds Zcash sighash methods to [`super::SighashCache`].
pub trait SighashCacheZcashExt<T: Borrow<Transaction>> {
    /// Compute ZIP-243 sighash for P2PKH inputs (Zcash transparent)
    ///
    /// # Arguments
    /// * `input_index` - Index of input being signed
    /// * `script_pubkey` - The scriptPubKey of the output being spent
    /// * `value` - Value of the output being spent
    /// * `sighash_type` - Sighash type (typically SIGHASH_ALL = 1)
    /// * `consensus_branch_id` - Zcash network upgrade branch ID
    /// * `version_group_id` - Zcash transaction version group ID (0x892F2085 for Sapling v4)
    /// * `expiry_height` - Transaction expiry height
    ///
    /// # ZIP-243 Reference
    /// https://zips.z.cash/zip-0243
    fn p2pkh_signature_hash_zcash(
        &mut self,
        input_index: usize,
        script_pubkey: &Script,
        value: Amount,
        sighash_type: u32,
        consensus_branch_id: u32,
        version_group_id: u32,
        expiry_height: u32,
    ) -> Result<ZcashSighash, transaction::InputsIndexError>;

    /// Compute ZIP-243 sighash for P2SH inputs (Zcash transparent)
    ///
    /// # Arguments
    /// * `input_index` - Index of input being signed
    /// * `redeem_script` - The redeemScript for P2SH
    /// * `value` - Value of the output being spent
    /// * `sighash_type` - Sighash type (typically SIGHASH_ALL = 1)
    /// * `consensus_branch_id` - Zcash network upgrade branch ID
    /// * `version_group_id` - Zcash transaction version group ID (0x892F2085 for Sapling v4)
    /// * `expiry_height` - Transaction expiry height
    fn p2sh_signature_hash_zcash(
        &mut self,
        input_index: usize,
        redeem_script: &Script,
        value: Amount,
        sighash_type: u32,
        consensus_branch_id: u32,
        version_group_id: u32,
        expiry_height: u32,
    ) -> Result<ZcashSighash, transaction::InputsIndexError>;
}

impl<T: Borrow<Transaction>> SighashCacheZcashExt<T> for SighashCache<T> {
    fn p2pkh_signature_hash_zcash(
        &mut self,
        input_index: usize,
        script_pubkey: &Script,
        value: Amount,
        sighash_type: u32,
        consensus_branch_id: u32,
        version_group_id: u32,
        expiry_height: u32,
    ) -> Result<ZcashSighash, transaction::InputsIndexError> {
        zcash_signature_hash_internal(
            self.transaction(),
            input_index,
            script_pubkey,
            value,
            sighash_type,
            consensus_branch_id,
            version_group_id,
            expiry_height,
        )
    }

    fn p2sh_signature_hash_zcash(
        &mut self,
        input_index: usize,
        redeem_script: &Script,
        value: Amount,
        sighash_type: u32,
        consensus_branch_id: u32,
        version_group_id: u32,
        expiry_height: u32,
    ) -> Result<ZcashSighash, transaction::InputsIndexError> {
        zcash_signature_hash_internal(
            self.transaction(),
            input_index,
            redeem_script,
            value,
            sighash_type,
            consensus_branch_id,
            version_group_id,
            expiry_height,
        )
    }
}

/// Internal implementation of ZIP-243 sighash
fn zcash_signature_hash_internal(
    tx: &Transaction,
    input_index: usize,
    script_code: &Script,
    value: Amount,
    sighash_type: u32,
    consensus_branch_id: u32,
    version_group_id: u32,
    expiry_height: u32,
) -> Result<ZcashSighash, transaction::InputsIndexError> {
    // Validate input index
    if input_index >= tx.input.len() {
        return Err(transaction::InputsIndexError(transaction::IndexOutOfBoundsError {
            index: input_index,
            length: tx.input.len(),
        }));
    }

    // Build personalization: "ZcashSigHash" || consensus_branch_id (little-endian)
    let mut personalization = [0u8; 16];
    personalization[..12].copy_from_slice(b"ZcashSigHash");
    personalization[12..16].copy_from_slice(&consensus_branch_id.to_le_bytes());

    // Compute hashPrevouts
    let hash_prevouts = if (sighash_type & 0x80) == 0 {
        // Not ANYONECANPAY
        zcash_hash_prevouts(tx)
    } else {
        [0u8; 32]
    };

    // Compute hashSequence
    let hash_sequence = if (sighash_type & 0x80) == 0
        && (sighash_type & 0x1f) != 2 // Not NONE
        && (sighash_type & 0x1f) != 3
    // Not SINGLE
    {
        zcash_hash_sequence(tx)
    } else {
        [0u8; 32]
    };

    // Compute hashOutputs
    let hash_outputs = match sighash_type & 0x1f {
        2 => [0u8; 32], // NONE
        3 => {
            // SINGLE
            if input_index < tx.output.len() {
                zcash_hash_single_output(tx, input_index)
            } else {
                [0u8; 32]
            }
        }
        _ => zcash_hash_outputs(tx), // ALL
    };

    // For transparent-only transactions, these are all zeros
    let hash_join_splits = [0u8; 32];
    let hash_shielded_spends = [0u8; 32];
    let hash_shielded_outputs = [0u8; 32];

    // Build the preimage using BLAKE2b-256 with personalization
    let mut data = Vec::with_capacity(256);

    // 1. Header (fOverwintered || nVersion) - 4 bytes
    // For Sapling (v4), this is 0x80000004
    let header = (tx.version.0 as u32) | 0x80000000;
    data.extend_from_slice(&header.to_le_bytes());

    // 2. nVersionGroupId - 4 bytes
    data.extend_from_slice(&version_group_id.to_le_bytes());

    // 3. hashPrevouts - 32 bytes
    data.extend_from_slice(&hash_prevouts);

    // 4. hashSequence - 32 bytes
    data.extend_from_slice(&hash_sequence);

    // 5. hashOutputs - 32 bytes
    data.extend_from_slice(&hash_outputs);

    // 6. hashJoinSplits - 32 bytes (zeros for transparent-only)
    data.extend_from_slice(&hash_join_splits);

    // 7. hashShieldedSpends - 32 bytes (zeros for transparent-only)
    data.extend_from_slice(&hash_shielded_spends);

    // 8. hashShieldedOutputs - 32 bytes (zeros for transparent-only)
    data.extend_from_slice(&hash_shielded_outputs);

    // 9. nLockTime - 4 bytes
    data.extend_from_slice(&tx.lock_time.to_consensus_u32().to_le_bytes());

    // 10. nExpiryHeight - 4 bytes
    data.extend_from_slice(&expiry_height.to_le_bytes());

    // 11. valueBalance - 8 bytes (0 for transparent-only)
    data.extend_from_slice(&0i64.to_le_bytes());

    // 12. nHashType - 4 bytes
    data.extend_from_slice(&sighash_type.to_le_bytes());

    // Per-input data (only for the input being signed):
    // 13. prevout - 36 bytes (txid + index)
    let input = &tx.input[input_index];
    data.extend_from_slice(input.previous_output.txid.as_ref());
    data.extend_from_slice(&input.previous_output.vout.to_le_bytes());

    // 14. scriptCode - variable
    let script_bytes = script_code.as_bytes();
    // Write compact size
    VarInt::from(script_bytes.len())
        .consensus_encode(&mut data)
        .expect("in-memory writers don't error");
    data.extend_from_slice(script_bytes);

    // 15. amount - 8 bytes
    data.extend_from_slice(&value.to_sat().to_le_bytes());

    // 16. nSequence - 4 bytes
    data.extend_from_slice(&input.sequence.0.to_le_bytes());

    // Hash with BLAKE2b-256 and personalization
    let result = blake2b_256_personal(&data, &personalization);

    Ok(ZcashSighash::from_byte_array(result))
}

/// Compute BLAKE2b-256 hash of all prevouts for ZIP-243
fn zcash_hash_prevouts(tx: &Transaction) -> [u8; 32] {
    let mut data = Vec::with_capacity(tx.input.len() * 36);

    for input in &tx.input {
        data.extend_from_slice(input.previous_output.txid.as_ref());
        data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
    }

    blake2b_256_personal(&data, b"ZcashPrevoutHash")
}

/// Compute BLAKE2b-256 hash of all sequences for ZIP-243
fn zcash_hash_sequence(tx: &Transaction) -> [u8; 32] {
    let mut data = Vec::with_capacity(tx.input.len() * 4);

    for input in &tx.input {
        data.extend_from_slice(&input.sequence.0.to_le_bytes());
    }

    blake2b_256_personal(&data, b"ZcashSequencHash")
}

/// Compute BLAKE2b-256 hash of all outputs for ZIP-243
fn zcash_hash_outputs(tx: &Transaction) -> [u8; 32] {
    let mut data = Vec::new();

    for output in &tx.output {
        data.extend_from_slice(&output.value.to_sat().to_le_bytes());
        let script_bytes = output.script_pubkey.as_bytes();
        VarInt::from(script_bytes.len())
            .consensus_encode(&mut data)
            .expect("in-memory writers don't error");
        data.extend_from_slice(script_bytes);
    }

    blake2b_256_personal(&data, b"ZcashOutputsHash")
}

/// Compute BLAKE2b-256 hash of a single output for SIGHASH_SINGLE
fn zcash_hash_single_output(tx: &Transaction, index: usize) -> [u8; 32] {
    let mut data = Vec::new();

    let output = &tx.output[index];
    data.extend_from_slice(&output.value.to_sat().to_le_bytes());
    let script_bytes = output.script_pubkey.as_bytes();
    VarInt::from(script_bytes.len())
        .consensus_encode(&mut data)
        .expect("in-memory writers don't error");
    data.extend_from_slice(script_bytes);

    blake2b_256_personal(&data, b"ZcashOutputsHash")
}

/// Compute BLAKE2b-256 hash with personalization for Zcash (ZIP-243).
pub(crate) fn blake2b_256_personal(data: &[u8], personalization: &[u8]) -> [u8; 32] {
    let mut core = Blake2bVarCore::new_with_params(&[], personalization, 0, 32);
    // Use the Lazy buffer for all data so the last block is retained in the buffer
    // until finalize, ensuring the correct finalization flag even when data.len()
    // is an exact multiple of the 128-byte BLAKE2b block size.
    let mut buffer: Buffer<Blake2bVarCore> = Default::default();
    buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));

    // Finalize
    let mut full_output: Output<Blake2bVarCore> = Default::default();
    blake2::digest::core_api::VariableOutputCore::finalize_variable_core(
        &mut core,
        &mut buffer,
        &mut full_output,
    );

    // Take the first 32 bytes (left truncation for BLAKE2b)
    let mut result = [0u8; 32];
    result.copy_from_slice(&full_output[..32]);
    result
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hex::FromHex;

    use super::*;
    use crate::blockdata::locktime::absolute;
    use crate::blockdata::witness::Witness;
    use crate::{OutPoint, ScriptBuf, Sequence, TxIn, TxOut};

    #[test]
    fn test_zcash_sighash_basic() {
        // Test basic Zcash sighash computation
        // This uses a simple transaction to verify the BLAKE2b-256 hash computation
        let tx = Transaction {
            version: transaction::Version(4),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000001:0",
                )
                .unwrap(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_hex(
                    "76a914000000000000000000000000000000000000000088ac",
                )
                .unwrap(),
            }],
        };

        let script_pubkey =
            ScriptBuf::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
        let value = Amount::from_sat(200_000);

        // Sapling consensus branch ID and version group ID
        let consensus_branch_id: u32 = 0x76b809bb;
        let version_group_id: u32 = 0x892F2085; // Sapling
        let expiry_height: u32 = 0;

        let mut cache = SighashCache::new(&tx);
        let result = cache
            .p2pkh_signature_hash_zcash(
                0,
                &script_pubkey,
                value,
                0x01, // SIGHASH_ALL
                consensus_branch_id,
                version_group_id,
                expiry_height,
            )
            .expect("sighash computation should succeed");

        // The result should be a valid 32-byte hash
        assert_eq!(result.to_byte_array().len(), 32);

        // Test that the hash is deterministic
        let mut cache2 = SighashCache::new(&tx);
        let result2 = cache2
            .p2pkh_signature_hash_zcash(
                0,
                &script_pubkey,
                value,
                0x01,
                consensus_branch_id,
                version_group_id,
                expiry_height,
            )
            .unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_zcash_hash_personalization() {
        // Test that different personalization strings produce different hashes
        let data = b"test data";

        let hash1 = blake2b_256_personal(data, b"ZcashPrevoutHash");
        let hash2 = blake2b_256_personal(data, b"ZcashSequencHash");
        let hash3 = blake2b_256_personal(data, b"ZcashOutputsHash");

        // All hashes should be different due to different personalization
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);

        // Same personalization and data should produce same hash
        let hash1_again = blake2b_256_personal(data, b"ZcashPrevoutHash");
        assert_eq!(hash1, hash1_again);
    }

    #[test]
    fn test_zcash_sighash_invalid_index() {
        let tx = Transaction {
            version: transaction::Version(4),
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let script_pubkey = ScriptBuf::new();
        let value = Amount::from_sat(0);
        let consensus_branch_id: u32 = 0x76b809bb;
        let version_group_id: u32 = 0x892F2085;
        let expiry_height: u32 = 0;

        let mut cache = SighashCache::new(&tx);
        let result = cache.p2pkh_signature_hash_zcash(
            0, // Invalid: no inputs
            &script_pubkey,
            value,
            0x01,
            consensus_branch_id,
            version_group_id,
            expiry_height,
        );

        assert!(result.is_err());
    }

    /// Test using ZIP-243 Test Vector 3 (transparent-only transaction)
    /// Source: https://zips.z.cash/zip-0243#test-vector-3
    #[test]
    fn test_zip243_vector3_transparent_only() {
        use crate::Txid;

        // ZIP-243 Test Vector 3: Testnet transparent-only transaction
        // txid: 97d8814886d07fc12bbac90c089a10f90906cbb53402ee26e576ef99276c492d

        // Build the transaction that matches the test vector
        // Input: spending from a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9:1
        // The txid in ZIP-243 is in internal byte order (little-endian), but Txid::from_str
        // expects display order (big-endian/reversed), so we reverse it:
        let prev_txid =
            Txid::from_str("d9042195d9a1b65b2f1f79d68ceb1a5ea6459c9651a6ad4dc1f465824785c6a8")
                .unwrap();

        let tx = Transaction {
            version: transaction::Version(4), // Sapling version
            lock_time: absolute::LockTime::from_consensus(307241), // 0x0004b029
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 1 },
                script_sig: ScriptBuf::new(), // Empty for unsigned tx
                sequence: Sequence(0xfffffffe),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(40_000_000), // 0.4 ZEC
                    script_pubkey: ScriptBuf::from_hex(
                        "76a9148132712c3ff19f3a151234616777420a6d7ef22688ac",
                    )
                    .unwrap(),
                },
                TxOut {
                    value: Amount::from_sat(9_999_755), // Remainder
                    script_pubkey: ScriptBuf::from_hex(
                        "76a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac",
                    )
                    .unwrap(),
                },
            ],
        };

        // The scriptCode for signing (P2PKH scriptPubKey of the output being spent)
        let script_code =
            ScriptBuf::from_hex("76a914507173527b4c3318a2aecd793bf1cfed705950cf88ac").unwrap();

        // Amount of the output being spent: 0.5 ZEC = 50_000_000 satoshis
        let amount = Amount::from_sat(50_000_000);

        // Sapling consensus branch ID and version group ID
        let consensus_branch_id: u32 = 0x76b809bb;
        let version_group_id: u32 = 0x892F2085; // Sapling

        // Expiry height from the test vector: 307272 (0x0004b048)
        let expiry_height: u32 = 307272;

        // Compute the sighash
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2pkh_signature_hash_zcash(
                0,                   // input index
                &script_code,        // scriptCode
                amount,              // amount
                0x01,                // SIGHASH_ALL
                consensus_branch_id, // Sapling branch ID
                version_group_id,    // Sapling version group ID
                expiry_height,       // expiry height
            )
            .expect("sighash computation should succeed");

        // Expected sighash from ZIP-243 Test Vector 3
        let expected_bytes: [u8; 32] =
            FromHex::from_hex("f3148f80dfab5e573d5edfe7a850f5fd39234f80b5429d3a57edcc11e34c585b")
                .unwrap();

        assert_eq!(
            sighash.to_byte_array(),
            expected_bytes,
            "ZIP-243 Test Vector 3 sighash mismatch"
        );
    }

    /// Test the intermediate hash values (hashPrevouts, hashSequence, hashOutputs)
    /// from ZIP-243 Test Vector 3
    #[test]
    fn test_zip243_vector3_intermediate_hashes() {
        use crate::Txid;

        // Same transaction as above
        let prev_txid =
            Txid::from_str("d9042195d9a1b65b2f1f79d68ceb1a5ea6459c9651a6ad4dc1f465824785c6a8")
                .unwrap();

        let tx = Transaction {
            version: transaction::Version(4),
            lock_time: absolute::LockTime::from_consensus(307241),
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 1 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xfffffffe),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(40_000_000),
                    script_pubkey: ScriptBuf::from_hex(
                        "76a9148132712c3ff19f3a151234616777420a6d7ef22688ac",
                    )
                    .unwrap(),
                },
                TxOut {
                    value: Amount::from_sat(9_999_755),
                    script_pubkey: ScriptBuf::from_hex(
                        "76a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac",
                    )
                    .unwrap(),
                },
            ],
        };

        // Test hashPrevouts
        let hash_prevouts = zcash_hash_prevouts(&tx);
        let expected_prevouts: [u8; 32] =
            FromHex::from_hex("fae31b8dec7b0b77e2c8d6b6eb0e7e4e55abc6574c26dd44464d9408a8e33f11")
                .unwrap();
        assert_eq!(hash_prevouts, expected_prevouts, "hashPrevouts mismatch");

        // Test hashSequence
        let hash_sequence = zcash_hash_sequence(&tx);
        let expected_sequence: [u8; 32] =
            FromHex::from_hex("6c80d37f12d89b6f17ff198723e7db1247c4811d1a695d74d930f99e98418790")
                .unwrap();
        assert_eq!(hash_sequence, expected_sequence, "hashSequence mismatch");

        // Test hashOutputs
        let hash_outputs = zcash_hash_outputs(&tx);
        let expected_outputs: [u8; 32] =
            FromHex::from_hex("d2b04118469b7810a0d1cc59568320aad25a84f407ecac40b4f605a4e6868454")
                .unwrap();
        assert_eq!(hash_outputs, expected_outputs, "hashOutputs mismatch");
    }

    /// Regression test: blake2b_256_personal must produce the correct hash when the
    /// input length is an exact multiple of the 128-byte BLAKE2b block size.
    ///
    /// The old implementation fed all complete blocks to `update_blocks` and left the
    /// buffer empty for `finalize_variable_core`, which then compressed a spurious
    /// all-zero block — producing a wrong hash for any block-aligned input.
    #[test]
    fn test_blake2b_256_personal_block_aligned() {
        // Expected values computed with Python hashlib:
        //   hashlib.blake2b(data, digest_size=32, person=b"ZcashOutputsHash").hexdigest()
        let persona = b"ZcashOutputsHash";

        // 256 bytes = 2 × block size
        let data256 = vec![0xabu8; 256];
        let expected256: [u8; 32] =
            FromHex::from_hex("f2cee55bab0bc6b421a97e26b7c55f63f22fea6cf5fbc5ad1c290872bd470f3e")
                .unwrap();
        assert_eq!(
            blake2b_256_personal(&data256, persona),
            expected256,
            "wrong hash for 256-byte (2-block) input"
        );

        // 128 bytes = 1 × block size
        let data128 = vec![0xabu8; 128];
        let expected128: [u8; 32] =
            FromHex::from_hex("8e802425ab1d83222d0bcf18140d61ae70670796be480fdd50b3027a3ca5478d")
                .unwrap();
        assert_eq!(
            blake2b_256_personal(&data128, persona),
            expected128,
            "wrong hash for 128-byte (1-block) input"
        );

        // 100 bytes (non-aligned) — sanity check that the fix didn't break the common case
        let data100 = vec![0xabu8; 100];
        let expected100: [u8; 32] =
            FromHex::from_hex("3df66bd2c00b813fff6119fde7464294eab4fbecc311dd18c2bddeb6120d97f7")
                .unwrap();
        assert_eq!(
            blake2b_256_personal(&data100, persona),
            expected100,
            "wrong hash for 100-byte (non-aligned) input"
        );
    }
}
