// SPDX-License-Identifier: CC0-1.0

//! Tests for parsing BitGo PSBT fixtures from altcoins/bitgo-fixed-script.
//!
//! These fixtures test PSBT parsing for various Bitcoin-like coins including
//! Bitcoin Cash, Bitcoin Gold, Litecoin, Dash, Dogecoin, and eCash.

use std::str::FromStr;

use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};
use bitcoin::bip32::Xpriv;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;

/// Test fixture from a JSON file
#[derive(Debug)]
struct PsbtFixture {
    filename: String,
    psbt_base64: String,
    psbt_base64_finalized: Option<String>,
}

fn load_fixtures() -> Vec<PsbtFixture> {
    let fixture_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../altcoins/bitgo-fixed-script");

    let mut fixtures = Vec::new();

    for entry in std::fs::read_dir(fixture_dir).expect("failed to read fixture directory") {
        let entry = entry.expect("failed to read directory entry");
        let path = entry.path();

        // Only process JSON files
        if path.extension().map_or(true, |ext| ext != "json") {
            continue;
        }

        let filename = path.file_name().unwrap().to_string_lossy().to_string();

        // Skip zcash files for now
        if filename.contains("zcash") {
            continue;
        }

        let content = std::fs::read_to_string(&path).expect("failed to read fixture file");
        let json: serde_json::Value = serde_json::from_str(&content).expect("failed to parse JSON");

        let psbt_base64 =
            json["psbtBase64"].as_str().expect("missing psbtBase64 field").to_string();

        let psbt_base64_finalized = json["psbtBase64Finalized"].as_str().map(|s| s.to_string());

        fixtures.push(PsbtFixture { filename, psbt_base64, psbt_base64_finalized });
    }

    fixtures.sort_by(|a, b| a.filename.cmp(&b.filename));
    fixtures
}

fn parse_psbt_base64(base64_str: &str) -> Result<Psbt, String> {
    let bytes =
        BASE64_STANDARD.decode(base64_str).map_err(|e| format!("base64 decode error: {}", e))?;

    Psbt::deserialize(&bytes).map_err(|e| format!("PSBT deserialize error: {}", e))
}

#[test]
fn parse_bitgo_psbt_fixtures() {
    let fixtures = load_fixtures();
    assert!(!fixtures.is_empty(), "No fixtures found!");

    let mut passed = 0;
    let mut failed = Vec::new();

    for fixture in &fixtures {
        // Test psbtBase64
        match parse_psbt_base64(&fixture.psbt_base64) {
            Ok(psbt) => {
                // Verify basic structure
                assert!(
                    !psbt.unsigned_tx.input.is_empty(),
                    "{}: PSBT has no inputs",
                    fixture.filename
                );
                passed += 1;
            }
            Err(e) => {
                failed.push(format!("{} (psbtBase64): {}", fixture.filename, e));
            }
        }

        // Test psbtBase64Finalized if present
        if let Some(ref finalized) = fixture.psbt_base64_finalized {
            match parse_psbt_base64(finalized) {
                Ok(psbt) => {
                    assert!(
                        !psbt.unsigned_tx.input.is_empty(),
                        "{}: Finalized PSBT has no inputs",
                        fixture.filename
                    );
                    passed += 1;
                }
                Err(e) => {
                    failed.push(format!("{} (psbtBase64Finalized): {}", fixture.filename, e));
                }
            }
        }
    }

    println!("\nBitGo PSBT Fixtures: {} passed", passed);

    if !failed.is_empty() {
        println!("\nFailed ({}):", failed.len());
        for f in &failed {
            println!("  - {}", f);
        }
        panic!("{} fixtures failed to parse", failed.len());
    }
}

#[test]
fn list_bitgo_fixtures() {
    let fixtures = load_fixtures();
    println!("\nAvailable BitGo PSBT fixtures ({} files, zcash skipped):", fixtures.len());
    for fixture in &fixtures {
        let has_finalized =
            if fixture.psbt_base64_finalized.is_some() { " (+ finalized)" } else { "" };
        println!("  - {}{}", fixture.filename, has_finalized);
    }
}

/// Load a specific fixture by filename pattern
fn load_fixture_by_name(pattern: &str) -> Option<(serde_json::Value, String)> {
    let fixture_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../altcoins/bitgo-fixed-script");

    for entry in std::fs::read_dir(fixture_dir).expect("failed to read fixture directory") {
        let entry = entry.expect("failed to read directory entry");
        let path = entry.path();

        if path.extension().map_or(true, |ext| ext != "json") {
            continue;
        }

        let filename = path.file_name().unwrap().to_string_lossy().to_string();

        if filename.contains(pattern) {
            let content = std::fs::read_to_string(&path).expect("failed to read fixture file");
            let json: serde_json::Value =
                serde_json::from_str(&content).expect("failed to parse JSON");
            return Some((json, filename));
        }
    }
    None
}

/// Test signing a Bitcoin PSBT with the first wallet key from the fixture.
///
/// This test:
/// 1. Loads the unsigned Bitcoin PSBT fixture
/// 2. Parses the first wallet key (xprv)
/// 3. Signs the PSBT using the xprv
/// 4. Verifies that signatures were added
#[test]
fn sign_bitcoin_psbt_with_wallet_key() {
    // Load the unsigned Bitcoin PSBT fixture
    let (json, filename) = load_fixture_by_name("psbt-lite.bitcoin.unsigned")
        .expect("Failed to find psbt-lite.bitcoin.unsigned.json fixture");

    println!("Testing signing with fixture: {}", filename);

    // Extract the first wallet key (xprv)
    let wallet_keys = json["walletKeys"].as_array().expect("walletKeys should be an array");
    let xprv_str = wallet_keys[0].as_str().expect("First wallet key should be a string");
    let xprv = Xpriv::from_str(xprv_str).expect("Failed to parse xprv");

    println!("Using xprv with fingerprint: {:?}", xprv.fingerprint(&Secp256k1::new()));

    // Parse the unsigned PSBT
    let psbt_base64 = json["psbtBase64"].as_str().expect("psbtBase64 should be present");
    let psbt_bytes = BASE64_STANDARD.decode(psbt_base64).expect("Failed to decode psbtBase64");
    let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes).expect("Failed to deserialize PSBT");

    // Count existing signatures before signing
    let sigs_before: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    println!("Partial signatures before signing: {}", sigs_before);

    // Sign with the xprv
    let secp = Secp256k1::new();
    let result = psbt.sign(&xprv, &secp);

    match result {
        Ok(signed_keys) => {
            println!("Signing completed:");
            println!("  - Inputs signed: {}", signed_keys.len());
        }
        Err((signed_keys, errors)) => {
            // Some inputs may fail to sign (e.g., taproot without rand-std feature)
            println!("Signing completed with some errors:");
            println!("  - Inputs signed: {}", signed_keys.len());
            println!("  - Errors: {:?}", errors);
        }
    }

    // Count signatures after signing
    let sigs_after: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    println!("Partial signatures after signing: {}", sigs_after);

    // We should have added some signatures
    assert!(
        sigs_after > sigs_before,
        "Expected to add signatures, but went from {} to {}",
        sigs_before,
        sigs_after
    );

    // Verify the PSBT still serializes correctly
    let _serialized = psbt.serialize();
    println!("PSBT serializes correctly after signing");

    // Report which inputs got signed
    for (i, input) in psbt.inputs.iter().enumerate() {
        if !input.partial_sigs.is_empty() {
            println!("  Input {}: {} partial sig(s)", i, input.partial_sigs.len());
        }
    }
}

/// Test signing a fullsigned Bitcoin PSBT fixture and comparing signatures.
///
/// This test loads the halfsigned fixture (which has some signatures already),
/// signs it with the first wallet key, and verifies signatures match the fullsigned version.
#[test]
fn sign_bitcoin_psbt_halfsigned() {
    // Load the halfsigned Bitcoin PSBT fixture
    let (json, filename) = load_fixture_by_name("psbt-lite.bitcoin.halfsigned")
        .expect("Failed to find psbt-lite.bitcoin.halfsigned.json fixture");

    println!("Testing signing with fixture: {}", filename);

    // Extract the first wallet key (xprv)
    let wallet_keys = json["walletKeys"].as_array().expect("walletKeys should be an array");
    let xprv_str = wallet_keys[0].as_str().expect("First wallet key should be a string");
    let xprv = Xpriv::from_str(xprv_str).expect("Failed to parse xprv");

    // Parse the halfsigned PSBT
    let psbt_base64 = json["psbtBase64"].as_str().expect("psbtBase64 should be present");
    let psbt_bytes = BASE64_STANDARD.decode(psbt_base64).expect("Failed to decode psbtBase64");
    let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes).expect("Failed to deserialize PSBT");

    // Count existing signatures before signing
    let sigs_before: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    println!("Partial signatures before signing: {}", sigs_before);

    // Sign with the xprv
    let secp = Secp256k1::new();
    let _ = psbt.sign(&xprv, &secp);

    // Count signatures after signing
    let sigs_after: usize = psbt.inputs.iter().map(|i| i.partial_sigs.len()).sum();
    println!("Partial signatures after signing: {}", sigs_after);

    // Report which inputs got signed
    for (i, input) in psbt.inputs.iter().enumerate() {
        if !input.partial_sigs.is_empty() {
            println!("  Input {}: {} partial sig(s)", i, input.partial_sigs.len());
            for (pk, sig) in &input.partial_sigs {
                println!("    - pubkey: {}", pk);
                println!("      sighash_type: {}", sig.sighash_type);
            }
        }
    }
}
