# ZIP-243 Test Vectors

Source: https://zips.z.cash/zip-0243

## Test Vector 1 (Shielded-only, no transparent inputs)

This transaction has NO transparent inputs (vin: 00), so it's not useful for testing
transparent sighash computation.

**Expected sighash** (with nIn = NOT_AN_INPUT, SIGHASH_ALL): `63d18534de5f2d1c9e169b73f9c783718adbef5c8a7d55b5e7a37affa1dd3ff3`

---

## Test Vector 2 (Mixed: 2 transparent inputs + shielded outputs)

**Transaction Header:**
- header: `04000080`
- nVersionGroupId: `85202f89` 
- nLockTime: `d7034302` (0x020343d7 = 33866711)
- nExpiryHeight: `011b9a07` (0x079a1b01 = 127671041)
- valueBalance: `6620edc067ff0200`

**Transparent Inputs (vin: 02):**
1. Input 0:
   - txid: `0bbe32a598c22adfb48cef72ba5d4287c0cefbacfd8ce195b4963c34a94bba7a`
   - vout: `175dae4b` (little-endian: 0x4bae5d17)
   - scriptSig: `0465ac6563`
   - nSequence: `53708915`

2. Input 1:
   - txid: `090f47a068e227433f9e49d3aa09e356d8d66d0c0121e91a3c4aa3f27fa1b633`
   - vout: `96e2b41d` (little-endian: 0x1db4e296)
   - scriptSig: `090063535300ac53ac51`
   - nSequence: `4e970568`

**Expected values (nIn = 0, SIGHASH_NONE = 2):**
- hashPrevouts: `cacf0f5210cce5fa65a59f314292b3111d299e7d9d582753cf61e1e408552ae4`
- hashSequence: zeros (due to SIGHASH_NONE)
- hashOutputs: zeros (due to SIGHASH_NONE)
- **sighash**: `bbe6d84f57c56b29b914c694baaccb891297e961de3eb46c68e3c89c47b1a1db`

---

## Test Vector 3 (Transparent-only) ⭐ BEST FOR TESTING

**Testnet transaction** with txid `97d8814886d07fc12bbac90c089a10f90906cbb53402ee26e576ef99276c492d`

This is a **transparent-only** transaction (no shielded components), perfect for testing.

**Raw Transaction:**
```
0400008085202f8901a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9010000006b483045022100a61e5d557568c2ddc1d9b03a7173c6ce7c996c4daecab007ac8f34bee01e6b9702204d38fdc0bcf2728a69fde78462a10fb45a9baa27873e6a5fc45fb5c76764202a01210365ffea3efa3908918a8b8627724af852fc9b86d7375b103ab0543cf418bcaa7ffeffffff02005a6202000000001976a9148132712c3ff19f3a151234616777420a6d7ef22688ac8b959800000000001976a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac29b0040048b004000000000000000000000000
```

**Transaction Fields:**
- header: `04000080` (version 4 with fOverwintered)
- nVersionGroupId: `85202f89` (Sapling)
- nLockTime: `29b00400` = 307241 (little-endian: 0x0004b029)
- nExpiryHeight: `48b00400` = 307272 (little-endian: 0x0004b048)
- valueBalance: `0000000000000000` (zeros for transparent-only)

**Transparent Input (vin: 01):**
- txid: `a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9`
- vout: `01000000` = 1
- scriptSig (signed): `6b483045022100a61e5d557568c2ddc1d9b03a7173c6ce7c996c4daecab007ac8f34bee01e6b9702204d38fdc0bcf2728a69fde78462a10fb45a9baa27873e6a5fc45fb5c76764202a01210365ffea3efa3908918a8b8627724af852fc9b86d7375b103ab0543cf418bcaa7f`
- nSequence: `feffffff` = 4294967294 (0xfffffffe)

**Transparent Outputs (vout: 02):**
1. Output 0:
   - value: `005a620200000000` = 40000000 satoshis (0.4 ZEC)
   - scriptPubKey: `1976a9148132712c3ff19f3a151234616777420a6d7ef22688ac`

2. Output 1:
   - value: `8b95980000000000` = 9999755 satoshis
   - scriptPubKey: `1976a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac`

**Sighash Input Data (for computing sighash of input 0):**
- prevout txid: `a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9`
- prevout vout: `01000000` = 1
- scriptCode: `1976a914507173527b4c3318a2aecd793bf1cfed705950cf88ac` (P2PKH)
- amount: `80f0fa0200000000` = 50000000 satoshis (0.5 ZEC)
- nSequence: `feffffff`

**Intermediate Hashes (SIGHASH_ALL):**
- hashPrevouts: `fae31b8dec7b0b77e2c8d6b6eb0e7e4e55abc6574c26dd44464d9408a8e33f11`
- hashSequence: `6c80d37f12d89b6f17ff198723e7db1247c4811d1a695d74d930f99e98418790`
- hashOutputs: `d2b04118469b7810a0d1cc59568320aad25a84f407ecac40b4f605a4e6868454`
- hashJoinSplits: zeros
- hashShieldedSpends: zeros
- hashShieldedOutputs: zeros

**Expected Sighash (nIn = 0, SIGHASH_ALL = 1):**
```
f3148f80dfab5e573d5edfe7a850f5fd39234f80b5429d3a57edcc11e34c585b
```

---

## Consensus Branch IDs

| Network Upgrade | Branch ID    | Transaction Version |
|-----------------|--------------|---------------------|
| Overwinter      | 0x5ba81b19   | 3                   |
| Sapling         | 0x76b809bb   | 4                   |
| Blossom         | 0x2bb40e60   | 4                   |
| Heartwood       | 0xf5b9230b   | 4                   |
| Canopy          | 0xe9ff75a6   | 4                   |
| NU5             | 0xc2d6d0b4   | 5                   |

## Personalization Strings

| Purpose  | Personalization (16 bytes)   |
|----------|------------------------------|
| Sighash  | "ZcashSigHash" + branch_id   |
| Prevouts | "ZcashPrevoutHash"           |
| Sequence | "ZcashSequencHash"           |
| Outputs  | "ZcashOutputsHash"           |

