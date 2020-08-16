#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "cfd_sys"]

extern crate libc;

use self::libc::{c_char, c_double, c_int, c_longlong, c_uint, c_void};

// references: https://github.com/rust-lang/libz-sys
#[rustfmt::skip]
macro_rules! fns {
  ($($arg:tt)*) => {
    item! {
      extern { $($arg)* }
    }
  }
}

// references: https://github.com/rust-lang/libz-sys
#[rustfmt::skip]
macro_rules! item {
  ($i:item) => ($i)
}

fns! {
  pub fn CfdSerializeByteData(
    handle: *const c_void,
    buffer: *const i8,
    output: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdRequestExecuteJson(
    handle: *const c_void,
    name: *const i8,
    json_string: *const i8,
    response_json_string: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCreateSimpleHandle(handle: *mut *mut c_void) -> c_int;
  pub fn CfdGetLastErrorMessage(handle: *const c_void, message: *mut *mut c_char) -> c_int;
  pub fn CfdFreeHandle(handle: *mut c_void) -> c_int;
  pub fn CfdGetConfidentialValueHex(
    handle: *const c_void,
    value_satoshi: c_longlong,
    ignore_version_info: bool,
    value_hex: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCreateConfidentialAddress(
    handle: *const c_void,
    address: *const i8,
    confidential_key: *const i8,
    confidential_address: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdParseConfidentialAddress(
    handle: *const c_void,
    confidential_address: *const i8,
    address: *mut *mut c_char,
    confidential_key: *mut *mut c_char,
    network_type: *mut c_int,
  ) -> c_int;
  pub fn CfdParseDescriptor(
    handle: *const c_void,
    descriptor: *const i8,
    network_type: c_int,
    bip32_derivation_path: *const i8,
    descriptor_handle: *mut *mut c_void,
    max_index: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetDescriptorData(
    handle: *const c_void,
    descriptor_handle: *const c_void,
    index: c_uint,
    max_index: *mut c_uint,
    depth: *mut c_uint,
    script_type: *mut c_int,
    locking_script: *mut *mut c_char,
    address: *mut *mut c_char,
    hash_type: *mut c_int,
    redeem_script: *mut *mut c_char,
    key_type: *mut c_int,
    pubkey: *mut *mut c_char,
    ext_pubkey: *mut *mut c_char,
    ext_privkey: *mut *mut c_char,
    is_multisig: *mut bool,
    max_key_num: *mut c_uint,
    req_sig_num: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetDescriptorMultisigKey(
    handle: *const c_void,
    descriptor_handle: *const c_void,
    key_index: c_uint,
    key_type: *mut c_int,
    pubkey: *mut *mut c_char,
    ext_pubkey: *mut *mut c_char,
    ext_privkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeDescriptorHandle(handle: *const c_void, descriptor_handle: *const c_void) -> c_int;
  pub fn CfdGetDescriptorChecksum(
    handle: *const c_void,
    network_type: c_int,
    descriptor: *const c_char,
    descriptor_added_checksum: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCreateExtkeyFromSeed(
    handle: *const c_void,
    seed_hex: *const i8,
    network_type: c_int,
    key_type: c_int,
    extkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCreateExtkey(
    handle: *const c_void,
    network_type: c_int,
    key_type: c_int,
    parent_key: *const i8,
    fingerprint: *const i8,
    key: *const i8,
    chain_code: *const i8,
    depth: u8,
    child_number: u32,
    extkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCreateExtkeyFromParent(
    handle: *const c_void,
    extkey: *const i8,
    child_number: c_uint,
    hardened: bool,
    network_type: c_int,
    key_type: c_int,
    child_extkey: *mut *mut c_char,
  ) -> c_int;

  pub fn CfdCreateExtkeyFromParentPath(
    handle: *const c_void,
    extkey: *const i8,
    path: *const i8,
    network_type: c_int,
    key_type: c_int,
    child_extkey: *mut *mut c_char,
  ) -> c_int;

  pub fn CfdCreateExtPubkey(
    handle: *const c_void,
    extkey: *const i8,
    network_type: c_int,
    ext_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetPrivkeyFromExtkey(
    handle: *const c_void,
    extkey: *const i8,
    network_type: c_int,
    privkey: *mut *mut c_char,
    wif: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetPubkeyFromExtkey(
    handle: *const c_void,
    extkey: *const i8,
    network_type: c_int,
    pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetExtkeyInformation(
    handle: *const c_void,
    extkey: *const i8,
    version: *mut *mut c_char,
    fingerprint: *mut *mut c_char,
    chain_code: *mut *mut c_char,
    depth: *mut c_uint,
    child_number: *mut c_uint,
  ) -> c_int;

  pub fn CfdInitializeMnemonicWordList(
    handle: *const c_void,
    language: *const i8,
    mnemonic_handle: *mut *mut c_void,
    max_index: *mut c_uint,
  ) -> c_int;

  pub fn CfdGetMnemonicWord(
    handle: *const c_void,
    mnemonic_handle: *const c_void,
    index: c_uint,
    mnemonic_word: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeMnemonicWordList(handle: *const c_void, mnemonic_handle: *const c_void) -> c_int;

  pub fn CfdConvertMnemonicToSeed(
    handle: *const c_void,
    mnemonic: *const i8,
    passphrase: *const i8,
    strict_check: bool,
    language: *const i8,
    use_ideographic_space: bool,
    seed: *mut *mut c_char,
    entropy: *mut *mut c_char,
  ) -> c_int;

  pub fn CfdConvertEntropyToMnemonic(
    handle: *const c_void,
    entropy: *const i8,
    language: *const i8,
    mnemonic: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCompressPubkey(
    handle: *const c_void,
    pubkey_hex: *const i8,
    compressed_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdUncompressPubkey(
    handle: *const c_void,
    pubkey_hex: *const i8,
    decompressed_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdPubkeyTweakAdd(
    handle: *const c_void,
    pubkey_hex: *const i8,
    tweak_hex: *const i8,
    tweaked_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdPubkeyTweakMul(
    handle: *const c_void,
    pubkey_hex: *const i8,
    tweak_hex: *const i8,
    tweaked_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdNegatePubkey(
    handle: *const c_void,
    pubkey_hex: *const i8,
    negate_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCreateKeyPair(
    handle: *const c_void,
    is_compressed: bool,
    network_type: c_int,
    pubkey: *mut *mut c_char,
    privkey: *mut *mut c_char,
    wif: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdParsePrivkeyWif(
    handle: *const c_void,
    wif: *const i8,
    privkey: *mut *mut c_char,
    network_type: *mut c_int,
    is_compressed: *mut bool,
  ) -> c_int;
  pub fn CfdPrivkeyTweakAdd(
    handle: *const c_void,
    privkey: *const i8,
    tweak_hex: *const i8,
    tweaked_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdPrivkeyTweakMul(
    handle: *const c_void,
    privkey: *const i8,
    tweak_hex: *const i8,
    tweaked_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdNegatePrivkey(
    handle: *const c_void,
    privkey: *const i8,
    negate_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetPrivkeyWif(
    handle: *const c_void,
    privkey: *const i8,
    network_type: c_int,
    is_compressed: bool,
    wif: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetPubkeyFromPrivkey(
    handle: *const c_void,
    privkey: *const i8,
    wif: *const i8,
    is_compressed: bool,
    pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCalculateEcSignature(
    handle: *const c_void,
    sighash: *const i8,
    privkey: *const i8,
    wif: *const i8,
    network_type: c_int,
    has_grind_r: bool,
    signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdInitializeCombinePubkey(handle: *const c_void, combine_handle: *mut *mut c_void) -> c_int;
  pub fn CfdAddCombinePubkey(
    handle: *const c_void,
    combine_handle: *const c_void,
    pubkey: *const i8,
  ) -> c_int;
  pub fn CfdFinalizeCombinePubkey(
    handle: *const c_void,
    combine_handle: *const c_void,
    combine_pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeCombinePubkeyHandle(handle: *const c_void, combine_handle: *const c_void) -> c_int;
  pub fn CfdNormalizeSignature(
    handle: *const c_void,
    signature: *const i8,
    normalize_signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdEncodeSignatureByDer(
    handle: *const c_void,
    signature: *const i8,
    sighash_type: c_int,
    is_anyone_can_pay: bool,
    der_signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdDecodeSignatureFromDer(
    handle: *const c_void,
    der_signature: *const i8,
    signature: *mut *mut c_char,
    sighash_type: *mut c_int,
    is_anyone_can_pay: *mut bool,
  ) -> c_int;
  pub fn CfdVerifyEcSignature(
    handle: *const c_void,
    sighash: *const i8,
    pubkey: *const i8,
    signature: *const i8,
  ) -> c_int;
  pub fn CfdCalculateSchnorrSignature(
    handle: *const c_void,
    oracle_privkey: *const i8,
    k_value: *const i8,
    message: *const i8,
    signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCalculateSchnorrSignatureWithNonce(
    handle: *const c_void,
    oracle_privkey: *const i8,
    k_value: *const i8,
    message: *const i8,
    signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdVerifySchnorrSignature(
    handle: *const c_void,
    pubkey: *const i8,
    signature: *const i8,
    message: *const i8,
  ) -> c_int;
  pub fn CfdVerifySchnorrSignatureWithNonce(
    handle: *const c_void,
    pubkey: *const i8,
    nonce: *const i8,
    signature: *const i8,
    message: *const i8,
  ) -> c_int;
  pub fn CfdGetSchnorrPubkey(
    handle: *const c_void,
    oracle_pubkey: *const i8,
    oracle_r_point: *const i8,
    message: *const i8,
    output: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetSchnorrPublicNonce(
    handle: *const c_void,
    privkey: *const i8,
    nonce: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdConvertScriptAsmToHex(
    handle: *const c_void,
    asm: *const i8,
    script_hex: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdParseScript(
    handle: *const c_void,
    script_hex: *const i8,
    script_handle: *mut *mut c_void,
    script_item_num: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetScriptItem(
    handle: *const c_void,
    script_handle: *const c_void,
    index: c_uint,
    script_item: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeScriptItemHandle(handle: *const c_void, script_handle: *const c_void) -> c_int;
  pub fn CfdInitializeMultisigScript(
    handle: *const c_void,
    network_type: c_int,
    hash_type: c_int,
    multisig_handle: *mut *mut c_void,
  ) -> c_int;
  pub fn CfdAddMultisigScriptData(
    handle: *const c_void,
    multisig_handle: *const c_void,
    pubkey: *const i8,
  ) -> c_int;
  pub fn CfdFinalizeMultisigScript(
    handle: *const c_void,
    multisig_handle: *const c_void,
    require_num: c_uint,
    address: *mut *mut c_char,
    redeem_script: *mut *mut c_char,
    witness_script: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeMultisigScriptHandle(handle: *const c_void, multisig_handle: *const c_void) -> c_int;
  pub fn CfdCreateAddress(
    handle: *const c_void,
    hash_type: c_int,
    pubkey: *const i8,
    redeem_script: *const i8,
    network_type: c_int,
    address: *mut *mut c_char,
    locking_script: *mut *mut c_char,
    p2sh_segwit_locking_script: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetAddressInfo(
    handle: *const c_void,
    address: *const i8,
    network_type: *mut c_int,
    hash_type: *mut c_int,
    witness_version: *mut c_int,
    locking_script: *mut *mut c_char,
    hash: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetAddressFromLockingScript(
    handle: *const c_void,
    locking_script: *const i8,
    network_type: c_int,
    address: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetAddressesFromMultisig(
    handle: *const c_void,
    redeem_script: *const i8,
    network_type: c_int,
    hash_type: c_int,
    addr_multisig_keys_handle: *mut *mut c_void,
    max_key_num: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetAddressFromMultisigKey(
    handle: *const c_void,
    addr_multisig_keys_handle: *const c_void,
    index: c_uint,
    address: *mut *mut c_char,
    pubkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeAddressesMultisigHandle(
    handle: *const c_void,
    addr_multisig_keys_handle: *const c_void,
  ) -> c_int;
  pub fn CfdInitializeTransaction(
    handle: *const c_void,
    network_type: c_int,
    version: c_uint,
    locktime: c_uint,
    tx_hex: *const i8,
    create_handle: *mut *mut c_void,
  ) -> c_int;
  pub fn CfdAddTransactionInput(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    sequence: c_uint,
  ) -> c_int;
  pub fn CfdAddTransactionOutput(
    handle: *const c_void,
    create_handle: *const c_void,
    value_satoshi: c_longlong,
    address: *const i8,
    direct_locking_script: *const i8,
    asset_string: *const i8,
  ) -> c_int;
  pub fn CfdFinalizeTransaction(
    handle: *const c_void,
    create_handle: *const c_void,
    tx_hex: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeTransactionHandle(handle: *const c_void, create_handle: *const c_void) -> c_int;
  pub fn CfdUpdateTxOutAmount(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    index: c_uint,
    value_satoshi: c_longlong,
    output_tx: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdAddTxSign(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    sign_data_hex: *const i8,
    use_der_encode: bool,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    clear_stack: bool,
    output_tx: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdAddPubkeyHashSign(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    pubkey: *const i8,
    signature: *const i8,
    use_der_encode: bool,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    output_tx: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdAddScriptHashSign(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    redeem_script: *const i8,
    clear_stack: bool,
    output_tx: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdAddSignWithPrivkeySimple(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    pubkey: *const i8,
    privkey: *const i8,
    value_satoshi: c_longlong,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    has_grind_r: bool,
    output_tx: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdInitializeMultisigSign(handle: *const c_void, multisig_handle: *mut *mut c_void) -> c_int;
  pub fn CfdAddMultisigSignData(
    handle: *const c_void,
    multisig_handle: *const c_void,
    signature: *const i8,
    related_pubkey: *const i8,
  ) -> c_int;
  pub fn CfdAddMultisigSignDataToDer(
    handle: *const c_void,
    multisig_handle: *const c_void,
    signature: *const i8,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    related_pubkey: *const i8,
  ) -> c_int;
  pub fn CfdFinalizeMultisigSign(
    handle: *const c_void,
    multisig_handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    redeem_script: *const i8,
    output_tx: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeMultisigSignHandle(handle: *const c_void, multisig_handle: *const c_void) -> c_int;
  pub fn CfdVerifySignature(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    signature: *const i8,
    hash_type: c_int,
    pubkey: *const i8,
    script: *const i8,
    txid: *const i8,
    vout: c_uint,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    value_satoshi: c_longlong,
    value_byte_hex: *const i8,
  ) -> c_int;
  pub fn CfdVerifyTxSign(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    address: *const i8,
    address_type: c_int,
    direct_locking_script: *const i8,
    value_satoshi: c_longlong,
    value_byte_hex: *const i8,
  ) -> c_int;
  pub fn CfdCreateSighash(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    pubkey: *const i8,
    redeem_script: *const i8,
    value_satoshi: c_longlong,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    sighash: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetTxInfo(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *mut *mut c_char,
    wtxid: *mut *mut c_char,
    size: *mut c_uint,
    vsize: *mut c_uint,
    weight: *mut c_uint,
    version: *mut c_uint,
    locktime: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetTxIn(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    index: c_uint,
    txid: *mut *mut c_char,
    vout: *mut c_uint,
    sequence: *mut c_uint,
    script_sig: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetTxInWitness(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    index: c_uint,
    stack_index: c_uint,
    stack_data: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetTxOut(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    index: c_uint,
    value_satoshi: *mut c_longlong,
    locking_script: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetTxInCount(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    count: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetTxInWitnessCount(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    index: c_uint,
    count: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetTxOutCount(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    count: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetTxInIndex(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    txid: *const i8,
    vout: c_uint,
    index: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetTxOutIndex(
    handle: *const c_void,
    network_type: c_int,
    tx_hex: *const i8,
    address: *const i8,
    direct_locking_script: *const i8,
    index: *mut c_uint,
  ) -> c_int;
  pub fn CfdInitializeEstimateFee(
    handle: *const c_void,
    fee_handle: *mut *mut c_void,
    is_elements: bool,
  ) -> c_int;
  pub fn CfdAddTxInForEstimateFee(
    handle: *const c_void,
    fee_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    descriptor: *const i8,
    asset: *const i8,
    is_issuance: bool,
    is_blind_issuance: bool,
    is_pegin: bool,
    pegin_btc_tx_size: c_uint,
    fedpeg_script: *const i8,
  ) -> c_int;
  pub fn CfdAddTxInTemplateForEstimateFee(
    handle: *const c_void,
    fee_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    descriptor: *const i8,
    asset: *const i8,
    is_issuance: bool,
    is_blind_issuance: bool,
    is_pegin: bool,
    pegin_btc_tx_size: c_uint,
    fedpeg_script: *const i8,
    scriptsig_template: *const i8,
  ) -> c_int;
  pub fn CfdSetOptionEstimateFee(
    handle: *const c_void,
    fee_handle: *const c_void,
    key: c_int,
    int64_value: c_longlong,
    double_value: c_double,
    bool_value: bool,
  ) -> c_int;
  pub fn CfdFinalizeEstimateFee(
    handle: *const c_void,
    fee_handle: *const c_void,
    tx_hex: *const i8,
    fee_asset: *const i8,
    tx_fee: *mut c_longlong,
    utxo_fee: *mut c_longlong,
    is_blind: bool,
    effective_fee_rate: c_double,
  ) -> c_int;
  pub fn CfdFreeEstimateFeeHandle(handle: *const c_void, fee_handle: *const c_void) -> c_int;
  pub fn CfdInitializeFundRawTx(
    handle: *const c_void,
    network_type: c_int,
    target_asset_count: c_uint,
    fee_asset: *const i8,
    fund_handle: *mut *mut c_void,
  ) -> c_int;
  pub fn CfdAddTxInForFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    amount: c_longlong,
    descriptor: *const i8,
    asset: *const i8,
    is_issuance: bool,
    is_blind_issuance: bool,
    is_pegin: bool,
    pegin_btc_tx_size: c_uint,
    fedpeg_script: *const i8,
  ) -> c_int;
  pub fn CfdAddTxInTemplateForFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    amount: c_longlong,
    descriptor: *const i8,
    asset: *const i8,
    is_issuance: bool,
    is_blind_issuance: bool,
    is_pegin: bool,
    pegin_btc_tx_size: c_uint,
    fedpeg_script: *const i8,
    scriptsig_template: *const i8,
  ) -> c_int;
  pub fn CfdAddUtxoForFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    amount: c_longlong,
    descriptor: *const i8,
    asset: *const i8,
  ) -> c_int;
  pub fn CfdAddUtxoTemplateForFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    amount: c_longlong,
    descriptor: *const i8,
    asset: *const i8,
    scriptsig_template: *const i8,
  ) -> c_int;
  pub fn CfdAddTargetAmountForFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    asset_index: c_uint,
    amount: c_longlong,
    asset: *const i8,
    reserved_address: *const i8,
  ) -> c_int;
  pub fn CfdSetOptionFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    key: c_int,
    int64_value: c_longlong,
    double_value: c_double,
    bool_value: bool,
  ) -> c_int;
  pub fn CfdFinalizeFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    tx_hex: *const i8,
    effective_fee_rate: c_double,
    tx_fee: *mut c_longlong,
    append_txout_count: *mut c_uint,
    output_tx: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetAppendTxOutFundRawTx(
    handle: *const c_void,
    fund_handle: *const c_void,
    index: c_uint,
    append_address: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeFundRawTxHandle(handle: *const c_void, fund_handle: *const c_void) -> c_int;

  pub fn CfdInitializeCoinSelection(
    handle: *const c_void,
    utxo_count: c_uint,
    target_asset_count: c_uint,
    fee_asset: *const i8,
    tx_fee_amount: c_longlong,
    effective_fee_rate: c_double,
    long_term_fee_rate: c_double,
    dust_fee_rate: c_double,
    knapsack_min_change: c_longlong,
    coin_select_handle: *mut *mut c_void,
  ) -> c_int;
  pub fn CfdAddCoinSelectionUtxo(
    handle: *const c_void,
    coin_select_handle: *const c_void,
    utxo_index: c_int,
    txid: *const i8,
    vout: c_uint,
    amount: c_longlong,
    asset: *const i8,
    descriptor: *const i8,
  ) -> c_int;
  pub fn CfdAddCoinSelectionUtxoTemplate(
    handle: *const c_void,
    coin_select_handle: *const c_void,
    utxo_index: c_int,
    txid: *const i8,
    vout: c_uint,
    amount: c_longlong,
    asset: *const i8,
    descriptor: *const i8,
    scriptsig_template: *const i8,
  ) -> c_int;
  pub fn CfdAddCoinSelectionAmount(
    handle: *const c_void,
    coin_select_handle: *const c_void,
    asset_index: c_uint,
    amount: c_longlong,
    asset: *const i8,
  ) -> c_int;
  pub fn CfdSetOptionCoinSelection(
    handle: *const c_void,
    coin_select_handle: *const c_void,
    key: c_int,
    int64_value: c_longlong,
    double_value: c_double,
    bool_value: bool,
  ) -> c_int;
  pub fn CfdFinalizeCoinSelection(
    handle: *const c_void,
    coin_select_handle: *const c_void,
    utxo_fee_amount: *mut c_longlong,
  ) -> c_int;
  pub fn CfdGetSelectedCoinIndex(
    handle: *const c_void,
    coin_select_handle: *const c_void,
    index: c_uint,
    utxo_index: *mut c_int,
  ) -> c_int;
  pub fn CfdGetSelectedCoinAssetAmount(
    handle: *const c_void,
    coin_select_handle: *const c_void,
    asset_index: c_uint,
    amount: *mut c_longlong,
  ) -> c_int;
  pub fn CfdFreeCoinSelectionHandle(handle: *const c_void, coin_select_handle: *const c_void) -> c_int;
}
