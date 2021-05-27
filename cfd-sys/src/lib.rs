#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "cfd_sys"]

extern crate libc;

use self::libc::{c_char, c_double, c_int, c_longlong, c_uchar, c_uint, c_void};

pub const BLIND_OPT_MINIMUM_RANGE_VALUE: c_int = 1;
pub const BLIND_OPT_EXPONENT: c_int = 2;
pub const BLIND_OPT_MINIMUM_BITS: c_int = 3;
pub const BLIND_OPT_COLLECT_BLINDER: c_int = 4;

pub const WITNESS_STACK_TYPE_NORMAL: c_int = 0;
pub const WITNESS_STACK_TYPE_PEGIN: c_int = 1;

pub const FUND_OPT_IS_BLIND: c_int = 1;
pub const FUND_OPT_DUST_FEE_RATE: c_int = 2;
pub const FUND_OPT_LONG_TERM_FEE_RATE: c_int = 3;
pub const FUND_OPT_KNAPSACK_MIN_CHANGE: c_int = 4;
pub const FUND_OPT_BLIND_EXPONENT: c_int = 5;
pub const FUND_OPT_BLIND_MINIMUM_BITS: c_int = 6;

pub const COIN_OPT_BLIND_EXPONENT: c_int = 1;
pub const COIN_OPT_BLIND_MINIMUM_BITS: c_int = 2;
pub const FEE_OPT_BLIND_EXPONENT: c_int = 1;
pub const FEE_OPT_BLIND_MINIMUM_BITS: c_int = 2;

pub const DEFAULT_BLIND_MINIMUM_BITS: c_int = 52;

pub const PSBT_RECORD_TYPE_GLOBAL: c_int = 1;
pub const PSBT_RECORD_TYPE_INPUT: c_int = 2;
pub const PSBT_RECORD_TYPE_OUTPUT: c_int = 3;

pub const PSBT_RECORD_INPUT_SIGNATURE: c_int = 1;
pub const PSBT_RECORD_INPUT_BIP32: c_int = 2;
pub const PSBT_RECORD_OUTPUT_BIP32: c_int = 3;
pub const PSBT_RECORD_GLOBAL_XPUB: c_int = 4;

pub const PSBT_OPT_ESTIMATE_FEE_RATE: c_int = 1;
pub const PSBT_OPT_DUST_FEE_RATE: c_int = 2;
pub const PSBT_OPT_LONG_TERM_FEE_RATE: c_int = 3;
pub const PSBT_OPT_KNAPSACK_MIN_CHANGE: c_int = 4;

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
  pub fn CfdEncryptAES(
    handle: *const c_void, key: *const c_char, cbc_iv: *const c_char, buffer: *const c_char,
    output: *mut *mut c_char) -> c_int;
  pub fn CfdDecryptAES(
    handle: *const c_void, key: *const c_char, cbc_iv: *const c_char, buffer: *const c_char,
    output: *mut *mut c_char) -> c_int;
  pub fn CfdEncodeBase64(handle: *const c_void, buffer: *const c_char, output: *mut *mut c_char) -> c_int;
  pub fn CfdDecodeBase64(handle: *const c_void, base64: *const c_char, output: *mut *mut c_char) -> c_int;
  pub fn CfdEncodeBase58(
    handle: *const c_void, buffer: *const c_char, use_checksum: bool, output: *mut *mut c_char) -> c_int;
  pub fn CfdDecodeBase58(
    handle: *const c_void, base58: *const c_char, use_checksum: bool, output: *mut *mut c_char) -> c_int;
  pub fn CfdRipemd160(
    handle: *const c_void, message: *const c_char, has_text: bool, output: *mut *mut c_char) -> c_int;
  pub fn CfdSha256(
    handle: *const c_void, message: *const c_char, has_text: bool, output: *mut *mut c_char) -> c_int;
  pub fn CfdHash160(
    handle: *const c_void, message: *const c_char, has_text: bool, output: *mut *mut c_char) -> c_int;
  pub fn CfdHash256(
    handle: *const c_void, message: *const c_char, has_text: bool, output: *mut *mut c_char) -> c_int;
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
  pub fn CfdGetPeginAddress(
    handle: *const c_void,
    mainchain_network_type: c_int,
    fedpeg_script: *const c_char,
    hash_type: c_int,
    pubkey: *const c_char,
    redeem_script: *const c_char,
    pegin_address: *mut *mut c_char,
    claim_script: *mut *mut c_char,
    tweaked_fedpeg_script: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdParseDescriptor(
    handle: *const c_void,
    descriptor: *const i8,
    network_type: c_int,
    bip32_derivation_path: *const i8,
    descriptor_handle: *mut *mut c_void,
    max_index: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetDescriptorRootData(
    handle: *const c_void,
    descriptor_handle: *const c_void,
    script_type: *mut c_int,
    locking_script: *mut *mut c_char,
    address: *mut *mut c_char,
    hash_type: *mut c_int,
    redeem_script: *mut *mut c_char,
    key_type: *mut c_int,
    pubkey: *mut *mut c_char,
    ext_pubkey: *mut *mut c_char,
    ext_privkey: *mut *mut c_char,
    schnorr_pubkey: *mut *mut c_char,
    tree_string: *mut *mut c_char,
    is_multisig: *mut bool,
    max_key_num: *mut c_uint,
    req_sig_num: *mut c_uint,
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
    depth: c_uchar,
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
  pub fn CfdGetPubkeyFingerprint(
    handle: *const c_void,
    pubkey: *const c_char,
    fingerprint: *mut *mut c_char,
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
  pub fn CfdSignEcdsaAdaptor(
    handle: *const c_void,
    message: *const i8,
    secret_key: *const i8,
    adaptor: *const i8,
    adaptor_signature: *mut *mut c_char,
    adaptor_proof: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdAdaptEcdsaAdaptor(
    handle: *const c_void,
    adaptor_signature: *const i8,
    adaptor_secret: *const i8,
    signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdExtractEcdsaAdaptorSecret(
    handle: *const c_void,
    adaptor_signature: *const i8,
    signature: *const i8,
    adaptor: *const i8,
    adaptor_secret: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdVerifyEcdsaAdaptor(
    handle: *const c_void,
    adaptor_signature: *const i8,
    proof: *const i8,
    adaptor: *const i8,
    message: *const i8,
    pubkey: *const i8,
  ) -> c_int;
  pub fn CfdGetSchnorrPubkeyFromPrivkey(
    handle: *const c_void,
    privkey: *const i8,
    pubkey: *mut *mut c_char,
    parity: *mut bool,
  ) -> c_int;
  pub fn CfdGetSchnorrPubkeyFromPubkey(
    handle: *const c_void,
    pubkey: *const i8,
    schnorr_pubkey: *mut *mut c_char,
    parity: *mut bool,
  ) -> c_int;
  pub fn CfdSchnorrPubkeyTweakAdd(
    handle: *const c_void,
    pubkey: *const i8,
    tweak: *const i8,
    output: *mut *mut c_char,
    parity: *mut bool,
  ) -> c_int;
  pub fn CfdSchnorrKeyPairTweakAdd(
    handle: *const c_void,
    privkey: *const i8,
    tweak: *const i8,
    tweaked_pubkey: *mut *mut c_char,
    tweaked_parity: *mut bool,
    tweaked_privkey: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdCheckTweakAddFromSchnorrPubkey(
    handle: *const c_void,
    tweaked_pubkey: *const i8,
    tweaked_parity: bool,
    base_pubkey: *const i8,
    tweak: *const i8,
  ) -> c_int;
  pub fn CfdSignSchnorr(
    handle: *const c_void,
    message: *const i8,
    secret_key: *const i8,
    aux_rand: *const i8,
    signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdSignSchnorrWithNonce(
    handle: *const c_void,
    message: *const i8,
    secret_key: *const i8,
    nonce: *const i8,
    signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdAddSighashTypeInSchnorrSignature(
    handle: *const c_void,
    signature: *const i8,
    sighash_type: c_int,
    anyone_can_pay: bool,
    added_signature: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdGetSighashTypeFromSchnorrSignature(
    handle: *const c_void,
    signature: *const i8,
    sighash_type: *mut c_int,
    anyone_can_pay: *mut bool,
  ) -> c_int;
  pub fn CfdComputeSchnorrSigPoint(
    handle: *const c_void,
    message: *const i8,
    nonce: *const i8,
    pubkey: *const i8,
    sig_point: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdVerifySchnorr(
    handle: *const c_void,
    signature: *const i8,
    message: *const i8,
    pubkey: *const i8,
  ) -> c_int;
  pub fn CfdSplitSchnorrSignature(
    handle: *const c_void,
    signature: *const i8,
    nonce: *mut *mut c_char,
    key: *mut *mut c_char,
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
  pub fn CfdInitializeTaprootScriptTree(
    handle: *const c_void,
    tree_handle: *mut *mut c_void,
  ) -> c_int;
  pub fn CfdSetInitialTapLeaf(
    handle: *const c_void,
    tree_handle: *const c_void,
    tapscript: *const i8,
    leaf_version: c_uchar,
  ) -> c_int;
  pub fn CfdSetInitialTapBranchByHash(
    handle: *const c_void,
    tree_handle: *const c_void,
    hash: *const i8,
  ) -> c_int;
  pub fn CfdSetScriptTreeFromString(
    handle: *const c_void,
    tree_handle: *const c_void,
    tree_string: *const i8,
    tapscript: *const i8,
    leaf_version: c_uchar,
    control_nodes: *const i8,
  ) -> c_int;
  pub fn CfdSetTapScriptByWitnessStack(
    handle: *const c_void,
    tree_handle: *const c_void,
    control_block: *const i8,
    tapscript: *const i8,
    internal_pubkey: *mut *mut i8,
  ) -> c_int;
  pub fn CfdAddTapBranchByHash(
    handle: *const c_void,
    tree_handle: *const c_void,
    branch_hash: *const i8,
  ) -> c_int;
  pub fn CfdAddTapBranchByScriptTree(
    handle: *const c_void,
    tree_handle: *const c_void,
    branch_tree: *const c_void,
  ) -> c_int;
  pub fn CfdAddTapBranchByScriptTreeString(
    handle: *const c_void,
    tree_handle: *const c_void,
    tree_string: *const i8,
  ) -> c_int;
  pub fn CfdAddTapBranchByTapLeaf(
    handle: *const c_void,
    tree_handle: *const c_void,
    tapscript: *const i8,
    leaf_version: c_uchar,
  ) -> c_int;
  pub fn CfdGetBaseTapLeaf(
    handle: *const c_void,
    tree_handle: *const c_void,
    leaf_version: *mut c_uchar,
    tapscript: *mut *mut i8,
    tap_leaf_hash: *mut *mut i8,
  ) -> c_int;
  pub fn CfdGetTapBranchCount(
    handle: *const c_void,
    tree_handle: *const c_void,
    branch_count: *mut c_uint,
  ) -> c_int;
  pub fn CfdGetTapBranchData(
    handle: *const c_void,
    tree_handle: *const c_void,
    index_from_leaf: c_uchar,
    is_root_data: bool,
    branch_hash: *mut *mut i8,
    leaf_version: *mut c_uchar,
    tapscript: *mut *mut i8,
    depth_by_leaf_or_end: *mut c_uchar,
  ) -> c_int;
  pub fn CfdGetTapBranchHandle(
    handle: *const c_void,
    tree_handle: *const c_void,
    index_from_leaf: c_uchar,
    branch_hash: *mut *mut i8,
    branch_tree_handle: *mut *mut c_void,
  ) -> c_int;
  pub fn CfdGetTaprootScriptTreeHash(
    handle: *const c_void,
    tree_handle: *const c_void,
    internal_pubkey: *const i8,
    hash: *mut *mut i8,
    tap_leaf_hash: *mut *mut i8,
    control_block: *mut *mut i8,
  ) -> c_int;
  pub fn CfdGetTaprootTweakedPrivkey(
    handle: *const c_void,
    tree_handle: *const c_void,
    internal_privkey: *const i8,
    tweaked_privkey: *mut *mut i8,
  ) -> c_int;
  pub fn CfdGetTaprootScriptTreeSrting(
    handle: *const c_void,
    tree_handle: *const c_void,
    tree_string: *mut *mut i8,
  ) -> c_int;
  pub fn CfdFreeTaprootScriptTreeHandle(
    handle: *const c_void,
    tree_handle: *const c_void,
  ) -> c_int;
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
  pub fn CfdSplitTxOut(
    handle: *const c_void,
    create_handle: *const c_void,
    split_output_handle: *const c_void,
    txout_index: c_uint,
  ) -> c_int;
  pub fn CfdUpdateWitnessStack(
    handle: *const c_void,
    create_handle: *const c_void,
    stack_type: c_int,
    txid: *const i8,
    vout: c_uint,
    stack_index: c_uint,
    stack_item: *const i8,
  ) -> c_int;
  pub fn CfdClearWitnessStack(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
  ) -> c_int;
  pub fn CfdUpdateTxInScriptSig(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    script_sig: *const i8,
  ) -> c_int;
  pub fn CfdSetTransactionUtxoData(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    amount: c_longlong,
    commitment: *const i8,
    descriptor: *const i8,
    address: *const i8,
    asset: *const i8,
    scriptsig_template: *const i8,
    can_insert: bool,
  ) -> c_int;
  pub fn CfdCreateSighashByHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    pubkey: *const i8,
    redeem_script: *const i8,
    tapleaf_hash: *const i8,
    code_separator_position: c_uint,
    annex: *const i8,
    sighash: *mut *mut i8,
  ) -> c_int;
  pub fn CfdAddSignWithPrivkeyByHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    privkey: *const i8,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    has_grind_r: bool,
    aux_rand: *const i8,
    annex: *const i8,
  ) -> c_int;
  pub fn CfdVerifyTxSignByHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
  ) -> c_int;
  pub fn CfdAddTxSignByHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    sign_data_hex: *const i8,
    use_der_encode: bool,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
    clear_stack: bool,
  ) -> c_int;
  pub fn CfdAddTaprootSignByHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    signature: *const i8,
    tapscript: *const i8,
    control_block: *const i8,
    annex: *const i8,
  ) -> c_int;
  pub fn CfdAddPubkeyHashSignByHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    pubkey: *const i8,
    signature: *const i8,
    use_der_encode: bool,
    sighash_type: c_int,
    sighash_anyone_can_pay: bool,
  ) -> c_int;
  pub fn CfdAddScriptHashLastSignByHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    txid: *const i8,
    vout: c_uint,
    hash_type: c_int,
    redeem_script: *const i8,
  ) -> c_int;
  pub fn CfdFinalizeTransaction(
    handle: *const c_void,
    create_handle: *const c_void,
    tx_hex: *mut *mut c_char,
  ) -> c_int;
  pub fn CfdFreeTransactionHandle(handle: *const c_void, create_handle: *const c_void) -> c_int;
  pub fn CfdCreateSplitTxOutHandle(
    handle: *const c_void,
    create_handle: *const c_void,
    split_output_handle: *mut *mut c_void,
  ) -> c_int;
  pub fn CfdAddSplitTxOutData(
    handle: *const c_void,
    split_output_handle: *const c_void,
    amount: c_longlong,
    address: *const i8,
    direct_locking_script: *const i8,
    direct_nonce: *const i8,
  ) -> c_int;
  pub fn CfdFreeSplitTxOutHandle(
    handle: *const c_void,
    split_output_handle: *const c_void,
  ) -> c_int;
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
  pub fn CfdInitializeTxDataHandle(handle: *const c_void, network_type: c_int, tx_hex: *const i8, tx_data_handle: *mut *mut c_void) -> c_int;
  pub fn CfdFreeTxDataHandle(handle: *const c_void, tx_data_handle: *const c_void) -> c_int;
  pub fn CfdGetTxInfoByHandle(
      handle: *const c_void, tx_data_handle: *const c_void,
      txid: *mut *mut c_char, wtxid: *mut *mut c_char,
      size: *mut c_uint, vsize: *mut c_uint,
      weight: *mut c_uint, version: *mut c_uint,
      locktime: *mut c_uint) -> c_int;
  pub fn CfdGetTxInByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, index: c_uint,
      txid: *mut *mut c_char,
      vout: *mut c_uint, sequence: *mut c_uint, script_sig: *mut *mut c_char) -> c_int;
  pub fn CfdGetTxInWitnessByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, stack_type: c_int,
      txin_index: c_uint,
      stack_index: c_uint,
      stack_data: *mut *mut c_char) -> c_int;
  pub fn CfdGetTxOutByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, index: c_uint,
      value_satoshi: *mut c_longlong,
      locking_script: *mut *mut c_char, asset: *mut *mut c_char) -> c_int;
  pub fn CfdGetTxInCountByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, count: *mut c_uint) -> c_int;
  pub fn CfdGetTxInWitnessCountByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, stack_type: c_int, txin_index: c_uint,
      count: *mut c_uint) -> c_int;
  pub fn CfdGetTxOutCountByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, count: *mut c_uint) -> c_int;
  pub fn CfdGetTxInIndexByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, txid: *const c_char, vout: c_uint,
      index: *mut c_uint) -> c_int;
  pub fn CfdGetTxOutIndexByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, address: *const c_char,
      direct_locking_script: *const c_char, index: *mut c_uint) -> c_int;
  pub fn CfdGetTxOutIndexWithOffsetByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, offset: c_uint, address: *const c_char,
      direct_locking_script: *const c_char, index: *mut c_uint) -> c_int;
  pub fn CfdInitializeConfidentialTx(
      handle: *const c_void, version: c_uint, locktime: c_uint, tx_string: *mut *mut c_char) -> c_int;
  pub fn CfdAddConfidentialTxOut(
      handle: *const c_void, tx_hex_string: *const c_char, asset_string: *const c_char,
      value_satoshi: c_longlong, value_commitment: *const c_char, address: *const c_char,
      direct_locking_script: *const c_char, nonce: *const c_char, tx_string: *mut *mut c_char) -> c_int;
  pub fn CfdUpdateConfidentialTxOut(
      handle: *const c_void, tx_hex_string: *const c_char, index: c_uint,
      asset_string: *const c_char, value_satoshi: c_longlong,
      value_commitment: *const c_char, address: *const c_char,
      direct_locking_script: *const c_char, nonce: *const c_char, tx_string: *mut *mut c_char) -> c_int;
  pub fn CfdGetConfidentialTxInfoByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, txid: *mut *mut c_char, wtxid: *mut *mut c_char,
      wit_hash: *mut *mut c_char, size: *mut c_uint, vsize: *mut c_uint, weight: *mut c_uint,
      version: *mut c_uint, locktime: *mut c_uint) -> c_int;
  pub fn CfdGetTxInIssuanceInfoByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, index: c_uint, entropy: *mut *mut c_char,
      nonce: *mut *mut c_char, asset_amount: *mut c_longlong, asset_value: *mut *mut c_char,
      token_amount: *mut c_longlong, token_value: *mut *mut c_char, asset_rangeproof: *mut *mut c_char,
      token_rangeproof: *mut *mut c_char) -> c_int;
  pub fn CfdGetConfidentialTxOutSimpleByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, index: c_uint, asset_string: *mut *mut c_char,
      value_satoshi: *mut c_longlong, value_commitment: *mut *mut c_char, nonce: *mut *mut c_char,
      locking_script: *mut *mut c_char) -> c_int;
  pub fn CfdGetConfidentialTxOutByHandle(
      handle: *const c_void, tx_data_handle: *const c_void, index: c_uint, asset_string: *mut *mut c_char,
      value_satoshi: *mut c_longlong, value_commitment: *mut *mut c_char, nonce: *mut *mut c_char,
      locking_script: *mut *mut c_char, surjection_proof: *mut *mut c_char, rangeproof: *mut *mut c_char) -> c_int;
  pub fn CfdSetRawReissueAsset(
      handle: *const c_void, tx_hex_string: *const c_char, txid: *const c_char, vout: c_uint,
      asset_amount: c_longlong, blinding_nonce: *const c_char, entropy: *const c_char,
      address: *const c_char, direct_locking_script: *const c_char,
      asset_string: *mut *mut c_char, tx_string: *mut *mut c_char) -> c_int;
  pub fn CfdGetIssuanceBlindingKey(
      handle: *const c_void, master_blinding_key: *const c_char, txid: *const c_char,
      vout: c_uint, blinding_key: *mut *mut c_char) -> c_int;
  pub fn CfdGetDefaultBlindingKey(
      handle: *const c_void, master_blinding_key: *const c_char, locking_script: *const c_char,
      blinding_key: *mut *mut c_char) -> c_int;
  pub fn CfdInitializeBlindTx(handle: *const c_void, blind_handle: *mut *mut c_void) -> c_int;
  pub fn CfdSetBlindTxOption(
      handle: *const c_void, blind_handle: *const c_void, key: c_int, value: c_longlong) -> c_int;
  pub fn CfdAddBlindTxInData(
      handle: *const c_void, blind_handle: *const c_void, txid: *const c_char, vout: c_uint,
      asset_string: *const c_char, asset_blind_factor: *const c_char,
      value_blind_factor: *const c_char, value_satoshi: c_longlong,
      asset_key: *const c_char, token_key: *const c_char) -> c_int;
  pub fn CfdAddBlindTxOutData(
      handle: *const c_void, blind_handle: *const c_void, index: c_uint,
      confidential_key: *const c_char) -> c_int;
  pub fn CfdAddBlindTxOutByAddress(
      handle: *const c_void, blind_handle: *const c_void, confidential_address: *const c_char) -> c_int;
  pub fn CfdFinalizeBlindTx(
      handle: *const c_void, blind_handle: *const c_void, tx_hex_string: *const c_char,
      tx_string: *mut *mut c_char) -> c_int;
  pub fn CfdGetBlindTxBlindData(
      handle: *const c_void, blind_handle: *const c_void, index: c_uint,
      vout: *mut c_uint, asset: *mut *mut c_char, value_satoshi: *mut c_longlong,
      asset_blind_factor: *mut *mut c_char, value_blind_factor: *mut *mut c_char,
      issuance_txid: *mut *mut c_char, issuance_vout: *mut c_uint,
      is_issuance_asset: *mut bool, is_issuance_token: *mut bool) -> c_int;
  pub fn CfdFreeBlindHandle(handle: *const c_void, blind_handle: *const c_void) -> c_int;
  pub fn CfdFinalizeElementsMultisigSign(
      handle: *const c_void, multi_sign_handle: *const c_void, tx_hex_string: *const c_char, txid: *const c_char, vout: c_uint, hash_type: c_int, witness_script: *const c_char, redeem_script: *const c_char, clear_stack: bool, tx_string: *mut *mut c_char) -> c_int;
  pub fn CfdAddConfidentialTxSignWithPrivkeySimple(
      handle: *const c_void, tx_hex_string: *const c_char, txid: *const c_char, vout: c_uint,
      hash_type: c_int, pubkey: *const c_char, privkey: *const c_char,
      value_satoshi: c_longlong, value_commitment: *const c_char, sighash_type: c_int,
      sighash_anyone_can_pay: bool, has_grind_r: bool, tx_string: *mut *mut c_char) -> c_int;
  pub fn CfdUnblindTxOut(
      handle: *const c_void, tx_hex_string: *const c_char, tx_out_index: c_uint,
      blinding_key: *const c_char, asset: *mut *mut c_char, value: *mut c_longlong,
      asset_blind_factor: *mut *mut c_char, value_blind_factor: *mut *mut c_char) -> c_int;
  pub fn CfdUnblindIssuance(
      handle: *const c_void, tx_hex_string: *const c_char, tx_in_index: c_uint,
      asset_blinding_key: *const c_char, token_blinding_key: *const c_char,
      asset: *mut *mut c_char, asset_value: *mut c_longlong, asset_blind_factor: *mut *mut c_char,
      asset_value_blind_factor: *mut *mut c_char, token: *mut *mut c_char, token_value: *mut c_longlong,
      token_blind_factor: *mut *mut c_char, token_value_blind_factor: *mut *mut c_char) -> c_int;
  pub fn CfdCreateConfidentialSighash(
      handle: *const c_void, tx_hex_string: *const c_char, txid: *const c_char, vout: c_uint,
      hash_type: c_int, pubkey: *const c_char, redeem_script: *const c_char,
      value_satoshi: c_longlong, value_commitment: *const c_char, sighash_type: c_int,
      sighash_anyone_can_pay: bool, sighash: *mut *mut c_char) -> c_int;
  pub fn CfdVerifyConfidentialTxSignature(
      handle: *const c_void, tx_hex: *const c_char, signature: *const c_char,
      pubkey: *const c_char, script: *const c_char, txid: *const c_char, vout: c_uint,
      sighash_type: c_int, sighash_anyone_can_pay: bool, value_satoshi: c_longlong,
      value_commitment: *const c_char, witness_version: c_int) -> c_int;
  pub fn CfdVerifyConfidentialTxSign(
      handle: *const c_void, tx_hex: *const c_char, txid: *const c_char, vout: c_uint,
      address: *const c_char, address_type: c_int, direct_locking_script: *const c_char,
      value_satoshi: c_longlong, value_commitment: *const c_char) -> c_int;
  pub fn CfdGetAssetCommitment(
      handle: *const c_void, asset: *const c_char, asset_blind_factor: *const c_char,
      asset_commitment: *mut *mut c_char) -> c_int;
  pub fn CfdGetValueCommitment(
      handle: *const c_void, value_satoshi: c_longlong, asset_commitment: *const c_char,
      value_blind_factor: *const c_char, value_commitment: *mut *mut c_char) -> c_int;
  pub fn CfdAddConfidentialTxOutput(
      handle: *const c_void, create_handle: *const c_void, value_satoshi: c_longlong,
      address: *const c_char, direct_locking_script: *const c_char,
      asset_string: *const c_char, nonce: *const c_char) -> c_int;
  pub fn CfdSetIssueAsset(
      handle: *const c_void, create_handle: *const c_void, txid: *const c_char,
      vout: c_uint, contract_hash: *const c_char, asset_amount: c_longlong,
      asset_address: *const c_char, asset_locking_script: *const c_char,
      token_amount: c_longlong, token_address: *const c_char, token_locking_script: *const c_char,
      is_blind_asset: bool, entropy: *mut *mut c_char, asset_string: *mut *mut c_char,
      token_string: *mut *mut c_char) -> c_int;
  pub fn CfdSetReissueAsset(
      handle: *const c_void, create_handle: *const c_void, txid: *const c_char,
      vout: c_uint, asset_amount: c_longlong, blinding_nonce: *const c_char,
      entropy: *const c_char, address: *const c_char, direct_locking_script: *const c_char,
      asset_string: *mut *mut c_char) -> c_int;
  pub fn CfdAddTxPeginInput(
      handle: *const c_void, create_handle: *const c_void, txid: *const c_char,
      vout: c_uint, amount: c_longlong, asset: *const c_char,
      mainchain_genesis_block_hash: *const c_char, claim_script: *const c_char,
      mainchain_tx_hex: *const c_char, txout_proof: *const c_char) -> c_int;
  pub fn CfdAddTxPegoutOutput(
      handle: *const c_void, create_handle: *const c_void, asset: *const c_char,
      amount: c_longlong, mainchain_network_type: c_int,
      elements_network_type: c_int,
      mainchain_genesis_block_hash: *const c_char, online_pubkey: *const c_char,
      master_online_key: *const c_char, mainchain_output_descriptor: *const c_char,
      bip32_counter: c_uint, whitelist: *const c_char,
      mainchain_address: *mut *mut c_char) -> c_int;
  pub fn CfdCreatePsbtHandle(
    handle: *const c_void, net_type: c_int, psbt_string: *const c_char,
    tx_hex_string: *const c_char, version: c_uint, locktime: c_uint,
    psbt_handle: *mut *mut c_void) -> c_int;
  pub fn CfdFreePsbtHandle(handle: *const c_void, psbt_handle: *const c_void) -> c_int;
  pub fn CfdGetPsbtData(
    handle: *const c_void, psbt_handle: *const c_void, psbt_base64: *mut *mut c_char, psbt_hex: *mut *mut c_char) -> c_int;
  pub fn CfdGetPsbtGlobalData(
    handle: *const c_void, psbt_handle: *const c_void, psbt_version: *mut c_uint, base_tx: *mut *mut c_char,
    txin_count: *mut c_uint, txout_count: *mut c_uint) -> c_int;
  pub fn CfdJoinPsbt(
    handle: *const c_void, psbt_handle: *const c_void, psbt_join_base64: *const c_char) -> c_int;
  pub fn CfdSignPsbt(
    handle: *const c_void, psbt_handle: *const c_void, privkey: *const c_char, has_grind_r: bool) -> c_int;
  pub fn CfdCombinePsbt(
    handle: *const c_void, psbt_handle: *const c_void, psbt_combine_base64: *const c_char) -> c_int;
  pub fn CfdFinalizePsbt(handle: *const c_void, psbt_handle: *const c_void) -> c_int;
  pub fn CfdExtractPsbtTransaction(
    handle: *const c_void, psbt_handle: *const c_void, transaction: *mut *mut c_char) -> c_int;
  pub fn CfdIsFinalizedPsbt(handle: *const c_void, psbt_handle: *const c_void) -> c_int;
  pub fn CfdIsFinalizedPsbtInput(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint) -> c_int;
  pub fn CfdAddPsbtTxInWithPubkey(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    sequence: c_uint, amount: c_longlong, locking_script: *const c_char,
    descriptor: *const c_char, full_tx_hex: *const c_char) -> c_int;
  pub fn CfdAddPsbtTxInWithScript(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    sequence: c_uint, amount: c_longlong, locking_script: *const c_char,
    redeem_script: *const c_char, descriptor: *const c_char,
    full_tx_hex: *const c_char) -> c_int;
  pub fn CfdSetPsbtTxInUtxo(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    amount: c_longlong, locking_script: *const c_char, full_tx_hex: *const c_char) -> c_int;
  pub fn CfdSetPsbtTxInBip32Pubkey(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    pubkey: *const c_char, fingerprint: *const c_char, bip32_path: *const c_char) -> c_int;
  pub fn CfdSetPsbtSignature(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    pubkey: *const c_char, der_signature: *const c_char) -> c_int;
  pub fn CfdSetPsbtSighashType(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    sighash_type: c_int) -> c_int;
  pub fn CfdSetPsbtFinalizeScript(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    scriptsig: *const c_char) -> c_int;
  pub fn CfdClearPsbtSignData(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint) -> c_int;
  pub fn CfdGetPsbtSighashType(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    sighash_type: *mut c_int) -> c_int;
  pub fn CfdGetPsbtUtxoData(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    amount: *mut c_longlong, locking_script: *mut *mut c_char, redeem_script: *mut *mut c_char,
    descriptor: *mut *mut c_char, full_tx_hex: *mut *mut c_char) -> c_int;
  pub fn CfdGetPsbtUtxoDataByIndex(
    handle: *const c_void, psbt_handle: *const c_void, index: c_uint, txid: *mut *mut c_char,
    vout: *mut c_uint, amount: *mut c_longlong, locking_script: *mut *mut c_char,
    redeem_script: *mut *mut c_char, descriptor: *mut *mut c_char, full_tx_hex: *mut *mut c_char) -> c_int;
  pub fn CfdAddPsbtTxOutWithPubkey(
    handle: *const c_void, psbt_handle: *const c_void, amount: c_longlong,
    locking_script: *const c_char, descriptor: *const c_char, index: *mut c_uint) -> c_int;
  pub fn CfdAddPsbtTxOutWithScript(
    handle: *const c_void, psbt_handle: *const c_void, amount: c_longlong,
    locking_script: *const c_char, redeem_script: *const c_char,
    descriptor: *const c_char, index: *mut c_uint) -> c_int;
  pub fn CfdSetPsbtTxOutBip32Pubkey(
    handle: *const c_void, psbt_handle: *const c_void, index: c_uint, pubkey: *const c_char,
    fingerprint: *const c_char, bip32_path: *const c_char) -> c_int;
  pub fn CfdGetPsbtTxInIndex(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint,
    index: *mut c_uint) -> c_int;
  pub fn CfdGetPsbtPubkeyRecord(
    handle: *const c_void, psbt_handle: *const c_void, record_kind: c_int, index: c_uint,
    pubkey: *const c_char, value: *mut *mut c_char) -> c_int;  // (txin:signature, key. txout:key)
  pub fn CfdIsFindPsbtPubkeyRecord(
    handle: *const c_void, psbt_handle: *const c_void, record_kind: c_int, index: c_uint,
    pubkey: *const c_char) -> c_int;
  pub fn CfdGetPsbtBip32Data(
    handle: *const c_void, psbt_handle: *const c_void, record_kind: c_int, index: c_uint,
    pubkey: *const c_char, fingerprint: *mut *mut c_char, bip32_path: *mut *mut c_char) -> c_int;
  pub fn CfdGetPsbtPubkeyList(
    handle: *const c_void, psbt_handle: *const c_void, record_kind: c_int, index: c_uint,
    list_num: *mut c_uint, pubkey_list_handle: *mut *mut c_void) -> c_int;
  pub fn CfdGetPsbtPubkeyListData(
    handle: *const c_void, pubkey_list_handle: *const c_void, index: c_uint, pubkey: *mut *mut c_char,
    pubkey_hex: *mut *mut c_char) -> c_int;
  pub fn CfdGetPsbtPubkeyListBip32Data(
    handle: *const c_void, pubkey_list_handle: *const c_void, index: c_uint, pubkey: *mut *mut c_char,
    fingerprint: *mut *mut c_char, bip32_path: *mut *mut c_char) -> c_int;
  pub fn CfdFreePsbtPubkeyList(handle: *const c_void, pubkey_list_handle: *const c_void) -> c_int;
  pub fn CfdGetPsbtByteDataList(
    handle: *const c_void, psbt_handle: *const c_void, record_kind: c_int, index: c_uint,
    list_num: *mut c_uint, data_list_handle: *mut *mut c_void) -> c_int;
  pub fn CfdGetPsbtByteDataItem(
    handle: *const c_void, data_list_handle: *const c_void, index: c_uint, data: *mut *mut c_char) -> c_int;
  pub fn CfdFreePsbtByteDataList(handle: *const c_void, data_list_handle: *const c_void) -> c_int;
  pub fn CfdAddPsbtGlobalXpubkey(
    handle: *const c_void, psbt_handle: *const c_void, xpubkey: *const c_char,
    fingerprint: *const c_char, bip32_path: *const c_char) -> c_int;
  pub fn CfdSetPsbtRedeemScript(
    handle: *const c_void, psbt_handle: *const c_void, record_type: c_int, index: c_uint,
    redeem_script: *const c_char) -> c_int;
  pub fn CfdAddPsbtRecord(
    handle: *const c_void, psbt_handle: *const c_void, record_type: c_int, index: c_uint,
    key: *const c_char, value: *const c_char) -> c_int;
  pub fn CfdGetPsbtRecord(
    handle: *const c_void, psbt_handle: *const c_void, record_type: c_int, index: c_uint,
    key: *const c_char, value: *mut *mut c_char) -> c_int;
  pub fn CfdIsFindPsbtRecord(
    handle: *const c_void, psbt_handle: *const c_void, record_type: c_int, index: c_uint,
    key: *const c_char) -> c_int;
  pub fn CfdVerifyPsbtTxIn(
    handle: *const c_void, psbt_handle: *const c_void, txid: *const c_char, vout: c_uint) -> c_int;
  pub fn CfdInitializeFundPsbt(handle: *const c_void, fund_handle: *mut *mut c_void) -> c_int;
  pub fn CfdFundPsbtAddToUtxoList(
    handle: *const c_void, fund_handle: *const c_void, txid: *const c_char, vout: c_uint,
    amount: c_longlong, asset: *const c_char, descriptor: *const c_char,
    scriptsig_template: *const c_char, full_utxo_tx: *const c_char) -> c_int;
  pub fn CfdSetOptionFundPsbt(
    handle: *const c_void, fund_handle: *const c_void, key: c_int, int64_value: c_longlong,
    double_value: c_double, bool_value: bool) -> c_int;
  pub fn CfdFinalizeFundPsbt(
    handle: *const c_void, psbt_handle: *const c_void, fund_handle: *const c_void,
    change_address_descriptor: *const c_char, tx_fee: *mut c_longlong,
    used_utxo_count: *mut c_uint) -> c_int;
  pub fn CfdGetFundPsbtUsedUtxo(
    handle: *const c_void, fund_handle: *const c_void, index: c_uint, utxo_index: *mut c_uint,
    txid: *mut *mut c_char, vout: *mut c_uint, amount: *mut c_longlong, asset: *mut *mut c_char,
    descriptor: *mut *mut c_char, scriptsig_template: *mut *mut c_char) -> c_int;
  pub fn CfdFreeFundPsbt(handle: *const c_void, fund_handle: *const c_void) -> c_int;
}
