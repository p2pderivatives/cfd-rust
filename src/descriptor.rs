extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uint, c_void};
use crate::address::{Address, HashType};
use crate::common::{
  alloc_c_string, collect_cstring_and_free, collect_multi_cstring_and_free, CfdError, ErrorHandle,
  Network,
};
use crate::hdwallet::{ExtPrivkey, ExtPubkey};
use crate::key::Pubkey;
use crate::schnorr::SchnorrPubkey;
use crate::script::{Script, TapBranch};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdFreeDescriptorHandle, CfdGetDescriptorChecksum, CfdGetDescriptorData,
  CfdGetDescriptorMultisigKey, CfdGetDescriptorRootData, CfdParseDescriptor,
};

/// The script type on descriptor.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DescriptorScriptType {
  /// ScriptType: null
  Null,
  /// ScriptType: sh
  Sh,
  /// ScriptType: wsh
  Wsh,
  /// ScriptType: pk
  Pk,
  /// ScriptType: pkh
  Pkh,
  /// ScriptType: wpkh
  Wpkh,
  /// ScriptType: combo
  Combo,
  /// ScriptType: multi
  Multi,
  /// ScriptType: sortedmulti
  SortedMulti,
  /// ScriptType: addr
  Addr,
  /// ScriptType: raw
  Raw,
  /// ScriptType: miniscript (internal)
  MiniScript,
  /// ScriptType: taproot
  Taproot,
}

impl DescriptorScriptType {
  pub(in crate) fn from_c_value(script_type: c_int) -> DescriptorScriptType {
    match script_type {
      1 => DescriptorScriptType::Sh,
      2 => DescriptorScriptType::Wsh,
      3 => DescriptorScriptType::Pk,
      4 => DescriptorScriptType::Pkh,
      5 => DescriptorScriptType::Wpkh,
      6 => DescriptorScriptType::Combo,
      7 => DescriptorScriptType::Multi,
      8 => DescriptorScriptType::SortedMulti,
      9 => DescriptorScriptType::Addr,
      10 => DescriptorScriptType::Raw,
      11 => DescriptorScriptType::MiniScript,
      12 => DescriptorScriptType::Taproot,
      _ => DescriptorScriptType::Null,
    }
  }
}

impl fmt::Display for DescriptorScriptType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      DescriptorScriptType::Null => write!(f, "type:null"),
      DescriptorScriptType::Sh => write!(f, "type:sh"),
      DescriptorScriptType::Wsh => write!(f, "type:wsh"),
      DescriptorScriptType::Pk => write!(f, "type:pk"),
      DescriptorScriptType::Pkh => write!(f, "type:pkh"),
      DescriptorScriptType::Wpkh => write!(f, "type:wpkh"),
      DescriptorScriptType::Combo => write!(f, "type:combo"),
      DescriptorScriptType::Multi => write!(f, "type:multi"),
      DescriptorScriptType::SortedMulti => write!(f, "type:sorted-multi"),
      DescriptorScriptType::Addr => write!(f, "type:address"),
      DescriptorScriptType::Raw => write!(f, "type:raw"),
      DescriptorScriptType::MiniScript => write!(f, "type:miniscript"),
      DescriptorScriptType::Taproot => write!(f, "type:taproot"),
    }
  }
}

/// The key type on descriptor.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DescriptorKeyType {
  /// key type: null
  Null,
  /// key type: public key
  Public,
  /// key type: bip32 ext pubkey
  Bip32,
  /// key type: bip32 ext privkey
  Bip32Priv,
  /// key type: schnorr pubkey
  Schnorr,
}

impl DescriptorKeyType {
  pub(in crate) fn from_c_value(key_type: c_int) -> DescriptorKeyType {
    match key_type {
      1 => DescriptorKeyType::Public,
      2 => DescriptorKeyType::Bip32,
      3 => DescriptorKeyType::Bip32Priv,
      4 => DescriptorKeyType::Schnorr,
      _ => DescriptorKeyType::Null,
    }
  }
}

impl fmt::Display for DescriptorKeyType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      DescriptorKeyType::Null => write!(f, "keyType:null"),
      DescriptorKeyType::Public => write!(f, "keyType:public"),
      DescriptorKeyType::Bip32 => write!(f, "keyType:bip32"),
      DescriptorKeyType::Bip32Priv => write!(f, "keyType:bip32-priv"),
      DescriptorKeyType::Schnorr => write!(f, "keyType:schnorr"),
    }
  }
}

/// A container that stores a key data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyData {
  key_type: DescriptorKeyType,
  pubkey: Pubkey,
  ext_pubkey: ExtPubkey,
  ext_privkey: ExtPrivkey,
  schnorr_pubkey: SchnorrPubkey,
}

impl KeyData {
  pub fn from_pubkey(pubkey: &Pubkey) -> KeyData {
    if pubkey.valid() {
      KeyData {
        key_type: DescriptorKeyType::Public,
        pubkey: pubkey.clone(),
        ext_pubkey: ExtPubkey::default(),
        ext_privkey: ExtPrivkey::default(),
        schnorr_pubkey: SchnorrPubkey::default(),
      }
    } else {
      KeyData::default()
    }
  }

  pub fn from_ext_pubkey(ext_pubkey: &ExtPubkey) -> KeyData {
    if ext_pubkey.valid() {
      KeyData {
        key_type: DescriptorKeyType::Bip32,
        pubkey: Pubkey::default(),
        ext_pubkey: ext_pubkey.clone(),
        ext_privkey: ExtPrivkey::default(),
        schnorr_pubkey: SchnorrPubkey::default(),
      }
    } else {
      KeyData::default()
    }
  }

  pub fn from_ext_privkey(ext_privkey: &ExtPrivkey) -> KeyData {
    match ext_privkey.valid() {
      true => KeyData {
        key_type: DescriptorKeyType::Bip32Priv,
        pubkey: Pubkey::default(),
        ext_pubkey: ExtPubkey::default(),
        ext_privkey: ext_privkey.clone(),
        schnorr_pubkey: SchnorrPubkey::default(),
      },
      _ => KeyData::default(),
    }
  }

  pub fn from_schnorr_pubkey(schnorr_pubkey: &SchnorrPubkey) -> KeyData {
    match schnorr_pubkey.valid() {
      true => KeyData {
        key_type: DescriptorKeyType::Schnorr,
        pubkey: Pubkey::default(),
        ext_pubkey: ExtPubkey::default(),
        ext_privkey: ExtPrivkey::default(),
        schnorr_pubkey: schnorr_pubkey.clone(),
      },
      _ => KeyData::default(),
    }
  }

  pub fn to_str(&self) -> String {
    match self.key_type {
      DescriptorKeyType::Public => self.pubkey.to_hex(),
      DescriptorKeyType::Bip32 => self.ext_pubkey.to_str().to_string(),
      DescriptorKeyType::Bip32Priv => self.ext_privkey.to_str().to_string(),
      DescriptorKeyType::Schnorr => self.schnorr_pubkey.to_hex(),
      _ => String::default(),
    }
  }

  pub fn get_type(&self) -> &DescriptorKeyType {
    &self.key_type
  }

  pub fn get_pubkey(&self) -> &Pubkey {
    &self.pubkey
  }

  pub fn get_ext_pubkey(&self) -> &ExtPubkey {
    &self.ext_pubkey
  }

  pub fn get_ext_privkey(&self) -> &ExtPrivkey {
    &self.ext_privkey
  }

  pub fn get_schnorr_pubkey(&self) -> &SchnorrPubkey {
    &self.schnorr_pubkey
  }
}

impl fmt::Display for KeyData {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Key:[{}, {}]", &self.key_type, &self.to_str())
  }
}

impl Default for KeyData {
  fn default() -> KeyData {
    KeyData {
      key_type: DescriptorKeyType::Null,
      pubkey: Pubkey::default(),
      ext_pubkey: ExtPubkey::default(),
      ext_privkey: ExtPrivkey::default(),
      schnorr_pubkey: SchnorrPubkey::default(),
    }
  }
}

/// A container that stores a descriptor script data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DescriptorScriptData {
  script_type: DescriptorScriptType,
  depth: u32,
  hash_type: HashType,
  address: Address,
  redeem_script: Script,
  key_data: KeyData,
  multisig_key_list: Vec<KeyData>,
  multisig_require_num: u8,
  script_tree: TapBranch,
}

impl DescriptorScriptData {
  pub fn from_raw_script(depth: u32, redeem_script: &Script) -> DescriptorScriptData {
    DescriptorScriptData {
      script_type: DescriptorScriptType::Raw,
      depth,
      redeem_script: redeem_script.clone(),
      ..DescriptorScriptData::default()
    }
  }

  pub fn from_address(depth: u32, hash_type: &HashType, address: &Address) -> DescriptorScriptData {
    DescriptorScriptData {
      script_type: DescriptorScriptType::Addr,
      depth,
      hash_type: *hash_type,
      address: address.clone(),
      ..DescriptorScriptData::default()
    }
  }

  pub fn from_pubkey(
    script_type: DescriptorScriptType,
    depth: u32,
    hash_type: HashType,
    address: Address,
    key_data: KeyData,
  ) -> DescriptorScriptData {
    DescriptorScriptData {
      script_type,
      depth,
      hash_type,
      address,
      key_data,
      ..DescriptorScriptData::default()
    }
  }

  pub fn from_script(
    script_type: DescriptorScriptType,
    depth: u32,
    hash_type: HashType,
    address: Address,
    script: Script,
  ) -> DescriptorScriptData {
    DescriptorScriptData {
      script_type,
      depth,
      hash_type,
      address,
      redeem_script: script,
      ..DescriptorScriptData::default()
    }
  }

  pub fn from_key_and_script(
    script_type: DescriptorScriptType,
    depth: u32,
    hash_type: HashType,
    address: Address,
    redeem_script: Script,
    key_data: KeyData,
  ) -> DescriptorScriptData {
    DescriptorScriptData {
      script_type,
      depth,
      hash_type,
      address,
      redeem_script,
      key_data,
      ..DescriptorScriptData::default()
    }
  }

  pub fn from_multisig(
    script_type: DescriptorScriptType,
    depth: u32,
    hash_type: HashType,
    address: Address,
    redeem_script: Script,
    multisig_key_list: &[KeyData],
    multisig_require_num: u8,
  ) -> DescriptorScriptData {
    DescriptorScriptData {
      script_type,
      depth,
      hash_type,
      address,
      redeem_script,
      multisig_key_list: multisig_key_list.to_vec(),
      multisig_require_num,
      ..DescriptorScriptData::default()
    }
  }

  pub fn by_taproot(
    script_type: DescriptorScriptType,
    hash_type: HashType,
    address: Address,
    key_data: KeyData,
    script_tree: TapBranch,
  ) -> DescriptorScriptData {
    DescriptorScriptData {
      script_type,
      hash_type,
      address,
      key_data,
      script_tree,
      ..DescriptorScriptData::default()
    }
  }

  pub fn get_script_type(&self) -> &DescriptorScriptType {
    &self.script_type
  }

  pub fn get_depth(&self) -> u32 {
    self.depth
  }

  pub fn get_hash_type(&self) -> &HashType {
    &self.hash_type
  }

  pub fn get_address(&self) -> &Address {
    &self.address
  }

  pub fn get_redeem_script(&self) -> &Script {
    &self.redeem_script
  }
  pub fn get_key_data(&self) -> &KeyData {
    &self.key_data
  }

  pub fn get_multisig_key_list(&self) -> &[KeyData] {
    &self.multisig_key_list
  }

  pub fn get_multisig_require_num(&self) -> u8 {
    self.multisig_require_num
  }

  pub fn get_script_tree(&self) -> &TapBranch {
    &self.script_tree
  }
}

impl fmt::Display for DescriptorScriptData {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.script_type)
  }
}

impl Default for DescriptorScriptData {
  fn default() -> DescriptorScriptData {
    DescriptorScriptData {
      script_type: DescriptorScriptType::Null,
      depth: 0,
      hash_type: HashType::Unknown,
      address: Address::default(),
      redeem_script: Script::default(),
      key_data: KeyData::default(),
      multisig_key_list: vec![],
      multisig_require_num: 0,
      script_tree: TapBranch::default(),
    }
  }
}

/// A container that stores a output descriptor.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Descriptor {
  descriptor: String,
  script_list: Vec<DescriptorScriptData>,
  root_data: DescriptorScriptData,
}

impl Descriptor {
  /// Parse from a descriptor string.
  ///
  /// # Arguments
  /// * `descriptor` - a descriptor string.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network};
  /// let desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  /// let descriptor = Descriptor::new(desc_str, &Network::Testnet).expect("Fail");
  /// ```
  pub fn new(descriptor: &str, network_type: &Network) -> Result<Descriptor, CfdError> {
    let desc = Descriptor::append_checksum(descriptor, network_type)?;
    Descriptor::parse_descriptor(&desc, "", network_type)
  }

  /// Get descriptor from deriving key.
  ///
  /// # Arguments
  /// * `descriptor` - A descriptor string.
  /// * `bip32_path` - A extkey derive bip32 path string.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network};
  /// let desc_str = "pkh(xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy/1/*)";
  /// let path = "2";
  /// let descriptor = Descriptor::with_derive_bip32path(desc_str, path, &Network::Testnet).expect("Fail");
  /// ```
  pub fn with_derive_bip32path(
    descriptor: &str,
    bip32_path: &str,
    network_type: &Network,
  ) -> Result<Descriptor, CfdError> {
    let desc = Descriptor::append_checksum(descriptor, network_type)?;
    Descriptor::parse_descriptor(&desc, bip32_path, network_type)
  }

  /// Create p2pk descriptor.
  ///
  /// # Arguments
  /// * `pubkey` - A pubkey.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let descriptor = Descriptor::p2pk(&key, &Network::Testnet).expect("Fail");
  /// ```
  pub fn p2pk(pubkey: &Pubkey, network_type: &Network) -> Result<Descriptor, CfdError> {
    let desc = format!("pk({})", pubkey.to_hex());
    Descriptor::new(&desc, network_type)
  }

  /// Create p2pkh descriptor.
  ///
  /// # Arguments
  /// * `pubkey` - A pubkey.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let descriptor = Descriptor::p2pkh(&key, &Network::Testnet).expect("Fail");
  /// ```
  pub fn p2pkh(pubkey: &Pubkey, network_type: &Network) -> Result<Descriptor, CfdError> {
    let desc = format!("pkh({})", pubkey.to_hex());
    Descriptor::new(&desc, network_type)
  }

  /// Create p2wpkh descriptor.
  ///
  /// # Arguments
  /// * `pubkey` - A pubkey.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let descriptor = Descriptor::p2wpkh(&key, &Network::Testnet).expect("Fail");
  /// ```
  pub fn p2wpkh(pubkey: &Pubkey, network_type: &Network) -> Result<Descriptor, CfdError> {
    let desc = format!("wpkh({})", pubkey.to_hex());
    Descriptor::new(&desc, network_type)
  }

  /// Create p2sh wrapped p2wpkh descriptor.
  ///
  /// # Arguments
  /// * `pubkey` - A pubkey.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let descriptor = Descriptor::p2sh_p2wpk(&key, &Network::Testnet).expect("Fail");
  /// ```
  pub fn p2sh_p2wpk(pubkey: &Pubkey, network_type: &Network) -> Result<Descriptor, CfdError> {
    let desc = format!("sh(wpkh({}))", pubkey.to_hex());
    Descriptor::new(&desc, network_type)
  }

  /// Create combo descriptor.
  ///
  /// # Arguments
  /// * `pubkey` - A pubkey.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let descriptor = Descriptor::combo(&key, &Network::Testnet).expect("Fail");
  /// ```
  pub fn combo(pubkey: &Pubkey, network_type: &Network) -> Result<Descriptor, CfdError> {
    let desc = format!("combo({})", pubkey.to_hex());
    Descriptor::new(&desc, network_type)
  }

  /// Create addr descriptor.
  ///
  /// # Arguments
  /// * `address` - An address.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Address};
  /// use std::str::FromStr;
  /// let addr_str = "bc1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4jcdzrv";
  /// let addr = Address::from_string(addr_str).expect("Fail");
  /// let descriptor = Descriptor::address(&addr).expect("Fail");
  /// ```
  pub fn address(address: &Address) -> Result<Descriptor, CfdError> {
    let desc = format!("addr({})", address.to_str());
    Descriptor::new(&desc, address.get_network_type())
  }

  /// Create raw script descriptor.
  ///
  /// # Arguments
  /// * `pubkey` - A pubkey.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Script};
  /// use std::str::FromStr;
  /// let op_1 = Script::from_asm("OP_TRUE").expect("Fail");
  /// let descriptor = Descriptor::raw_script(&op_1, &Network::Testnet).expect("Fail");
  /// ```
  pub fn raw_script(
    locking_script: &Script,
    network_type: &Network,
  ) -> Result<Descriptor, CfdError> {
    let desc = format!("raw({})", locking_script.to_hex());
    Descriptor::new(&desc, network_type)
  }

  /// Create multisig descriptor.
  ///
  /// # Arguments
  /// * `pubkey_list` - Multisig pubkey list.
  /// * `require_num` - A multisig require number.
  /// * `hash_type` - A hash type.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, HashType, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key1_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key2_str = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  /// let key3_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let key1 = Pubkey::from_str(key1_str).expect("fail");
  /// let key2 = Pubkey::from_str(key2_str).expect("fail");
  /// let key3 = Pubkey::from_str(key3_str).expect("fail");
  /// let pubkey_list = vec![key1, key2, key3];
  /// let require_num: u8 = 2;
  /// let desc = Descriptor::multisig(&pubkey_list, require_num, &HashType::P2wsh, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn multisig(
    pubkey_list: &[Pubkey],
    require_num: u8,
    hash_type: &HashType,
    network_type: &Network,
  ) -> Result<Descriptor, CfdError> {
    Descriptor::multisig_base(pubkey_list, require_num, hash_type, network_type, false)
  }

  /// Create sorted multisig descriptor.
  ///
  /// # Arguments
  /// * `pubkey_list` - Multisig pubkey list.
  /// * `require_num` - A multisig require number.
  /// * `hash_type` - A hash type.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, HashType, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key1_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key2_str = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  /// let key3_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let key1 = Pubkey::from_str(key1_str).expect("fail");
  /// let key2 = Pubkey::from_str(key2_str).expect("fail");
  /// let key3 = Pubkey::from_str(key3_str).expect("fail");
  /// let pubkey_list = vec![key1, key2, key3];
  /// let require_num: u8 = 2;
  /// let desc = Descriptor::sorted_multisig(&pubkey_list, require_num, &HashType::P2wsh, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn sorted_multisig(
    pubkey_list: &[Pubkey],
    require_num: u8,
    hash_type: &HashType,
    network_type: &Network,
  ) -> Result<Descriptor, CfdError> {
    Descriptor::multisig_base(pubkey_list, require_num, hash_type, network_type, true)
  }

  pub fn taproot_single(schnorr_pubkey: &SchnorrPubkey) -> Result<Descriptor, CfdError> {
    let desc = format!("tr({})", schnorr_pubkey.to_hex());
    Descriptor::new(&desc, &Network::Mainnet)
  }

  fn multisig_base(
    pubkey_list: &[Pubkey],
    require_num: u8,
    hash_type: &HashType,
    network_type: &Network,
    use_sort: bool,
  ) -> Result<Descriptor, CfdError> {
    let mut pubkeys = String::default();
    for pubkey in pubkey_list {
      pubkeys = match pubkeys.is_empty() {
        true => pubkey.to_hex(),
        _ => format!("{},{}", pubkeys, pubkey.to_hex()),
      };
    }
    let target = if use_sort { "sortedmulti" } else { "multi" };
    let desc_multi = format!("{}({},{})", target, require_num, pubkeys);
    let desc = match hash_type {
      HashType::P2sh => Ok(format!("sh({})", desc_multi)),
      HashType::P2wsh => Ok(format!("wsh({})", desc_multi)),
      HashType::P2shP2wsh => Ok(format!("sh(wsh({}))", desc_multi)),
      _ => Err(CfdError::IllegalArgument(
        "unsupported hash type.".to_string(),
      )),
    }?;
    Descriptor::new(&desc, network_type)
  }

  fn parse_descriptor(
    descriptor: &str,
    bip32_path: &str,
    network_type: &Network,
  ) -> Result<Descriptor, CfdError> {
    let descriptor_str = alloc_c_string(descriptor)?;
    let bip32_path_str = alloc_c_string(bip32_path)?;
    let mut handle = ErrorHandle::new()?;
    let mut max_num: c_uint = 0;
    let mut descriptor_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdParseDescriptor(
        handle.as_handle(),
        descriptor_str.as_ptr(),
        network_type.to_c_value(),
        bip32_path_str.as_ptr(),
        &mut descriptor_handle,
        &mut max_num,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          let mut result: Result<Descriptor, CfdError> =
            Err(CfdError::Unknown("Failed to parse_descriptor.".to_string()));
          let mut list: Vec<DescriptorScriptData> = vec![];
          list.reserve(max_num as usize);
          let mut key_list_obj: Vec<KeyData> = vec![];
          let mut index = 0;
          let root_data = {
            let mut script_type: c_int = 0;
            let mut key_type: c_int = 0;
            let mut hash_type: c_int = 0;
            let mut locking_script: *mut c_char = ptr::null_mut();
            let mut address: *mut c_char = ptr::null_mut();
            let mut pubkey: *mut c_char = ptr::null_mut();
            let mut redeem_script: *mut c_char = ptr::null_mut();
            let mut ext_pubkey: *mut c_char = ptr::null_mut();
            let mut ext_privkey: *mut c_char = ptr::null_mut();
            let mut schnorr_pubkey: *mut c_char = ptr::null_mut();
            let mut tree_string: *mut c_char = ptr::null_mut();
            let mut is_multisig: bool = false;
            let mut max_key_num: c_uint = 0;
            let mut req_sig_num: c_uint = 0;
            let error_code = unsafe {
              CfdGetDescriptorRootData(
                handle.as_handle(),
                descriptor_handle,
                &mut script_type,
                &mut locking_script,
                &mut address,
                &mut hash_type,
                &mut redeem_script,
                &mut key_type,
                &mut pubkey,
                &mut ext_pubkey,
                &mut ext_privkey,
                &mut schnorr_pubkey,
                &mut tree_string,
                &mut is_multisig,
                &mut max_key_num,
                &mut req_sig_num,
              )
            };
            if error_code != 0 {
              Err(handle.get_error(error_code))
            } else {
              let str_list = unsafe {
                collect_multi_cstring_and_free(&[
                  locking_script,
                  address,
                  pubkey,
                  redeem_script,
                  ext_pubkey,
                  ext_privkey,
                  schnorr_pubkey,
                  tree_string,
                ])
              }?;
              let addr_str = &str_list[1];
              let pubkey_obj = &str_list[2];
              let script_str = &str_list[3];
              let ext_pubkey_obj = &str_list[4];
              let ext_privkey_obj = &str_list[5];
              let schnorr_pubkey_obj = &str_list[6];
              let tree_string_obj = &str_list[7];
              let addr = match addr_str.is_empty() {
                false => Address::from_string(addr_str)?,
                _ => Address::default(),
              };
              let script = match script_str.is_empty() {
                false => Script::from_hex(script_str)?,
                _ => Script::default(),
              };
              let script_tree = match tree_string_obj.is_empty() {
                false => TapBranch::from_string(tree_string_obj)?,
                _ => TapBranch::default(),
              };
              if is_multisig {
                key_list_obj =
                  Descriptor::collect_multisig_data(&handle, descriptor_handle, max_key_num)?;
              }
              let key_type_obj = DescriptorKeyType::from_c_value(key_type);
              let key_data = match key_type_obj {
                DescriptorKeyType::Null => KeyData::default(),
                _ => Descriptor::collect_key_data(
                  key_type,
                  pubkey_obj,
                  ext_pubkey_obj,
                  ext_privkey_obj,
                  schnorr_pubkey_obj,
                )?,
              };
              Ok(DescriptorScriptData {
                script_type: DescriptorScriptType::from_c_value(script_type),
                depth: 0,
                hash_type: HashType::from_c_value(hash_type),
                address: addr,
                redeem_script: script,
                key_data,
                multisig_key_list: key_list_obj.clone(),
                multisig_require_num: req_sig_num as u8,
                script_tree,
              })
            }
          }?;

          while index <= max_num {
            let mut max_index: c_uint = 0;
            let mut depth: c_uint = 0;
            let mut script_type: c_int = 0;
            let mut key_type: c_int = 0;
            let mut hash_type: c_int = 0;
            let mut locking_script: *mut c_char = ptr::null_mut();
            let mut address: *mut c_char = ptr::null_mut();
            let mut pubkey: *mut c_char = ptr::null_mut();
            let mut redeem_script: *mut c_char = ptr::null_mut();
            let mut ext_pubkey: *mut c_char = ptr::null_mut();
            let mut ext_privkey: *mut c_char = ptr::null_mut();
            let mut is_multisig: bool = false;
            let mut max_key_num: c_uint = 0;
            let mut req_sig_num: c_uint = 0;
            let error_code = unsafe {
              CfdGetDescriptorData(
                handle.as_handle(),
                descriptor_handle,
                index,
                &mut max_index,
                &mut depth,
                &mut script_type,
                &mut locking_script,
                &mut address,
                &mut hash_type,
                &mut redeem_script,
                &mut key_type,
                &mut pubkey,
                &mut ext_pubkey,
                &mut ext_privkey,
                &mut is_multisig,
                &mut max_key_num,
                &mut req_sig_num,
              )
            };
            if error_code != 0 {
              result = Err(handle.get_error(error_code));
              break;
            }
            let str_list = unsafe {
              collect_multi_cstring_and_free(&[
                locking_script,
                address,
                pubkey,
                redeem_script,
                ext_pubkey,
                ext_privkey,
              ])
            }?;
            let locking_script_str = &str_list[0];
            let addr_str = &str_list[1];
            let pubkey_obj = &str_list[2];
            let script_str = &str_list[3];
            let ext_pubkey_obj = &str_list[4];
            let ext_privkey_obj = &str_list[5];
            let mut addr = Address::default();
            let mut script = Script::default();
            if !addr_str.is_empty() {
              addr = Address::from_string(addr_str)?;
            }
            if !script_str.is_empty() {
              script = Script::from_hex(script_str)?;
            }
            let type_obj = DescriptorScriptType::from_c_value(script_type);
            let hash_type_obj = HashType::from_c_value(hash_type);
            let data = match type_obj {
              DescriptorScriptType::Pk | DescriptorScriptType::Pkh | DescriptorScriptType::Wpkh => {
                let key_data = Descriptor::collect_key_data(
                  key_type,
                  pubkey_obj,
                  ext_pubkey_obj,
                  ext_privkey_obj,
                  "",
                )?;
                Ok(DescriptorScriptData::from_pubkey(
                  type_obj,
                  depth,
                  hash_type_obj,
                  addr,
                  key_data,
                ))
              }
              DescriptorScriptType::Sh
              | DescriptorScriptType::Wsh
              | DescriptorScriptType::Multi
              | DescriptorScriptType::SortedMulti => {
                if is_multisig {
                  if key_list_obj.is_empty() {
                    key_list_obj =
                      Descriptor::collect_multisig_data(&handle, descriptor_handle, max_key_num)?;
                  }
                  Ok(DescriptorScriptData::from_multisig(
                    type_obj,
                    depth,
                    hash_type_obj,
                    addr,
                    script,
                    &key_list_obj,
                    req_sig_num as u8,
                  ))
                } else {
                  Ok(DescriptorScriptData::from_script(
                    type_obj,
                    depth,
                    hash_type_obj,
                    addr,
                    script,
                  ))
                }
              }
              DescriptorScriptType::Raw => {
                Ok(DescriptorScriptData::from_raw_script(depth, &script))
              }
              DescriptorScriptType::Addr => Ok(DescriptorScriptData::from_address(
                depth,
                &hash_type_obj,
                &addr,
              )),
              DescriptorScriptType::Combo => {
                if pubkey_obj.is_empty() && ext_pubkey_obj.is_empty() && ext_privkey_obj.is_empty()
                {
                  let script_obj = Script::from_hex(locking_script_str)?;
                  Ok(DescriptorScriptData::from_script(
                    type_obj,
                    depth,
                    hash_type_obj,
                    addr,
                    script_obj,
                  ))
                } else {
                  let key_data = Descriptor::collect_key_data(
                    key_type,
                    pubkey_obj,
                    ext_pubkey_obj,
                    ext_privkey_obj,
                    "",
                  )?;
                  Ok(DescriptorScriptData::from_pubkey(
                    type_obj,
                    depth,
                    hash_type_obj,
                    addr,
                    key_data,
                  ))
                }
              }
              _ => Ok(DescriptorScriptData::default()),
            }?;

            list.push(data);
            index += 1;
          }
          if list.len() == ((max_num + 1) as usize) {
            result = Ok(Descriptor {
              descriptor: descriptor.to_string(),
              script_list: list,
              root_data,
            });
          }
          result
        };
        unsafe {
          CfdFreeDescriptorHandle(handle.as_handle(), descriptor_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn to_str(&self) -> &str {
    &self.descriptor
  }

  pub fn get_script_list(&self) -> &[DescriptorScriptData] {
    &self.script_list
  }

  pub fn get_root_data(&self) -> &DescriptorScriptData {
    &self.root_data
  }

  pub fn get_hash_type(&self) -> &HashType {
    &self.root_data.hash_type
  }

  pub fn get_address(&self) -> &Address {
    &self.root_data.address
  }

  pub fn get_script_tree(&self) -> &TapBranch {
    &self.root_data.script_tree
  }

  /// Exist script-hash.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, HashType, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key1_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key2_str = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  /// let key3_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let key1 = Pubkey::from_str(key1_str).expect("fail");
  /// let key2 = Pubkey::from_str(key2_str).expect("fail");
  /// let key3 = Pubkey::from_str(key3_str).expect("fail");
  /// let pubkey_list = vec![key1, key2, key3];
  /// let require_num: u8 = 2;
  /// let descriptor = Descriptor::multisig(&pubkey_list, require_num, &HashType::P2wsh, &Network::Mainnet).expect("Fail");
  /// let has_script = descriptor.has_script_hash();
  /// ```
  pub fn has_script_hash(&self) -> bool {
    match self.root_data.script_type {
      DescriptorScriptType::Sh | DescriptorScriptType::Wsh => {
        matches!(
          self.root_data.hash_type,
          HashType::P2sh | HashType::P2wsh | HashType::P2shP2wsh
        )
      }
      _ => false,
    }
  }

  pub fn get_redeem_script(&self) -> Result<&Script, CfdError> {
    match self.has_script_hash() {
      false => Err(CfdError::IllegalState(
        "Not exist redeem script.".to_string(),
      )),
      _ => Ok(&self.root_data.redeem_script),
    }
  }

  /// Exist key-hash.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let descriptor = Descriptor::combo(&key, &Network::Testnet).expect("Fail");
  /// let has_key_hash = descriptor.has_key_hash();
  /// ```
  pub fn has_key_hash(&self) -> bool {
    match self.root_data.script_type {
      DescriptorScriptType::Sh
      | DescriptorScriptType::Pkh
      | DescriptorScriptType::Wpkh
      | DescriptorScriptType::Combo => {
        matches!(
          self.root_data.hash_type,
          HashType::P2pkh | HashType::P2wpkh | HashType::P2shP2wpkh
        )
      }
      _ => false,
    }
  }

  pub fn has_taproot(&self) -> bool {
    self.root_data.script_type == DescriptorScriptType::Taproot
  }

  pub fn has_tapscript(&self) -> bool {
    self.has_taproot() && !self.root_data.script_tree.to_str().is_empty()
  }

  pub fn get_key_data(&self) -> Result<&KeyData, CfdError> {
    match self.root_data.key_data.key_type {
      DescriptorKeyType::Null => Err(CfdError::IllegalState("Not exist key data.".to_string())),
      _ => Ok(&self.root_data.key_data),
    }
  }

  /// Exist multisig.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, HashType, Network, Pubkey};
  /// use std::str::FromStr;
  /// let key1_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key2_str = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  /// let key3_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let key1 = Pubkey::from_str(key1_str).expect("fail");
  /// let key2 = Pubkey::from_str(key2_str).expect("fail");
  /// let key3 = Pubkey::from_str(key3_str).expect("fail");
  /// let pubkey_list = vec![key1, key2, key3];
  /// let require_num: u8 = 2;
  /// let descriptor = Descriptor::multisig(&pubkey_list, require_num, &HashType::P2wsh, &Network::Mainnet).expect("Fail");
  /// let has_script = descriptor.has_multisig();
  /// ```
  pub fn has_multisig(&self) -> bool {
    self.root_data.multisig_require_num != 0
  }

  pub fn get_multisig_key_list(&self) -> Result<Vec<KeyData>, CfdError> {
    match self.has_multisig() {
      false => Err(CfdError::IllegalState(
        "Not exist multisig data.".to_string(),
      )),
      _ => Ok(self.root_data.multisig_key_list.to_vec()),
    }
  }

  fn append_checksum(descriptor: &str, network_type: &Network) -> Result<String, CfdError> {
    let descriptor_str = alloc_c_string(descriptor)?;
    let mut handle = ErrorHandle::new()?;
    let mut desc_added_checksum: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetDescriptorChecksum(
        handle.as_handle(),
        network_type.to_c_value(),
        descriptor_str.as_ptr(),
        &mut desc_added_checksum,
      )
    };
    let result = match error_code {
      0 => unsafe { collect_cstring_and_free(desc_added_checksum) },
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  fn collect_key_data(
    key_type: c_int,
    pubkey: &str,
    ext_pubkey: &str,
    ext_privkey: &str,
    schnorr_pubkey: &str,
  ) -> Result<KeyData, CfdError> {
    let key_type_obj = DescriptorKeyType::from_c_value(key_type);
    match key_type_obj {
      DescriptorKeyType::Public => {
        let pubkey_obj = Pubkey::from_str(pubkey)?;
        Ok(KeyData::from_pubkey(&pubkey_obj))
      }
      DescriptorKeyType::Bip32 => {
        let ext_key_obj = ExtPubkey::from_str(ext_pubkey)?;
        Ok(KeyData::from_ext_pubkey(&ext_key_obj))
      }
      DescriptorKeyType::Bip32Priv => {
        let ext_key_obj = ExtPrivkey::from_str(ext_privkey)?;
        Ok(KeyData::from_ext_privkey(&ext_key_obj))
      }
      DescriptorKeyType::Schnorr => {
        let key_obj = match schnorr_pubkey.is_empty() {
          true => SchnorrPubkey::from_str(pubkey)?,
          _ => SchnorrPubkey::from_str(schnorr_pubkey)?,
        };
        Ok(KeyData::from_schnorr_pubkey(&key_obj))
      }
      _ => Err(CfdError::Internal("invalid key type status.".to_string())),
    }
  }

  fn collect_multisig_data(
    handle: &ErrorHandle,
    descriptor_handle: *const c_void,
    key_num: c_uint,
  ) -> Result<Vec<KeyData>, CfdError> {
    let mut result = Err(CfdError::Unknown(
      "Failed to collect_multisig_data.".to_string(),
    ));
    let mut list: Vec<KeyData> = vec![];
    list.reserve(key_num as usize);
    let mut index = 0;

    while index < key_num {
      let key_data = {
        let mut key_type: c_int = 0;
        let mut pubkey: *mut c_char = ptr::null_mut();
        let mut ext_pubkey: *mut c_char = ptr::null_mut();
        let mut ext_privkey: *mut c_char = ptr::null_mut();
        let error_code = unsafe {
          CfdGetDescriptorMultisigKey(
            handle.as_handle(),
            descriptor_handle,
            index,
            &mut key_type,
            &mut pubkey,
            &mut ext_pubkey,
            &mut ext_privkey,
          )
        };
        if error_code != 0 {
          Err(handle.get_error(error_code))
        } else {
          let str_list =
            unsafe { collect_multi_cstring_and_free(&[pubkey, ext_pubkey, ext_privkey]) }?;

          let pubkey_obj = &str_list[0];
          let ext_pubkey_obj = &str_list[1];
          let ext_privkey_obj = &str_list[2];
          Descriptor::collect_key_data(key_type, pubkey_obj, ext_pubkey_obj, ext_privkey_obj, "")
        }
      }?;
      list.push(key_data);
      index += 1;
    }
    if list.len() == (key_num as usize) {
      result = Ok(list);
    }
    result
  }
}

impl fmt::Display for Descriptor {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.descriptor)
  }
}

impl Default for Descriptor {
  fn default() -> Descriptor {
    Descriptor {
      descriptor: String::default(),
      script_list: vec![],
      root_data: DescriptorScriptData::default(),
    }
  }
}
