extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uint, c_void};
use crate::common::{
  alloc_c_string, byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free,
  collect_multi_cstring_and_free, hex_from_bytes, ByteData, CfdError, ErrorHandle, Network,
};
use crate::key::{Privkey, Pubkey};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdConvertEntropyToMnemonic, CfdConvertMnemonicToSeed, CfdCreateExtPubkey, CfdCreateExtkey,
  CfdCreateExtkeyFromParent, CfdCreateExtkeyFromParentPath, CfdCreateExtkeyFromSeed,
  CfdFreeMnemonicWordList, CfdGetExtkeyInformation, CfdGetMnemonicWord, CfdGetPrivkeyFromExtkey,
  CfdGetPubkeyFromExtkey, CfdInitializeMnemonicWordList,
};

/// xpriv mainnet version
pub const XPRIV_MAINNET_VERSION: &str = "0488ade4";
/// xpriv testnet version
pub const XPRIV_TESTNET_VERSION: &str = "04358394";
/// xpub mainnet version
pub const XPUB_MAINNET_VERSION: &str = "0488b21e";
/// xpub testnet version
pub const XPUB_TESTNET_VERSION: &str = "043587cf";

/// An enumeration of extkey type.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(in crate) enum ExtKeyType {
  Privkey,
  Pubkey,
}

impl ExtKeyType {
  pub fn to_c_value(&self) -> c_int {
    match self {
      ExtKeyType::Privkey => 0,
      ExtKeyType::Pubkey => 1,
    }
  }
}

impl fmt::Display for ExtKeyType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      ExtKeyType::Privkey => write!(f, "ExtPrivkey"),
      ExtKeyType::Pubkey => write!(f, "ExtPubkey"),
    }
  }
}

/// A container that stores a extkey.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExtKey {
  extkey: String,
  version: ByteData,
  fingerprint: ByteData,
  chain_code: ByteData,
  depth: u8,
  child_number: u32,
  network_type: Network,
}

fn generate_pubkey(extkey: &str, network_type: Network) -> Result<Pubkey, CfdError> {
  let extkey_str = alloc_c_string(extkey)?;
  let mut handle = ErrorHandle::new()?;
  let mut pubkey_hex: *mut c_char = ptr::null_mut();
  let error_code = unsafe {
    CfdGetPubkeyFromExtkey(
      handle.as_handle(),
      extkey_str.as_ptr(),
      network_type.to_c_value(),
      &mut pubkey_hex,
    )
  };
  let result = match error_code {
    0 => {
      let pubkey_obj = unsafe { collect_cstring_and_free(pubkey_hex) }?;
      Pubkey::from_str(&pubkey_obj)
    }
    _ => Err(handle.get_error(error_code)),
  };
  handle.free_handle();
  result
}

fn generate_privkey(extkey: &str, network_type: Network) -> Result<Privkey, CfdError> {
  let extkey_str = alloc_c_string(extkey)?;
  let mut handle = ErrorHandle::new()?;
  let mut privkey_hex: *mut c_char = ptr::null_mut();
  let mut wif: *mut c_char = ptr::null_mut();
  let error_code = unsafe {
    CfdGetPrivkeyFromExtkey(
      handle.as_handle(),
      extkey_str.as_ptr(),
      network_type.to_c_value(),
      &mut privkey_hex,
      &mut wif,
    )
  };
  let result = match error_code {
    0 => {
      let str_list = unsafe { collect_multi_cstring_and_free(&[privkey_hex, wif]) }?;
      let wif_obj = &str_list[1];
      Privkey::from_wif(wif_obj)
    }
    _ => Err(handle.get_error(error_code)),
  };
  handle.free_handle();
  result
}

impl ExtKey {
  fn from_extkey(extkey: &str) -> Result<ExtKey, CfdError> {
    let extkey_str = alloc_c_string(extkey)?;
    let mut handle = ErrorHandle::new()?;
    let mut version: *mut c_char = ptr::null_mut();
    let mut fingerprint: *mut c_char = ptr::null_mut();
    let mut chain_code: *mut c_char = ptr::null_mut();
    let mut depth: c_uint = 0;
    let mut child_number: c_uint = 0;
    let error_code = unsafe {
      CfdGetExtkeyInformation(
        handle.as_handle(),
        extkey_str.as_ptr(),
        &mut version,
        &mut fingerprint,
        &mut chain_code,
        &mut depth,
        &mut child_number,
      )
    };
    let result = match error_code {
      0 => {
        let str_list =
          unsafe { collect_multi_cstring_and_free(&[version, fingerprint, chain_code]) }?;
        let version_str = &str_list[0];
        let fingerprint_obj = &str_list[1];
        let chain_code_obj = &str_list[2];
        let version_byte = byte_from_hex_unsafe(version_str);
        let fingerprint_byte = byte_from_hex_unsafe(fingerprint_obj);
        let chain_code_byte = byte_from_hex_unsafe(chain_code_obj);
        let net_type = match &version_str as &str {
          XPRIV_MAINNET_VERSION => Ok(Network::Mainnet),
          XPRIV_TESTNET_VERSION => Ok(Network::Testnet),
          XPUB_MAINNET_VERSION => Ok(Network::Mainnet),
          XPUB_TESTNET_VERSION => Ok(Network::Testnet),
          _ => Err(CfdError::IllegalArgument(
            "unsupported version.".to_string(),
          )),
        }?;
        Ok(ExtKey {
          extkey: extkey.to_string(),
          version: ByteData::from_slice(&version_byte),
          fingerprint: ByteData::from_slice(&fingerprint_byte),
          chain_code: ByteData::from_slice(&chain_code_byte),
          depth: depth as u8,
          child_number,
          network_type: net_type,
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub(in crate) fn derive_from_number(
    &self,
    child_number: u32,
    hardened: bool,
    key_type: &ExtKeyType,
  ) -> Result<ExtKey, CfdError> {
    let extkey_str = alloc_c_string(&self.extkey)?;
    let mut handle = ErrorHandle::new()?;
    let mut extkey_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateExtkeyFromParent(
        handle.as_handle(),
        extkey_str.as_ptr(),
        child_number,
        hardened,
        self.get_network_type().to_c_value(),
        key_type.to_c_value(),
        &mut extkey_hex,
      )
    };
    let result = match error_code {
      0 => {
        let extkey_obj = unsafe { collect_cstring_and_free(extkey_hex) }?;
        ExtKey::from_extkey(&extkey_obj)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub(in crate) fn derive_from_number_list(
    &self,
    number_list: &[u32],
    key_type: &ExtKeyType,
  ) -> Result<ExtKey, CfdError> {
    if number_list.is_empty() {
      return Err(CfdError::IllegalArgument("list is empty.".to_string()));
    }
    let mut temp_extkey = self.clone();
    for child_number in number_list {
      temp_extkey = temp_extkey.derive_from_number(*child_number, false, &key_type)?;
    }
    Ok(temp_extkey)
  }

  pub(in crate) fn derive_from_path(
    &self,
    path: &str,
    key_type: &ExtKeyType,
  ) -> Result<ExtKey, CfdError> {
    let extkey_str = alloc_c_string(&self.extkey)?;
    let path_str = alloc_c_string(path)?;
    let mut handle = ErrorHandle::new()?;
    let mut extkey_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateExtkeyFromParentPath(
        handle.as_handle(),
        extkey_str.as_ptr(),
        path_str.as_ptr(),
        self.get_network_type().to_c_value(),
        key_type.to_c_value(),
        &mut extkey_hex,
      )
    };
    let result = match error_code {
      0 => {
        let extkey_obj = unsafe { collect_cstring_and_free(extkey_hex) }?;
        ExtKey::from_extkey(&extkey_obj)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  #[inline]
  pub fn to_str(&self) -> &str {
    &self.extkey
  }

  #[inline]
  pub fn get_version(&self) -> &ByteData {
    &self.version
  }

  #[inline]
  pub fn get_fingerprint(&self) -> &ByteData {
    &self.fingerprint
  }

  #[inline]
  pub fn get_chain_code(&self) -> &ByteData {
    &self.chain_code
  }

  #[inline]
  pub fn get_depth(&self) -> u8 {
    self.depth
  }

  #[inline]
  pub fn get_child_number(&self) -> u32 {
    self.child_number
  }

  #[inline]
  pub fn get_network_type(&self) -> &Network {
    &self.network_type
  }
}

impl fmt::Display for ExtKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.extkey)
  }
}

impl Default for ExtKey {
  fn default() -> ExtKey {
    ExtKey {
      extkey: String::default(),
      version: ByteData::default(),
      fingerprint: ByteData::default(),
      chain_code: ByteData::default(),
      depth: 0,
      child_number: 0,
      network_type: Network::Mainnet,
    }
  }
}

/// A container that stores a ext privkey.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExtPrivkey {
  extkey: ExtKey,
  privkey: Privkey,
}

impl ExtPrivkey {
  /// Generate from a seed.
  ///
  /// # Arguments
  /// * `seed` - A seed byte data.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ExtPrivkey, Network};
  /// let seed = [1; 32];
  /// let extkey = ExtPrivkey::from_seed(&seed, &Network::Testnet).expect("Fail");
  /// ```
  pub fn from_seed(seed: &[u8], network_type: &Network) -> Result<ExtPrivkey, CfdError> {
    let seed_str = alloc_c_string(&hex_from_bytes(seed))?;
    let mut handle = ErrorHandle::new()?;
    let mut extkey_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateExtkeyFromSeed(
        handle.as_handle(),
        seed_str.as_ptr(),
        network_type.to_c_value(),
        ExtKeyType::Privkey.to_c_value(),
        &mut extkey_hex,
      )
    };
    let result = match error_code {
      0 => {
        let extkey_obj = unsafe { collect_cstring_and_free(extkey_hex) }?;
        ExtPrivkey::new(&extkey_obj)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Parse from an ext privkey string.
  ///
  /// # Arguments
  /// * `key` - An ext privkey string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// ```
  pub fn new(extkey: &str) -> Result<ExtPrivkey, CfdError> {
    let extkey_ret = ExtKey::from_extkey(extkey);
    if let Err(ret) = extkey_ret {
      return Err(ret);
    }
    ExtPrivkey::from_key(extkey_ret.unwrap())
  }

  fn from_key(extkey: ExtKey) -> Result<ExtPrivkey, CfdError> {
    let privkey = generate_privkey(extkey.to_str(), *extkey.get_network_type())?;
    Ok(ExtPrivkey { extkey, privkey })
  }

  /// Derive key.
  ///
  /// # Arguments
  /// * `child_number` - A child number for derive.
  /// * `hardened` - A hardened flag.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// let derive_key = extkey.derive_from_number(2, true).expect("Fail");
  /// ```
  pub fn derive_from_number(
    &self,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPrivkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number(child_number, hardened, &ExtKeyType::Privkey)?;
    ExtPrivkey::from_key(extkey)
  }

  /// Derive from number list.
  ///
  /// # Arguments
  /// * `number_list` - Multiple child number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// let number_list = [0x80000002, 1];
  /// let derive_key = extkey.derive_from_number_list(&number_list).expect("Fail");
  /// ```
  pub fn derive_from_number_list(&self, number_list: &[u32]) -> Result<ExtPrivkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number_list(number_list, &ExtKeyType::Privkey)?;
    ExtPrivkey::from_key(extkey)
  }

  /// Derive from number path string.
  ///
  /// # Arguments
  /// * `path` - child number path (bip32 path).
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// let path = "2'/1";
  /// let derive_key = extkey.derive_from_path(path).expect("Fail");
  /// ```
  pub fn derive_from_path(&self, path: &str) -> Result<ExtPrivkey, CfdError> {
    let extkey = self.extkey.derive_from_path(path, &ExtKeyType::Privkey)?;
    ExtPrivkey::from_key(extkey)
  }

  /// Get ext pubkey.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// let ext_pubkey = extkey.get_ext_pubkey().expect("Fail");
  /// ```
  pub fn get_ext_pubkey(&self) -> Result<ExtPubkey, CfdError> {
    let extkey_str = alloc_c_string(&self.extkey.to_str())?;
    let mut handle = ErrorHandle::new()?;
    let mut ext_pubkey_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateExtPubkey(
        handle.as_handle(),
        extkey_str.as_ptr(),
        self.extkey.get_network_type().to_c_value(),
        &mut ext_pubkey_hex,
      )
    };
    let result = match error_code {
      0 => {
        let ext_pubkey_obj = unsafe { collect_cstring_and_free(ext_pubkey_hex) }?;
        ExtPubkey::new(&ext_pubkey_obj)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Derive pubkey.
  ///
  /// # Arguments
  /// * `child_number` - A child number for derive.
  /// * `hardened` - A hardened flag.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// let derive_pubkey = extkey.derive_pubkey_from_number(2, true).expect("Fail");
  /// ```
  pub fn derive_pubkey_from_number(
    &self,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number(child_number, hardened, &ExtKeyType::Privkey)?;
    let ext_privkey = ExtPrivkey::from_key(extkey)?;
    ext_privkey.get_ext_pubkey()
  }

  /// Derive pubkey from number list.
  ///
  /// # Arguments
  /// * `number_list` - Multiple child number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// let number_list = [0x80000002, 1];
  /// let derive_pubkey = extkey.derive_pubkey_from_number_list(&number_list).expect("Fail");
  /// ```
  pub fn derive_pubkey_from_number_list(&self, number_list: &[u32]) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number_list(number_list, &ExtKeyType::Privkey)?;
    let ext_privkey = ExtPrivkey::from_key(extkey)?;
    ext_privkey.get_ext_pubkey()
  }

  /// Derive pubkey from number path string.
  ///
  /// # Arguments
  /// * `path` - child number path (bip32 path).
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPrivkey;
  /// let key = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
  /// let extkey = ExtPrivkey::new(key).expect("Fail");
  /// let path = "2'/1";
  /// let derive_pubkey = extkey.derive_pubkey_from_path(path).expect("Fail");
  /// ```
  pub fn derive_pubkey_from_path(&self, path: &str) -> Result<ExtPubkey, CfdError> {
    let extkey = self.extkey.derive_from_path(path, &ExtKeyType::Privkey)?;
    let ext_privkey = ExtPrivkey::from_key(extkey)?;
    ext_privkey.get_ext_pubkey()
  }

  #[inline]
  pub fn get_privkey(&self) -> &Privkey {
    &self.privkey
  }

  #[inline]
  pub fn to_str(&self) -> &str {
    &self.extkey.extkey
  }

  #[inline]
  pub fn get_version(&self) -> &ByteData {
    &self.extkey.version
  }

  #[inline]
  pub fn get_fingerprint(&self) -> &ByteData {
    &self.extkey.fingerprint
  }

  #[inline]
  pub fn get_chain_code(&self) -> &ByteData {
    &self.extkey.chain_code
  }

  #[inline]
  pub fn get_depth(&self) -> u8 {
    self.extkey.depth
  }

  #[inline]
  pub fn get_child_number(&self) -> u32 {
    self.extkey.child_number
  }

  #[inline]
  pub fn get_network_type(&self) -> &Network {
    &self.extkey.network_type
  }

  #[inline]
  pub fn valid(&self) -> bool {
    !self.extkey.extkey.is_empty()
  }
}

impl fmt::Display for ExtPrivkey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.extkey)
  }
}

impl FromStr for ExtPrivkey {
  type Err = CfdError;
  fn from_str(string: &str) -> Result<ExtPrivkey, CfdError> {
    ExtPrivkey::new(string)
  }
}

impl Default for ExtPrivkey {
  fn default() -> ExtPrivkey {
    ExtPrivkey {
      extkey: ExtKey::default(),
      privkey: Privkey::default(),
    }
  }
}

/// A container that stores a ext pubkey.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExtPubkey {
  extkey: ExtKey,
  pubkey: Pubkey,
}

impl ExtPubkey {
  /// Parse from an ext pubkey string.
  ///
  /// # Arguments
  /// * `key` - An ext pubkey string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPubkey;
  /// let key = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  /// let extkey = ExtPubkey::new(key).expect("Fail");
  /// ```
  pub fn new(extkey: &str) -> Result<ExtPubkey, CfdError> {
    let extkey_ret = ExtKey::from_extkey(extkey)?;
    ExtPubkey::from_key(extkey_ret)
  }

  /// Create ext pubkey from parent pubkey.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `parent_pubkey` - A parent pubkey.
  /// * `pubkey` - A current pubkey.
  /// * `chain_code` - A chain code.
  /// * `depth` - A depth.
  /// * `child_number` - A current child number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ExtPubkey, Pubkey, ByteData, Network};
  /// use std::str::FromStr;
  /// let extkey = ExtPubkey::from_parent_info(
  ///   Network::Testnet,
  ///   Pubkey::from_str("02ca30dbb25a2cf96344a04ae2144fb28a17f006c34cfb973b9f21623db27c5cd3").expect("Fail"),
  ///   Pubkey::from_str("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3").expect("Fail"),
  ///   ByteData::from_str("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e").expect("Fail"),
  ///   4,
  ///   44,
  /// ).expect("Fail");
  /// ```
  pub fn from_parent_info(
    network_type: Network,
    parent_pubkey: Pubkey,
    pubkey: Pubkey,
    chain_code: ByteData,
    depth: u32,
    child_number: u32,
  ) -> Result<ExtPubkey, CfdError> {
    ExtPubkey::create_ext_pubkey(
      ptr::null(),
      &parent_pubkey,
      network_type,
      pubkey,
      chain_code,
      depth,
      child_number,
    )
  }

  /// Create ext pubkey from parent pubkey fingerprint.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `fingerprint` - A parent pubkey fingerprint.
  /// * `pubkey` - A current pubkey.
  /// * `chain_code` - A chain code.
  /// * `depth` - A depth.
  /// * `child_number` - A current child number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ExtPubkey, Pubkey, ByteData, Network};
  /// use std::str::FromStr;
  /// let extkey = ExtPubkey::create(
  ///   Network::Testnet,
  ///   ByteData::from_str("a53a8ff3").expect("Fail"),
  ///   Pubkey::from_str("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3").expect("Fail"),
  ///   ByteData::from_str("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e").expect("Fail"),
  ///   4,
  ///   44,
  /// ).expect("Fail");
  /// ```
  pub fn create(
    network_type: Network,
    fingerprint: ByteData,
    pubkey: Pubkey,
    chain_code: ByteData,
    depth: u32,
    child_number: u32,
  ) -> Result<ExtPubkey, CfdError> {
    ExtPubkey::create_ext_pubkey(
      &fingerprint,
      ptr::null(),
      network_type,
      pubkey,
      chain_code,
      depth,
      child_number,
    )
  }

  fn create_ext_pubkey(
    fingerprint: *const ByteData,
    parent_pubkey: *const Pubkey,
    network_type: Network,
    pubkey: Pubkey,
    chain_code: ByteData,
    depth: u32,
    child_number: u32,
  ) -> Result<ExtPubkey, CfdError> {
    let fingerprint_hex = unsafe {
      match fingerprint.as_ref() {
        Some(fingerprint) => alloc_c_string(&fingerprint.to_hex()),
        _ => alloc_c_string(""),
      }
    }?;
    let parent_pubkey_hex = unsafe {
      match parent_pubkey.as_ref() {
        Some(parent_pubkey) => alloc_c_string(&parent_pubkey.to_hex()),
        _ => alloc_c_string(""),
      }
    }?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let chain_code_hex = alloc_c_string(&chain_code.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut extkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateExtkey(
        handle.as_handle(),
        network_type.to_c_value(),
        ExtKeyType::Pubkey.to_c_value(),
        parent_pubkey_hex.as_ptr(),
        fingerprint_hex.as_ptr(),
        pubkey_hex.as_ptr(),
        chain_code_hex.as_ptr(),
        depth as u8,
        child_number,
        &mut extkey,
      )
    };
    let result = match error_code {
      0 => {
        let extkey_obj = unsafe { collect_cstring_and_free(extkey) }?;
        ExtPubkey::new(&extkey_obj)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  fn validate(extkey: &ExtKey) -> Result<(), CfdError> {
    match &extkey.version.to_hex() as &str {
      XPUB_MAINNET_VERSION => Ok(()),
      XPUB_TESTNET_VERSION => Ok(()),
      _ => Err(CfdError::IllegalArgument(
        "Invalid xpub version.".to_string(),
      )),
    }
  }

  fn from_key(extkey: ExtKey) -> Result<ExtPubkey, CfdError> {
    let _ret = ExtPubkey::validate(&extkey)?;
    let pubkey = generate_pubkey(extkey.to_str(), *extkey.get_network_type())?;
    Ok(ExtPubkey { extkey, pubkey })
  }

  /// Derive pubkey.
  ///
  /// # Arguments
  /// * `child_number` - A child number for derive.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPubkey;
  /// let key = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  /// let extkey = ExtPubkey::new(key).expect("Fail");
  /// let derive_pubkey = extkey.derive_from_number(2).expect("Fail");
  /// ```
  pub fn derive_from_number(&self, child_number: u32) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number(child_number, false, &ExtKeyType::Pubkey)?;
    ExtPubkey::from_key(extkey)
  }

  /// Derive pubkey from number list.
  ///
  /// # Arguments
  /// * `number_list` - Multiple child number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPubkey;
  /// let key = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  /// let extkey = ExtPubkey::new(key).expect("Fail");
  /// let number_list = [2, 1];
  /// let derive_pubkey = extkey.derive_from_number_list(&number_list).expect("Fail");
  /// ```
  pub fn derive_from_number_list(&self, number_list: &[u32]) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number_list(number_list, &ExtKeyType::Pubkey)?;
    ExtPubkey::from_key(extkey)
  }

  /// Derive pubkey from number path string.
  ///
  /// # Arguments
  /// * `path` - child number path (bip32 path).
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ExtPubkey;
  /// let key = "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy";
  /// let extkey = ExtPubkey::new(key).expect("Fail");
  /// let path = "2/1";
  /// let derive_pubkey = extkey.derive_from_path(path).expect("Fail");
  /// ```
  pub fn derive_from_path(&self, path: &str) -> Result<ExtPubkey, CfdError> {
    let extkey = self.extkey.derive_from_path(path, &ExtKeyType::Pubkey)?;
    ExtPubkey::from_key(extkey)
  }

  #[inline]
  pub fn get_pubkey(&self) -> &Pubkey {
    &self.pubkey
  }

  #[inline]
  pub fn to_str(&self) -> &str {
    &self.extkey.extkey
  }

  #[inline]
  pub fn get_version(&self) -> &ByteData {
    &self.extkey.version
  }

  #[inline]
  pub fn get_fingerprint(&self) -> &ByteData {
    &self.extkey.fingerprint
  }

  #[inline]
  pub fn get_chain_code(&self) -> &ByteData {
    &self.extkey.chain_code
  }

  #[inline]
  pub fn get_depth(&self) -> u8 {
    self.extkey.depth
  }

  #[inline]
  pub fn get_child_number(&self) -> u32 {
    self.extkey.child_number
  }

  #[inline]
  pub fn get_network_type(&self) -> &Network {
    &self.extkey.network_type
  }

  #[inline]
  pub fn valid(&self) -> bool {
    !self.extkey.extkey.is_empty()
  }
}

impl fmt::Display for ExtPubkey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.extkey)
  }
}

impl FromStr for ExtPubkey {
  type Err = CfdError;
  fn from_str(string: &str) -> Result<ExtPubkey, CfdError> {
    ExtPubkey::new(string)
  }
}

impl Default for ExtPubkey {
  fn default() -> ExtPubkey {
    ExtPubkey {
      extkey: ExtKey::default(),
      pubkey: Pubkey::default(),
    }
  }
}

/// The language for mnemonic.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MnemonicLanguage {
  /// English
  EN,
  /// Spanish
  ES,
  /// French
  FR,
  /// Italic
  IT,
  /// Japanese
  JP,
  /// Simplified Chinese (China)
  ZhCn,
  /// Traditional Chinese (Taiwan)
  ZhTw,
}

impl MnemonicLanguage {
  pub(in crate) fn to_str(&self) -> String {
    match self {
      MnemonicLanguage::EN => "en".to_string(),
      MnemonicLanguage::ES => "es".to_string(),
      MnemonicLanguage::FR => "fr".to_string(),
      MnemonicLanguage::IT => "it".to_string(),
      MnemonicLanguage::JP => "jp".to_string(),
      MnemonicLanguage::ZhCn => "zhs".to_string(),
      MnemonicLanguage::ZhTw => "zht".to_string(),
    }
  }
}

/// A container that stores a hdwallet seed.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HDWallet {
  seed: Vec<u8>,
}

impl HDWallet {
  /// Get mnemonic word list by english.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::HDWallet;
  /// let en_words = HDWallet::mnemonic_word_list_en().expect("Fail");
  /// ```
  pub fn mnemonic_word_list_en() -> Result<Vec<String>, CfdError> {
    HDWallet::mnemonic_word_list(MnemonicLanguage::EN)
  }

  /// Get mnemonic word list.
  ///
  /// # Arguments
  /// * `lang` - A mnemonic language.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, MnemonicLanguage};
  /// let en_words = HDWallet::mnemonic_word_list(MnemonicLanguage::EN).expect("Fail");
  /// ```
  pub fn mnemonic_word_list(lang: MnemonicLanguage) -> Result<Vec<String>, CfdError> {
    let language = alloc_c_string(&lang.to_str())?;
    let mut handle = ErrorHandle::new()?;
    let mut max_num: c_uint = 0;
    let mut mnemonic_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeMnemonicWordList(
        handle.as_handle(),
        language.as_ptr(),
        &mut mnemonic_handle,
        &mut max_num,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          let mut list: Vec<String> = vec![];
          list.reserve(max_num as usize);
          let mut index = 0;
          let mut result: Result<Vec<String>, CfdError> = Err(CfdError::Unknown(
            "Failed to mnemonic_word_list.".to_string(),
          ));

          while index < max_num {
            let word = {
              let mut mnemonic_word: *mut c_char = ptr::null_mut();
              let error_code = unsafe {
                CfdGetMnemonicWord(
                  handle.as_handle(),
                  mnemonic_handle,
                  index,
                  &mut mnemonic_word,
                )
              };
              match error_code {
                0 => unsafe { collect_cstring_and_free(mnemonic_word) },
                _ => Err(handle.get_error(error_code)),
              }
            }?;
            list.push(word);
            index += 1;
          }
          if list.len() == (max_num as usize) {
            result = Ok(list);
          }
          result
        };
        unsafe {
          CfdFreeMnemonicWordList(handle.as_handle(), mnemonic_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get mnemonic from entropy.
  ///
  /// # Arguments
  /// * `entropy` - An entropy.
  /// * `lang` - A mnemonic language.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, MnemonicLanguage};
  /// let entropy = [1; 32];
  /// let mnemonic = HDWallet::mnemonic_from_entropy(&entropy, MnemonicLanguage::EN).expect("Fail");
  /// ```
  pub fn mnemonic_from_entropy(entropy: &[u8], lang: MnemonicLanguage) -> Result<String, CfdError> {
    let entropy_hex = alloc_c_string(&hex_from_bytes(&entropy))?;
    let language = alloc_c_string(&lang.to_str())?;
    let mut handle = ErrorHandle::new()?;
    let mut mnemonic: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdConvertEntropyToMnemonic(
        handle.as_handle(),
        entropy_hex.as_ptr(),
        language.as_ptr(),
        &mut mnemonic,
      )
    };
    let result = match error_code {
      0 => unsafe { collect_cstring_and_free(mnemonic) },
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get entropy from mnemonic.
  ///
  /// # Arguments
  /// * `mnemonic` - A mnemonic string (join space).
  /// * `lang` - A mnemonic language.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, MnemonicLanguage};
  /// let entropy = HDWallet::entropy_from_mnemonic(
  ///   "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
  ///   MnemonicLanguage::EN,
  /// ).expect("Fail");
  /// ```
  pub fn entropy_from_mnemonic(
    mnemonic: &str,
    lang: MnemonicLanguage,
  ) -> Result<Vec<u8>, CfdError> {
    let tmp_mnemonic = mnemonic.replace("　", " ");
    let passphrase = alloc_c_string("")?;
    let language = alloc_c_string(&lang.to_str())?;
    let mnemonic_str = alloc_c_string(&tmp_mnemonic)?;
    let mut handle = ErrorHandle::new()?;
    let mut seed: *mut c_char = ptr::null_mut();
    let mut entropy: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdConvertMnemonicToSeed(
        handle.as_handle(),
        mnemonic_str.as_ptr(),
        passphrase.as_ptr(),
        true,
        language.as_ptr(),
        false,
        &mut seed,
        &mut entropy,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[seed, entropy]) }?;
        let entropy_obj = &str_list[1];
        byte_from_hex(entropy_obj)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Create from mnemonic.
  ///
  /// # Arguments
  /// * `mnemonic` - A mnemonic string (join space).
  /// * `lang` - A mnemonic language.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, MnemonicLanguage};
  /// let wallet = HDWallet::from_mnemonic(
  ///   "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
  ///   MnemonicLanguage::EN,
  /// ).expect("Fail");
  /// ```
  pub fn from_mnemonic(mnemonic: &str, lang: MnemonicLanguage) -> Result<HDWallet, CfdError> {
    HDWallet::from_mnemonic_passphrase(mnemonic, lang, "")
  }

  /// Create from mnemonic passphrase.
  ///
  /// # Arguments
  /// * `mnemonic` - A mnemonic string (join space).
  /// * `lang` - A mnemonic language.
  /// * `passphrase` - A passphrase.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, MnemonicLanguage};
  /// let wallet = HDWallet::from_mnemonic_passphrase(
  ///   "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
  ///   MnemonicLanguage::EN,
  ///   "pass",
  /// ).expect("Fail");
  /// ```
  pub fn from_mnemonic_passphrase(
    mnemonic: &str,
    lang: MnemonicLanguage,
    passphrase: &str,
  ) -> Result<HDWallet, CfdError> {
    let tmp_mnemonic = mnemonic.replace("　", " ");
    let passphrase = alloc_c_string(passphrase)?;
    let language = alloc_c_string(&lang.to_str())?;
    let mnemonic_str = alloc_c_string(&tmp_mnemonic)?;
    let mut handle = ErrorHandle::new()?;
    let mut seed: *mut c_char = ptr::null_mut();
    let mut entropy: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdConvertMnemonicToSeed(
        handle.as_handle(),
        mnemonic_str.as_ptr(),
        passphrase.as_ptr(),
        true,
        language.as_ptr(),
        false,
        &mut seed,
        &mut entropy,
      )
    };
    let result = match error_code {
      0 => {
        let list = unsafe { collect_multi_cstring_and_free(&[seed, entropy]) }?;
        let seed_obj = &list[0];
        Ok(HDWallet {
          seed: byte_from_hex_unsafe(seed_obj),
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Create from seed.
  ///
  /// # Arguments
  /// * `seed` - A seed byte.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::HDWallet;
  /// let seed = [1; 32];
  /// let wallet = HDWallet::from_slice(&seed).expect("Fail");
  /// ```
  pub fn from_slice(seed: &[u8]) -> Result<HDWallet, CfdError> {
    // verify
    let _verify = ExtPrivkey::from_seed(seed, &Network::Mainnet)?;
    Ok(HDWallet {
      seed: seed.to_vec(),
    })
  }

  #[inline]
  pub fn to_seed(&self) -> &[u8] {
    &self.seed
  }

  /// Generate ext privkey from a seed.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let extkey = hdwallet.get_privkey(&Network::Testnet).expect("Fail");
  /// ```
  pub fn get_privkey(&self, network_type: &Network) -> Result<ExtPrivkey, CfdError> {
    ExtPrivkey::from_seed(&self.seed, network_type)
  }

  /// Generate ext privkey from a seed, and derive from number path string.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `path` - child number path (bip32 path).
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let path = "2'/1";
  /// let derive_key = hdwallet.get_privkey_from_path(&Network::Testnet, path).expect("Fail");
  /// ```
  pub fn get_privkey_from_path(
    &self,
    network_type: &Network,
    bip32path: &str,
  ) -> Result<ExtPrivkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type)?;
    ext_priv.derive_from_path(bip32path)
  }

  /// Generate ext privkey from a seed, and derive from number.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `child_number` - A child number for derive.
  /// * `hardened` - A hardened flag.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let derive_key = hdwallet.get_privkey_from_number(&Network::Testnet, 2, true).expect("Fail");
  /// ```
  pub fn get_privkey_from_number(
    &self,
    network_type: &Network,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPrivkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type)?;
    ext_priv.derive_from_number(child_number, hardened)
  }

  /// Generate ext privkey from a seed, and derive from number lists.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `child_number_list` - Multiple child number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let child_number_list = vec![0x80000002, 1];
  /// let derive_key = hdwallet.get_privkey_from_number_list(&Network::Testnet, &child_number_list).expect("Fail");
  /// ```
  pub fn get_privkey_from_number_list(
    &self,
    network_type: &Network,
    child_number_list: &[u32],
  ) -> Result<ExtPrivkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type)?;
    ext_priv.derive_from_number_list(child_number_list)
  }

  /// Generate ext pubkey from a seed.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let extkey = hdwallet.get_pubkey(&Network::Testnet).expect("Fail");
  /// ```
  pub fn get_pubkey(&self, network_type: &Network) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type)?;
    ext_priv.get_ext_pubkey()
  }

  /// Generate ext pubkey from a seed, and derive from number path string.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `path` - child number path (bip32 path).
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let path = "2'/1";
  /// let derive_key = hdwallet.get_pubkey_from_path(&Network::Testnet, path).expect("Fail");
  /// ```
  pub fn get_pubkey_from_path(
    &self,
    network_type: &Network,
    bip32path: &str,
  ) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type)?;
    ext_priv.derive_pubkey_from_path(bip32path)
  }

  /// Generate ext pubkey from a seed, and derive from number.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `child_number` - A child number for derive.
  /// * `hardened` - A hardened flag.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let derive_key = hdwallet.get_pubkey_from_number(&Network::Testnet, 2, true).expect("Fail");
  /// ```
  pub fn get_pubkey_from_number(
    &self,
    network_type: &Network,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type)?;
    ext_priv.derive_pubkey_from_number(child_number, hardened)
  }

  /// Generate ext pubkey from a seed, and derive from number lists.
  ///
  /// # Arguments
  /// * `network_type` - A target network.
  /// * `child_number_list` - Multiple child number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{HDWallet, Network};
  /// let seed = [1; 32];
  /// let hdwallet = HDWallet::from_slice(&seed).expect("Fail");
  /// let child_number_list = vec![0x80000002, 1];
  /// let derive_key = hdwallet.get_pubkey_from_number_list(&Network::Testnet, &child_number_list).expect("Fail");
  /// ```
  pub fn get_pubkey_from_number_list(
    &self,
    network_type: &Network,
    child_number_list: &[u32],
  ) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type)?;
    ext_priv.derive_pubkey_from_number_list(child_number_list)
  }
}

impl fmt::Display for HDWallet {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.seed);
    write!(f, "seed:{}", s)
  }
}
