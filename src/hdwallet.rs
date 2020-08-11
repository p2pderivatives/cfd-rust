extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uint, c_void};
use crate::common::{
  byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free, hex_from_bytes, ByteData,
  CfdError, ErrorHandle, Network,
};
use crate::key::{Privkey, Pubkey};
use std::ffi::CString;
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

pub const XPRIV_MAINNET_VERSION: &str = "0488ade4";
pub const XPRIV_TESTNET_VERSION: &str = "04358394";
pub const XPUB_MAINNET_VERSION: &str = "0488b21e";
pub const XPUB_TESTNET_VERSION: &str = "043587cf";

#[derive(Debug, PartialEq, Eq, Clone)]
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
  let result: Result<Pubkey, CfdError>;
  let extkey_obj = CString::new(extkey);
  if extkey_obj.is_err() {
    return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
  }
  let extkey_str = extkey_obj.unwrap();
  let err_handle = ErrorHandle::new();
  if let Err(err_handle) = err_handle {
    return Err(err_handle);
  }
  let handle = err_handle.unwrap();
  let mut pubkey_hex: *mut c_char = ptr::null_mut();
  let error_code = unsafe {
    CfdGetPubkeyFromExtkey(
      handle.as_handle(),
      extkey_str.as_ptr(),
      network_type.to_c_value(),
      &mut pubkey_hex,
    )
  };
  if error_code == 0 {
    let pubkey_obj = unsafe { collect_cstring_and_free(pubkey_hex) };
    if let Err(ret) = pubkey_obj {
      result = Err(ret);
    } else {
      result = Pubkey::from_str(&pubkey_obj.unwrap());
    }
  } else {
    result = Err(handle.get_error(error_code));
  }
  handle.free_handle();
  result
}

fn generate_privkey(extkey: &str, network_type: Network) -> Result<Privkey, CfdError> {
  let result: Result<Privkey, CfdError>;
  let extkey_obj = CString::new(extkey);
  if extkey_obj.is_err() {
    return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
  }
  let extkey_str = extkey_obj.unwrap();
  let err_handle = ErrorHandle::new();
  if let Err(err_handle) = err_handle {
    return Err(err_handle);
  }
  let handle = err_handle.unwrap();
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
  if error_code == 0 {
    let privkey_obj = unsafe { collect_cstring_and_free(privkey_hex) };
    let wif_obj = unsafe { collect_cstring_and_free(wif) };
    if let Err(ret) = privkey_obj {
      result = Err(ret);
    } else if let Err(ret) = wif_obj {
      result = Err(ret);
    } else {
      result = Privkey::from_wif(&wif_obj.unwrap());
    }
  } else {
    result = Err(handle.get_error(error_code));
  }
  handle.free_handle();
  result
}

impl ExtKey {
  fn from_extkey(extkey: &str) -> Result<ExtKey, CfdError> {
    let result: Result<ExtKey, CfdError>;
    let extkey_obj = CString::new(extkey);
    if extkey_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let extkey_str = extkey_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let version_obj;
      let fingerprint_obj;
      let chain_code_obj;
      unsafe {
        version_obj = collect_cstring_and_free(version);
        fingerprint_obj = collect_cstring_and_free(fingerprint);
        chain_code_obj = collect_cstring_and_free(chain_code);
      }
      if let Err(ret) = version_obj {
        result = Err(ret);
      } else if let Err(ret) = fingerprint_obj {
        result = Err(ret);
      } else if let Err(ret) = chain_code_obj {
        result = Err(ret);
      } else {
        let version_str = version_obj.unwrap();
        let version_byte = byte_from_hex_unsafe(&version_str);
        let fingerprint_byte = byte_from_hex_unsafe(&fingerprint_obj.unwrap());
        let chain_code_byte = byte_from_hex_unsafe(&chain_code_obj.unwrap());
        let net_type: Result<Network, CfdError> = match &version_str as &str {
          XPRIV_MAINNET_VERSION => Ok(Network::Mainnet),
          XPRIV_TESTNET_VERSION => Ok(Network::Testnet),
          XPUB_MAINNET_VERSION => Ok(Network::Mainnet),
          XPUB_TESTNET_VERSION => Ok(Network::Testnet),
          _ => Err(CfdError::IllegalArgument(
            "unsupported version.".to_string(),
          )),
        };
        if let Err(ret) = net_type {
          result = Err(ret);
        } else {
          let extkey_obj = ExtKey {
            extkey: extkey.to_string(),
            version: ByteData::from_slice(&version_byte),
            fingerprint: ByteData::from_slice(&fingerprint_byte),
            chain_code: ByteData::from_slice(&chain_code_byte),
            depth: depth as u8,
            child_number,
            network_type: net_type.unwrap(),
          };
          result = Ok(extkey_obj);
        }
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub(in crate) fn derive_from_number(
    &self,
    child_number: u32,
    hardened: bool,
    key_type: &ExtKeyType,
  ) -> Result<ExtKey, CfdError> {
    let result: Result<ExtKey, CfdError>;
    let extkey_obj = CString::new(self.extkey.clone());
    if extkey_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let extkey_str = extkey_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let extkey_obj = unsafe { collect_cstring_and_free(extkey_hex) };
      if let Err(ret) = extkey_obj {
        result = Err(ret);
      } else {
        result = ExtKey::from_extkey(&extkey_obj.unwrap());
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
      let result = temp_extkey.derive_from_number(*child_number, false, &key_type);
      if let Err(ret) = result {
        return Err(ret);
      }
      temp_extkey = result.unwrap();
    }
    Ok(temp_extkey)
  }

  pub(in crate) fn derive_from_path(
    &self,
    path: &str,
    key_type: &ExtKeyType,
  ) -> Result<ExtKey, CfdError> {
    let result: Result<ExtKey, CfdError>;
    let extkey_obj = CString::new(self.extkey.clone());
    let path_obj = CString::new(path);
    if extkey_obj.is_err() || path_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let extkey_str = extkey_obj.unwrap();
    let path_str = path_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let extkey_obj = unsafe { collect_cstring_and_free(extkey_hex) };
      if let Err(ret) = extkey_obj {
        result = Err(ret);
      } else {
        result = ExtKey::from_extkey(&extkey_obj.unwrap());
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExtPrivkey {
  extkey: ExtKey,
  privkey: Privkey,
}

impl ExtPrivkey {
  pub fn from_seed(seed: &[u8], network_type: &Network) -> Result<ExtPrivkey, CfdError> {
    let result: Result<ExtPrivkey, CfdError>;
    let seed_obj = CString::new(hex_from_bytes(seed));
    if seed_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let seed_str = seed_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let extkey_obj = unsafe { collect_cstring_and_free(extkey_hex) };
      if let Err(ret) = extkey_obj {
        result = Err(ret);
      } else {
        result = ExtPrivkey::new(&extkey_obj.unwrap());
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn new(extkey: &str) -> Result<ExtPrivkey, CfdError> {
    let extkey_ret = ExtKey::from_extkey(extkey);
    if let Err(ret) = extkey_ret {
      return Err(ret);
    }
    ExtPrivkey::from_key(extkey_ret.unwrap())
  }

  fn from_key(extkey: ExtKey) -> Result<ExtPrivkey, CfdError> {
    let privkey_obj = generate_privkey(extkey.to_str(), *extkey.get_network_type());
    if let Err(ret) = privkey_obj {
      return Err(ret);
    }
    Ok(ExtPrivkey {
      extkey,
      privkey: privkey_obj.unwrap(),
    })
  }

  pub fn derive_from_number(
    &self,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPrivkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number(child_number, hardened, &ExtKeyType::Privkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    ExtPrivkey::from_key(extkey.unwrap())
  }

  pub fn derive_from_number_list(&self, number_list: &[u32]) -> Result<ExtPrivkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number_list(number_list, &ExtKeyType::Privkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    ExtPrivkey::from_key(extkey.unwrap())
  }
  pub fn derive_from_path(&self, path: &str) -> Result<ExtPrivkey, CfdError> {
    let extkey = self.extkey.derive_from_path(path, &ExtKeyType::Privkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    ExtPrivkey::from_key(extkey.unwrap())
  }

  pub fn get_ext_pubkey(&self) -> Result<ExtPubkey, CfdError> {
    let result: Result<ExtPubkey, CfdError>;
    let extkey_obj = CString::new(self.extkey.to_str());
    if extkey_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let extkey_str = extkey_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut ext_pubkey_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateExtPubkey(
        handle.as_handle(),
        extkey_str.as_ptr(),
        self.extkey.get_network_type().to_c_value(),
        &mut ext_pubkey_hex,
      )
    };
    if error_code == 0 {
      let ext_pubkey_obj = unsafe { collect_cstring_and_free(ext_pubkey_hex) };
      if let Err(ret) = ext_pubkey_obj {
        result = Err(ret);
      } else {
        result = ExtPubkey::new(&ext_pubkey_obj.unwrap());
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn derive_pubkey_from_number(
    &self,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number(child_number, hardened, &ExtKeyType::Privkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    let ext_privkey = ExtPrivkey::from_key(extkey.unwrap());
    if let Err(ret) = ext_privkey {
      return Err(ret);
    }
    ext_privkey.unwrap().get_ext_pubkey()
  }

  pub fn derive_pubkey_from_number_list(&self, number_list: &[u32]) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number_list(number_list, &ExtKeyType::Privkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    let ext_privkey = ExtPrivkey::from_key(extkey.unwrap());
    if let Err(ret) = ext_privkey {
      return Err(ret);
    }
    ext_privkey.unwrap().get_ext_pubkey()
  }

  pub fn derive_pubkey_from_path(&self, path: &str) -> Result<ExtPubkey, CfdError> {
    let extkey = self.extkey.derive_from_path(path, &ExtKeyType::Privkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    let ext_privkey = ExtPrivkey::from_key(extkey.unwrap());
    if let Err(ret) = ext_privkey {
      return Err(ret);
    }
    ext_privkey.unwrap().get_ext_pubkey()
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExtPubkey {
  extkey: ExtKey,
  pubkey: Pubkey,
}

impl ExtPubkey {
  pub fn new(extkey: &str) -> Result<ExtPubkey, CfdError> {
    let extkey_ret = ExtKey::from_extkey(extkey);
    if let Err(ret) = extkey_ret {
      return Err(ret);
    }
    ExtPubkey::from_key(extkey_ret.unwrap())
  }

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
    let result: Result<ExtPubkey, CfdError>;

    let fingerprint_obj = unsafe {
      if let Some(fingerprint) = fingerprint.as_ref() {
        CString::new(fingerprint.to_hex())
      } else {
        CString::new(String::default())
      }
    };
    let parent_pubkey_obj = unsafe {
      if let Some(parent_pubkey) = parent_pubkey.as_ref() {
        CString::new(parent_pubkey.to_hex())
      } else {
        CString::new(String::default())
      }
    };
    let pubkey_obj = CString::new(pubkey.to_hex());
    let chain_code_obj = CString::new(chain_code.to_hex());
    if fingerprint_obj.is_err()
      || parent_pubkey_obj.is_err()
      || pubkey_obj.is_err()
      || chain_code_obj.is_err()
    {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let parent_pubkey_hex = parent_pubkey_obj.unwrap();
    let pubkey_hex = pubkey_obj.unwrap();
    let fingerprint_hex = fingerprint_obj.unwrap();
    let chain_code_hex = chain_code_obj.unwrap();

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let extkey_obj = unsafe { collect_cstring_and_free(extkey) };
      if let Err(ret) = extkey_obj {
        result = Err(ret);
      } else {
        result = ExtPubkey::new(&extkey_obj.unwrap());
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
    let extkey_ret = ExtPubkey::validate(&extkey);
    if let Err(ret) = extkey_ret {
      return Err(ret);
    }
    let pubkey_obj = generate_pubkey(extkey.to_str(), *extkey.get_network_type());
    if let Err(ret) = pubkey_obj {
      return Err(ret);
    }
    Ok(ExtPubkey {
      extkey,
      pubkey: pubkey_obj.unwrap(),
    })
  }

  pub fn derive_from_number(
    &self,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number(child_number, hardened, &ExtKeyType::Pubkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    ExtPubkey::from_key(extkey.unwrap())
  }
  pub fn derive_from_number_list(&self, number_list: &[u32]) -> Result<ExtPubkey, CfdError> {
    let extkey = self
      .extkey
      .derive_from_number_list(number_list, &ExtKeyType::Pubkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    ExtPubkey::from_key(extkey.unwrap())
  }
  pub fn derive_from_path(&self, path: &str) -> Result<ExtPubkey, CfdError> {
    let extkey = self.extkey.derive_from_path(path, &ExtKeyType::Pubkey);
    if let Err(ret) = extkey {
      return Err(ret);
    }
    ExtPubkey::from_key(extkey.unwrap())
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

pub enum MnemonicLanguage {
  EN,
  ES,
  FR,
  IT,
  JP,
  ZhCn,
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HDWallet {
  seed: Vec<u8>,
}

impl HDWallet {
  pub fn mnemonic_word_list_en() -> Result<Vec<String>, CfdError> {
    HDWallet::mnemonic_word_list(MnemonicLanguage::EN)
  }

  pub fn mnemonic_word_list(lang: MnemonicLanguage) -> Result<Vec<String>, CfdError> {
    let mut result: Result<Vec<String>, CfdError> = Err(CfdError::Unknown(
      "Failed to mnemonic_word_list.".to_string(),
    ));

    let lang_obj = CString::new(lang.to_str());
    if lang_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let language = lang_obj.unwrap();

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let mut list: Vec<String> = vec![];
      list.reserve(max_num as usize);
      let mut index = 0;

      while index < max_num {
        let mut mnemonic_word: *mut c_char = ptr::null_mut();
        let error_code = unsafe {
          CfdGetMnemonicWord(
            handle.as_handle(),
            mnemonic_handle,
            index,
            &mut mnemonic_word,
          )
        };
        if error_code == 0 {
          let mnemonic_word_obj = unsafe { collect_cstring_and_free(mnemonic_word) };
          if let Err(ret) = mnemonic_word_obj {
            result = Err(ret);
            break;
          } else {
            let word = mnemonic_word_obj.unwrap();
            list.push(word);
          }
        } else {
          result = Err(handle.get_error(error_code));
          break;
        }
        index += 1;
      }
      unsafe {
        CfdFreeMnemonicWordList(handle.as_handle(), mnemonic_handle);
      }
      if list.len() == (max_num as usize) {
        result = Ok(list);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn mnemonic_from_entropy(entropy: &[u8], lang: MnemonicLanguage) -> Result<String, CfdError> {
    let result: Result<String, CfdError>;

    let entropy_obj = CString::new(hex_from_bytes(&entropy));
    let language_obj = CString::new(lang.to_str());
    if entropy_obj.is_err() || language_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let entropy_hex = entropy_obj.unwrap();
    let language = language_obj.unwrap();

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut mnemonic: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdConvertEntropyToMnemonic(
        handle.as_handle(),
        entropy_hex.as_ptr(),
        language.as_ptr(),
        &mut mnemonic,
      )
    };
    if error_code == 0 {
      let mnemonic_obj = unsafe { collect_cstring_and_free(mnemonic) };
      if let Err(ret) = mnemonic_obj {
        result = Err(ret);
      } else {
        result = Ok(mnemonic_obj.unwrap());
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn entropy_from_mnemonic(
    mnemonic: &str,
    lang: MnemonicLanguage,
  ) -> Result<Vec<u8>, CfdError> {
    let result: Result<Vec<u8>, CfdError>;
    let mnemonic_obj = CString::new(mnemonic);
    let language_obj = CString::new(lang.to_str());
    let passphrase_obj = CString::new(String::default());
    if mnemonic_obj.is_err() || language_obj.is_err() || passphrase_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let mnemonic_str = mnemonic_obj.unwrap();
    let language = language_obj.unwrap();
    let passphrase = passphrase_obj.unwrap();

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let seed_obj = unsafe { collect_cstring_and_free(seed) };
      let entropy_obj = unsafe { collect_cstring_and_free(entropy) };
      if let Err(ret) = seed_obj {
        result = Err(ret);
      } else if let Err(ret) = entropy_obj {
        result = Err(ret);
      } else {
        result = byte_from_hex(&entropy_obj.unwrap());
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn from_mnemonic(mnemonic: &str, lang: MnemonicLanguage) -> Result<HDWallet, CfdError> {
    HDWallet::from_mnemonic_passphrase(mnemonic, lang, "")
  }

  pub fn from_mnemonic_passphrase(
    mnemonic: &str,
    lang: MnemonicLanguage,
    passphrase: &str,
  ) -> Result<HDWallet, CfdError> {
    let result: Result<HDWallet, CfdError>;
    let mnemonic_obj = CString::new(mnemonic);
    let language_obj = CString::new(lang.to_str());
    let passphrase_obj = CString::new(passphrase);
    if mnemonic_obj.is_err() || language_obj.is_err() || passphrase_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let mnemonic_str = mnemonic_obj.unwrap();
    let language = language_obj.unwrap();
    let passphrase = passphrase_obj.unwrap();

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let seed_obj = unsafe { collect_cstring_and_free(seed) };
      let entropy_obj = unsafe { collect_cstring_and_free(entropy) };
      if let Err(ret) = seed_obj {
        result = Err(ret);
      } else if let Err(ret) = entropy_obj {
        result = Err(ret);
      } else {
        result = Ok(HDWallet {
          seed: byte_from_hex_unsafe(&seed_obj.unwrap()),
        });
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn from_slice(seed: &[u8]) -> Result<HDWallet, CfdError> {
    // verify
    let ext_priv = ExtPrivkey::from_seed(seed, &Network::Mainnet);
    if let Err(ret) = ext_priv {
      Err(ret)
    } else {
      Ok(HDWallet {
        seed: seed.to_vec(),
      })
    }
  }

  #[inline]
  pub fn to_seed(&self) -> &[u8] {
    &self.seed
  }

  pub fn get_privkey(&self, network_type: &Network) -> Result<ExtPrivkey, CfdError> {
    ExtPrivkey::from_seed(&self.seed, network_type)
  }
  pub fn get_privkey_from_path(
    &self,
    network_type: &Network,
    bip32path: &str,
  ) -> Result<ExtPrivkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type);
    if let Err(ret) = ext_priv {
      return Err(ret);
    }
    ext_priv.unwrap().derive_from_path(bip32path)
  }
  pub fn get_privkey_from_number(
    &self,
    network_type: &Network,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPrivkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type);
    if let Err(ret) = ext_priv {
      return Err(ret);
    }
    ext_priv.unwrap().derive_from_number(child_number, hardened)
  }

  pub fn get_privkey_from_number_list(
    &self,
    network_type: &Network,
    child_number_list: &[u32],
  ) -> Result<ExtPrivkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type);
    if let Err(ret) = ext_priv {
      return Err(ret);
    }
    ext_priv.unwrap().derive_from_number_list(child_number_list)
  }

  pub fn get_pubkey(&self, network_type: &Network) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type);
    if let Err(ret) = ext_priv {
      return Err(ret);
    }
    ext_priv.unwrap().get_ext_pubkey()
  }
  pub fn get_pubkey_from_path(
    &self,
    network_type: &Network,
    bip32path: &str,
  ) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type);
    if let Err(ret) = ext_priv {
      return Err(ret);
    }
    ext_priv.unwrap().derive_pubkey_from_path(bip32path)
  }
  pub fn get_pubkey_from_number(
    &self,
    network_type: &Network,
    child_number: u32,
    hardened: bool,
  ) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type);
    if let Err(ret) = ext_priv {
      return Err(ret);
    }
    ext_priv
      .unwrap()
      .derive_pubkey_from_number(child_number, hardened)
  }
  pub fn get_pubkey_from_number_list(
    &self,
    network_type: &Network,
    child_number_list: &[u32],
  ) -> Result<ExtPubkey, CfdError> {
    let ext_priv = ExtPrivkey::from_seed(&self.seed, &network_type);
    if let Err(ret) = ext_priv {
      return Err(ret);
    }
    ext_priv
      .unwrap()
      .derive_pubkey_from_number_list(child_number_list)
  }
}

impl fmt::Display for HDWallet {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.seed);
    write!(f, "seed:{}", s)
  }
}
