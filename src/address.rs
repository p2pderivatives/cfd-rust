extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uint, c_void};
use crate::common::{
  alloc_c_string, collect_cstring_and_free, collect_multi_cstring_and_free, CfdError, ErrorHandle,
  Network,
};
use crate::{key::Pubkey, script::Script};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdCreateAddress, CfdFreeAddressesMultisigHandle, CfdGetAddressFromLockingScript,
  CfdGetAddressFromMultisigKey, CfdGetAddressInfo, CfdGetAddressesFromMultisig,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashType {
  P2pkh,
  P2sh,
  P2wpkh,
  P2wsh,
  P2shP2wpkh,
  P2shP2wsh,
  Unknown,
}

impl HashType {
  pub(in crate) fn from_c_value(hash_type: c_int) -> HashType {
    match hash_type {
      1 => HashType::P2sh,
      2 => HashType::P2pkh,
      3 => HashType::P2wsh,
      4 => HashType::P2wpkh,
      5 => HashType::P2shP2wsh,
      6 => HashType::P2shP2wpkh,
      _ => HashType::Unknown,
    }
  }

  pub(in crate) fn to_c_value(&self) -> c_int {
    match self {
      HashType::P2sh => 1,
      HashType::P2pkh => 2,
      HashType::P2wsh => 3,
      HashType::P2wpkh => 4,
      HashType::P2shP2wsh => 5,
      HashType::P2shP2wpkh => 6,
      HashType::Unknown => 0,
    }
  }

  pub fn to_address_type(&self) -> AddressType {
    match self {
      HashType::P2pkh => AddressType::P2pkhAddress,
      HashType::P2sh => AddressType::P2shAddress,
      HashType::P2wpkh => AddressType::P2wpkhAddress,
      HashType::P2wsh => AddressType::P2wshAddress,
      HashType::P2shP2wpkh => AddressType::P2shP2wpkhAddress,
      HashType::P2shP2wsh => AddressType::P2shP2wshAddress,
      HashType::Unknown => AddressType::Unknown,
    }
  }

  pub fn get_witness_version(&self) -> WitnessVersion {
    match self {
      HashType::P2wpkh => WitnessVersion::Version0,
      HashType::P2wsh => WitnessVersion::Version0,
      HashType::P2shP2wpkh => WitnessVersion::Version0,
      HashType::P2shP2wsh => WitnessVersion::Version0,
      _ => WitnessVersion::None,
    }
  }
}

impl fmt::Display for HashType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      HashType::P2sh => write!(f, "HashType:p2sh"),
      HashType::P2pkh => write!(f, "HashType:p2pkh"),
      HashType::P2wsh => write!(f, "HashType:p2wsh"),
      HashType::P2wpkh => write!(f, "HashType:p2wpkh"),
      HashType::P2shP2wsh => write!(f, "HashType:p2sh-p2wsh"),
      HashType::P2shP2wpkh => write!(f, "HashType:p2sh-p2wpkh"),
      HashType::Unknown => write!(f, "HashType:unknown"),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AddressType {
  P2pkhAddress,
  P2shAddress,
  P2wpkhAddress,
  P2wshAddress,
  P2shP2wpkhAddress,
  P2shP2wshAddress,
  Unknown,
}

impl AddressType {
  pub(in crate) fn to_c_value(&self) -> c_int {
    match self {
      AddressType::P2shAddress => 1,
      AddressType::P2pkhAddress => 2,
      AddressType::P2wshAddress => 3,
      AddressType::P2wpkhAddress => 4,
      AddressType::P2shP2wshAddress => 5,
      AddressType::P2shP2wpkhAddress => 6,
      AddressType::Unknown => 0,
    }
  }

  pub(in crate) fn to_c_hash_type(&self) -> c_int {
    self.to_c_value()
  }
}

impl fmt::Display for AddressType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      AddressType::P2shAddress => write!(f, "Address:p2sh"),
      AddressType::P2pkhAddress => write!(f, "Address:p2pkh"),
      AddressType::P2wshAddress => write!(f, "Address:p2wsh"),
      AddressType::P2wpkhAddress => write!(f, "Address:p2wpkh"),
      AddressType::P2shP2wshAddress => write!(f, "Address:p2sh-p2wsh"),
      AddressType::P2shP2wpkhAddress => write!(f, "Address:p2sh-p2wpkh"),
      AddressType::Unknown => write!(f, "Address:unknown"),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WitnessVersion {
  None,
  Version0,
  Version1,  // version 1 (for future use)
  Version2,  // version 2 (for future use)
  Version3,  // version 3 (for future use)
  Version4,  // version 4 (for future use)
  Version5,  // version 5 (for future use)
  Version6,  // version 6 (for future use)
  Version7,  // version 7 (for future use)
  Version8,  // version 8 (for future use)
  Version9,  // version 9 (for future use)
  Version10, // version 10 (for future use)
  Version11, // version 11 (for future use)
  Version12, // version 12 (for future use)
  Version13, // version 13 (for future use)
  Version14, // version 14 (for future use)
  Version15, // version 15 (for future use)
  Version16, // version 16 (for future use)
}

impl fmt::Display for WitnessVersion {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      WitnessVersion::None => write!(f, "Segwit:none"),
      WitnessVersion::Version0 => write!(f, "Segwit:v0"),
      WitnessVersion::Version1 => write!(f, "Segwit:v1"),
      WitnessVersion::Version2 => write!(f, "Segwit:v2"),
      WitnessVersion::Version3 => write!(f, "Segwit:v3"),
      WitnessVersion::Version4 => write!(f, "Segwit:v4"),
      WitnessVersion::Version5 => write!(f, "Segwit:v5"),
      WitnessVersion::Version6 => write!(f, "Segwit:v6"),
      WitnessVersion::Version7 => write!(f, "Segwit:v7"),
      WitnessVersion::Version8 => write!(f, "Segwit:v8"),
      WitnessVersion::Version9 => write!(f, "Segwit:v9"),
      WitnessVersion::Version10 => write!(f, "Segwit:v10"),
      WitnessVersion::Version11 => write!(f, "Segwit:v11"),
      WitnessVersion::Version12 => write!(f, "Segwit:v12"),
      WitnessVersion::Version13 => write!(f, "Segwit:v13"),
      WitnessVersion::Version14 => write!(f, "Segwit:v14"),
      WitnessVersion::Version15 => write!(f, "Segwit:v15"),
      WitnessVersion::Version16 => write!(f, "Segwit:v16"),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Address {
  address: String,
  locking_script: Script,
  network_type: Network,
  address_type: AddressType,
  p2sh_wrapped_segwit_script: Script,
  witness_version: WitnessVersion,
}

impl Address {
  pub fn from_string(address: &str) -> Result<Address, CfdError> {
    let addr = alloc_c_string(address)?;
    let handle = ErrorHandle::new()?;
    let mut network_type_c: c_int = 0;
    let mut hash_type_c: c_int = 0;
    let mut witness_version_c: c_int = 0;
    let mut locking_script: *mut c_char = ptr::null_mut();
    let mut hash: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetAddressInfo(
        handle.as_handle(),
        addr.as_ptr(),
        &mut network_type_c,
        &mut hash_type_c,
        &mut witness_version_c,
        &mut locking_script,
        &mut hash,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[locking_script, hash]) }?;
        let script_obj = &str_list[0];
        let script = Script::from_hex(script_obj)?;
        let hash_type = HashType::from_c_value(hash_type_c);
        Ok(Address {
          address: address.to_string(),
          locking_script: script,
          network_type: Network::from_c_value(network_type_c),
          address_type: hash_type.to_address_type(),
          p2sh_wrapped_segwit_script: Script::default(),
          witness_version: hash_type.get_witness_version(),
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn from_locking_script(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    let hex = alloc_c_string(&script.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut address: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetAddressFromLockingScript(
        handle.as_handle(),
        hex.as_ptr(),
        network_type.to_c_value(),
        &mut address,
      )
    };
    let result = match error_code {
      0 => {
        let address_obj = unsafe { collect_cstring_and_free(address) }?;
        Address::from_string(&address_obj)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  #[inline]
  pub fn from_multisig(
    require_num: u8,
    pubkey_list: &[Pubkey],
    address_type: &AddressType,
    network_type: &Network,
  ) -> Result<Address, CfdError> {
    let script = Script::multisig(require_num, pubkey_list)?;
    Address::get_address(
      ptr::null(),
      &script,
      address_type.to_c_value(),
      network_type.to_c_value(),
    )
  }

  pub fn p2pkh(pubkey: &Pubkey, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      pubkey,
      ptr::null(),
      HashType::P2pkh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  // FIXME: move address struct
  pub fn p2wpkh(pubkey: &Pubkey, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      pubkey,
      ptr::null(),
      HashType::P2wpkh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  pub fn p2sh_p2wpkh(pubkey: &Pubkey, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      pubkey,
      ptr::null(),
      HashType::P2shP2wpkh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  pub fn p2sh(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      ptr::null(),
      script,
      HashType::P2sh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  pub fn p2wsh(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      ptr::null(),
      script,
      HashType::P2wsh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  pub fn p2sh_p2wsh(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      ptr::null(),
      script,
      HashType::P2shP2wsh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  #[inline]
  pub fn to_str(&self) -> &str {
    &self.address
  }

  #[inline]
  pub fn get_locking_script(&self) -> &Script {
    &self.locking_script
  }

  #[inline]
  pub fn get_network_type(&self) -> &Network {
    &self.network_type
  }

  #[inline]
  pub fn get_address_type(&self) -> &AddressType {
    &self.address_type
  }

  pub fn get_p2sh_wrapped_script(&self) -> Result<&Script, CfdError> {
    match self.address_type {
      AddressType::P2shP2wpkhAddress => Ok(&self.p2sh_wrapped_segwit_script),
      AddressType::P2shP2wshAddress => Ok(&self.p2sh_wrapped_segwit_script),
      _ => Err(CfdError::IllegalState(
        "current address is not p2sh-segwit.".to_string(),
      )),
    }
  }

  pub fn get_witness_version(&self) -> WitnessVersion {
    self.witness_version
  }

  pub fn valid(&self) -> bool {
    if !self.address.is_empty() {
      false
    } else if let Ok(_result) = Address::from_string(&self.address) {
      true
    } else {
      false
    }
  }

  pub fn get_multisig_addresses(
    multisig_script: &Script,
    address_type: &AddressType,
    network_type: &Network,
  ) -> Result<Vec<MultisigItem>, CfdError> {
    let redeem_script = alloc_c_string(&multisig_script.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut max_key_num: c_uint = 0;
    let mut addr_multisig_keys_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdGetAddressesFromMultisig(
        handle.as_handle(),
        redeem_script.as_ptr(),
        network_type.to_c_value(),
        address_type.to_c_hash_type(),
        &mut addr_multisig_keys_handle,
        &mut max_key_num,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          let mut list: Vec<MultisigItem> = vec![];
          list.reserve(max_key_num as usize);
          let mut index = 0;
          let mut result: Result<Vec<MultisigItem>, CfdError> = Err(CfdError::Unknown(
            "Failed to get_multisig_addresses.".to_string(),
          ));

          while index < max_key_num {
            let item = {
              let mut address: *mut c_char = ptr::null_mut();
              let mut pubkey: *mut c_char = ptr::null_mut();
              let error_code = unsafe {
                CfdGetAddressFromMultisigKey(
                  handle.as_handle(),
                  addr_multisig_keys_handle,
                  index,
                  &mut address,
                  &mut pubkey,
                )
              };
              match error_code {
                0 => {
                  let str_list = unsafe { collect_multi_cstring_and_free(&[address, pubkey]) }?;
                  let addr_obj = &str_list[0];
                  let pubkey_obj = &str_list[1];
                  let address = Address::from_string(&addr_obj)?;
                  let pubkey = Pubkey::from_str(&pubkey_obj)?;
                  Ok(MultisigItem { address, pubkey })
                }
                _ => Err(handle.get_error(error_code)),
              }
            }?;
            list.push(item);
            index += 1;
          }
          if list.len() == (max_key_num as usize) {
            result = Ok(list)
          }
          result
        };
        unsafe {
          CfdFreeAddressesMultisigHandle(handle.as_handle(), addr_multisig_keys_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  fn get_address(
    pubkey: *const Pubkey,
    script: *const Script,
    hash_type: c_int,
    network_type: c_int,
  ) -> Result<Address, CfdError> {
    let pubkey_hex = unsafe {
      match pubkey.as_ref() {
        Some(pubkey) => alloc_c_string(&pubkey.to_hex()),
        _ => alloc_c_string(""),
      }
    }?;
    let redeem_script = unsafe {
      match script.as_ref() {
        Some(script) => alloc_c_string(&script.to_hex()),
        _ => alloc_c_string(""),
      }
    }?;
    let handle = ErrorHandle::new()?;
    let mut address: *mut c_char = ptr::null_mut();
    let mut locking_script: *mut c_char = ptr::null_mut();
    let mut p2sh_segwit_locking_script: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateAddress(
        handle.as_handle(),
        hash_type,
        pubkey_hex.as_ptr(),
        redeem_script.as_ptr(),
        network_type,
        &mut address,
        &mut locking_script,
        &mut p2sh_segwit_locking_script,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe {
          collect_multi_cstring_and_free(&[address, locking_script, p2sh_segwit_locking_script])
        }?;
        let addr_obj = &str_list[0];
        let script_obj = &str_list[1];
        let segwit_obj = &str_list[2];
        let addr_locking_script = Script::from_hex(script_obj)?;
        let segwit_script = Script::from_hex(segwit_obj)?;
        let hash_type_obj = HashType::from_c_value(hash_type);
        Ok(Address {
          address: addr_obj.clone(),
          locking_script: addr_locking_script,
          network_type: Network::from_c_value(network_type),
          address_type: hash_type_obj.to_address_type(),
          p2sh_wrapped_segwit_script: segwit_script,
          witness_version: hash_type_obj.get_witness_version(),
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

impl FromStr for Address {
  type Err = CfdError;
  fn from_str(string: &str) -> Result<Address, CfdError> {
    Address::from_string(string)
  }
}

impl fmt::Display for Address {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.address)
  }
}

impl Default for Address {
  fn default() -> Address {
    Address {
      address: String::default(),
      locking_script: Script::default(),
      network_type: Network::Mainnet,
      address_type: AddressType::Unknown,
      p2sh_wrapped_segwit_script: Script::default(),
      witness_version: WitnessVersion::None,
    }
  }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MultisigItem {
  address: Address,
  pubkey: Pubkey,
}

impl MultisigItem {
  #[inline]
  pub fn new(address: Address, pubkey: Pubkey) -> MultisigItem {
    MultisigItem { address, pubkey }
  }
  #[inline]
  pub fn get_address(&self) -> &Address {
    &self.address
  }
  #[inline]
  pub fn get_pubkey(&self) -> &Pubkey {
    &self.pubkey
  }
}

impl fmt::Display for MultisigItem {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let address = self.address.to_str();
    let pubkey = &self.pubkey.to_hex();
    write!(f, "address:{}, pubkey:{}", address, pubkey)
  }
}
