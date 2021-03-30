extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uint, c_void};
use crate::common::{
  alloc_c_string, collect_cstring_and_free, collect_multi_cstring_and_free, ByteData, CfdError,
  ErrorHandle, Network,
};
use crate::{key::Pubkey, schnorr::SchnorrPubkey, script::Script};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdCreateAddress, CfdFreeAddressesMultisigHandle, CfdGetAddressFromLockingScript,
  CfdGetAddressFromMultisigKey, CfdGetAddressInfo, CfdGetAddressesFromMultisig,
};

/// Hash type of locking script.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashType {
  /// p2pkh
  P2pkh,
  /// p2sh
  P2sh,
  /// p2wpkh
  P2wpkh,
  /// p2wsh
  P2wsh,
  /// p2sh-p2wpkh
  P2shP2wpkh,
  /// p2sh-p2wsh
  P2shP2wsh,
  /// taproot
  Taproot,
  /// unknown type
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
      7 => HashType::Taproot,
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
      HashType::Taproot => 7,
      HashType::Unknown => 0xff,
    }
  }

  /// Get address type from hash type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AddressType;
  /// use cfd_rust::HashType;
  /// let hash_type = HashType::P2wpkh;
  /// let addr_type = hash_type.to_address_type();
  /// ```
  pub fn to_address_type(&self) -> AddressType {
    match self {
      HashType::P2pkh => AddressType::P2pkhAddress,
      HashType::P2sh => AddressType::P2shAddress,
      HashType::P2wpkh => AddressType::P2wpkhAddress,
      HashType::P2wsh => AddressType::P2wshAddress,
      HashType::P2shP2wpkh => AddressType::P2shP2wpkhAddress,
      HashType::P2shP2wsh => AddressType::P2shP2wshAddress,
      HashType::Taproot => AddressType::TaprootAddress,
      HashType::Unknown => AddressType::Unknown,
    }
  }

  /// Get witness version from hash type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AddressType;
  /// use cfd_rust::HashType;
  /// let hash_type = HashType::P2wpkh;
  /// let witness_version = hash_type.get_witness_version();
  /// ```
  pub fn get_witness_version(&self) -> WitnessVersion {
    self.to_address_type().get_witness_version()
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
      HashType::Taproot => write!(f, "HashType:taproot"),
      HashType::Unknown => write!(f, "HashType:unknown"),
    }
  }
}

/// Address type of bitcoin address.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AddressType {
  /// p2pkh address
  P2pkhAddress,
  /// p2sh address. (May include p2sh-segwit)
  P2shAddress,
  /// p2wpkh address (bech32)
  P2wpkhAddress,
  /// p2wsh address (bech32)
  P2wshAddress,
  /// p2sh-p2wpkh address (p2sh-segwit)
  P2shP2wpkhAddress,
  /// p2sh-p2wsh address (p2sh-segwit)
  P2shP2wshAddress,
  /// taproot address
  TaprootAddress,
  /// unknown address
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
      AddressType::TaprootAddress => 7,
      AddressType::Unknown => 0xff,
    }
  }

  pub(in crate) fn to_c_hash_type(&self) -> c_int {
    self.to_c_value()
  }

  /// Get hash type from address type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AddressType;
  /// use cfd_rust::HashType;
  /// let addr_type = AddressType::P2wpkhAddress;
  /// let hash_type = addr_type.to_hash_type();
  /// ```
  pub fn to_hash_type(&self) -> HashType {
    match self {
      AddressType::P2pkhAddress => HashType::P2pkh,
      AddressType::P2shAddress => HashType::P2sh,
      AddressType::P2wpkhAddress => HashType::P2wpkh,
      AddressType::P2wshAddress => HashType::P2wsh,
      AddressType::P2shP2wpkhAddress => HashType::P2shP2wpkh,
      AddressType::P2shP2wshAddress => HashType::P2shP2wsh,
      AddressType::TaprootAddress => HashType::Taproot,
      AddressType::Unknown => HashType::Unknown,
    }
  }

  /// Get witness version from hash type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::AddressType;
  /// use cfd_rust::WitnessVersion;
  /// let addr_type = AddressType::P2wpkhAddress;
  /// let witness_version = addr_type.get_witness_version();
  /// ```
  pub fn get_witness_version(&self) -> WitnessVersion {
    match self {
      AddressType::TaprootAddress => WitnessVersion::Version1,
      AddressType::P2wpkhAddress => WitnessVersion::Version0,
      AddressType::P2wshAddress => WitnessVersion::Version0,
      AddressType::P2shP2wpkhAddress => WitnessVersion::Version0,
      AddressType::P2shP2wshAddress => WitnessVersion::Version0,
      _ => WitnessVersion::None,
    }
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
      AddressType::TaprootAddress => write!(f, "Address:taproot"),
      AddressType::Unknown => write!(f, "Address:unknown"),
    }
  }
}

/// Witness version of bitcoin address.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WitnessVersion {
  /// not witness target
  None,
  /// witness version 0
  Version0,
  /// witness version 1
  Version1,
  /// witness version 2 (for future use)
  Version2,
  /// witness version 3 (for future use)
  Version3,
  /// witness version 4 (for future use)
  Version4,
  /// witness version 5 (for future use)
  Version5,
  /// witness version 6 (for future use)
  Version6,
  /// witness version 7 (for future use)
  Version7,
  /// witness version 8 (for future use)
  Version8,
  /// witness version 9 (for future use)
  Version9,
  /// witness version 10 (for future use)
  Version10,
  /// witness version 11 (for future use)
  Version11,
  /// witness version 12 (for future use)
  Version12,
  /// witness version 13 (for future use)
  Version13,
  /// witness version 14 (for future use)
  Version14,
  /// witness version 15 (for future use)
  Version15,
  /// witness version 16 (for future use)
  Version16,
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

/// A container that stores a bitcoin address.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Address {
  address: String,
  locking_script: Script,
  network_type: Network,
  address_type: AddressType,
  p2sh_wrapped_segwit_script: Script,
  witness_version: WitnessVersion,
  hash: ByteData,
}

impl Address {
  /// Parse from an address string.
  ///
  /// # Arguments
  /// * `address` - An address string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// let addr_str = "bc1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4jcdzrv";
  /// let addr = Address::from_string(addr_str).expect("Fail");
  /// ```
  pub fn from_string(address: &str) -> Result<Address, CfdError> {
    let addr = alloc_c_string(address)?;
    let mut handle = ErrorHandle::new()?;
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
        let hash_obj = ByteData::from_str(&str_list[1])?;
        let script = Script::from_hex(script_obj)?;
        let hash_type = HashType::from_c_value(hash_type_c);
        Ok(Address {
          address: address.to_string(),
          locking_script: script,
          network_type: Network::from_c_value(network_type_c),
          address_type: hash_type.to_address_type(),
          witness_version: hash_type.get_witness_version(),
          hash: hash_obj,
          ..Address::default()
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Create from a locking script.
  ///
  /// # Arguments
  /// * `script` - A locking script.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Script;
  /// let script_hex = "0014f4b7463a98e4c248fecc737f180e204efc5a99b5";
  /// let script = Script::from_hex(script_hex).expect("fail");
  /// let addr = Address::from_locking_script(&script, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn from_locking_script(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    let hex = alloc_c_string(&script.to_hex())?;
    let mut handle = ErrorHandle::new()?;
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

  /// Update address type. (for p2sh-segwit)
  ///
  /// # Arguments
  /// * `address_type` - A target address type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, AddressType, Network, Script};
  /// let script_hex = "a91405bc4d5d12925f008cef06ba387ade16a49d7a3187";
  /// let script = Script::from_hex(script_hex).expect("fail");
  /// let mut p2sh_addr = Address::from_locking_script(
  ///   &script, &Network::Mainnet).expect("Fail");
  /// let addr = p2sh_addr.update_address_type(&AddressType::P2shP2wpkhAddress);
  /// ```
  pub fn update_address_type(mut self, address_type: &AddressType) -> Address {
    match address_type {
      AddressType::P2shP2wpkhAddress | AddressType::P2shP2wshAddress => {
        if self.address_type == AddressType::P2shAddress {
          self.address_type = *address_type;
          self.witness_version = address_type.get_witness_version();
        }
        self
      }
      _ => self,
    }
  }

  /// Create multisig address.
  ///
  /// # Arguments
  /// * `require_num` - A multisig require number.
  /// * `pubkey_list` - Multisig pubkey list.
  /// * `address_type` - An address type.
  /// * `network_type` - A target network.
  ///
  /// # See
  /// * Script::multisig
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::AddressType;
  /// use cfd_rust::Network;
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key1_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key2_str = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  /// let key3_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let key1 = Pubkey::from_str(key1_str).expect("fail");
  /// let key2 = Pubkey::from_str(key2_str).expect("fail");
  /// let key3 = Pubkey::from_str(key3_str).expect("fail");
  /// let pubkey_list = vec![key1, key2, key3];
  /// let require_num: u8 = 2;
  /// let addr = Address::from_multisig(require_num, &pubkey_list, &AddressType::P2wshAddress, &Network::Mainnet).expect("Fail");
  /// ```
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
      ptr::null(),
      &script,
      address_type.to_c_value(),
      network_type.to_c_value(),
    )
  }

  /// Create p2pkh address.
  ///
  /// # Arguments
  /// * `pubkey` - A public key.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let addr = Address::p2pkh(&key, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn p2pkh(pubkey: &Pubkey, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      pubkey,
      ptr::null(),
      ptr::null(),
      HashType::P2pkh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  /// Create p2wpkh address.
  ///
  /// # Arguments
  /// * `pubkey` - A public key.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let addr = Address::p2wpkh(&key, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn p2wpkh(pubkey: &Pubkey, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      pubkey,
      ptr::null(),
      ptr::null(),
      HashType::P2wpkh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  /// Create p2sh wrapped p2wpkh address.
  ///
  /// # Arguments
  /// * `pubkey` - A public key.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let addr = Address::p2sh_p2wpkh(&key, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn p2sh_p2wpkh(pubkey: &Pubkey, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      pubkey,
      ptr::null(),
      ptr::null(),
      HashType::P2shP2wpkh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  /// Create p2sh address.
  ///
  /// # Arguments
  /// * `script` - A redeem script.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Script;
  /// use std::str::FromStr;
  /// let script_hex = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";
  /// let script = Script::from_hex(script_hex).expect("fail");
  /// let addr = Address::p2sh(&script, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn p2sh(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      ptr::null(),
      ptr::null(),
      script,
      HashType::P2sh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  /// Create p2wsh address.
  ///
  /// # Arguments
  /// * `script` - A redeem script.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Script;
  /// use std::str::FromStr;
  /// let script_hex = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";
  /// let script = Script::from_hex(script_hex).expect("fail");
  /// let addr = Address::p2wsh(&script, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn p2wsh(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      ptr::null(),
      ptr::null(),
      script,
      HashType::P2wsh.to_c_value(),
      network_type.to_c_value(),
    )
  }

  /// Create p2sh wrapped p2wsh address.
  ///
  /// # Arguments
  /// * `script` - A redeem script.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Script;
  /// use std::str::FromStr;
  /// let script_hex = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";
  /// let script = Script::from_hex(script_hex).expect("fail");
  /// let addr = Address::p2sh_p2wsh(&script, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn p2sh_p2wsh(script: &Script, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      ptr::null(),
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

  pub fn get_witness_version(&self) -> WitnessVersion {
    self.witness_version
  }

  pub fn get_hash(&self) -> &ByteData {
    &self.hash
  }

  /// Get p2wpkh or p2wsh locking script on p2sh-segwit.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let addr = Address::p2sh_p2wpkh(&key, &Network::Mainnet).expect("fail");
  /// let script = addr.get_p2sh_wrapped_script().expect("Fail");
  /// ```
  pub fn get_p2sh_wrapped_script(&self) -> Result<&Script, CfdError> {
    match self.address_type {
      AddressType::P2shP2wpkhAddress => Ok(&self.p2sh_wrapped_segwit_script),
      AddressType::P2shP2wshAddress => Ok(&self.p2sh_wrapped_segwit_script),
      _ => Err(CfdError::IllegalState(
        "current address is not p2sh-segwit.".to_string(),
      )),
    }
  }

  /// Create taproot address.
  ///
  /// # Arguments
  /// * `pubkey` - A schnorr public key.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Pubkey;
  /// use cfd_rust::SchnorrPubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let pk = Pubkey::from_str(&key_str).expect("fail");
  /// let (key, parity) = SchnorrPubkey::from_pubkey(&pk).expect("fail");
  /// let addr = Address::taproot(&key, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn taproot(pubkey: &SchnorrPubkey, network_type: &Network) -> Result<Address, CfdError> {
    Address::get_address(
      ptr::null(),
      pubkey,
      ptr::null(),
      HashType::Taproot.to_c_value(),
      network_type.to_c_value(),
    )
  }

  /// Validate an address.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::Network;
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let addr = Address::p2sh_p2wpkh(&key, &Network::Mainnet).expect("fail");
  /// let valid = addr.valid();
  /// ```
  pub fn valid(&self) -> bool {
    if self.address.is_empty() {
      false
    } else {
      matches!(Address::from_string(&self.address), Ok(_result))
    }
  }

  /// Create p2sh wrapped p2wsh address.
  ///
  /// # Arguments
  /// * `script` - A redeem script.
  /// * `address_type` - An address type on.
  /// * `network_type` - A target network.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Address;
  /// use cfd_rust::AddressType;
  /// use cfd_rust::Network;
  /// use cfd_rust::Script;
  /// let script_hex = "522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae";
  /// let script = Script::from_hex(script_hex).expect("fail");
  /// let addr_list = Address::get_multisig_addresses(&script, &AddressType::P2wpkhAddress, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn get_multisig_addresses(
    multisig_script: &Script,
    address_type: &AddressType,
    network_type: &Network,
  ) -> Result<Vec<MultisigItem>, CfdError> {
    let redeem_script = alloc_c_string(&multisig_script.to_hex())?;
    let mut handle = ErrorHandle::new()?;
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
    schnorr_pubkey: *const SchnorrPubkey,
    script: *const Script,
    hash_type: c_int,
    network_type: c_int,
  ) -> Result<Address, CfdError> {
    let pubkey_hex = unsafe {
      match pubkey.as_ref() {
        Some(pubkey) => alloc_c_string(&pubkey.to_hex()),
        _ => match schnorr_pubkey.as_ref() {
          Some(schnorr_pubkey) => alloc_c_string(&schnorr_pubkey.to_hex()),
          _ => alloc_c_string(""),
        },
      }
    }?;
    let redeem_script = unsafe {
      match script.as_ref() {
        Some(script) => alloc_c_string(&script.to_hex()),
        _ => alloc_c_string(""),
      }
    }?;
    let mut handle = ErrorHandle::new()?;
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
        let addr_str = &str_list[0];
        let script_obj = &str_list[1];
        let segwit_obj = &str_list[2];
        let hash_obj = unsafe {
          match schnorr_pubkey.as_ref() {
            Some(schnorr_pubkey) => ByteData::from_str(&schnorr_pubkey.to_hex()),
            _ => Ok(ByteData::default()),
          }?
        };
        let addr_locking_script = Script::from_hex(script_obj)?;
        let segwit_script = Script::from_hex(segwit_obj)?;
        let hash_type_obj = HashType::from_c_value(hash_type);
        Ok(Address {
          address: addr_str.clone(),
          locking_script: addr_locking_script,
          network_type: Network::from_c_value(network_type),
          address_type: hash_type_obj.to_address_type(),
          p2sh_wrapped_segwit_script: segwit_script,
          witness_version: hash_type_obj.get_witness_version(),
          hash: hash_obj,
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
      hash: ByteData::default(),
    }
  }
}

/// A container that stores a multisig address and pubkey.
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
