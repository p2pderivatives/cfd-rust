extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_void};
use crate::common::{
  alloc_c_string, byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free,
  collect_multi_cstring_and_free, copy_array_32byte, hex_from_bytes, ByteData, CfdError,
  ErrorHandle, Network,
};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdAddCombinePubkey, CfdCalculateEcSignature, CfdCalculateSchnorrSignature,
  CfdCalculateSchnorrSignatureWithNonce, CfdCompressPubkey, CfdCreateKeyPair,
  CfdDecodeSignatureFromDer, CfdEncodeSignatureByDer, CfdFinalizeCombinePubkey,
  CfdFreeCombinePubkeyHandle, CfdGetPrivkeyWif, CfdGetPubkeyFromPrivkey, CfdGetSchnorrPubkey,
  CfdGetSchnorrPublicNonce, CfdInitializeCombinePubkey, CfdNegatePrivkey, CfdNegatePubkey,
  CfdNormalizeSignature, CfdParsePrivkeyWif, CfdPrivkeyTweakAdd, CfdPrivkeyTweakMul,
  CfdPubkeyTweakAdd, CfdPubkeyTweakMul, CfdUncompressPubkey, CfdVerifyEcSignature,
  CfdVerifySchnorrSignature, CfdVerifySchnorrSignatureWithNonce,
};

/// private key buffer size.
pub const PRIVKEY_SIZE: usize = 32;
/// compressed public key size.
pub const PUBKEY_COMPRESSED_SIZE: usize = 33;
/// uncompressed public key size.
pub const PUBKEY_UNCOMPRESSED_SIZE: usize = 65;

/// A container that stores a private key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Privkey {
  key: [u8; PRIVKEY_SIZE],
  wif: String,
  net_type: Network,
  is_compressed: bool,
}

impl Privkey {
  fn from_bytes(key: &[u8]) -> Privkey {
    let mut privkey = Privkey {
      key: [0; PRIVKEY_SIZE],
      wif: String::default(),
      net_type: Network::Mainnet,
      is_compressed: true,
    };
    privkey.key = copy_array_32byte(&key);
    privkey
  }

  /// Generate from slice.
  ///
  /// # Arguments
  /// * `key` - A private key bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("Fail");
  /// ```
  pub fn from_slice(key: &[u8]) -> Result<Privkey, CfdError> {
    if key.len() != PRIVKEY_SIZE {
      return Err(CfdError::IllegalArgument("invalid privkey.".to_string()));
    }
    let mut privkey = Privkey::from_bytes(key);
    privkey.wif = privkey.generate_wif(&privkey.net_type, privkey.is_compressed)?;
    Ok(privkey)
  }

  /// Generate from vector.
  ///
  /// # Arguments
  /// * `key` - A private key bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let key = Privkey::from_vec(bytes).expect("Fail");
  /// ```
  pub fn from_vec(key: Vec<u8>) -> Result<Privkey, CfdError> {
    Privkey::from_slice(&key)
  }

  /// Generate from wif.
  ///
  /// # Arguments
  /// * `wif` - A wallet import format string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let wif = "5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23";
  /// let key = Privkey::from_wif(&wif).expect("Fail");
  /// ```
  pub fn from_wif(wif: &str) -> Result<Privkey, CfdError> {
    let wif_str = alloc_c_string(wif)?;
    let handle = ErrorHandle::new()?;
    let mut privkey_hex: *mut c_char = ptr::null_mut();
    let mut is_compressed = true;
    let mut network_type: c_int = 0;
    let error_code = unsafe {
      CfdParsePrivkeyWif(
        handle.as_handle(),
        wif_str.as_ptr(),
        &mut privkey_hex,
        &mut network_type,
        &mut is_compressed,
      )
    };
    let result = match error_code {
      0 => {
        let privkey = unsafe { collect_cstring_and_free(privkey_hex) }?;
        let key = byte_from_hex_unsafe(&privkey);
        let mut privkey = Privkey::from_bytes(&key);
        privkey.wif = wif.to_string();
        privkey.net_type = Network::from_c_value(network_type);
        privkey.is_compressed = is_compressed;
        Ok(privkey)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Generate random private key.
  ///
  /// # Arguments
  /// * `network_type` - A network type.
  /// * `is_compressed` - A pubkey compressed state.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Privkey, Network};
  /// let key = Privkey::generate(&Network::Mainnet, true).expect("Fail");
  /// ```
  pub fn generate(network_type: &Network, is_compressed: bool) -> Result<Privkey, CfdError> {
    let handle = ErrorHandle::new()?;
    let mut pubkey_hex: *mut c_char = ptr::null_mut();
    let mut privkey_hex: *mut c_char = ptr::null_mut();
    let mut wif: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateKeyPair(
        handle.as_handle(),
        is_compressed,
        network_type.to_c_value(),
        &mut pubkey_hex,
        &mut privkey_hex,
        &mut wif,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[pubkey_hex, privkey_hex, wif]) }?;
        let privkey_obj = &str_list[1];
        let wif_str = &str_list[2];
        let privkey_bytes = byte_from_hex_unsafe(&privkey_obj);
        let mut privkey = Privkey::from_bytes(&privkey_bytes);
        privkey.wif = wif_str.clone();
        privkey.net_type = *network_type;
        privkey.is_compressed = is_compressed;
        Ok(privkey)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Add a tweak byte.
  ///
  /// # Arguments
  /// * `data` - A tweaked 32 byte buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let tweak_value = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let tweaked_key = key.tweak_add(&tweak_value).expect("Fail");
  /// ```
  pub fn tweak_add(&self, data: &[u8]) -> Result<Privkey, CfdError> {
    let privkey = alloc_c_string(&hex_from_bytes(&self.key))?;
    let tweak = alloc_c_string(&hex_from_bytes(data))?;
    let handle = ErrorHandle::new()?;
    let mut tweak_privkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPrivkeyTweakAdd(
        handle.as_handle(),
        privkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_privkey,
      )
    };
    let result = match error_code {
      0 => {
        let tweaked = unsafe { collect_cstring_and_free(tweak_privkey) }?;
        let tweaked_privkey = byte_from_hex_unsafe(&tweaked);
        Privkey::from_slice(&tweaked_privkey)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Multiplicate a tweak byte.
  ///
  /// # Arguments
  /// * `data` - A tweaked 32 byte buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let tweak_value = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let tweaked_key = key.tweak_mul(&tweak_value).expect("Fail");
  /// ```
  pub fn tweak_mul(&self, data: &[u8]) -> Result<Privkey, CfdError> {
    let privkey = alloc_c_string(&hex_from_bytes(&self.key))?;
    let tweak = alloc_c_string(&hex_from_bytes(data))?;
    let handle = ErrorHandle::new()?;
    let mut tweak_privkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPrivkeyTweakMul(
        handle.as_handle(),
        privkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_privkey,
      )
    };
    let result = match error_code {
      0 => {
        let tweaked = unsafe { collect_cstring_and_free(tweak_privkey) }?;
        let tweaked_privkey = byte_from_hex_unsafe(&tweaked);
        Privkey::from_slice(&tweaked_privkey)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Negate a key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let key = key.negate().expect("Fail");
  /// ```
  pub fn negate(&self) -> Result<Privkey, CfdError> {
    let privkey = alloc_c_string(&hex_from_bytes(&self.key))?;
    let handle = ErrorHandle::new()?;
    let mut negate_privkey: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdNegatePrivkey(handle.as_handle(), privkey.as_ptr(), &mut negate_privkey) };
    let result = match error_code {
      0 => {
        let negated = unsafe { collect_cstring_and_free(negate_privkey) }?;
        let negated_privkey = byte_from_hex_unsafe(&negated);
        Privkey::from_slice(&negated_privkey)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get a private key slice.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let key_bytes = key.to_slice();
  /// ```
  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.key
  }

  /// Get a private key hex string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let key_hex = key.to_hex();
  /// ```
  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.key)
  }

  /// Get a wallet import format string.
  ///
  /// - default network is Mainnet.
  /// - default pubkey compressed is true.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let key_wif = key.to_wif();
  /// ```
  #[inline]
  pub fn to_wif(&self) -> &str {
    &self.wif
  }

  pub fn to_network(&self) -> &Network {
    &self.net_type
  }

  pub fn is_compressed_pubkey(&self) -> bool {
    self.is_compressed
  }

  /// Generate a wallet import format string.
  ///
  /// # Arguments
  /// * `network_type` - A network type.
  /// * `is_compressed` - A pubkey compressed state.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Privkey, Network};
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let key_wif = key.generate_wif(&Network::Regtest, true).expect("Fail");
  /// ```
  pub fn generate_wif(
    &self,
    network_type: &Network,
    is_compressed: bool,
  ) -> Result<String, CfdError> {
    if (!self.wif.is_empty())
      && (*network_type == self.net_type)
      && (is_compressed == self.is_compressed)
    {
      return Ok(self.to_wif().to_string());
    }
    let privkey = alloc_c_string(&self.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut wif: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetPrivkeyWif(
        handle.as_handle(),
        privkey.as_ptr(),
        network_type.to_c_value(),
        is_compressed,
        &mut wif,
      )
    };
    let result = match error_code {
      0 => unsafe { collect_cstring_and_free(wif) },
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get a public key from this private key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let pubkey = key.get_pubkey().expect("Fail");
  /// ```
  pub fn get_pubkey(&self) -> Result<Pubkey, CfdError> {
    Privkey::generate_pubkey(&self.key, self.is_compressed)
  }

  /// Generate a public key.
  ///
  /// # Arguments
  /// * `key` - A private key array.
  /// * `is_compressed` - A pubkey compressed state.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key_wif = Privkey::generate_pubkey(&bytes, true).expect("Fail");
  /// ```
  pub fn generate_pubkey(key: &[u8], is_compressed: bool) -> Result<Pubkey, CfdError> {
    let privkey = alloc_c_string(&hex_from_bytes(key))?;
    let handle = ErrorHandle::new()?;
    let wif: *const i8 = ptr::null();
    let mut pubkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetPubkeyFromPrivkey(
        handle.as_handle(),
        privkey.as_ptr(),
        wif,
        is_compressed,
        &mut pubkey,
      )
    };
    let result = match error_code {
      0 => {
        let pubkey_obj = unsafe { collect_cstring_and_free(pubkey) }?;
        Pubkey::from_vec(byte_from_hex_unsafe(&pubkey_obj))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Calculate an ec signature.
  ///
  /// # Arguments
  /// * `sighash` - A signature hash.
  /// * `has_grind_r` - A grind-r flag.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let sighash = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let sig = key.calculate_ec_signature(&sighash, true).expect("Fail");
  /// ```
  pub fn calculate_ec_signature(
    &self,
    sighash: &[u8],
    has_grind_r: bool,
  ) -> Result<SignParameter, CfdError> {
    let signature_hash = alloc_c_string(&hex_from_bytes(sighash))?;
    let privkey = alloc_c_string(&hex_from_bytes(&self.key))?;
    let handle = ErrorHandle::new()?;
    let wif: *const i8 = ptr::null();
    let network_type: c_int = 0;
    let mut signature_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCalculateEcSignature(
        handle.as_handle(),
        signature_hash.as_ptr(),
        privkey.as_ptr(),
        wif,
        network_type,
        has_grind_r,
        &mut signature_hex,
      )
    };
    let result = match error_code {
      0 => {
        let signature = unsafe { collect_cstring_and_free(signature_hex) }?;
        let signature_bytes = byte_from_hex_unsafe(&signature);
        let sign_param = SignParameter::from_vec(signature_bytes);
        Ok(sign_param.set_use_der_encode(&SigHashType::All))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Calculate a schnorr signature.
  ///
  /// # Arguments
  /// * `k_value` - A 32-byte k-value.
  /// * `message` - A 32-byte message buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let k_value = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let message = vec![2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let sig = key.calculate_schnorr_signature(&k_value, &message).expect("Fail");
  /// ```
  pub fn calculate_schnorr_signature(
    &self,
    k_value: &[u8],
    message: &[u8],
  ) -> Result<SignParameter, CfdError> {
    let privkey = alloc_c_string(&self.to_hex())?;
    let k_value_str = alloc_c_string(&hex_from_bytes(k_value))?;
    let message_str = alloc_c_string(&hex_from_bytes(message))?;
    let handle = ErrorHandle::new()?;
    let mut signature_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCalculateSchnorrSignature(
        handle.as_handle(),
        privkey.as_ptr(),
        k_value_str.as_ptr(),
        message_str.as_ptr(),
        &mut signature_hex,
      )
    };
    let result = match error_code {
      0 => {
        let signature = unsafe { collect_cstring_and_free(signature_hex) }?;
        let signature_bytes = byte_from_hex_unsafe(&signature);
        let sign_param = SignParameter::from_vec(signature_bytes);
        Ok(sign_param.set_use_der_encode(&SigHashType::All))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Calculate a schnorr signature with nonce.
  ///
  /// # Arguments
  /// * `k_value` - A 32-byte k-value.
  /// * `message` - A 32-byte message buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let k_value = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let message = vec![2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let sig = key.calculate_schnorr_signature_with_nonce(&k_value, &message).expect("Fail");
  /// ```
  pub fn calculate_schnorr_signature_with_nonce(
    &self,
    k_value: &[u8],
    message: &[u8],
  ) -> Result<SignParameter, CfdError> {
    let privkey = alloc_c_string(&self.to_hex())?;
    let k_value_str = alloc_c_string(&hex_from_bytes(k_value))?;
    let message_str = alloc_c_string(&hex_from_bytes(message))?;
    let handle = ErrorHandle::new()?;
    let mut signature_hex: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCalculateSchnorrSignatureWithNonce(
        handle.as_handle(),
        privkey.as_ptr(),
        k_value_str.as_ptr(),
        message_str.as_ptr(),
        &mut signature_hex,
      )
    };
    let result = match error_code {
      0 => {
        let signature = unsafe { collect_cstring_and_free(signature_hex) }?;
        let signature_bytes = byte_from_hex_unsafe(&signature);
        let sign_param = SignParameter::from_vec(signature_bytes);
        Ok(sign_param.set_use_der_encode(&SigHashType::All))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get a schnorr public nonce from private key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let nonce = key.get_schnorr_public_nonce().expect("Fail");
  /// ```
  pub fn get_schnorr_public_nonce(&self) -> Result<Pubkey, CfdError> {
    let privkey = alloc_c_string(&self.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut nonce: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdGetSchnorrPublicNonce(handle.as_handle(), privkey.as_ptr(), &mut nonce) };
    let result = match error_code {
      0 => {
        let nonce_hex = unsafe { collect_cstring_and_free(nonce) }?;
        Pubkey::from_str(&nonce_hex)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Validate a private key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let valid = key.valid();
  /// ```
  #[inline]
  pub fn valid(&self) -> bool {
    for i in &self.key {
      if *i != 0 {
        return true;
      }
    }
    false
  }
}

impl fmt::Display for Privkey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    // fmt::LowerHex::fmt(self, f);
    if self.wif.is_empty() {
      let s = hex::encode(&self.key);
      write!(f, "{}", s)
    } else {
      let s = &self.wif;
      write!(f, "{}", s)
    }
  }
}

impl FromStr for Privkey {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Privkey, CfdError> {
    match Privkey::from_wif(text) {
      Ok(result) => Ok(result),
      _ => match byte_from_hex(text) {
        Ok(byte_array) => Privkey::from_vec(byte_array),
        Err(e) => Err(e),
      },
    }
  }
}

impl Default for Privkey {
  fn default() -> Privkey {
    Privkey {
      key: [0; PRIVKEY_SIZE],
      wif: String::default(),
      net_type: Network::Mainnet,
      is_compressed: true,
    }
  }
}

/// A container that stores a public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Pubkey {
  key: Vec<u8>,
}

impl Pubkey {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `key` - A public key bytes
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// let bytes = [2; 33];
  /// let key = Pubkey::from_slice(&bytes).expect("Fail");
  /// ```
  pub fn from_slice(key: &[u8]) -> Result<Pubkey, CfdError> {
    Pubkey::from_vec(key.to_vec())
  }

  /// Generate from vector.
  ///
  /// # Arguments
  /// * `key` - A public key vector
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// let bytes = vec![2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let key = Pubkey::from_vec(bytes).expect("Fail");
  /// ```
  pub fn from_vec(key: Vec<u8>) -> Result<Pubkey, CfdError> {
    let len = key.len();
    match len {
      PUBKEY_COMPRESSED_SIZE | PUBKEY_UNCOMPRESSED_SIZE => match Pubkey::valid_key(&key) {
        true => Ok(Pubkey { key }),
        _ => Err(CfdError::IllegalArgument(
          "invalid pubkey format.".to_string(),
        )),
      },
      _ => Err(CfdError::IllegalArgument(
        "invalid pubkey format.".to_string(),
      )),
    }
  }

  /// Get a public key slice.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let key_slice = key.to_slice();
  /// ```
  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.key
  }

  /// Get a public key hex string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let key_hex = key.to_hex();
  /// ```
  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.key)
  }

  #[inline]
  pub fn to_str(&self) -> String {
    self.to_hex()
  }

  /// Get a compressed public key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let uncompressed_key_str = "04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80";
  /// let uncompressed_key = Pubkey::from_str(uncompressed_key_str).expect("fail");
  /// let key = uncompressed_key.compress().expect("Fail");
  /// ```
  pub fn compress(&self) -> Result<Pubkey, CfdError> {
    let pubkey = alloc_c_string(&self.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut compressed_pubkey: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdCompressPubkey(handle.as_handle(), pubkey.as_ptr(), &mut compressed_pubkey) };
    let result = match error_code {
      0 => {
        let compress_pubkey = unsafe { collect_cstring_and_free(compressed_pubkey) }?;
        Ok(Pubkey {
          key: byte_from_hex_unsafe(&compress_pubkey),
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get a uncompressed public key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let compressed_key_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let compressed_key = Pubkey::from_str(compressed_key_str).expect("fail");
  /// let key = compressed_key.compress().expect("Fail");
  /// ```
  pub fn uncompress(&self) -> Result<Pubkey, CfdError> {
    let pubkey = alloc_c_string(&self.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut decompressed_pubkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdUncompressPubkey(
        handle.as_handle(),
        pubkey.as_ptr(),
        &mut decompressed_pubkey,
      )
    };
    let result = match error_code {
      0 => {
        let decompress_pubkey = unsafe { collect_cstring_and_free(decompressed_pubkey) }?;
        Ok(Pubkey {
          key: byte_from_hex_unsafe(&decompress_pubkey),
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Add a tweak byte.
  ///
  /// # Arguments
  /// * `data` - A tweaked 32 byte buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let tweak_value = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let tweaked_key = key.tweak_add(&tweak_value).expect("Fail");
  /// ```
  pub fn tweak_add(&self, data: &[u8]) -> Result<Pubkey, CfdError> {
    let pubkey = alloc_c_string(&hex_from_bytes(&self.key))?;
    let tweak = alloc_c_string(&hex_from_bytes(data))?;
    let handle = ErrorHandle::new()?;
    let mut tweak_pubkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPubkeyTweakAdd(
        handle.as_handle(),
        pubkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_pubkey,
      )
    };
    let result = match error_code {
      0 => {
        let tweaked = unsafe { collect_cstring_and_free(tweak_pubkey) }?;
        Pubkey::from_vec(byte_from_hex_unsafe(&tweaked))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Multiplicate a tweak byte.
  ///
  /// # Arguments
  /// * `data` - A tweaked 32 byte buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let tweak_value = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let tweaked_key = key.tweak_mul(&tweak_value).expect("Fail");
  /// ```
  pub fn tweak_mul(&self, data: &[u8]) -> Result<Pubkey, CfdError> {
    let pubkey = alloc_c_string(&hex_from_bytes(&self.key))?;
    let tweak = alloc_c_string(&hex_from_bytes(data))?;
    let handle = ErrorHandle::new()?;
    let mut tweak_pubkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPubkeyTweakMul(
        handle.as_handle(),
        pubkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_pubkey,
      )
    };
    let result = match error_code {
      0 => {
        let tweaked = unsafe { collect_cstring_and_free(tweak_pubkey) }?;
        Pubkey::from_vec(byte_from_hex_unsafe(&tweaked))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Negate a key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let pubkey = key.negate().expect("Fail");
  /// ```
  pub fn negate(&self) -> Result<Pubkey, CfdError> {
    let pubkey = alloc_c_string(&hex_from_bytes(&self.key))?;
    let handle = ErrorHandle::new()?;
    let mut negate_pubkey: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdNegatePubkey(handle.as_handle(), pubkey.as_ptr(), &mut negate_pubkey) };
    let result = match error_code {
      0 => {
        let negated = unsafe { collect_cstring_and_free(negate_pubkey) }?;
        Pubkey::from_vec(byte_from_hex_unsafe(&negated))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Combine multiple pubkeys.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key1_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key2_str = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  /// let key3_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let key1 = Pubkey::from_str(key1_str).expect("fail");
  /// let key2 = Pubkey::from_str(key2_str).expect("fail");
  /// let key3 = Pubkey::from_str(key3_str).expect("fail");
  /// let pubkeys = vec![key1, key2, key3];
  /// let key = Pubkey::combine(&pubkeys).expect("Fail");
  /// ```
  pub fn combine(pubkey_list: &[Pubkey]) -> Result<Pubkey, CfdError> {
    if pubkey_list.is_empty() {
      return Err(CfdError::IllegalArgument(
        "pubkey list is empty.".to_string(),
      ));
    } else if pubkey_list.len() == 1 {
      return Ok(pubkey_list[0].clone());
    }

    let handle = ErrorHandle::new()?;
    let mut combine_handle: *mut c_void = ptr::null_mut();
    let error_code: i32 =
      unsafe { CfdInitializeCombinePubkey(handle.as_handle(), &mut combine_handle) };
    let result = match error_code {
      0 => {
        let ret = {
          for pubkey in pubkey_list {
            let _err = {
              let pubkey_hex = alloc_c_string(&hex_from_bytes(&pubkey.key))?;
              let error_code = unsafe {
                CfdAddCombinePubkey(handle.as_handle(), combine_handle, pubkey_hex.as_ptr())
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          let mut combine_pubkey: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdFinalizeCombinePubkey(handle.as_handle(), combine_handle, &mut combine_pubkey)
          };
          match error_code {
            0 => {
              let pubkey = unsafe { collect_cstring_and_free(combine_pubkey) }?;
              Pubkey::from_vec(byte_from_hex_unsafe(&pubkey))
            }
            _ => Err(handle.get_error(error_code)),
          }
        };
        unsafe {
          CfdFreeCombinePubkeyHandle(handle.as_handle(), combine_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Verify an ec-signature.
  ///
  /// # Arguments
  /// * `sighash` - A 32 byte signature hash.
  /// * `signature` - A 64 byte signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let sighash = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let signature = [1; 64];
  /// let is_verify = key.verify_ec_signature(&sighash, &signature).expect("fail");
  /// ```
  pub fn verify_ec_signature(&self, sighash: &[u8], signature: &[u8]) -> Result<bool, CfdError> {
    let pubkey = alloc_c_string(&self.to_hex())?;
    let sighash_hex = alloc_c_string(&hex_from_bytes(sighash))?;
    let signature_hex = alloc_c_string(&hex_from_bytes(signature))?;
    let handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifyEcSignature(
        handle.as_handle(),
        sighash_hex.as_ptr(),
        pubkey.as_ptr(),
        signature_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(true),
      7 => Ok(false), // SignVerification
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Verify a schnorr-signature.
  ///
  /// # Arguments
  /// * `signature` - A 64 byte signature.
  /// * `message` - A 32 byte message buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let signature = [1; 64];
  /// let message = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let is_verify = key.verify_schnorr_signature(&signature, &message).expect("fail");
  /// ```
  pub fn verify_schnorr_signature(
    &self,
    signature: &[u8],
    message: &[u8],
  ) -> Result<bool, CfdError> {
    let pubkey = alloc_c_string(&self.to_hex())?;
    let message_hex = alloc_c_string(&hex_from_bytes(message))?;
    let signature_hex = alloc_c_string(&hex_from_bytes(signature))?;
    let handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifySchnorrSignature(
        handle.as_handle(),
        pubkey.as_ptr(),
        signature_hex.as_ptr(),
        message_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(true),
      7 => Ok(false), // SignVerification
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Verify a schnorr-signature.
  ///
  /// # Arguments
  /// * `nonce` - A nonce public key (33 byte).
  /// * `signature` - A 32 byte signature.
  /// * `message` - A 32 byte message buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let nonce_byte = [2; 33];
  /// let nonce = Pubkey::from_slice(&nonce_byte).expect("fail");
  /// let signature = [1; 32];
  /// let message = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let is_verify = key.verify_schnorr_signature_with_nonce(&nonce, &signature, &message).expect("fail");
  /// ```
  pub fn verify_schnorr_signature_with_nonce(
    &self,
    nonce: &Pubkey,
    signature: &[u8],
    message: &[u8],
  ) -> Result<bool, CfdError> {
    let pubkey = alloc_c_string(&self.to_hex())?;
    let nonce_hex = alloc_c_string(&nonce.to_hex())?;
    let message_hex = alloc_c_string(&hex_from_bytes(message))?;
    let signature_hex = alloc_c_string(&hex_from_bytes(signature))?;
    let handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifySchnorrSignatureWithNonce(
        handle.as_handle(),
        pubkey.as_ptr(),
        nonce_hex.as_ptr(),
        signature_hex.as_ptr(),
        message_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(true),
      7 => Ok(false), // SignVerification
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get a schnorr public key from oracle public key.
  ///
  /// # Arguments
  /// * `nonce` - A nonce public key (33 byte).
  /// * `signature` - A 32 byte signature.
  /// * `message` - A 32 byte message buffer.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let oracle_pubkey = Pubkey::from_str(key_str).expect("fail");
  /// let oracle_r_point_byte = [2; 33];
  /// let oracle_r_point = Pubkey::from_slice(&oracle_r_point_byte).expect("fail");
  /// let message = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let schnorr_pubkey = oracle_pubkey.get_schnorr_pubkey(&oracle_r_point, &message).expect("Fail");
  /// ```
  pub fn get_schnorr_pubkey(
    &self,
    oracle_r_point: &Pubkey,
    message: &[u8],
  ) -> Result<Pubkey, CfdError> {
    let pubkey = alloc_c_string(&self.to_hex())?;
    let oracle_r_point_str = alloc_c_string(&oracle_r_point.to_hex())?;
    let message_str = alloc_c_string(&hex_from_bytes(message))?;
    let handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetSchnorrPubkey(
        handle.as_handle(),
        pubkey.as_ptr(),
        oracle_r_point_str.as_ptr(),
        message_str.as_ptr(),
        &mut output,
      )
    };
    let result = match error_code {
      0 => {
        let output_obj = unsafe { collect_cstring_and_free(output) }?;
        Pubkey::from_slice(&byte_from_hex_unsafe(&output_obj))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Validate a public key.
  ///
  /// # Arguments
  /// * `key` - A public key slice.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let valid = Pubkey::valid_key(key.to_slice());
  /// ```
  #[inline]
  pub fn valid_key(key: &[u8]) -> bool {
    let pubkey = Pubkey { key: key.to_vec() };
    pubkey.valid()
  }

  /// Validate a public key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let key_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key = Pubkey::from_str(key_str).expect("fail");
  /// let valid = key.valid();
  /// ```
  #[inline]
  pub fn valid(&self) -> bool {
    match self.compress() {
      Ok(_result) => true,
      _ => false,
    }
  }
}

impl fmt::Display for Pubkey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.key);
    write!(f, "{}", s)
  }
}

impl FromStr for Pubkey {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Pubkey, CfdError> {
    match byte_from_hex(text) {
      Ok(byte_array) => Pubkey::from_vec(byte_array),
      Err(e) => Err(e),
    }
  }
}

impl Default for Pubkey {
  fn default() -> Pubkey {
    Pubkey { key: vec![] }
  }
}

/// A container that stores private and public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyPair {
  privkey: Privkey,
  pubkey: Pubkey,
}

impl KeyPair {
  /// Set a key pair.
  ///
  /// # Arguments
  /// * `privkey` - A private key.
  /// * `pubkey` - A public key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// use cfd_rust::KeyPair;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let pubkey = key.get_pubkey().expect("fail");
  /// let key_pair = KeyPair::new(&key, &pubkey);
  /// ```
  pub fn new(privkey: &Privkey, pubkey: &Pubkey) -> KeyPair {
    KeyPair {
      privkey: privkey.clone(),
      pubkey: pubkey.clone(),
    }
  }

  pub fn to_privkey(&self) -> &Privkey {
    &self.privkey
  }

  pub fn to_pubkey(&self) -> &Pubkey {
    &self.pubkey
  }
}

impl Default for KeyPair {
  fn default() -> KeyPair {
    KeyPair {
      privkey: Privkey::default(),
      pubkey: Pubkey::default(),
    }
  }
}

/// An enumeration definition of signature hash type.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SigHashType {
  /// SigHashType::All
  All,
  /// SigHashType::None
  None,
  /// SigHashType::Single
  Single,
  /// SigHashType::All + AnyoneCanPay
  AllPlusAnyoneCanPay,
  /// SigHashType::None + AnyoneCanPay
  NonePlusAnyoneCanPay,
  /// SigHashType::Single + AnyoneCanPay
  SinglePlusAnyoneCanPay,
}

impl SigHashType {
  /// Create a new instance.
  ///
  /// # Arguments
  /// * `sighash_type` - A base sighash type.
  /// * `anyone_can_pay` - An anyone can pay flag.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SigHashType;
  /// let all_anyone_can_pay = SigHashType::new(&SigHashType::All, true);
  /// ```
  #[inline]
  pub fn new(sighash_type: &SigHashType, anyone_can_pay: bool) -> SigHashType {
    if anyone_can_pay {
      match sighash_type {
        SigHashType::All | SigHashType::AllPlusAnyoneCanPay => SigHashType::AllPlusAnyoneCanPay,
        SigHashType::None | SigHashType::NonePlusAnyoneCanPay => SigHashType::NonePlusAnyoneCanPay,
        SigHashType::Single | SigHashType::SinglePlusAnyoneCanPay => {
          SigHashType::SinglePlusAnyoneCanPay
        }
      }
    } else {
      match sighash_type {
        SigHashType::All | SigHashType::AllPlusAnyoneCanPay => SigHashType::All,
        SigHashType::None | SigHashType::NonePlusAnyoneCanPay => SigHashType::None,
        SigHashType::Single | SigHashType::SinglePlusAnyoneCanPay => SigHashType::Single,
      }
    }
  }

  /// Get an anyone can pay flag.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SigHashType;
  /// let hash_type = SigHashType::NonePlusAnyoneCanPay;
  /// let anyone_can_pay = hash_type.is_anyone_can_pay();
  /// ```
  #[inline]
  pub fn is_anyone_can_pay(&self) -> bool {
    match self {
      SigHashType::AllPlusAnyoneCanPay
      | SigHashType::NonePlusAnyoneCanPay
      | SigHashType::SinglePlusAnyoneCanPay => true,
      SigHashType::All | SigHashType::None | SigHashType::Single => false,
    }
  }

  pub(in crate) fn from_c_value(sighash_type: c_int) -> SigHashType {
    match sighash_type {
      1 => SigHashType::All,
      2 => SigHashType::None,
      3 => SigHashType::Single,
      _ => SigHashType::All,
    }
  }

  pub(in crate) fn to_c_value(&self) -> c_int {
    match self {
      SigHashType::All | SigHashType::AllPlusAnyoneCanPay => 1,
      SigHashType::None | SigHashType::NonePlusAnyoneCanPay => 2,
      SigHashType::Single | SigHashType::SinglePlusAnyoneCanPay => 3,
    }
  }
}

impl fmt::Display for SigHashType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let _ = match *self {
      SigHashType::All | SigHashType::AllPlusAnyoneCanPay => write!(f, "sighashType:All"),
      SigHashType::None | SigHashType::NonePlusAnyoneCanPay => write!(f, "sighashType:None"),
      SigHashType::Single | SigHashType::SinglePlusAnyoneCanPay => write!(f, "sighashType:Single"),
    }?;
    match self.is_anyone_can_pay() {
      true => write!(f, ", anyoneCanPay"),
      _ => Ok(()),
    }
  }
}

/// A container that stores sign parameter.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignParameter {
  data: Vec<u8>,
  sighash_type: SigHashType,

  pubkey: Pubkey,
  use_der_encode: bool,
}

impl SignParameter {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - A byte data used for sign.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// let bytes = [1; 32];
  /// let param = SignParameter::from_slice(&bytes);
  /// ```
  pub fn from_slice(data: &[u8]) -> SignParameter {
    SignParameter {
      data: data.to_vec(),
      sighash_type: SigHashType::All,
      pubkey: Pubkey::default(),
      use_der_encode: false,
    }
  }

  /// Generate from vector.
  ///
  /// # Arguments
  /// * `data` - A byte data used for sign.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// let bytes = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let param = SignParameter::from_vec(bytes);
  /// ```
  pub fn from_vec(data: Vec<u8>) -> SignParameter {
    SignParameter::from_slice(&data)
  }

  /// Set a sighash type.
  ///
  /// # Arguments
  /// * `sighash_type` - A signature hash type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// use cfd_rust::SigHashType;
  /// let bytes = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let param = SignParameter::from_vec(bytes)
  ///     .set_signature_hash(&SigHashType::All);
  /// ```
  #[inline]
  pub fn set_signature_hash(mut self, sighash_type: &SigHashType) -> SignParameter {
    self.sighash_type = *sighash_type;
    self
  }

  /// Set a sighash type and der encode flag.
  ///
  /// # Arguments
  /// * `sighash_type` - A signature hash type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// use cfd_rust::SigHashType;
  /// let bytes = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let param = SignParameter::from_vec(bytes)
  ///     .set_use_der_encode(&SigHashType::All);
  /// ```
  #[inline]
  pub fn set_use_der_encode(mut self, sighash_type: &SigHashType) -> SignParameter {
    if self.data.len() > 65 {
      // target is already der-encoded. unused sighash-type.
      self.set_signature_hash(&sighash_type)
    } else {
      self.use_der_encode = true;
      self.set_signature_hash(&sighash_type)
    }
  }

  /// Set a related pubkey. Used to sort multisig signatures.
  ///
  /// # Arguments
  /// * `pubkey` - A public key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// use cfd_rust::SigHashType;
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let pubkey_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let pubkey = Pubkey::from_str(pubkey_str).expect("fail");
  /// let bytes = vec![1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
  /// let param = SignParameter::from_vec(bytes)
  ///     .set_use_der_encode(&SigHashType::All)
  ///     .set_related_pubkey(&pubkey);
  /// ```
  #[inline]
  pub fn set_related_pubkey(mut self, pubkey: &Pubkey) -> SignParameter {
    self.pubkey = pubkey.clone();
    self
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.data
  }

  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.data)
  }

  #[inline]
  pub fn to_data(&self) -> ByteData {
    ByteData::from_slice(&self.data)
  }

  #[inline]
  pub fn can_use_der_encode(&self) -> bool {
    self.use_der_encode
  }

  #[inline]
  pub fn get_sighash_type(&self) -> &SigHashType {
    &self.sighash_type
  }

  #[inline]
  pub fn get_related_pubkey(&self) -> &Pubkey {
    &self.pubkey
  }

  #[inline]
  pub fn len(&self) -> usize {
    self.data.len()
  }

  #[inline]
  pub fn is_empty(&self) -> bool {
    self.data.is_empty()
  }

  /// Get a normalized signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// let bytes = [1; 64];
  /// let signature = SignParameter::from_slice(&bytes);
  /// let normalized_sig = signature.normalize().expect("Fail");
  /// ```
  pub fn normalize(&self) -> Result<SignParameter, CfdError> {
    let signature_hex = alloc_c_string(&hex_from_bytes(&self.data))?;
    let handle = ErrorHandle::new()?;
    let mut normalize_signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdNormalizeSignature(
        handle.as_handle(),
        signature_hex.as_ptr(),
        &mut normalize_signature,
      )
    };
    let result = match error_code {
      0 => {
        let normalized = unsafe { collect_cstring_and_free(normalize_signature) }?;
        Ok(SignParameter::from_vec(byte_from_hex_unsafe(&normalized)))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get a der-encoded signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// let bytes = [1; 64];
  /// let signature = SignParameter::from_slice(&bytes);
  /// let der_encoded_sig = signature.to_der_encode().expect("Fail");
  /// ```
  pub fn to_der_encode(&self) -> Result<SignParameter, CfdError> {
    let signature_hex = alloc_c_string(&hex_from_bytes(&self.data))?;
    let handle = ErrorHandle::new()?;
    let mut der_signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdEncodeSignatureByDer(
        handle.as_handle(),
        signature_hex.as_ptr(),
        self.sighash_type.to_c_value(),
        self.sighash_type.is_anyone_can_pay(),
        &mut der_signature,
      )
    };
    let result = match error_code {
      0 => {
        let der_encoded = unsafe { collect_cstring_and_free(der_signature) }?;
        let mut sig = SignParameter::from_vec(byte_from_hex_unsafe(&der_encoded));
        sig.sighash_type = self.sighash_type;
        Ok(sig)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Get a der-encoded signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::SignParameter;
  /// use std::str::FromStr;
  /// let der_encoded_sig = SignParameter::from_str("30440220773420c0ded41a55b1f1205cfb632f08f3f911a53e7338a0dac73ec6cbe3ca4702201907434d046185abedc5afddc2761a642bccc70af6d22b46394f1d04a8b2422601").expect("Fail");
  /// let signature = der_encoded_sig.to_der_decode().expect("Fail");
  /// ```
  pub fn to_der_decode(&self) -> Result<SignParameter, CfdError> {
    let signature_hex = alloc_c_string(&hex_from_bytes(&self.data))?;
    let handle = ErrorHandle::new()?;
    let mut signature: *mut c_char = ptr::null_mut();
    let mut sighash_type_value: c_int = 0;
    let mut is_anyone_can_pay = false;
    let error_code = unsafe {
      CfdDecodeSignatureFromDer(
        handle.as_handle(),
        signature_hex.as_ptr(),
        &mut signature,
        &mut sighash_type_value,
        &mut is_anyone_can_pay,
      )
    };
    let result = match error_code {
      0 => {
        let der_decoded = unsafe { collect_cstring_and_free(signature) }?;
        let sign_param = SignParameter::from_vec(byte_from_hex_unsafe(&der_decoded));
        let sighash_type = SigHashType::from_c_value(sighash_type_value);
        Ok(sign_param.set_signature_hash(&SigHashType::new(&sighash_type, is_anyone_can_pay)))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

impl fmt::Display for SignParameter {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let data = hex::encode(&self.data);
    let len = self.data.len();
    match len {
      64 | 65 | 70..=72 => write!(
        f,
        "data:{}, {}, canDerEncode:{}",
        data, self.sighash_type, self.use_der_encode
      )?,
      _ => write!(f, "data:{}", data)?,
    }

    if self.pubkey.valid() {
      write!(f, ", pubkey={}", self.pubkey)?;
    }
    Ok(())
  }
}

impl FromStr for SignParameter {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<SignParameter, CfdError> {
    match byte_from_hex(text) {
      Ok(byte_array) => Ok(SignParameter::from_vec(byte_array)),
      Err(e) => Err(e),
    }
  }
}

impl Default for SignParameter {
  fn default() -> SignParameter {
    SignParameter::from_slice(&[])
  }
}
