extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_void};
use crate::common::{
  byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free, hex_from_bytes, ByteData,
  CfdError, ErrorHandle, Network,
};
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::result::Result;
use std::result::Result::{Err, Ok};
use std::str;

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
    if key.len() >= PRIVKEY_SIZE {
      let result = slice_as_array!(&key, [u8; PRIVKEY_SIZE]);
      if let Some(value) = result {
        privkey.key = *value;
      }
    }
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
  /// let key_result = Privkey::from_slice(&bytes);
  /// ```
  pub fn from_slice(key: &[u8]) -> Result<Privkey, CfdError> {
    if key.len() != PRIVKEY_SIZE {
      return Err(CfdError::IllegalArgument("invalid privkey.".to_string()));
    }
    let mut privkey = Privkey::from_bytes(key);
    let wif = privkey.generate_wif(&privkey.net_type, privkey.is_compressed);
    if let Ok(wif) = wif {
      privkey.wif = wif;
    } else if let Err(result) = wif {
      return Err(result);
    }
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
  /// let key_result = Privkey::from_vec(bytes);
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
  /// let key_result = Privkey::from_wif(&wif);
  /// ```
  pub fn from_wif(wif: &str) -> Result<Privkey, CfdError> {
    let mut result: Result<Privkey, CfdError> =
      Err(CfdError::Unknown("failed to generate wif".to_string()));

    let wif_obj = CString::new(wif);
    if wif_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let wif_str = wif_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let privkey = unsafe { collect_cstring_and_free(privkey_hex) };
      if let Err(result) = privkey {
        return Err(result);
      } else if let Ok(privkey_hex) = privkey {
        let key = byte_from_hex_unsafe(&privkey_hex);
        let mut privkey = Privkey::from_bytes(&key);
        privkey.wif = wif.to_string();
        privkey.net_type = Network::from_c_value(network_type);
        privkey.is_compressed = is_compressed;
        result = Ok(privkey);
      }
    } else {
      return Err(handle.get_error(error_code));
    }
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
  /// let key_result = Privkey::generate(&Network::Mainnet, true);
  /// ```
  pub fn generate(network_type: &Network, is_compressed: bool) -> Result<Privkey, CfdError> {
    let result: Result<Privkey, CfdError>;

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let pubkey_obj;
      let privkey_obj;
      let wif_obj;
      unsafe {
        pubkey_obj = collect_cstring_and_free(pubkey_hex);
        privkey_obj = collect_cstring_and_free(privkey_hex);
        wif_obj = collect_cstring_and_free(wif);
      }
      if let Err(ret) = pubkey_obj {
        result = Err(ret);
      } else if let Err(ret) = privkey_obj {
        result = Err(ret);
      } else if let Err(ret) = wif_obj {
        result = Err(ret);
      } else {
        let privkey_bytes = byte_from_hex_unsafe(&privkey_obj.unwrap());
        let wif = wif_obj.unwrap();
        let mut privkey = Privkey::from_bytes(&privkey_bytes);
        privkey.wif = wif;
        privkey.net_type = *network_type;
        privkey.is_compressed = is_compressed;
        result = Ok(privkey);
      }
    } else {
      return Err(handle.get_error(error_code));
    }
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
  /// let tweaked_key_result = key.tweak_add(&tweak_value);
  /// ```
  pub fn tweak_add(&self, data: &[u8]) -> Result<Privkey, CfdError> {
    let result: Result<Privkey, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.key));
    let tweak_obj = CString::new(hex_from_bytes(data));
    if hex_obj.is_err() || tweak_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let privkey = hex_obj.unwrap();
    let tweak = tweak_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut tweak_privkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPrivkeyTweakAdd(
        handle.as_handle(),
        privkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_privkey,
      )
    };
    if error_code == 0 {
      let tweaked = unsafe { collect_cstring_and_free(tweak_privkey) };
      if let Err(ret) = tweaked {
        result = Err(ret);
      } else {
        let tweaked_privkey = byte_from_hex_unsafe(&tweaked.unwrap());
        result = Privkey::from_slice(&tweaked_privkey);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let tweaked_key_result = key.tweak_mul(&tweak_value);
  /// ```
  pub fn tweak_mul(&self, data: &[u8]) -> Result<Privkey, CfdError> {
    let result: Result<Privkey, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.key));
    let tweak_obj = CString::new(hex_from_bytes(data));
    if hex_obj.is_err() || tweak_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let privkey = hex_obj.unwrap();
    let tweak = tweak_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut tweak_privkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPrivkeyTweakMul(
        handle.as_handle(),
        privkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_privkey,
      )
    };
    if error_code == 0 {
      let tweaked = unsafe { collect_cstring_and_free(tweak_privkey) };
      if let Err(ret) = tweaked {
        result = Err(ret);
      } else {
        let tweaked_privkey = byte_from_hex_unsafe(&tweaked.unwrap());
        result = Privkey::from_slice(&tweaked_privkey);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let key_result = key.negate();
  /// ```
  pub fn negate(&self) -> Result<Privkey, CfdError> {
    let result: Result<Privkey, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.key));
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let privkey = hex_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut negate_privkey: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdNegatePrivkey(handle.as_handle(), privkey.as_ptr(), &mut negate_privkey) };
    if error_code == 0 {
      let negated = unsafe { collect_cstring_and_free(negate_privkey) };
      if let Err(ret) = negated {
        result = Err(ret);
      } else {
        let negated_privkey = byte_from_hex_unsafe(&negated.unwrap());
        result = Privkey::from_slice(&negated_privkey);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let key_wif_result = key.generate_wif(&Network::Regtest, true);
  /// ```
  pub fn generate_wif(
    &self,
    network_type: &Network,
    is_compressed: bool,
  ) -> Result<String, CfdError> {
    if self.wif.is_empty() {
      let result: Result<String, CfdError>;

      let hex_obj = CString::new(self.to_hex());
      if hex_obj.is_err() {
        return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
      }
      let privkey = hex_obj.unwrap();
      let err_handle = ErrorHandle::new();
      if let Err(err_handle) = err_handle {
        return Err(err_handle);
      }
      let handle = err_handle.unwrap();
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
      if error_code == 0 {
        result = unsafe { collect_cstring_and_free(wif) };
      } else {
        result = Err(handle.get_error(error_code));
      }
      handle.free_handle();
      result
    } else {
      Ok(self.to_wif().to_string())
    }
  }

  /// Get a public key from this private key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Privkey;
  /// let bytes = [1; 32];
  /// let key = Privkey::from_slice(&bytes).expect("fail");
  /// let key_result = key.get_pubkey();
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
  /// let key_wif_result = Privkey::generate_pubkey(&bytes, true);
  /// ```
  pub fn generate_pubkey(
    key: &[u8; PRIVKEY_SIZE],
    is_compressed: bool,
  ) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(key));
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let privkey = hex_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let pubkey_obj = unsafe { collect_cstring_and_free(pubkey) };
      if let Err(ret) = pubkey_obj {
        result = Err(ret);
      } else {
        result = Pubkey::from_vec(byte_from_hex_unsafe(&pubkey_obj.unwrap()));
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let sig_result = key.calculate_ec_signature(&sighash, true);
  /// ```
  pub fn calculate_ec_signature(
    &self,
    sighash: &[u8],
    has_grind_r: bool,
  ) -> Result<SignParameter, CfdError> {
    let result: Result<SignParameter, CfdError>;
    let privkey_obj = CString::new(hex_from_bytes(&self.key));
    let hex_obj = CString::new(hex_from_bytes(sighash));
    if hex_obj.is_err() || privkey_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let signature_hash = hex_obj.unwrap();
    let privkey = privkey_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let signature = unsafe { collect_cstring_and_free(signature_hex) };
      if let Err(ret) = signature {
        result = Err(ret);
      } else {
        let signature_bytes = byte_from_hex_unsafe(&signature.unwrap());
        let mut sign_param = SignParameter::from_vec(signature_bytes);
        sign_param = sign_param.set_use_der_encode(&SigHashType::All);
        result = Ok(sign_param);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let sig_result = key.calculate_schnorr_signature(&k_value, &message);
  /// ```
  pub fn calculate_schnorr_signature(
    &self,
    k_value: &[u8],
    message: &[u8],
  ) -> Result<SignParameter, CfdError> {
    let result: Result<SignParameter, CfdError>;
    let privkey_obj = CString::new(self.to_hex());
    let k_value_obj = CString::new(hex_from_bytes(k_value));
    let message_obj = CString::new(hex_from_bytes(message));
    if privkey_obj.is_err() || k_value_obj.is_err() || message_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let privkey = privkey_obj.unwrap();
    let k_value_str = k_value_obj.unwrap();
    let message_str = message_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let signature = unsafe { collect_cstring_and_free(signature_hex) };
      if let Err(ret) = signature {
        result = Err(ret);
      } else {
        let signature_bytes = byte_from_hex_unsafe(&signature.unwrap());
        let mut sign_param = SignParameter::from_vec(signature_bytes);
        sign_param = sign_param.set_use_der_encode(&SigHashType::All);
        result = Ok(sign_param);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let sig_result = key.calculate_schnorr_signature_with_nonce(&k_value, &message);
  /// ```
  pub fn calculate_schnorr_signature_with_nonce(
    &self,
    k_value: &[u8],
    message: &[u8],
  ) -> Result<SignParameter, CfdError> {
    let result: Result<SignParameter, CfdError>;
    let privkey_obj = CString::new(self.to_hex());
    let k_value_obj = CString::new(hex_from_bytes(k_value));
    let message_obj = CString::new(hex_from_bytes(message));
    if privkey_obj.is_err() || k_value_obj.is_err() || message_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let privkey = privkey_obj.unwrap();
    let k_value_str = k_value_obj.unwrap();
    let message_str = message_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let signature = unsafe { collect_cstring_and_free(signature_hex) };
      if let Err(ret) = signature {
        result = Err(ret);
      } else {
        let signature_bytes = byte_from_hex_unsafe(&signature.unwrap());
        let mut sign_param = SignParameter::from_vec(signature_bytes);
        sign_param = sign_param.set_use_der_encode(&SigHashType::All);
        result = Ok(sign_param);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let key_result = key.get_schnorr_public_nonce();
  /// ```
  pub fn get_schnorr_public_nonce(&self) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;
    let privkey_obj = CString::new(self.to_hex());
    if privkey_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let privkey = privkey_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut nonce: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdGetSchnorrPublicNonce(handle.as_handle(), privkey.as_ptr(), &mut nonce) };
    if error_code == 0 {
      let nonce_obj = unsafe { collect_cstring_and_free(nonce) };
      if let Err(ret) = nonce_obj {
        result = Err(ret);
      } else {
        let nonce_bytes = byte_from_hex_unsafe(&nonce_obj.unwrap());
        result = Pubkey::from_slice(&nonce_bytes);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
      write!(f, "{}", s)?;
    } else {
      let s = &self.wif;
      write!(f, "{}", s)?;
    }
    Ok(())
  }
}

impl str::FromStr for Privkey {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Privkey, CfdError> {
    let wif_result = Privkey::from_wif(text);
    if let Ok(result) = wif_result {
      return Ok(result);
    }

    let result = byte_from_hex(text);
    match result {
      Ok(result) => Privkey::from_vec(result),
      Err(result) => Err(result),
    }
  }
}

impl Default for Privkey {
  fn default() -> Privkey {
    Privkey {
      key: [0; PRIVKEY_SIZE],
      wif: "".to_string(),
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
  /// let key_result = Pubkey::from_slice(&bytes);
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
  /// let key_result = Pubkey::from_vec(bytes);
  /// ```
  pub fn from_vec(key: Vec<u8>) -> Result<Pubkey, CfdError> {
    let len = key.len();
    match len {
      PUBKEY_COMPRESSED_SIZE | PUBKEY_UNCOMPRESSED_SIZE => {
        if Pubkey::valid_key(&key) {
          Ok(Pubkey { key })
        } else {
          Err(CfdError::IllegalArgument(
            "invalid pubkey format.".to_string(),
          ))
        }
      }
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

  /// Get a compressed public key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Pubkey;
  /// use std::str::FromStr;
  /// let uncompressed_key_str = "04fb82cb7d7bc1454f777582971473e702fbd058d40fe0958a9baecc37b89f7b0e92e67ae4804fc1da350f13d8be66dea93cbb2f8e78f178f661c30d7eead45a80";
  /// let uncompressed_key = Pubkey::from_str(uncompressed_key_str).expect("fail");
  /// let key_result = uncompressed_key.compress();
  /// ```
  pub fn compress(&self) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;

    let hex_obj = CString::new(self.to_hex());
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut compressed_pubkey: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdCompressPubkey(handle.as_handle(), pubkey.as_ptr(), &mut compressed_pubkey) };
    if error_code == 0 {
      let compress_pubkey = unsafe { collect_cstring_and_free(compressed_pubkey) };
      if let Err(ret) = compress_pubkey {
        result = Err(ret);
      } else {
        let compressed_key = byte_from_hex_unsafe(&compress_pubkey.unwrap());
        result = Ok(Pubkey {
          key: compressed_key,
        });
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let key_result = compressed_key.compress();
  /// ```
  pub fn uncompress(&self) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;

    let hex_obj = CString::new(self.to_hex());
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut decompressed_pubkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdUncompressPubkey(
        handle.as_handle(),
        pubkey.as_ptr(),
        &mut decompressed_pubkey,
      )
    };
    if error_code == 0 {
      let decompress_pubkey = unsafe { collect_cstring_and_free(decompressed_pubkey) };
      if let Err(ret) = decompress_pubkey {
        result = Err(ret);
      } else {
        let decompressed_key = byte_from_hex_unsafe(&decompress_pubkey.unwrap());
        result = Ok(Pubkey {
          key: decompressed_key,
        });
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let tweaked_key_result = key.tweak_add(&tweak_value);
  /// ```
  pub fn tweak_add(&self, data: &[u8]) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.key));
    let tweak_obj = CString::new(hex_from_bytes(data));
    if hex_obj.is_err() || tweak_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();
    let tweak = tweak_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut tweak_pubkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPubkeyTweakAdd(
        handle.as_handle(),
        pubkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_pubkey,
      )
    };
    if error_code == 0 {
      let tweaked = unsafe { collect_cstring_and_free(tweak_pubkey) };
      if let Err(ret) = tweaked {
        result = Err(ret);
      } else {
        let tweaked_pubkey = byte_from_hex_unsafe(&tweaked.unwrap());
        result = Pubkey::from_vec(tweaked_pubkey);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let tweaked_key_result = key.tweak_mul(&tweak_value);
  /// ```
  pub fn tweak_mul(&self, data: &[u8]) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.key));
    let tweak_obj = CString::new(hex_from_bytes(data));
    if hex_obj.is_err() || tweak_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();
    let tweak = tweak_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut tweak_pubkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdPubkeyTweakMul(
        handle.as_handle(),
        pubkey.as_ptr(),
        tweak.as_ptr(),
        &mut tweak_pubkey,
      )
    };
    if error_code == 0 {
      let tweaked = unsafe { collect_cstring_and_free(tweak_pubkey) };
      if let Err(ret) = tweaked {
        result = Err(ret);
      } else {
        let tweaked_pubkey = byte_from_hex_unsafe(&tweaked.unwrap());
        result = Pubkey::from_vec(tweaked_pubkey);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let key_result = key.negate();
  /// ```
  pub fn negate(&self) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.key));
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut negate_pubkey: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdNegatePubkey(handle.as_handle(), pubkey.as_ptr(), &mut negate_pubkey) };
    if error_code == 0 {
      let negated = unsafe { collect_cstring_and_free(negate_pubkey) };
      if let Err(ret) = negated {
        result = Err(ret);
      } else {
        let negated_pubkey = byte_from_hex_unsafe(&negated.unwrap());
        result = Pubkey::from_vec(negated_pubkey);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let key_result = Pubkey::combine(&pubkeys);
  /// ```
  pub fn combine(pubkey_list: &[Pubkey]) -> Result<Pubkey, CfdError> {
    let mut result: Result<Pubkey, CfdError> =
      Err(CfdError::Unknown("failed to privkey negate".to_string()));
    if pubkey_list.is_empty() {
      return Err(CfdError::IllegalArgument(
        "pubkey list is empty.".to_string(),
      ));
    }
    if pubkey_list.len() == 1 {
      return Ok(pubkey_list[0].clone());
    }

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut combine_handle: *mut c_void = ptr::null_mut();
    let mut error_code: i32 =
      unsafe { CfdInitializeCombinePubkey(handle.as_handle(), &mut combine_handle) };
    if error_code != 0 {
      result = Err(handle.get_error(error_code));
    } else {
      for pubkey in pubkey_list {
        let hex_obj = CString::new(hex_from_bytes(&pubkey.key));
        if hex_obj.is_err() {
          result = Err(CfdError::MemoryFull("CString::new fail.".to_string()));
          error_code = 1;
          break;
        }
        let pubkey_hex = hex_obj.unwrap();
        error_code =
          unsafe { CfdAddCombinePubkey(handle.as_handle(), combine_handle, pubkey_hex.as_ptr()) };
        if error_code != 0 {
          result = Err(handle.get_error(error_code));
          break;
        }
      }
      if error_code == 0 {
        let mut combine_pubkey: *mut c_char = ptr::null_mut();
        error_code = unsafe {
          CfdFinalizeCombinePubkey(handle.as_handle(), combine_handle, &mut combine_pubkey)
        };
        if error_code == 0 {
          let pubkey = unsafe { collect_cstring_and_free(combine_pubkey) };
          if let Err(ret) = pubkey {
            result = Err(ret);
          } else {
            let combine_key = byte_from_hex_unsafe(&pubkey.unwrap());
            result = Pubkey::from_vec(combine_key);
          }
        } else {
          result = Err(handle.get_error(error_code));
        }
      }
      unsafe {
        CfdFreeCombinePubkeyHandle(handle.as_handle(), combine_handle);
      }
    }
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
    let result: Result<bool, CfdError>;
    let hex_obj = CString::new(self.to_hex());
    let sighash_obj = CString::new(hex_from_bytes(sighash));
    let signature_obj = CString::new(hex_from_bytes(signature));
    if hex_obj.is_err() || sighash_obj.is_err() || signature_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();
    let sighash_hex = sighash_obj.unwrap();
    let signature_hex = signature_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let error_code = unsafe {
      CfdVerifyEcSignature(
        handle.as_handle(),
        sighash_hex.as_ptr(),
        pubkey.as_ptr(),
        signature_hex.as_ptr(),
      )
    };
    if error_code == 0 {
      result = Ok(true);
    } else if error_code == 7 {
      // SignVerification
      result = Ok(false);
    } else {
      result = Err(handle.get_error(error_code));
    }
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
    let result: Result<bool, CfdError>;
    let hex_obj = CString::new(self.to_hex());
    let message_obj = CString::new(hex_from_bytes(message));
    let signature_obj = CString::new(hex_from_bytes(signature));
    if hex_obj.is_err() || message_obj.is_err() || signature_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();
    let message_hex = message_obj.unwrap();
    let signature_hex = signature_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let error_code = unsafe {
      CfdVerifySchnorrSignature(
        handle.as_handle(),
        pubkey.as_ptr(),
        signature_hex.as_ptr(),
        message_hex.as_ptr(),
      )
    };
    if error_code == 0 {
      result = Ok(true);
    } else if error_code == 7 {
      // SignVerification
      result = Ok(false);
    } else {
      result = Err(handle.get_error(error_code));
    }
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
    let result: Result<bool, CfdError>;
    let hex_obj = CString::new(self.to_hex());
    let nonce_obj = CString::new(nonce.to_hex());
    let message_obj = CString::new(hex_from_bytes(message));
    let signature_obj = CString::new(hex_from_bytes(signature));
    if hex_obj.is_err() || nonce_obj.is_err() || message_obj.is_err() || signature_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = hex_obj.unwrap();
    let nonce_hex = nonce_obj.unwrap();
    let message_hex = message_obj.unwrap();
    let signature_hex = signature_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let error_code = unsafe {
      CfdVerifySchnorrSignatureWithNonce(
        handle.as_handle(),
        pubkey.as_ptr(),
        nonce_hex.as_ptr(),
        signature_hex.as_ptr(),
        message_hex.as_ptr(),
      )
    };
    if error_code == 0 {
      result = Ok(true);
    } else if error_code == 7 {
      // SignVerification
      result = Ok(false);
    } else {
      result = Err(handle.get_error(error_code));
    }
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
  /// let schnorr_pubkey_result = oracle_pubkey.get_schnorr_pubkey(&oracle_r_point, &message);
  /// ```
  pub fn get_schnorr_pubkey(
    &self,
    oracle_r_point: &Pubkey,
    message: &[u8],
  ) -> Result<Pubkey, CfdError> {
    let result: Result<Pubkey, CfdError>;
    let oracle_pubkey_obj = CString::new(self.to_hex());
    let oracle_r_point_obj = CString::new(oracle_r_point.to_hex());
    let message_obj = CString::new(hex_from_bytes(message));
    if oracle_pubkey_obj.is_err() || oracle_r_point_obj.is_err() || oracle_r_point_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let pubkey = oracle_pubkey_obj.unwrap();
    let oracle_r_point_str = oracle_r_point_obj.unwrap();
    let message_str = message_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let output_obj = unsafe { collect_cstring_and_free(output) };
      if let Err(ret) = output_obj {
        result = Err(ret);
      } else {
        let schnorr_pubkey = byte_from_hex_unsafe(&output_obj.unwrap());
        result = Pubkey::from_slice(&schnorr_pubkey);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
    if let Ok(_result) = pubkey.compress() {
      true
    } else {
      false
    }
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
    if let Ok(_result) = self.compress() {
      true
    } else {
      false
    }
  }
}

impl fmt::Display for Pubkey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let s = hex::encode(&self.key);
    write!(f, "{}", s)?;
    Ok(())
  }
}

impl str::FromStr for Pubkey {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Pubkey, CfdError> {
    let result = byte_from_hex(text);
    match result {
      Ok(result) => Pubkey::from_vec(result),
      Err(result) => Err(result),
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

/// An enumeration definition of  signature hash type.
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
    let ret = match *self {
      SigHashType::All | SigHashType::AllPlusAnyoneCanPay => write!(f, "sighashType:All"),
      SigHashType::None | SigHashType::NonePlusAnyoneCanPay => write!(f, "sighashType:None"),
      SigHashType::Single | SigHashType::SinglePlusAnyoneCanPay => write!(f, "sighashType:Single"),
    };
    if let Err(result) = ret {
      Err(result)
    } else if self.is_anyone_can_pay() {
      write!(f, ", anyoneCanPay")
    } else {
      Ok(())
    }
  }
}

/// a container that stores sign parameter.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignParameter {
  data: Vec<u8>,
  sighash_type: SigHashType,

  pubkey: Pubkey,
  use_der_encode: bool,
}

impl SignParameter {
  pub fn from_slice(data: &[u8]) -> SignParameter {
    SignParameter {
      data: data.to_vec(),
      sighash_type: SigHashType::All,
      pubkey: Pubkey::default(),
      use_der_encode: false,
    }
  }

  pub fn from_vec(data: Vec<u8>) -> SignParameter {
    SignParameter::from_slice(&data)
  }

  #[inline]
  pub fn set_signature_hash(mut self, sighash_type: &SigHashType) -> SignParameter {
    self.sighash_type = *sighash_type;
    self
  }

  #[inline]
  pub fn set_use_der_encode(mut self, sighash_type: &SigHashType) -> SignParameter {
    self.use_der_encode = true;
    self.set_signature_hash(&sighash_type)
  }

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

  pub fn normalize(&self) -> Result<SignParameter, CfdError> {
    let result: Result<SignParameter, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.data));
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let signature_hex = hex_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut normalize_signature: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdNormalizeSignature(
        handle.as_handle(),
        signature_hex.as_ptr(),
        &mut normalize_signature,
      )
    };
    if error_code == 0 {
      let normalized = unsafe { collect_cstring_and_free(normalize_signature) };
      if let Err(ret) = normalized {
        result = Err(ret);
      } else {
        let signature = byte_from_hex_unsafe(&normalized.unwrap());
        result = Ok(SignParameter::from_vec(signature));
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn to_der_encode(&self) -> Result<SignParameter, CfdError> {
    let result: Result<SignParameter, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.data));
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let signature_hex = hex_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let der_encoded = unsafe { collect_cstring_and_free(der_signature) };
      if let Err(ret) = der_encoded {
        result = Err(ret);
      } else {
        let signature = byte_from_hex_unsafe(&der_encoded.unwrap());
        result = Ok(SignParameter::from_vec(signature));
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn to_der_decode(&self) -> Result<SignParameter, CfdError> {
    let result: Result<SignParameter, CfdError>;
    let hex_obj = CString::new(hex_from_bytes(&self.data));
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let signature_hex = hex_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let der_decoded = unsafe { collect_cstring_and_free(signature) };
      if let Err(ret) = der_decoded {
        result = Err(ret);
      } else {
        let mut sign_param = SignParameter::from_vec(byte_from_hex_unsafe(&der_decoded.unwrap()));
        let sighash_type = SigHashType::from_c_value(sighash_type_value);
        sign_param =
          sign_param.set_signature_hash(&SigHashType::new(&sighash_type, is_anyone_can_pay));
        result = Ok(sign_param);
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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

impl str::FromStr for SignParameter {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<SignParameter, CfdError> {
    let result = byte_from_hex(text);
    match result {
      Ok(result) => Ok(SignParameter::from_vec(result)),
      Err(result) => Err(result),
    }
  }
}
