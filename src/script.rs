extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uint, c_void};
use crate::common::{
  alloc_c_string, byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free,
  collect_multi_cstring_and_free, hex_from_bytes, ErrorHandle,
};
use crate::{
  common::{ByteData, CfdError},
  key::Pubkey,
};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};

use self::cfd_sys::{
  CfdAddMultisigScriptData, CfdConvertScriptAsmToHex, CfdFinalizeMultisigScript,
  CfdFreeMultisigScriptHandle, CfdFreeScriptItemHandle, CfdGetScriptItem,
  CfdInitializeMultisigScript, CfdParseScript,
};

/// A container that stores a bitcoin script.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Script {
  buffer: Vec<u8>,
  asm: String,
}

impl Script {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - An unsigned 8bit slice that holds the byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Script;
  /// let bytes: Vec<u8> = vec![0];
  /// let op_0 = Script::from_slice(&bytes);
  /// ```
  #[inline]
  pub fn from_slice(data: &[u8]) -> Result<Script, CfdError> {
    let script_hex = alloc_c_string(&hex_from_bytes(data))?;
    let handle = ErrorHandle::new()?;
    let mut script_handle: *mut c_void = ptr::null_mut();
    let mut script_item_num: c_uint = 0;
    let error_code = unsafe {
      CfdParseScript(
        handle.as_handle(),
        script_hex.as_ptr(),
        &mut script_handle,
        &mut script_item_num,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          let mut list: Vec<String> = vec![];
          list.reserve(script_item_num as usize);
          let mut index: c_uint = 0;
          while index < script_item_num {
            let asm_str = {
              let mut asm: *mut c_char = ptr::null_mut();
              let error_code =
                unsafe { CfdGetScriptItem(handle.as_handle(), script_handle, index, &mut asm) };
              match error_code {
                0 => unsafe { collect_cstring_and_free(asm) },
                _ => Err(handle.get_error(error_code)),
              }
            }?;
            list.push(asm_str);
            index += 1;
          }
          let asm = list.iter().map(|s| s.trim()).collect::<Vec<_>>().join(" ");
          Ok(Script {
            buffer: data.to_vec(),
            asm,
          })
        };
        unsafe {
          CfdFreeScriptItemHandle(handle.as_handle(), script_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Generate from hex string.
  ///
  /// # Arguments
  /// * `hex` - A hex string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Script;
  /// let op_0 = Script::from_hex("00").expect("Fail");
  /// ```
  #[inline]
  pub fn from_hex(hex: &str) -> Result<Script, CfdError> {
    let buf = byte_from_hex(hex)?;
    Script::from_slice(&buf)
  }

  /// Generate from ByteData.
  ///
  /// # Arguments
  /// * `data` - An unsigned 8bit slice that holds the byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ByteData, Script};
  /// let bytes: Vec<u8> = vec![0];
  /// let data = ByteData::from_slice(&bytes);
  /// let op_0 = Script::from_data(&data).expect("Fail");
  /// ```
  #[inline]
  pub fn from_data(data: &ByteData) -> Result<Script, CfdError> {
    Script::from_slice(&data.to_slice())
  }

  /// Generate from asm string.
  /// (For multiple scripts, set a character string separated by spaces.)
  ///
  /// # Arguments
  /// * `asm` - A asm string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Script;
  /// let op_0_data = Script::from_asm("OP_0 01020304").expect("Fail");
  /// ```
  #[inline]
  pub fn from_asm(asm: &str) -> Result<Script, CfdError> {
    let asm_str = alloc_c_string(asm)?;
    let handle = ErrorHandle::new()?;
    let mut script_hex: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdConvertScriptAsmToHex(handle.as_handle(), asm_str.as_ptr(), &mut script_hex) };
    let result = match error_code {
      0 => {
        let hex = unsafe { collect_cstring_and_free(script_hex) }?;
        Ok(Script {
          buffer: byte_from_hex_unsafe(&hex),
          asm: asm.to_string(),
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  /// Generate from asm strings.
  ///
  /// # Arguments
  /// * `strings` - A asm strings.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Script;
  /// let script_str_list = vec!["OP_0".to_string(), "01020304".to_string()];
  /// let op_0_data = Script::from_str_array(&script_str_list).expect("Fail");
  /// ```
  #[inline]
  pub fn from_str_array(strings: &[String]) -> Result<Script, CfdError> {
    let asm = strings
      .iter()
      .map(|s| s.trim())
      .collect::<Vec<_>>()
      .join(" ");
    Script::from_asm(&asm)
  }

  /// Generate from asm string list.
  ///
  /// # Arguments
  /// * `strings` - A asm strings.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Script;
  /// let script_str_list = ["OP_0", "01020304"];
  /// let op_0_data = Script::from_strings(&script_str_list).expect("Fail");
  /// ```
  pub fn from_strings(strings: &[&str]) -> Result<Script, CfdError> {
    let asm = strings
      .iter()
      .map(|s| s.trim())
      .collect::<Vec<_>>()
      .join(" ");
    Script::from_asm(&asm)
  }

  #[inline]
  pub fn to_slice(&self) -> &Vec<u8> {
    &self.buffer
  }

  #[inline]
  pub fn to_data(&self) -> ByteData {
    ByteData::from_slice(&self.buffer)
  }

  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.buffer)
  }

  #[inline]
  pub fn to_asm(&self) -> &String {
    &self.asm
  }

  /// Get asm list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Script;
  /// let script_str_list = ["OP_0", "01020304"];
  /// let op_0_data = Script::from_strings(&script_str_list).expect("Fail");
  /// let asm_list = op_0_data.get_items();
  /// ```
  #[inline]
  pub fn get_items(&self) -> Vec<&str> {
    self.asm.split(' ').collect::<Vec<_>>()
  }

  #[inline]
  pub fn is_empty(&self) -> bool {
    self.buffer.is_empty()
  }

  /// Create multisig script.
  ///
  /// # Arguments
  /// * `require_num` - A multisig require number.
  /// * `pubkey_list` - Multisig pubkey list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Pubkey, Script};
  /// use std::str::FromStr;
  /// let key1_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
  /// let key2_str = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  /// let key3_str = "02239519ec61760ca0bae700d96581d417d9a37dddfc1eb54b9cd5da3788d387b3";
  /// let key1 = Pubkey::from_str(key1_str).expect("fail");
  /// let key2 = Pubkey::from_str(key2_str).expect("fail");
  /// let key3 = Pubkey::from_str(key3_str).expect("fail");
  /// let pubkey_list = vec![key1, key2, key3];
  /// let require_num: u8 = 2;
  /// let addr= Script::multisig(require_num, &pubkey_list).expect("Fail");
  /// ```
  #[inline]
  pub fn multisig(require_num: u8, pubkey_list: &[Pubkey]) -> Result<Script, CfdError> {
    if pubkey_list.is_empty() {
      return Err(CfdError::IllegalArgument(
        "pubkey list is empty.".to_string(),
      ));
    }

    let handle = ErrorHandle::new()?;
    let network_type: c_int = 0; // mainnet
    let hash_type: c_int = 1; // p2sh
    let mut multisig_handle: *mut c_void = ptr::null_mut();
    let mut error_code: i32 = unsafe {
      CfdInitializeMultisigScript(
        handle.as_handle(),
        network_type,
        hash_type,
        &mut multisig_handle,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          for pubkey in pubkey_list {
            let _err = {
              let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
              error_code = unsafe {
                CfdAddMultisigScriptData(handle.as_handle(), multisig_handle, pubkey_hex.as_ptr())
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          let mut address: *mut c_char = ptr::null_mut();
          let mut redeem_script: *mut c_char = ptr::null_mut();
          let mut witness_script: *mut c_char = ptr::null_mut();
          error_code = unsafe {
            CfdFinalizeMultisigScript(
              handle.as_handle(),
              multisig_handle,
              require_num as c_uint,
              &mut address,
              &mut redeem_script,
              &mut witness_script,
            )
          };
          match error_code {
            0 => {
              let str_list = unsafe {
                collect_multi_cstring_and_free(&[address, redeem_script, witness_script])
              }?;
              let script_bytes = byte_from_hex_unsafe(&str_list[1]);
              Script::from_slice(&script_bytes)
            }
            _ => Err(handle.get_error(error_code)),
          }
        };
        unsafe {
          CfdFreeMultisigScriptHandle(handle.as_handle(), multisig_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

impl Default for Script {
  fn default() -> Script {
    Script {
      buffer: vec![],
      asm: String::default(),
    }
  }
}

impl fmt::Display for Script {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Script[{}]", &self.asm)
  }
}
