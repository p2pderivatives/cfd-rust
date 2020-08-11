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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Script {
  buffer: Vec<u8>,
  asm: String,
}

impl Script {
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

  #[inline]
  pub fn from_hex(hex: &str) -> Result<Script, CfdError> {
    let buf = byte_from_hex(hex)?;
    Script::from_slice(&buf)
  }

  #[inline]
  pub fn from_data(data: &ByteData) -> Result<Script, CfdError> {
    Script::from_slice(&data.to_slice())
  }

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

  #[inline]
  pub fn from_str_array(strings: &[String]) -> Result<Script, CfdError> {
    let asm = strings
      .iter()
      .map(|s| s.trim())
      .collect::<Vec<_>>()
      .join(" ");
    Script::from_asm(&asm)
  }

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

  #[inline]
  pub fn get_items(&self) -> Vec<&str> {
    self.asm.split(' ').collect::<Vec<_>>()
  }

  #[inline]
  pub fn is_empty(&self) -> bool {
    self.buffer.is_empty()
  }

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
