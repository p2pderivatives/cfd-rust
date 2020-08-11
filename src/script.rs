extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uint, c_void};
use crate::common::{
  byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free, hex_from_bytes, ErrorHandle,
};
use crate::{
  common::{ByteData, CfdError},
  key::Pubkey,
};
use std::ffi::CString;
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
    let mut result: Result<Script, CfdError> =
      Err(CfdError::Unknown("failed to from_asm".to_string()));
    let hex_obj = CString::new(hex_from_bytes(data));
    if hex_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let script_hex = hex_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut script_handle: *mut c_void = ptr::null_mut();
    let mut script_item_num: c_uint = 0;
    let mut error_code = unsafe {
      CfdParseScript(
        handle.as_handle(),
        script_hex.as_ptr(),
        &mut script_handle,
        &mut script_item_num,
      )
    };
    if error_code == 0 {
      let mut list: Vec<String> = vec![];
      list.reserve(script_item_num as usize);
      let mut index: c_uint = 0;
      //for index in 0..=script_item_num {
      while index < script_item_num {
        let mut asm: *mut c_char = ptr::null_mut();
        error_code =
          unsafe { CfdGetScriptItem(handle.as_handle(), script_handle, index, &mut asm) };
        if error_code == 0 {
          let asm_obj = unsafe { collect_cstring_and_free(asm) };
          if let Err(ret) = asm_obj {
            result = Err(ret);
            error_code = 1;
            break;
          } else {
            list.push(asm_obj.unwrap());
          }
        } else {
          result = Err(handle.get_error(error_code));
          break;
        }
        index += 1;
      }
      unsafe {
        CfdFreeScriptItemHandle(handle.as_handle(), script_handle);
      }
      if error_code == 0 {
        let asm = list.iter().map(|s| s.trim()).collect::<Vec<_>>().join(" ");
        result = Ok(Script {
          buffer: data.to_vec(),
          asm,
        });
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  #[inline]
  pub fn from_hex(hex: &str) -> Result<Script, CfdError> {
    let buf = byte_from_hex(hex);
    if let Err(ret) = buf {
      Err(ret)
    } else {
      Script::from_slice(&buf.unwrap())
    }
  }

  #[inline]
  pub fn from_data(data: &ByteData) -> Result<Script, CfdError> {
    Script::from_slice(&data.to_slice())
  }

  #[inline]
  pub fn from_asm(asm: &str) -> Result<Script, CfdError> {
    let result: Result<Script, CfdError>;
    let asm_obj = CString::new(asm);
    if asm_obj.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let asm_str = asm_obj.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut script_hex: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdConvertScriptAsmToHex(handle.as_handle(), asm_str.as_ptr(), &mut script_hex) };
    if error_code == 0 {
      let hex = unsafe { collect_cstring_and_free(script_hex) };
      if let Err(ret) = hex {
        result = Err(ret);
      } else {
        let script_bytes = byte_from_hex_unsafe(&hex.unwrap());
        result = Ok(Script {
          buffer: script_bytes,
          asm: asm.to_string(),
        });
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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
    let mut result: Result<Script, CfdError> =
      Err(CfdError::Unknown("failed to privkey negate".to_string()));
    if pubkey_list.is_empty() {
      return Err(CfdError::IllegalArgument(
        "pubkey list is empty.".to_string(),
      ));
    }

    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code != 0 {
      result = Err(handle.get_error(error_code));
    } else {
      for pubkey in pubkey_list {
        let hex_obj = CString::new(pubkey.to_hex());
        if hex_obj.is_err() {
          result = Err(CfdError::MemoryFull("CString::new fail.".to_string()));
          error_code = 1;
          break;
        }
        let pubkey_hex = hex_obj.unwrap();
        error_code = unsafe {
          CfdAddMultisigScriptData(handle.as_handle(), multisig_handle, pubkey_hex.as_ptr())
        };
        if error_code != 0 {
          result = Err(handle.get_error(error_code));
          break;
        }
      }
      if error_code == 0 {
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
        if error_code == 0 {
          let addr_obj;
          let script_obj;
          let wit_script_obj;
          unsafe {
            addr_obj = collect_cstring_and_free(address);
            script_obj = collect_cstring_and_free(redeem_script);
            wit_script_obj = collect_cstring_and_free(witness_script);
          }
          if let Err(ret) = addr_obj {
            result = Err(ret);
          } else if let Err(ret) = script_obj {
            result = Err(ret);
          } else if let Err(ret) = wit_script_obj {
            result = Err(ret);
          } else {
            let script_bytes = byte_from_hex_unsafe(&script_obj.unwrap());
            result = Script::from_slice(&script_bytes);
          }
        } else {
          result = Err(handle.get_error(error_code));
        }
      }
      unsafe {
        CfdFreeMultisigScriptHandle(handle.as_handle(), multisig_handle);
      }
    }
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
    let s = &self.asm;
    write!(f, "Script[{}]", s)?;
    Ok(())
  }
}
