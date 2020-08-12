extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int};
use crate::common::{
  alloc_c_string, collect_cstring_and_free, collect_multi_cstring_and_free, CfdError, ErrorHandle,
};
use crate::{address::Address, key::Pubkey};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{CfdCreateConfidentialAddress, CfdParseConfidentialAddress};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialAddress {
  confidential_address: String,
  address: Address,
  confidential_key: Pubkey,
}

impl ConfidentialAddress {
  pub fn new(
    address: &Address,
    confidential_key: &Pubkey,
  ) -> Result<ConfidentialAddress, CfdError> {
    let addr = alloc_c_string(address.to_str())?;
    let ct_key = alloc_c_string(&confidential_key.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut confidential_address: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateConfidentialAddress(
        handle.as_handle(),
        addr.as_ptr(),
        ct_key.as_ptr(),
        &mut confidential_address,
      )
    };
    let result = match error_code {
      0 => {
        let ct_addr_obj = unsafe { collect_cstring_and_free(confidential_address) }?;
        Ok(ConfidentialAddress {
          confidential_address: ct_addr_obj,
          address: address.clone(),
          confidential_key: confidential_key.clone(),
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn parse(confidential_address: &str) -> Result<ConfidentialAddress, CfdError> {
    let ct_addr = alloc_c_string(confidential_address)?;
    let handle = ErrorHandle::new()?;
    let mut network_type_c: c_int = 0;
    let mut address: *mut c_char = ptr::null_mut();
    let mut confidential_key: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdParseConfidentialAddress(
        handle.as_handle(),
        ct_addr.as_ptr(),
        &mut address,
        &mut confidential_key,
        &mut network_type_c,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[address, confidential_key]) }?;
        let addr_obj = &str_list[0];
        let ct_key_obj = &str_list[1];
        let addr = Address::from_string(&addr_obj)?;
        let ct_key = Pubkey::from_str(&ct_key_obj)?;
        Ok(ConfidentialAddress {
          confidential_address: confidential_address.to_string(),
          address: addr,
          confidential_key: ct_key,
        })
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  #[inline]
  pub fn to_str(&self) -> &str {
    &self.confidential_address
  }

  #[inline]
  pub fn get_address(&self) -> &Address {
    &self.address
  }

  #[inline]
  pub fn get_confidential_key(&self) -> &Pubkey {
    &self.confidential_key
  }
}

impl FromStr for ConfidentialAddress {
  type Err = CfdError;
  fn from_str(string: &str) -> Result<ConfidentialAddress, CfdError> {
    ConfidentialAddress::parse(string)
  }
}

impl fmt::Display for ConfidentialAddress {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.confidential_address)
  }
}

impl Default for ConfidentialAddress {
  fn default() -> ConfidentialAddress {
    ConfidentialAddress {
      confidential_address: String::default(),
      address: Address::default(),
      confidential_key: Pubkey::default(),
    }
  }
}
