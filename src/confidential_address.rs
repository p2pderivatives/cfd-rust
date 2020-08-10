extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int};
use crate::common::{collect_cstring_and_free, CfdError, ErrorHandle};
use crate::{address::Address, key::Pubkey};
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::result::Result;
use std::result::Result::{Err, Ok};
use std::str;
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
    let result: Result<ConfidentialAddress, CfdError>;

    let address_str = CString::new(address.to_str().to_string());
    let ct_key_str = CString::new(confidential_key.to_hex());
    if address_str.is_err() || ct_key_str.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let addr = address_str.unwrap();
    let ct_key = ct_key_str.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
    let mut confidential_address: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateConfidentialAddress(
        handle.as_handle(),
        addr.as_ptr(),
        ct_key.as_ptr(),
        &mut confidential_address,
      )
    };
    if error_code == 0 {
      let ct_addr_obj = unsafe { collect_cstring_and_free(confidential_address) };
      if let Err(cfd_error) = ct_addr_obj {
        result = Err(cfd_error);
      } else {
        result = Ok(ConfidentialAddress {
          confidential_address: ct_addr_obj.unwrap(),
          address: address.clone(),
          confidential_key: confidential_key.clone(),
        });
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
    handle.free_handle();
    result
  }

  pub fn parse(confidential_address: &str) -> Result<ConfidentialAddress, CfdError> {
    let result: Result<ConfidentialAddress, CfdError>;

    let ct_address_str = CString::new(confidential_address.to_string());
    if ct_address_str.is_err() {
      return Err(CfdError::MemoryFull("CString::new fail.".to_string()));
    }
    let ct_addr = ct_address_str.unwrap();
    let err_handle = ErrorHandle::new();
    if let Err(err_handle) = err_handle {
      return Err(err_handle);
    }
    let handle = err_handle.unwrap();
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
    if error_code == 0 {
      let addr_obj;
      let ct_key_obj;
      unsafe {
        addr_obj = collect_cstring_and_free(address);
        ct_key_obj = collect_cstring_and_free(confidential_key);
      }
      if let Err(cfd_error) = addr_obj {
        result = Err(cfd_error);
      } else if let Err(cfd_error) = ct_key_obj {
        result = Err(cfd_error);
      } else {
        let addr = Address::from_string(&addr_obj.unwrap());
        let ct_key = Pubkey::from_str(&ct_key_obj.unwrap());
        if let Err(cfd_error) = addr {
          result = Err(cfd_error);
        } else if let Err(cfd_error) = ct_key {
          result = Err(cfd_error);
        } else {
          result = Ok(ConfidentialAddress {
            confidential_address: confidential_address.to_string(),
            address: addr.unwrap(),
            confidential_key: ct_key.unwrap(),
          });
        }
      }
    } else {
      result = Err(handle.get_error(error_code));
    }
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

impl str::FromStr for ConfidentialAddress {
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
