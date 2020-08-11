extern crate cfd_sys;
extern crate hex;
extern crate libc;

use self::libc::{c_char, c_int, c_void};
use std::error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::ptr;
use std::{io, str};

use self::cfd_sys::{
  CfdCreateSimpleHandle, CfdFreeHandle, CfdGetConfidentialValueHex, CfdGetLastErrorMessage,
  CfdRequestExecuteJson, CfdSerializeByteData,
};

/// error on cfd.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CfdError {
  /// Unknown error.
  Unknown(String),
  /// Internal error.
  Internal(String),
  /// Memory full error.
  MemoryFull(String),
  /// Illegal input argument error.
  IllegalArgument(String),
  /// Illegal statement error.
  IllegalState(String),
  /// Input argument out of range.
  OutOfRange(String),
  /// Invalid setting/
  InvalidSetting(String),
  /// connection error.
  Connection(String),
  /// Disk access error.
  DiskAccess(String),
  /// Sign verification error.
  SignVerification(String),
}

impl fmt::Display for CfdError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      CfdError::Unknown(ref a) => write!(f, "[Unknown]: {}", a),
      CfdError::Internal(ref a) => write!(f, "[Internal]: {}", a),
      CfdError::MemoryFull(ref a) => write!(f, "[MemoryFull]: {}", a),
      CfdError::IllegalArgument(ref a) => write!(f, "[IllegalArgument]: {}", a),
      CfdError::IllegalState(ref a) => write!(f, "[IllegalState]: {}", a),
      CfdError::OutOfRange(ref a) => write!(f, "[OutOfRange]: {}", a),
      CfdError::InvalidSetting(ref a) => write!(f, "[InvalidSetting]: {}", a),
      CfdError::Connection(ref a) => write!(f, "[Connection]: {}", a),
      CfdError::DiskAccess(ref a) => write!(f, "[DiskAccess]: {}", a),
      CfdError::SignVerification(ref a) => write!(f, "[SignVerification]: {}", a),
    }
  }
}

impl error::Error for CfdError {
  fn description(&self) -> &str {
    match *self {
      CfdError::Unknown(..) => "unknown error",
      CfdError::Internal(..) => "internal error",
      CfdError::MemoryFull(..) => "memory full error",
      CfdError::IllegalArgument(..) => "illegal input argument error",
      CfdError::IllegalState(..) => "illegal statement error",
      CfdError::OutOfRange(..) => "input argument out of range",
      CfdError::InvalidSetting(..) => "invalid setting",
      CfdError::Connection(..) => "connection error",
      CfdError::DiskAccess(..) => "disk access error",
      CfdError::SignVerification(..) => "sign verification error",
    }
  }
}

/// Network type of node.
/// target is bitcoin or liquid.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Network {
  /// Bitcoin: Mainnet
  Mainnet,
  /// Bitcoin: Testnet
  Testnet,
  /// Bitcoin: Regtest
  Regtest,
  /// Elements: Liquid V1
  LiquidV1,
  /// Elements: Regtest
  ElementsRegtest,
  /// Elements: CustomChain (for feature)
  CustomChain,
}

impl Network {
  pub(in crate) fn to_c_value(&self) -> c_int {
    match self {
      Network::Mainnet => 0,
      Network::Testnet => 1,
      Network::Regtest => 2,
      Network::LiquidV1 => 10,
      Network::ElementsRegtest => 11,
      Network::CustomChain => 12,
    }
  }

  pub(in crate) fn from_c_value(net_type: c_int) -> Network {
    match net_type {
      0 => Network::Mainnet,
      1 => Network::Testnet,
      2 => Network::Regtest,
      10 => Network::LiquidV1,
      11 => Network::ElementsRegtest,
      12 => Network::CustomChain,
      _ => Network::Mainnet,
    }
  }
}

impl fmt::Display for Network {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match *self {
      Network::Mainnet => write!(f, "Mainnet"),
      Network::Testnet => write!(f, "Testnet"),
      Network::Regtest => write!(f, "Regtest"),
      Network::LiquidV1 => write!(f, "LiquidV1"),
      Network::ElementsRegtest => write!(f, "ElementsRegtest"),
      Network::CustomChain => write!(f, "CustomChain"),
    }
  }
}

/// A container that stores a byte array.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ByteData {
  data: Vec<u8>,
}

impl ByteData {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - An unsigned 8bit slice that holds the byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes: Vec<u8> = vec![0, 1, 2, 3];
  /// let data = ByteData::from_slice(&bytes);
  /// ```
  #[inline]
  pub fn from_slice(data: &[u8]) -> ByteData {
    ByteData {
      data: data.to_vec(),
    }
  }

  /// Generate with reversed slices.
  ///
  /// # Arguments
  /// * `data` - An unsigned 8bit slice that holds the byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes: Vec<u8> = vec![3, 2, 1, 0];
  /// let data = ByteData::from_slice(&bytes);
  /// ```
  #[inline]
  pub fn from_slice_reverse(data: &[u8]) -> ByteData {
    let mut array = data.to_vec();
    array.reverse();
    ByteData { data: array }
  }

  /// Write the byte data to writer.
  ///
  /// # Arguments
  /// * `writer` - An output writer.
  pub fn write_into<W: io::Write>(&self, mut writer: W) {
    let write_res = writer.write_all(&self.data);
    debug_assert!(write_res.is_ok());
  }

  /// Output slice into byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes: Vec<u8> = vec![0, 1, 2, 3];
  /// let data = ByteData::from_slice(&bytes);
  /// let byte_array = data.to_slice();
  /// // &bytes == &byte_array
  /// ```
  #[inline]
  pub fn to_slice(&self) -> &[u8] {
    &self.data
  }

  /// Output hex string into byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes: Vec<u8> = vec![0, 1, 2, 3];
  /// let data = ByteData::from_slice(&bytes);
  /// let hex = data.to_hex();
  /// // hex == "00010203"
  /// ```
  #[inline]
  pub fn to_hex(&self) -> String {
    hex_from_bytes(&self.data)
  }

  /// Get byte data length.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes: Vec<u8> = vec![0, 1, 2, 3];
  /// let data = ByteData::from_slice(&bytes);
  /// let length = data.len();
  /// // length == 4
  /// ```
  #[inline]
  pub fn len(&self) -> usize {
    self.data.len()
  }

  /// Check empty byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes1: Vec<u8> = vec![0, 1, 2, 3];
  /// let bytes2: Vec<u8> = vec![];
  /// let data1 = ByteData::from_slice(&bytes1);
  /// let data2 = ByteData::from_slice(&bytes2);
  /// let empty1 = data1.is_empty();
  /// let empty2 = data2.is_empty();
  /// let length1 = data1.len();
  /// let length2 = data2.len();
  /// // empty1 == false, length1 == 4
  /// // empty2 == true, length2 == 0
  /// ```
  #[inline]
  pub fn is_empty(&self) -> bool {
    self.data.is_empty()
  }

  /// Get serialized byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes: Vec<u8> = vec![0, 1, 2, 3];
  /// let data = ByteData::from_slice(&bytes);
  /// let serial_result = data.serialize();
  /// if let Ok(serialized_data) = serial_result {
  ///   let serial_hex = serialized_data.to_hex();
  ///   // serial_hex == "0400010203"
  /// }
  /// ```
  pub fn serialize(&self) -> Result<ByteData, CfdError> {
    let buffer = alloc_c_string(&hex_from_bytes(&self.data))?;
    let handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdSerializeByteData(handle.as_handle(), buffer.as_ptr(), &mut output) };
    let result = match error_code {
      0 => {
        let c_output = unsafe { collect_cstring_and_free(output) }?;
        Ok(ByteData::from_slice(&byte_from_hex_unsafe(&c_output)))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
  /// Concat two byte data.
  ///
  /// # Arguments
  /// * `other` - An other byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ByteData;
  /// let bytes1: Vec<u8> = vec![0, 1, 2, 3];
  /// let bytes2: Vec<u8> = vec![4, 5, 6, 7];
  /// let data1 = ByteData::from_slice(&bytes1);
  /// let data2 = ByteData::from_slice(&bytes2);
  /// let concat_data = data1.concat(&data2);
  /// // concat_data.to_hex() == "0001020304050607"
  /// ```
  pub fn concat(&self, other: &ByteData) -> ByteData {
    if other.data.is_empty() {
      return self.clone();
    }
    let mut new_buffer = self.data.clone();
    new_buffer.extend(&other.data);
    ByteData { data: new_buffer }
  }
}

impl fmt::Display for ByteData {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", hex::encode(&self.data))
  }
}

impl Default for ByteData {
  fn default() -> ByteData {
    ByteData { data: vec![] }
  }
}

impl str::FromStr for ByteData {
  type Err = CfdError;
  fn from_str(hex: &str) -> Result<ByteData, CfdError> {
    let result = byte_from_hex(hex)?;
    Ok(ByteData::from_slice(&result))
  }
}

/// A container that stores a amount.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Amount {
  satoshi_amount: i64,
}

impl Amount {
  /// Create amount from satoshi.
  ///
  /// # Arguments
  /// * `amount` - A satoshi amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Amount;
  /// let amount = Amount::new(100000);
  /// ```
  pub fn new(amount: i64) -> Amount {
    Amount {
      satoshi_amount: amount,
    }
  }

  /// Create amount from bitcoin.
  ///
  /// # Arguments
  /// * `btc` - A bitcoin amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Amount;
  /// let amount = Amount::from_btc(0.001);
  /// ```
  pub fn from_btc(btc: f64) -> Amount {
    let value = btc * 100000000_f64;
    let amount = value.round() as i64;
    Amount {
      satoshi_amount: amount,
    }
  }

  /// Get satoshi amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Amount;
  /// let amount = Amount::from_btc(0.001);
  /// let satoshi = amount.as_satoshi_amount();
  /// // satoshi == 100000
  /// ```
  pub fn as_satoshi_amount(&self) -> i64 {
    self.satoshi_amount
  }

  /// Get bitcoin amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Amount;
  /// let amount = Amount::new(100000);
  /// let btc = amount.as_btc();
  /// // btc == 100000
  /// ```
  pub fn as_btc(&self) -> f64 {
    let value: f64 = self.satoshi_amount as f64;
    value / 100000000_f64
  }

  /// Get bitcoin bytes.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Amount;
  /// let amount = Amount::new(100000);
  /// let byte_data_result = amount.as_byte();
  /// if let Ok(_byte_data) = byte_data_result {
  ///   // byte_data == "a086010000000000"
  /// }
  /// ```
  pub fn as_byte(&self) -> Result<Vec<u8>, CfdError> {
    let handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetConfidentialValueHex(handle.as_handle(), self.satoshi_amount, true, &mut output)
    };
    let result = match error_code {
      0 => {
        let hex = unsafe { collect_cstring_and_free(output) }?;
        byte_from_hex(&hex)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

impl Default for Amount {
  fn default() -> Amount {
    Amount { satoshi_amount: 0 }
  }
}

pub fn request_json(request: &str, option: &str) -> Result<String, CfdError> {
  let req_name = alloc_c_string(request)?;
  let opt_data = alloc_c_string(option)?;
  let handle = ErrorHandle::new()?;
  let mut output: *mut c_char = ptr::null_mut();
  let error_code = unsafe {
    CfdRequestExecuteJson(
      handle.as_handle(),
      req_name.as_ptr(),
      opt_data.as_ptr(),
      &mut output,
    )
  };
  let result = match error_code {
    0 => unsafe { collect_cstring_and_free(output) },
    _ => Err(handle.get_error(error_code)),
  };
  handle.free_handle();
  result
}

#[derive(Debug)]
pub(in crate) struct ErrorHandle {
  handle: *mut c_void,
}

impl ErrorHandle {
  pub fn new() -> Result<ErrorHandle, CfdError> {
    let mut result: Result<ErrorHandle, CfdError> =
      Err(CfdError::Internal("failed to ErrorHandle".to_string()));
    let mut handle: *mut c_void = ptr::null_mut();
    unsafe {
      let cfd_ret = CfdCreateSimpleHandle(&mut handle);
      if cfd_ret == 0 {
        if !handle.is_null() {
          result = Ok(ErrorHandle { handle });
        }
      } else {
        result = Err(CfdError::Internal(format!(
          "failed to CfdCreateSimpleHandle:{}",
          cfd_ret
        )));
      }
      result
    }
  }

  #[inline]
  pub fn as_handle(&self) -> *const c_void {
    self.handle
  }

  pub fn get_error_message(&self) -> String {
    let mut result = String::default();
    let mut message: *mut c_char = ptr::null_mut() as *mut c_char;
    let cfd_ret = unsafe { CfdGetLastErrorMessage(self.handle, &mut message) };
    if cfd_ret == 0 {
      let message_obj = unsafe { collect_cstring_and_free(message) };
      if let Ok(message) = message_obj {
        result = message;
      }
    } else {
      println!("CfdGetLastErrorMessage NG:{}", cfd_ret);
    }
    result
  }

  pub fn free_handle(&self) -> bool {
    unsafe {
      let mut result: bool = false;
      if self.handle.is_null() {
        println!("CfdFreeHandle NG. null-ptr.");
      } else {
        let cfd_ret = CfdFreeHandle(self.handle);
        if cfd_ret == 0 {
          // self.handle = ptr::null_mut();
          result = true;
        } else {
          println!("CfdFreeHandle NG:{}", cfd_ret);
        }
      }
      result
    }
  }

  pub fn get_error(&self, error_code: c_int) -> CfdError {
    let err_msg = self.get_error_message();
    match error_code {
      -1 => CfdError::Unknown(err_msg),
      -2 => CfdError::Internal(err_msg),
      -3 => CfdError::MemoryFull(err_msg),
      1 => CfdError::IllegalArgument(err_msg),
      2 => CfdError::IllegalState(err_msg),
      3 => CfdError::OutOfRange(err_msg),
      4 => CfdError::InvalidSetting(err_msg),
      5 => CfdError::Connection(err_msg),
      6 => CfdError::DiskAccess(err_msg),
      7 => CfdError::SignVerification(err_msg),
      _ => CfdError::Unknown(err_msg),
    }
  }
}

#[inline]
pub(in crate) fn alloc_c_string(text: &str) -> Result<CString, CfdError> {
  let result = CString::new(text);
  match result {
    Ok(string_buffer) => Ok(string_buffer),
    Err(_) => Err(CfdError::MemoryFull("CString::new fail.".to_string())),
  }
}

#[inline]
pub(in crate) fn hex_from_bytes(bytes: &[u8]) -> String {
  match bytes.is_empty() {
    true => String::default(),
    _ => hex::encode(bytes),
  }
}

#[inline]
pub(in crate) fn byte_from_hex(hex: &str) -> Result<Vec<u8>, CfdError> {
  match (hex.len() % 2) != 0 {
    true => Err(CfdError::IllegalArgument("Illegal hex format.".to_string())),
    _ => Ok(byte_from_hex_unsafe(hex)),
  }
}

#[inline]
pub(in crate) fn byte_from_hex_unsafe(hex: &str) -> Vec<u8> {
  let mut result: Vec<u8> = vec![];
  let len = hex.len();
  if (len != 0) && ((len % 2) == 0) {
    if let Ok(data) = hex::decode(hex) {
      result = data;
    }
  }
  result
}

pub(in crate) fn copy_array_32byte(buffer: &[u8]) -> [u8; 32] {
  let mut result: [u8; 32] = [0; 32];
  if buffer.len() >= 32 {
    let mut index: usize = 0;
    while index < result.len() {
      result[index] = buffer[index];
      index += 1;
    }
  }
  result
}

/// # Safety
///
/// This function should not be called before the horsemen are ready.
pub(in crate) unsafe fn collect_multi_cstring_and_free(
  address_list: &[*mut c_char],
) -> Result<Vec<String>, CfdError> {
  let mut list: Vec<String> = vec![];
  let mut err_obj: CfdError = CfdError::Unknown(String::default());
  for target in address_list {
    match collect_cstring_and_free(*target) {
      Ok(text) => list.push(text),
      Err(e) => {
        err_obj = e;
      }
    }
  }
  if list.len() == address_list.len() {
    Ok(list)
  } else {
    Err(err_obj)
  }
}

/// # Safety
///
/// This function should not be called before the horsemen are ready.
pub(in crate) unsafe fn collect_cstring_and_free(address: *mut c_char) -> Result<String, CfdError> {
  // empty-response is not alloc buffer.
  match address.is_null() {
    true => Ok(String::default()),
    _ => {
      let c_string: &CStr = CStr::from_ptr(address);
      let result = match c_string.to_str() {
        Ok(output) => Ok(output.to_string()),
        _ => Err(CfdError::Unknown(
          "Failed to convert CStr to str.".to_string(),
        )),
      };
      libc::free(address as *mut libc::c_void);
      result
    }
  }
}
