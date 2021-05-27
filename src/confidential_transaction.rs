extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_longlong, c_uint, c_void};
use crate::common::{
  alloc_c_string, byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free,
  collect_multi_cstring_and_free, hex_from_bytes, request_json, Amount, ByteData, CfdError,
  ErrorHandle, Network, ReverseContainer,
};
use crate::transaction::{
  set_fund_tx_option, BlockHash, CreateTxData, FeeData, FeeOption, FundOptionValue,
  FundTargetOption, FundTransactionData, HashTypeData, OutPoint, ScriptWitness, SigHashOption,
  Transaction, TransactionOperation, TxData, TxDataHandle, TxInData, Txid, UtxoData,
  SEQUENCE_LOCK_TIME_FINAL,
};
use crate::{
  address::{Address, HashType},
  confidential_address::ConfidentialAddress,
  descriptor::Descriptor,
  key::{KeyPair, Privkey, Pubkey, SigHashType, SignParameter},
  script::Script,
};
use std::collections::HashMap;
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdAddBlindTxInData, CfdAddBlindTxOutByAddress, CfdAddBlindTxOutData, CfdAddCoinSelectionAmount,
  CfdAddCoinSelectionUtxoTemplate, CfdAddConfidentialTxOutput,
  CfdAddConfidentialTxSignWithPrivkeySimple, CfdAddTargetAmountForFundRawTx,
  CfdAddTransactionInput, CfdAddTxInTemplateForEstimateFee, CfdAddTxInTemplateForFundRawTx,
  CfdAddTxPeginInput, CfdAddTxPegoutOutput, CfdAddUtxoTemplateForFundRawTx,
  CfdCreateConfidentialSighash, CfdFinalizeBlindTx, CfdFinalizeCoinSelection,
  CfdFinalizeEstimateFee, CfdFinalizeFundRawTx, CfdFinalizeTransaction, CfdFreeBlindHandle,
  CfdFreeCoinSelectionHandle, CfdFreeEstimateFeeHandle, CfdFreeFundRawTxHandle,
  CfdFreeTransactionHandle, CfdGetAppendTxOutFundRawTx, CfdGetAssetCommitment,
  CfdGetBlindTxBlindData, CfdGetConfidentialTxInfoByHandle, CfdGetConfidentialTxOutSimpleByHandle,
  CfdGetConfidentialValueHex, CfdGetDefaultBlindingKey, CfdGetIssuanceBlindingKey,
  CfdGetSelectedCoinIndex, CfdGetTxInByHandle, CfdGetTxInIndexByHandle,
  CfdGetTxInIssuanceInfoByHandle, CfdGetTxOutIndex, CfdGetValueCommitment, CfdInitializeBlindTx,
  CfdInitializeCoinSelection, CfdInitializeEstimateFee, CfdInitializeFundRawTx,
  CfdInitializeTransaction, CfdSetBlindTxOption, CfdSetIssueAsset, CfdSetOptionCoinSelection,
  CfdSetOptionEstimateFee, CfdSetReissueAsset, CfdUnblindIssuance, CfdUnblindTxOut,
  CfdUpdateTxOutAmount, BLIND_OPT_COLLECT_BLINDER, BLIND_OPT_EXPONENT, BLIND_OPT_MINIMUM_BITS,
  BLIND_OPT_MINIMUM_RANGE_VALUE, COIN_OPT_BLIND_EXPONENT, COIN_OPT_BLIND_MINIMUM_BITS,
  DEFAULT_BLIND_MINIMUM_BITS, FEE_OPT_BLIND_EXPONENT, FEE_OPT_BLIND_MINIMUM_BITS,
  FUND_OPT_BLIND_EXPONENT, FUND_OPT_BLIND_MINIMUM_BITS, FUND_OPT_DUST_FEE_RATE, FUND_OPT_IS_BLIND,
  FUND_OPT_KNAPSACK_MIN_CHANGE, FUND_OPT_LONG_TERM_FEE_RATE, WITNESS_STACK_TYPE_NORMAL,
  WITNESS_STACK_TYPE_PEGIN,
};

/// commitment size.
pub const COMMITMENT_SIZE: usize = 33;
/// blind factor size.
pub const BLIND_FACTOR_SIZE: usize = 32;

/// A container that stores a blind factor.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlindFactor {
  data: ReverseContainer,
}

impl BlindFactor {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - An unsigned 32byte slice that holds the byte data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::BlindFactor;
  /// let bytes = [2; 32];
  /// let data = BlindFactor::from_slice(&bytes);
  /// ```
  pub fn from_slice(data: &[u8; BLIND_FACTOR_SIZE]) -> BlindFactor {
    BlindFactor {
      data: ReverseContainer::from_slice(data),
    }
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8; BLIND_FACTOR_SIZE] {
    self.data.to_slice()
  }

  pub fn to_hex(&self) -> String {
    self.data.to_hex()
  }

  /// check empty data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::BlindFactor;
  /// let bytes = [1; 32];
  /// let bf = BlindFactor::from_slice(&bytes);
  /// let empty = bf.is_empty();
  /// ```
  #[inline]
  pub fn is_empty(&self) -> bool {
    self.data.is_empty()
  }
}

impl FromStr for BlindFactor {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<BlindFactor, CfdError> {
    match text.len() {
      0 | 1 => Ok(BlindFactor::default()),
      _ => {
        let data = ReverseContainer::from_str(text)?;
        Ok(BlindFactor { data })
      }
    }
  }
}

impl fmt::Display for BlindFactor {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.to_hex())
  }
}

impl Default for BlindFactor {
  fn default() -> BlindFactor {
    BlindFactor {
      data: ReverseContainer::default(),
    }
  }
}

#[inline]
pub(in crate) fn get_commitment_from_byte(buffer: &[u8], buffer_size: usize) -> [u8; 33] {
  let mut result: [u8; 33] = [0; 33];
  if buffer.len() >= buffer_size {
    let mut index: usize = 0;
    let mut offset: usize = 0;
    if buffer.len() == buffer_size {
      offset = 1;
      result[0] = 1;
    }
    while index < buffer.len() {
      result[offset + index] = buffer[index];
      index += 1;
    }
  }
  result
}

#[inline]
pub(in crate) fn get_byte_from_commitment(buffer: &[u8], buffer_size: usize) -> Vec<u8> {
  let mut result: Vec<u8> = vec![0];
  if buffer[0] == 0 {
    return result;
  }
  let mut index: usize = 0;
  let mut offset: usize = 0;
  if buffer[0] == 1 {
    result.resize(buffer_size, 0);
    offset = 1;
  } else {
    result.resize(COMMITMENT_SIZE, 0);
  }
  while index < result.len() {
    result[index] = buffer[offset + index];
    index += 1;
  }
  result
}

/// A container that stores an elements asset.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialAsset {
  data: Vec<u8>,
}

impl ConfidentialAsset {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - An unsigned slice that holds the asset data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ConfidentialAsset;
  /// let empty_1 = ConfidentialAsset::from_slice(&[]).expect("Fail");
  /// let empty_2 = ConfidentialAsset::from_slice(&[0]).expect("Fail");
  /// let bytes = [2; 32];
  /// let asset = ConfidentialAsset::from_slice(&bytes).expect("Fail");
  /// let commitment_bytes = [10; 33];
  /// let commitment = ConfidentialAsset::from_slice(&commitment_bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<ConfidentialAsset, CfdError> {
    match data.len() {
      0 => Ok(ConfidentialAsset::default()),
      1 => match data[0] {
        0 => Ok(ConfidentialAsset::default()),
        _ => Err(CfdError::IllegalArgument(
          "Invalid asset null format.".to_string(),
        )),
      },
      32 => {
        let asset_obj = ConfidentialAsset {
          data: get_commitment_from_byte(data, 32).to_vec(),
        };
        Ok(asset_obj)
      }
      33 => match data[0] {
        0 => Ok(ConfidentialAsset::default()),
        1 | 10 | 11 => {
          let asset_obj = ConfidentialAsset {
            data: get_commitment_from_byte(data, 32).to_vec(),
          };
          Ok(asset_obj)
        }
        _ => Err(CfdError::IllegalArgument(
          "Invalid asset version format.".to_string(),
        )),
      },
      _ => Err(CfdError::IllegalArgument(
        "Invalid asset format.".to_string(),
      )),
    }
  }

  pub fn to_data(&self) -> &[u8] {
    &self.data
  }

  pub fn to_hex(&self) -> String {
    match self.data[0] {
      0 => "00".to_string(),
      _ => hex_from_bytes(&self.data),
    }
  }

  pub fn is_blind(&self) -> bool {
    matches!(self.data[0], 10 | 11)
  }

  pub fn is_empty(&self) -> bool {
    matches!(self.data[0], 0)
  }

  pub fn as_bytes(&self) -> Vec<u8> {
    get_byte_from_commitment(&self.data, 32)
  }

  pub fn as_str(&self) -> String {
    match self.data[0] {
      1 => {
        let arr = self.as_bytes();
        let data = ByteData::from_slice_reverse(&arr);
        data.to_hex()
      }
      _ => hex_from_bytes(&self.as_bytes()),
    }
  }

  /// Get commitment from asset blinder.
  ///
  /// # Arguments
  /// * `asset_blind_factor` - An asset blind factor.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{BlindFactor, ConfidentialAsset};
  /// use std::str::FromStr;
  /// let asset = ConfidentialAsset::from_str("6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3").expect("Fail");
  /// let abf = BlindFactor::from_str("346dbdba35c19f6e3958a2c00881024503f6611d23d98d270b98ef9de3edc7a3").expect("Fail");
  /// let commitment = asset.get_commitment(&abf).expect("Fail");
  /// ```
  pub fn get_commitment(
    &self,
    asset_blind_factor: &BlindFactor,
  ) -> Result<ConfidentialAsset, CfdError> {
    if self.is_blind() {
      // asset is blinded
      return Ok(self.clone());
    }
    let asset_str = alloc_c_string(&self.to_hex())?;
    let abf_str = alloc_c_string(&asset_blind_factor.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetAssetCommitment(
        handle.as_handle(),
        asset_str.as_ptr(),
        abf_str.as_ptr(),
        &mut output,
      )
    };
    let result = match error_code {
      0 => {
        let hex = unsafe { collect_cstring_and_free(output) }?;
        ConfidentialAsset::from_str(&hex)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn get_unblind_asset(&self) -> Result<String, CfdError> {
    if self.is_blind() {
      Err(CfdError::IllegalState("asset is commitment.".to_string()))
    } else if self.is_empty() {
      Err(CfdError::IllegalState("asset is empty.".to_string()))
    } else {
      Ok(self.as_str())
    }
  }
}

impl fmt::Display for ConfidentialAsset {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "asset[{}]", self.as_str())
  }
}

impl FromStr for ConfidentialAsset {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<ConfidentialAsset, CfdError> {
    let byte_array = byte_from_hex(text)?;
    match byte_array.len() {
      32 => {
        let bytes = ByteData::from_slice_reverse(&byte_array);
        ConfidentialAsset::from_slice(bytes.to_slice())
      }
      _ => ConfidentialAsset::from_slice(&byte_array),
    }
  }
}

impl Default for ConfidentialAsset {
  fn default() -> ConfidentialAsset {
    ConfidentialAsset { data: vec![0] }
  }
}

/// A container that stores an elements nonce.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialNonce {
  data: Vec<u8>,
}

impl ConfidentialNonce {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - An unsigned slice that holds the nonce data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ConfidentialNonce;
  /// let empty_1 = ConfidentialNonce::from_slice(&[]).expect("Fail");
  /// let empty_2 = ConfidentialNonce::from_slice(&[0]).expect("Fail");
  /// let commitment_bytes = [3; 33];
  /// let commitment = ConfidentialNonce::from_slice(&commitment_bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<ConfidentialNonce, CfdError> {
    match data.len() {
      0 => Ok(ConfidentialNonce::default()),
      1 => match data[0] {
        0 => Ok(ConfidentialNonce::default()),
        _ => Err(CfdError::IllegalArgument(
          "Invalid nonce null format.".to_string(),
        )),
      },
      32 => {
        let nonce_obj = ConfidentialNonce {
          data: get_commitment_from_byte(data, 32).to_vec(),
        };
        Ok(nonce_obj)
      }
      33 => match data[0] {
        0 => Ok(ConfidentialNonce::default()),
        1 | 2 | 3 => {
          let nonce_obj = ConfidentialNonce {
            data: get_commitment_from_byte(data, 32).to_vec(),
          };
          Ok(nonce_obj)
        }
        _ => Err(CfdError::IllegalArgument(
          "Invalid nonce version format.".to_string(),
        )),
      },
      _ => Err(CfdError::IllegalArgument(
        "Invalid nonce format.".to_string(),
      )),
    }
  }

  /// Generate from pubkey.
  ///
  /// # Arguments
  /// * `pubkey` - A confidential key.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ConfidentialNonce, Pubkey};
  /// let bytes = [3; 33];
  /// let ct_key = Pubkey::from_slice(&bytes).expect("Fail");
  /// let nonce = ConfidentialNonce::from_pubkey(&ct_key).expect("Fail");
  /// ```
  pub fn from_pubkey(pubkey: &Pubkey) -> Result<ConfidentialNonce, CfdError> {
    ConfidentialNonce::from_slice(pubkey.to_slice())
  }

  pub fn to_hex(&self) -> String {
    match self.data[0] {
      0 => "00".to_string(),
      _ => hex_from_bytes(&self.data),
    }
  }

  pub fn to_data(&self) -> &[u8] {
    &self.data
  }

  pub fn is_blind(&self) -> bool {
    matches!(self.data[0], 2 | 3)
  }

  pub fn is_empty(&self) -> bool {
    matches!(self.data[0], 0)
  }

  pub fn as_bytes(&self) -> Vec<u8> {
    if self.data[0] == 0 {
      vec![]
    } else {
      get_byte_from_commitment(&self.data, 32)
    }
  }

  pub fn as_str(&self) -> String {
    hex_from_bytes(&self.as_bytes())
  }
}

impl fmt::Display for ConfidentialNonce {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "nonce[{}]", self.as_str())
  }
}

impl FromStr for ConfidentialNonce {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<ConfidentialNonce, CfdError> {
    let byte_array = byte_from_hex(text)?;
    ConfidentialNonce::from_slice(&byte_array)
  }
}

impl Default for ConfidentialNonce {
  fn default() -> ConfidentialNonce {
    ConfidentialNonce { data: vec![0] }
  }
}

/// A container that stores an elements value.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialValue {
  data: Vec<u8>,
  amount: i64,
}

impl ConfidentialValue {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - An unsigned slice that holds the value data.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ConfidentialValue;
  /// let empty_1 = ConfidentialValue::from_slice(&[]).expect("Fail");
  /// let empty_2 = ConfidentialValue::from_slice(&[0]).expect("Fail");
  /// let bytes = [1; 8];
  /// let value = ConfidentialValue::from_slice(&bytes).expect("Fail");
  /// let commitment_bytes = [8; 33];
  /// let commitment = ConfidentialValue::from_slice(&commitment_bytes).expect("Fail");
  /// ```
  pub fn from_slice(data: &[u8]) -> Result<ConfidentialValue, CfdError> {
    match data.len() {
      0 => Ok(ConfidentialValue::default()),
      1 => match data[0] {
        0 => Ok(ConfidentialValue::default()),
        _ => Err(CfdError::IllegalArgument(
          "Invalid value null format.".to_string(),
        )),
      },
      8 => {
        let value_obj = ConfidentialValue {
          data: get_commitment_from_byte(data, 8).to_vec(),
          amount: ConfidentialValue::get_amount(data),
        };
        Ok(value_obj)
      }
      9 | 33 => match data[0] {
        0 => Ok(ConfidentialValue::default()),
        1 | 8 | 9 => {
          if (data.len() == 9 && data[0] != 1) || (data.len() != 9 && data[0] == 1) {
            Err(CfdError::IllegalArgument(
              "Invalid value version format.".to_string(),
            ))
          } else {
            let mut value_obj = ConfidentialValue {
              data: get_commitment_from_byte(data, 8).to_vec(),
              ..ConfidentialValue::default()
            };
            if data[0] == 1 {
              let unblind_data = get_byte_from_commitment(&value_obj.data, 8);
              value_obj.amount = ConfidentialValue::get_amount(&unblind_data);
            }
            Ok(value_obj)
          }
        }
        _ => Err(CfdError::IllegalArgument(
          "Invalid value version format.".to_string(),
        )),
      },
      _ => Err(CfdError::IllegalArgument(
        "Invalid value format.".to_string(),
      )),
    }
  }

  fn get_amount(data: &[u8]) -> i64 {
    let mut value: i64 = 0;
    for i in data {
      value <<= 8;
      value += *i as i64;
    }
    value
  }

  /// Generate from amount.
  ///
  /// # Arguments
  /// * `amount` - A satoshi amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ConfidentialValue;
  /// let value = ConfidentialValue::from_amount(50000).expect("Fail");
  /// ```
  pub fn from_amount(amount: i64) -> Result<ConfidentialValue, CfdError> {
    let data = {
      let mut handle = ErrorHandle::new()?;
      let mut output: *mut c_char = ptr::null_mut();
      let error_code =
        unsafe { CfdGetConfidentialValueHex(handle.as_handle(), amount, true, &mut output) };
      let result = match error_code {
        0 => {
          let hex = unsafe { collect_cstring_and_free(output) }?;
          byte_from_hex(&hex)
        }
        _ => Err(handle.get_error(error_code)),
      };
      handle.free_handle();
      result
    }?;
    let value_obj = ConfidentialValue {
      data: get_commitment_from_byte(&data, 8).to_vec(),
      amount,
    };
    Ok(value_obj)
  }

  pub fn to_data(&self) -> &[u8] {
    &self.data
  }

  pub fn to_amount(&self) -> i64 {
    self.amount
  }

  pub fn is_blind(&self) -> bool {
    matches!(self.data[0], 8 | 9)
  }

  pub fn is_empty(&self) -> bool {
    matches!(self.data[0], 0)
  }

  pub fn as_bytes(&self) -> Vec<u8> {
    get_byte_from_commitment(&self.data, 8)
  }

  pub fn as_byte_data(&self) -> ByteData {
    ByteData::from_slice(&self.as_bytes())
  }

  pub fn as_str(&self) -> String {
    hex_from_bytes(&self.as_bytes())
  }

  pub fn as_amount(&self) -> Amount {
    Amount::new(self.amount)
  }

  /// Get value commitment.
  ///
  /// # Arguments
  /// * `amount` - A satoshi amount.
  /// * `asset_commitment` - An asset on commitment.
  /// * `amount_blind_factor` - An amount blind factor.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{BlindFactor, ConfidentialAsset, ConfidentialValue};
  /// use std::str::FromStr;
  /// let ct_asset = ConfidentialAsset::from_str("0a533b742a568c0b5285bf5bdfe9623a78082d19fac9be1678f7c3adbb48b34d29").expect("Fail");
  /// let vbf = BlindFactor::from_str("fe3357df1f35df75412d9ad86ebd99e622e26019722f316027787a685e2cd71a").expect("Fail");
  /// let amount = 13000000000000;
  /// let commitment = ConfidentialValue::get_commitment(amount, &ct_asset, &vbf).expect("Fail");
  /// ```
  pub fn get_commitment(
    amount: i64,
    asset_commitment: &ConfidentialAsset,
    amount_blind_factor: &BlindFactor,
  ) -> Result<ConfidentialValue, CfdError> {
    if !asset_commitment.is_blind() {
      return Err(CfdError::IllegalArgument("Invalid asset.".to_string()));
    }
    let asset_str = alloc_c_string(&asset_commitment.as_str())?;
    let vbf_str = alloc_c_string(&amount_blind_factor.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetValueCommitment(
        handle.as_handle(),
        amount,
        asset_str.as_ptr(),
        vbf_str.as_ptr(),
        &mut output,
      )
    };
    let result = match error_code {
      0 => {
        let hex = unsafe { collect_cstring_and_free(output) }?;
        ConfidentialValue::from_str(&hex)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

impl fmt::Display for ConfidentialValue {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    if self.is_blind() {
      write!(f, "value[{}]", self.as_str())
    } else {
      write!(f, "value[{}]", self.amount)
    }
  }
}

impl FromStr for ConfidentialValue {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<ConfidentialValue, CfdError> {
    let byte_array = byte_from_hex(text)?;
    ConfidentialValue::from_slice(&byte_array)
  }
}

impl Default for ConfidentialValue {
  fn default() -> ConfidentialValue {
    ConfidentialValue {
      data: vec![0],
      amount: 0,
    }
  }
}

/// Calculate default issuance blinding key.
///
/// # Arguments
/// * `master_blinding_key` - A master blinding key.
/// * `outpoint` - A target issuance out-point.
///
/// # Example
///
/// ```
/// use cfd_rust::{OutPoint, Privkey, get_issuance_blinding_key};
/// let outpoint = OutPoint::from_str(
///   "0202020202020202020202020202020202020202020202020202020202020202",
///   1).expect("Fail");
/// let key = [3; 32];
/// let blinding_key = Privkey::from_slice(&key).expect("Fail");
/// let issuance_key = get_issuance_blinding_key(&blinding_key, &outpoint).expect("Fail");
/// ```
pub fn get_issuance_blinding_key(
  master_blinding_key: &Privkey,
  outpoint: &OutPoint,
) -> Result<Privkey, CfdError> {
  let privkey = alloc_c_string(&master_blinding_key.to_hex())?;
  let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
  let mut handle = ErrorHandle::new()?;
  let mut output: *mut c_char = ptr::null_mut();
  let error_code = unsafe {
    CfdGetIssuanceBlindingKey(
      handle.as_handle(),
      privkey.as_ptr(),
      txid.as_ptr(),
      outpoint.get_vout(),
      &mut output,
    )
  };
  let result = match error_code {
    0 => {
      let hex = unsafe { collect_cstring_and_free(output) }?;
      Privkey::from_str(&hex)
    }
    _ => Err(handle.get_error(error_code)),
  };
  handle.free_handle();
  result
}

/// Calculate elements default blinding key.
///
/// # Arguments
/// * `master_blinding_key` - A master blinding key.
/// * `locking_script` - A target locking script.
///
/// # Example
///
/// ```
/// use cfd_rust::{Privkey, Script, get_default_blinding_key};
/// let locking_script = Script::from_hex(
///   "0020e63f67c1e9ca880c430f91e05a8f383ff047c74792029403260ecf019b698801").expect("Fail");
/// let key = [3; 32];
/// let blinding_key = Privkey::from_slice(&key).expect("Fail");
/// let issuance_key = get_default_blinding_key(&blinding_key, &locking_script).expect("Fail");
/// ```
pub fn get_default_blinding_key(
  master_blinding_key: &Privkey,
  locking_script: &Script,
) -> Result<Privkey, CfdError> {
  let privkey = alloc_c_string(&master_blinding_key.to_hex())?;
  let script = alloc_c_string(&locking_script.to_hex())?;
  let mut handle = ErrorHandle::new()?;
  let mut output: *mut c_char = ptr::null_mut();
  let error_code = unsafe {
    CfdGetDefaultBlindingKey(
      handle.as_handle(),
      privkey.as_ptr(),
      script.as_ptr(),
      &mut output,
    )
  };
  let result = match error_code {
    0 => {
      let hex = unsafe { collect_cstring_and_free(output) }?;
      Privkey::from_str(&hex)
    }
    _ => Err(handle.get_error(error_code)),
  };
  handle.free_handle();
  result
}

/// decode transaction to json.
///
/// # Arguments
/// * `network` - A network type.
/// * `tx` - A transaction.
pub fn decode_raw_transaction(network: &Network, tx: &str) -> Result<String, CfdError> {
  match network.is_elements() {
    true => {
      let mainchain_network = match network {
        Network::LiquidV1 => Network::Mainnet,
        _ => Network::Regtest,
      };
      let data = format!(
        "{{\"hex\":\"{}\",\"network\":\"{}\",\"mainchainNetwork\":\"{}\"}}",
        tx,
        network.to_str(),
        mainchain_network.to_str()
      );
      request_json("ElementsDecodeRawTransaction", &data)
    }
    _ => {
      let data = format!(
        "{{\"hex\":\"{}\",\"network\":\"{}\"}}",
        tx,
        network.to_str()
      );
      request_json("DecodeRawTransaction", &data)
    }
  }
}

// ----------------------------------------------------------------------------

/// A container that stores a input address data.
#[derive(PartialEq, Eq, Clone)]
pub enum InputAddress {
  Addr(Address),
  CtAddr(ConfidentialAddress),
}

/// A container that stores a reverse byte container.
#[derive(PartialEq, Eq, Clone)]
pub struct IssuanceKeyItem {
  pub asset_blinding_key: Privkey,
  pub token_blinding_key: Privkey,
}

impl IssuanceKeyItem {
  pub fn new(asset_blinding_key: &Privkey, token_blinding_key: &Privkey) -> IssuanceKeyItem {
    IssuanceKeyItem {
      asset_blinding_key: asset_blinding_key.clone(),
      token_blinding_key: token_blinding_key.clone(),
    }
  }
}

impl Default for IssuanceKeyItem {
  fn default() -> IssuanceKeyItem {
    IssuanceKeyItem {
      asset_blinding_key: Privkey::default(),
      token_blinding_key: Privkey::default(),
    }
  }
}

/// A map that stores an issuance key.
#[derive(PartialEq, Eq, Clone)]
pub struct IssuanceKeyMap {
  map: HashMap<OutPoint, IssuanceKeyItem>,
}

impl IssuanceKeyMap {
  pub fn new() -> IssuanceKeyMap {
    IssuanceKeyMap::default()
  }

  pub fn insert(&mut self, outpoint: &OutPoint, asset_blinding_key: &Privkey) -> &IssuanceKeyMap {
    let item = IssuanceKeyItem::new(asset_blinding_key, asset_blinding_key);
    self.map.insert(outpoint.clone(), item);
    self
  }

  pub fn insert_keys(
    &mut self,
    outpoint: &OutPoint,
    asset_blinding_key: &Privkey,
    token_blinding_key: &Privkey,
  ) -> &IssuanceKeyMap {
    let item = IssuanceKeyItem::new(asset_blinding_key, token_blinding_key);
    self.map.insert(outpoint.clone(), item);
    self
  }

  pub fn get_value(&self, outpoint: &OutPoint) -> Option<&IssuanceKeyItem> {
    self.map.get(&outpoint)
  }
}

impl Default for IssuanceKeyMap {
  fn default() -> IssuanceKeyMap {
    IssuanceKeyMap {
      map: HashMap::new(),
    }
  }
}

/// A map that stores an confidential key.
#[derive(PartialEq, Eq, Clone)]
pub struct KeyIndexMap {
  map: HashMap<u32, Pubkey>,
}

impl KeyIndexMap {
  pub fn new() -> KeyIndexMap {
    KeyIndexMap::default()
  }

  pub fn insert(&mut self, txout_index: u32, confidential_key: &Pubkey) -> &KeyIndexMap {
    self.map.insert(txout_index, confidential_key.clone());
    self
  }

  pub fn get_value(&self, txout_index: u32) -> Option<&Pubkey> {
    self.map.get(&txout_index)
  }

  pub fn get_index_list(&self) -> Vec<u32> {
    let mut list: Vec<u32> = vec![];
    list.reserve(self.map.len());
    for index in self.map.keys() {
      list.push(*index);
    }
    list
  }
}

impl Default for KeyIndexMap {
  fn default() -> KeyIndexMap {
    KeyIndexMap {
      map: HashMap::new(),
    }
  }
}

/// A container that stores blind option data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlindOption {
  pub minimum_range_value: i64,
  pub exponent: i32,
  pub minimum_bits: i32,
  pub collect_blinder: bool,
}

impl Default for BlindOption {
  fn default() -> BlindOption {
    BlindOption {
      minimum_range_value: 1,
      exponent: 0,
      minimum_bits: DEFAULT_BLIND_MINIMUM_BITS,
      collect_blinder: false,
    }
  }
}

/// A container that stores elements utxo option data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ElementsUtxoOptionData {
  pub is_issuance: bool,
  pub is_blind_issuance: bool,
  pub is_pegin: bool,
  pub pegin_btc_tx_size: u32,
  pub fedpeg_script: Script,
}

impl fmt::Display for ElementsUtxoOptionData {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "option({}, {})[", &self.is_issuance, self.is_pegin)
  }
}

impl Default for ElementsUtxoOptionData {
  fn default() -> ElementsUtxoOptionData {
    ElementsUtxoOptionData {
      is_issuance: false,
      is_blind_issuance: true,
      is_pegin: false,
      pegin_btc_tx_size: 0,
      fedpeg_script: Script::default(),
    }
  }
}

/// A container that stores elements utxo information.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ElementsUtxoData {
  pub utxo: UtxoData,
  pub asset: ConfidentialAsset,
  pub value_commitment: ConfidentialValue,
  pub asset_blind_factor: BlindFactor,
  pub amount_blind_factor: BlindFactor,
  pub option: ElementsUtxoOptionData,
}

impl ElementsUtxoData {
  /// Create from out-point.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  /// * `asset` - A utxo asset.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ConfidentialAsset, OutPoint, ElementsUtxoData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let bytes = [2; 32];
  /// let asset = ConfidentialAsset::from_slice(&bytes).expect("Fail");
  /// let utxo = ElementsUtxoData::from_outpoint(&outpoint, amount, &asset);
  /// ```
  pub fn from_outpoint(
    outpoint: &OutPoint,
    amount: i64,
    asset: &ConfidentialAsset,
  ) -> Result<ElementsUtxoData, CfdError> {
    asset.get_unblind_asset()?;
    Ok(ElementsUtxoData {
      utxo: UtxoData::from_outpoint(outpoint, amount),
      asset: asset.clone(),
      value_commitment: ConfidentialValue::default(),
      asset_blind_factor: BlindFactor::default(),
      amount_blind_factor: BlindFactor::default(),
      option: ElementsUtxoOptionData::default(),
    })
  }

  /// Create from descriptor.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  /// * `asset` - A utxo asset.
  /// * `descriptor` - An output descriptor.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ConfidentialAsset, Descriptor, Network, OutPoint, ElementsUtxoData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  /// let descriptor = Descriptor::new(desc_str, &Network::ElementsRegtest).expect("Fail");
  /// let bytes = [2; 32];
  /// let asset = ConfidentialAsset::from_slice(&bytes).expect("Fail");
  /// let utxo = ElementsUtxoData::from_descriptor(&outpoint, amount, &asset, &descriptor);
  /// ```
  pub fn from_descriptor(
    outpoint: &OutPoint,
    amount: i64,
    asset: &ConfidentialAsset,
    descriptor: &Descriptor,
  ) -> Result<ElementsUtxoData, CfdError> {
    asset.get_unblind_asset()?;
    Ok(ElementsUtxoData {
      utxo: UtxoData::from_descriptor(outpoint, amount, descriptor),
      asset: asset.clone(),
      value_commitment: ConfidentialValue::default(),
      asset_blind_factor: BlindFactor::default(),
      amount_blind_factor: BlindFactor::default(),
      option: ElementsUtxoOptionData::default(),
    })
  }

  /// Create object.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  /// * `asset` - A utxo asset.
  /// * `descriptor` - An output descriptor.
  /// * `scriptsig_template` - A script template for calculating script hash signed size.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ConfidentialAsset, Descriptor, Network, OutPoint, Script, ElementsUtxoData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  /// let descriptor = Descriptor::new(desc_str, &Network::ElementsRegtest).expect("Fail");
  /// let script = Script::default();
  /// let bytes = [2; 32];
  /// let asset = ConfidentialAsset::from_slice(&bytes).expect("Fail");
  /// let utxo = ElementsUtxoData::new(&outpoint, amount, &asset, &descriptor, &script);
  /// ```
  pub fn new(
    outpoint: &OutPoint,
    amount: i64,
    asset: &ConfidentialAsset,
    descriptor: &Descriptor,
    scriptsig_template: &Script,
  ) -> Result<ElementsUtxoData, CfdError> {
    asset.get_unblind_asset()?;
    Ok(ElementsUtxoData {
      utxo: UtxoData::new(outpoint, amount, descriptor, scriptsig_template),
      asset: asset.clone(),
      value_commitment: ConfidentialValue::default(),
      asset_blind_factor: BlindFactor::default(),
      amount_blind_factor: BlindFactor::default(),
      option: ElementsUtxoOptionData::default(),
    })
  }

  pub fn get_amount(&self) -> Amount {
    Amount::new(self.utxo.amount)
  }

  pub fn set_value_commitment(
    mut self,
    value_commitment: &ConfidentialValue,
  ) -> Result<ElementsUtxoData, CfdError> {
    if !value_commitment.is_blind() {
      return Err(CfdError::IllegalArgument(
        "it's not value commitment.".to_string(),
      ));
    }
    self.value_commitment = value_commitment.clone();
    Ok(self)
  }

  pub fn set_blinder(
    mut self,
    asset_blind_factor: &BlindFactor,
    amount_blind_factor: &BlindFactor,
  ) -> ElementsUtxoData {
    self.asset_blind_factor = asset_blind_factor.clone();
    self.amount_blind_factor = amount_blind_factor.clone();
    self
  }

  pub fn set_blind_info(
    mut self,
    value_commitment: &ConfidentialValue,
    asset_blind_factor: &BlindFactor,
    amount_blind_factor: &BlindFactor,
  ) -> Result<ElementsUtxoData, CfdError> {
    self.value_commitment = value_commitment.clone();
    self.asset_blind_factor = asset_blind_factor.clone();
    self.amount_blind_factor = amount_blind_factor.clone();
    if !asset_blind_factor.is_empty() || !amount_blind_factor.is_empty() {
      let asset_commitment = self.asset.get_commitment(&asset_blind_factor)?;
      let commitment = ConfidentialValue::get_commitment(
        self.utxo.amount,
        &asset_commitment,
        &amount_blind_factor,
      )?;
      if !value_commitment.eq(&commitment) {
        return Err(CfdError::IllegalArgument(
          "unmatch value commitment.".to_string(),
        ));
      }
    }
    Ok(self)
  }

  pub fn set_option_info(
    mut self,
    is_issuance: bool,
    is_blind_issuance: bool,
    is_pegin: bool,
    pegin_btc_tx_size: u32,
    fedpeg_script: &Script,
  ) -> ElementsUtxoData {
    let option = ElementsUtxoOptionData {
      is_issuance,
      is_blind_issuance,
      is_pegin,
      pegin_btc_tx_size,
      fedpeg_script: fedpeg_script.clone(),
    };
    self.option = option;
    self
  }
}

impl fmt::Display for ElementsUtxoData {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "utxo({}, asset: {})[", &self.utxo, self.asset)
  }
}

impl Default for ElementsUtxoData {
  fn default() -> ElementsUtxoData {
    ElementsUtxoData {
      utxo: UtxoData::default(),
      asset: ConfidentialAsset::default(),
      value_commitment: ConfidentialValue::default(),
      asset_blind_factor: BlindFactor::default(),
      amount_blind_factor: BlindFactor::default(),
      option: ElementsUtxoOptionData::default(),
    }
  }
}

/// A container that stores transaction output request data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialTxOutData {
  pub amount: i64,
  pub address: Address,
  pub confidential_address: ConfidentialAddress,
  pub locking_script: Script,
  pub asset: ConfidentialAsset,
  pub nonce: ConfidentialNonce,
}

impl ConfidentialTxOutData {
  pub fn from_address(
    amount: i64,
    asset: &ConfidentialAsset,
    address: &Address,
  ) -> ConfidentialTxOutData {
    ConfidentialTxOutData {
      amount,
      address: address.clone(),
      asset: asset.clone(),
      ..ConfidentialTxOutData::default()
    }
  }

  pub fn from_confidential_address(
    amount: i64,
    asset: &ConfidentialAsset,
    confidential_address: &ConfidentialAddress,
  ) -> ConfidentialTxOutData {
    ConfidentialTxOutData {
      amount,
      address: confidential_address.get_address().clone(),
      confidential_address: confidential_address.clone(),
      asset: asset.clone(),
      ..ConfidentialTxOutData::default()
    }
  }

  pub fn from_locking_script(
    amount: i64,
    asset: &ConfidentialAsset,
    locking_script: &Script,
    nonce: &ConfidentialNonce,
  ) -> ConfidentialTxOutData {
    ConfidentialTxOutData {
      amount,
      locking_script: locking_script.clone(),
      nonce: nonce.clone(),
      asset: asset.clone(),
      ..ConfidentialTxOutData::default()
    }
  }

  pub fn from_fee(amount: i64, asset: &ConfidentialAsset) -> ConfidentialTxOutData {
    ConfidentialTxOutData {
      amount,
      asset: asset.clone(),
      ..ConfidentialTxOutData::default()
    }
  }

  pub fn from_destroy_amount(
    amount: i64,
    asset: &ConfidentialAsset,
  ) -> Result<ConfidentialTxOutData, CfdError> {
    let data = ConfidentialTxOutData {
      amount,
      asset: asset.clone(),
      locking_script: Script::from_slice(&[0x6a])?,
      ..ConfidentialTxOutData::default()
    };
    Ok(data)
  }

  pub fn get_address_str(&self) -> &str {
    match self.confidential_address.valid() {
      true => self.confidential_address.to_str(),
      _ => self.address.to_str(),
    }
  }

  pub fn from_str(
    address: &str,
    asset: &ConfidentialAsset,
    amount: i64,
  ) -> Result<ConfidentialTxOutData, CfdError> {
    let mut txout = ConfidentialTxOutData {
      asset: asset.clone(),
      amount,
      ..ConfidentialTxOutData::default()
    };
    let ct_addr_ret = ConfidentialAddress::parse(address);
    if let Ok(ct_addr) = ct_addr_ret {
      txout.confidential_address = ct_addr;
    } else {
      let addr = Address::from_string(address)?;
      txout.address = addr;
    }
    Ok(txout)
  }
}

impl Default for ConfidentialTxOutData {
  fn default() -> ConfidentialTxOutData {
    ConfidentialTxOutData {
      amount: 0,
      address: Address::default(),
      confidential_address: ConfidentialAddress::default(),
      locking_script: Script::default(),
      asset: ConfidentialAsset::default(),
      nonce: ConfidentialNonce::default(),
    }
  }
}

/// A container that stores an issuance input data.
#[derive(PartialEq, Eq, Clone)]
pub struct IssuanceInputData {
  pub contract_hash: ByteData,
  pub asset_amount: i64,
  pub asset_address: InputAddress,
  pub asset_locking_script: Script,
  pub token_amount: i64,
  pub token_address: InputAddress,
  pub token_locking_script: Script,
  pub has_blind: bool,
}

impl Default for IssuanceInputData {
  fn default() -> IssuanceInputData {
    IssuanceInputData {
      contract_hash: ByteData::default(),
      asset_amount: 0,
      asset_address: InputAddress::Addr(Address::default()),
      asset_locking_script: Script::default(),
      token_amount: 0,
      token_address: InputAddress::Addr(Address::default()),
      token_locking_script: Script::default(),
      has_blind: false,
    }
  }
}

/// A container that stores a reissuance input data.
#[derive(PartialEq, Eq, Clone)]
pub struct ReissuanceInputData {
  pub blinding_nonce: BlindFactor,
  pub entropy: BlindFactor,
  pub asset_amount: i64,
  pub asset_address: InputAddress,
  pub asset_locking_script: Script,
}

impl Default for ReissuanceInputData {
  fn default() -> ReissuanceInputData {
    ReissuanceInputData {
      blinding_nonce: BlindFactor::default(),
      entropy: BlindFactor::default(),
      asset_amount: 0,
      asset_address: InputAddress::Addr(Address::default()),
      asset_locking_script: Script::default(),
    }
  }
}

/// A container that stores a issuance output data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IssuanceOutputData {
  pub entropy: BlindFactor,
  pub asset: ConfidentialAsset,
  pub token: ConfidentialAsset,
}

impl Default for IssuanceOutputData {
  fn default() -> IssuanceOutputData {
    IssuanceOutputData {
      entropy: BlindFactor::default(),
      asset: ConfidentialAsset::default(),
      token: ConfidentialAsset::default(),
    }
  }
}

/// A container that stores a pegin input data.
#[derive(PartialEq, Eq, Clone)]
pub struct PeginInputData {
  pub amount: i64,
  pub asset: ConfidentialAsset,
  pub mainchain_genesis_block_hash: BlockHash,
  pub claim_script: Script,
  pub transaction: Transaction,
  pub txout_proof: ByteData,
}

/// A container that stores a pegout input data.
#[derive(PartialEq, Eq, Clone)]
pub struct PegoutInputData {
  pub amount: i64,
  pub asset: ConfidentialAsset,
  pub mainchain_network_type: Network,
  pub elements_network_type: Network,
  pub mainchain_genesis_block_hash: BlockHash,
  pub online_privkey: Privkey,
  pub offline_output_descriptor: String,
  pub bip32_counter: u32,
  pub whitelist: ByteData,
}

/// A container that stores ConfidentialTransaction data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialTxData {
  pub tx_data: TxData,
  pub wit_hash: Txid,
}

impl Default for ConfidentialTxData {
  fn default() -> ConfidentialTxData {
    // default txid: version=2, locktime=0
    let txid_value =
      match Txid::from_str("c7e8a6e4ebd4981c43ff919703d54e91b4b3cb2325caf102dfc384bcad455c6f") {
        Ok(_txid) => _txid,
        _ => Txid::default(),
      };
    let wit_hash =
      match Txid::from_str("d8a93718eaf9feba4362d2c091d4e58ccabe9f779957336269b4b917be9856da") {
        Ok(_txid) => _txid,
        _ => Txid::default(),
      };
    ConfidentialTxData {
      tx_data: TxData {
        txid: txid_value.clone(),
        wtxid: txid_value,
        size: 11,
        vsize: 11,
        weight: 44,
        ..TxData::default()
      },
      wit_hash,
    }
  }
}

/// A container that stores unblinded data.
#[derive(PartialEq, Eq, Clone)]
pub struct UnblindData {
  pub asset: ConfidentialAsset,
  pub amount: ConfidentialValue,
  pub asset_blind_factor: BlindFactor,
  pub amount_blind_factor: BlindFactor,
}

impl Default for UnblindData {
  fn default() -> UnblindData {
    UnblindData {
      asset: ConfidentialAsset::default(),
      amount: ConfidentialValue::default(),
      asset_blind_factor: BlindFactor::default(),
      amount_blind_factor: BlindFactor::default(),
    }
  }
}

/// A container that stores unblinded issuance data.
#[derive(PartialEq, Eq, Clone)]
pub struct UnblindIssuanceData {
  pub asset_data: UnblindData,
  pub token_data: UnblindData,
}

impl Default for UnblindIssuanceData {
  fn default() -> UnblindIssuanceData {
    UnblindIssuanceData {
      asset_data: UnblindData::default(),
      token_data: UnblindData::default(),
    }
  }
}

/// A container that stores elements coin selection data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ElementsCoinSelectionData {
  pub select_utxo_list: Vec<ElementsUtxoData>,
  pub utxo_fee_amount: i64,
}

impl ElementsCoinSelectionData {
  pub fn new(
    select_utxo_list: Vec<ElementsUtxoData>,
    utxo_fee_amount: i64,
  ) -> ElementsCoinSelectionData {
    ElementsCoinSelectionData {
      select_utxo_list,
      utxo_fee_amount,
    }
  }

  pub fn get_total_amount(&self) -> i64 {
    let mut total = 0;
    for utxo in self.select_utxo_list.iter() {
      total += utxo.utxo.amount;
    }
    total
  }
}

impl Default for ElementsCoinSelectionData {
  fn default() -> ElementsCoinSelectionData {
    ElementsCoinSelectionData {
      select_utxo_list: vec![],
      utxo_fee_amount: 0,
    }
  }
}

/// A container that stores ConfidentialTransaction input issuance.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Issuance {
  pub asset_entropy: BlindFactor,
  pub asset_blinding_nonce: BlindFactor,
  pub asset_amount: ConfidentialValue,
  pub inflation_keys: ConfidentialValue,
  pub amount_range_proof: ByteData,
  pub inflation_keys_range_proof: ByteData,
}

impl Default for Issuance {
  fn default() -> Issuance {
    Issuance {
      asset_entropy: BlindFactor::default(),
      asset_blinding_nonce: BlindFactor::default(),
      asset_amount: ConfidentialValue::default(),
      inflation_keys: ConfidentialValue::default(),
      amount_range_proof: ByteData::default(),
      inflation_keys_range_proof: ByteData::default(),
    }
  }
}

/// A container that stores blind data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlindData {
  pub vout: u32,
  pub asset: ConfidentialAsset,
  pub amount: ConfidentialValue,
  pub asset_blind_factor: BlindFactor,
  pub amount_blind_factor: BlindFactor,
  pub issuance_outpoint: OutPoint,
  pub is_issuance_asset: bool,
  pub is_issuance_token: bool,
}

impl BlindData {
  pub fn new(
    vout: u32,
    data: &UnblindData,
    issuance_outpoint: &OutPoint,
    is_issuance_asset: bool,
    is_issuance_token: bool,
  ) -> BlindData {
    BlindData {
      vout,
      asset: data.asset.clone(),
      amount: data.amount.clone(),
      asset_blind_factor: data.asset_blind_factor.clone(),
      amount_blind_factor: data.amount_blind_factor.clone(),
      issuance_outpoint: issuance_outpoint.clone(),
      is_issuance_asset,
      is_issuance_token,
    }
  }

  pub fn is_issuance(&self) -> bool {
    self.is_issuance_asset || self.is_issuance_token
  }
}

impl Default for BlindData {
  fn default() -> BlindData {
    BlindData {
      vout: 0,
      asset: ConfidentialAsset::default(),
      amount: ConfidentialValue::default(),
      asset_blind_factor: BlindFactor::default(),
      amount_blind_factor: BlindFactor::default(),
      issuance_outpoint: OutPoint::default(),
      is_issuance_asset: false,
      is_issuance_token: false,
    }
  }
}

/// A container that stores ConfidentialTransaction input.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialTxIn {
  pub outpoint: OutPoint,
  pub sequence: u32,
  pub script_sig: Script,
  pub issuance: Issuance,
  pub script_witness: ScriptWitness,
  pub pegin_witness: ScriptWitness,
}

impl ConfidentialTxIn {
  pub fn from_data_list(list: &[TxInData]) -> Vec<ConfidentialTxIn> {
    let mut output: Vec<ConfidentialTxIn> = vec![];
    output.reserve(list.len());
    for item in list {
      output.push(ConfidentialTxIn {
        outpoint: item.outpoint.clone(),
        sequence: item.sequence,
        script_sig: item.script_sig.clone(),
        issuance: Issuance::default(),
        script_witness: ScriptWitness::default(),
        pegin_witness: ScriptWitness::default(),
      });
    }
    output
  }
}

impl Default for ConfidentialTxIn {
  fn default() -> ConfidentialTxIn {
    ConfidentialTxIn {
      outpoint: OutPoint::default(),
      sequence: SEQUENCE_LOCK_TIME_FINAL,
      script_sig: Script::default(),
      issuance: Issuance::default(),
      script_witness: ScriptWitness::default(),
      pegin_witness: ScriptWitness::default(),
    }
  }
}

/// A container that stores ConfidentialTransaction output.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialTxOut {
  pub locking_script: Script,
  pub asset: ConfidentialAsset,
  pub value: ConfidentialValue,
  pub nonce: ConfidentialNonce,
  pub range_proof: ByteData,
  pub surjection_proof: ByteData,
}

impl ConfidentialTxOut {
  pub fn from_data_list(list: &[ConfidentialTxOutData]) -> Vec<ConfidentialTxOut> {
    let mut output: Vec<ConfidentialTxOut> = vec![];
    output.reserve(list.len());
    for item in list {
      let script = if item.address.valid() {
        item.address.get_locking_script()
      } else {
        &item.locking_script
      };
      let mut txout = ConfidentialTxOut {
        locking_script: script.clone(),
        ..ConfidentialTxOut::default()
      };
      if let Ok(value) = ConfidentialValue::from_amount(item.amount) {
        txout.value = value;
      }
      output.push(txout);
    }
    output
  }
}

impl Default for ConfidentialTxOut {
  fn default() -> ConfidentialTxOut {
    ConfidentialTxOut {
      locking_script: Script::default(),
      asset: ConfidentialAsset::default(),
      value: ConfidentialValue::default(),
      nonce: ConfidentialNonce::default(),
      range_proof: ByteData::default(),
      surjection_proof: ByteData::default(),
    }
  }
}

/// A container that stores elements transaction.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfidentialTransaction {
  tx: Vec<u8>,
  data: ConfidentialTxData,
  txin_list: Vec<ConfidentialTxIn>,
  txout_list: Vec<ConfidentialTxOut>,
}

impl ConfidentialTransaction {
  pub fn to_str(&self) -> String {
    hex_from_bytes(&self.tx)
  }

  pub fn to_bytes(&self) -> &[u8] {
    &self.tx
  }

  pub fn to_slice(&self) -> &[u8] {
    &self.tx
  }

  pub fn as_txid(&self) -> &Txid {
    &self.data.tx_data.txid
  }

  pub fn get_info(&self) -> &ConfidentialTxData {
    &self.data
  }

  pub fn get_txin_list(&self) -> &[ConfidentialTxIn] {
    &self.txin_list
  }

  pub fn get_txout_list(&self) -> &[ConfidentialTxOut] {
    &self.txout_list
  }

  /// Create initial empty ConfidentialTransaction.
  ///
  /// # Arguments
  /// * `version` - A ConfidentialTransaction version.
  /// * `locktime` - A ConfidentialTransaction locktime.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ConfidentialTransaction;
  /// let tx = ConfidentialTransaction::new(2, 0).expect("Fail");
  /// ```
  pub fn new(version: u32, locktime: u32) -> Result<ConfidentialTransaction, CfdError> {
    ConfidentialTransaction::create_tx(version, locktime, &[], &[])
  }

  /// Get ConfidentialTransaction from bytes.
  ///
  /// # Arguments
  /// * `tx` - A ConfidentialTransaction byte array.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::ConfidentialTransaction;
  /// let tx = ConfidentialTransaction::new(2, 0).expect("Fail");
  /// let tx2 = ConfidentialTransaction::from_slice(tx.to_bytes()).expect("Fail");
  /// ```
  pub fn from_slice(tx: &[u8]) -> Result<ConfidentialTransaction, CfdError> {
    let hex = hex_from_bytes(tx);
    ConfidentialTransaction::from_str(&hex)
  }

  /// Create initial ConfidentialTransaction.
  ///
  /// # Arguments
  /// * `version` - A ConfidentialTransaction version.
  /// * `locktime` - A ConfidentialTransaction locktime.
  /// * `txin_list` - ConfidentialTransaction input list.
  /// * `txout_list` - ConfidentialTransaction output list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, OutPoint, ConfidentialAsset, ConfidentialTransaction, TxInData, ConfidentialTxOutData};
  /// use std::str::FromStr;
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("ex1qjex3wgf33j9u0vqk6r4exa9xyr5t3z5c7saq0d").expect("Fail");
  /// let asset = ConfidentialAsset::from_str("0202020202020202020202020202020202020202020202020202020202020202").expect("Fail");
  /// let txout_list = [ConfidentialTxOutData::from_address(amount, &asset, &addr)];
  /// let tx = ConfidentialTransaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// ```
  pub fn create_tx(
    version: u32,
    locktime: u32,
    txin_list: &[TxInData],
    txout_list: &[ConfidentialTxOutData],
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx = ope.create(version, locktime, txin_list, txout_list)?;
    let data = ope.get_tx_data(ope.get_last_tx())?;
    Ok(ConfidentialTransaction {
      tx,
      data,
      txin_list: ConfidentialTxIn::from_data_list(txin_list),
      txout_list: ConfidentialTxOut::from_data_list(txout_list),
    })
  }

  /// Append to ConfidentialTransaction.
  ///
  /// # Arguments
  /// * `txin_list` - ConfidentialTransaction input list.
  /// * `txout_list` - ConfidentialTransaction output list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, OutPoint, ConfidentialAsset, ConfidentialTransaction, TxInData, ConfidentialTxOutData};
  /// use std::str::FromStr;
  /// let tx = ConfidentialTransaction::new(2, 0).expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("ex1qjex3wgf33j9u0vqk6r4exa9xyr5t3z5c7saq0d").expect("Fail");
  /// let asset = ConfidentialAsset::from_str("0202020202020202020202020202020202020202020202020202020202020202").expect("Fail");
  /// let txout_list = [ConfidentialTxOutData::from_address(amount, &asset, &addr)];
  /// let tx2 = tx.append_data(&txin_list, &txout_list).expect("Fail");
  /// ```
  pub fn append_data(
    &self,
    txin_list: &[TxInData],
    txout_list: &[ConfidentialTxOutData],
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx = ope.update(&hex_from_bytes(&self.tx), txin_list, txout_list)?;
    let last_tx = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let data = ope2.get_all_data(last_tx)?;
    Ok(ConfidentialTransaction {
      tx,
      data,
      txin_list: ope2.get_txin_list_cache().to_vec(),
      txout_list: ope2.get_txout_list_cache().to_vec(),
    })
  }

  /// Update witness stack.
  ///
  /// # Arguments
  /// * `outpoint` - An outpoint.
  /// * `stack_index` - A witness stack index.
  /// * `data` - A witness stack data.
  pub fn update_witness_stack(
    &self,
    outpoint: &OutPoint,
    stack_index: u32,
    data: &ByteData,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx = ope.update_witness_stack(&hex_from_bytes(&self.tx), outpoint, stack_index, data)?;
    Ok(ConfidentialTransaction {
      tx,
      data: ope.get_last_tx_data().clone(),
      txin_list: ope.get_txin_list_cache().to_vec(),
      txout_list: self.txout_list.clone(),
      // txin_utxo_list: self.txin_utxo_list.clone(),
    })
  }

  /// Update pegin witness stack.
  ///
  /// # Arguments
  /// * `outpoint` - An outpoint.
  /// * `stack_index` - A pegin witness stack index.
  /// * `data` - A witness stack data.
  ///
  /// # Example
  pub fn update_pegin_witness_stack(
    &self,
    outpoint: &OutPoint,
    stack_index: u32,
    data: &ByteData,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx =
      ope.update_pegin_witness_stack(&hex_from_bytes(&self.tx), outpoint, stack_index, data)?;
    Ok(ConfidentialTransaction {
      tx,
      data: ope.get_last_tx_data().clone(),
      txin_list: ope.get_txin_list_cache().to_vec(),
      txout_list: self.txout_list.clone(),
      // txin_utxo_list: self.txin_utxo_list.clone(),
    })
  }

  /// Update amount.
  ///
  /// # Arguments
  /// * `index` - A txout index.
  /// * `amount` - A satoshi amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, OutPoint, ConfidentialAsset, ConfidentialTransaction, TxInData, ConfidentialTxOutData};
  /// use std::str::FromStr;
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("ex1qjex3wgf33j9u0vqk6r4exa9xyr5t3z5c7saq0d").expect("Fail");
  /// let asset = ConfidentialAsset::from_str("0202020202020202020202020202020202020202020202020202020202020202").expect("Fail");
  /// let txout_list = [ConfidentialTxOutData::from_address(amount, &asset, &addr)];
  /// let tx = ConfidentialTransaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// let tx2 = tx.update_amount(0, 60000).expect("Fail");
  /// ```
  pub fn update_amount(
    &self,
    index: u32,
    amount: i64,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx = ope.update_output_amount(&hex_from_bytes(&self.tx), index, amount)?;
    let data = ope.get_tx_data(ope.get_last_tx())?;
    let mut tx_obj = ConfidentialTransaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txout_list[index as usize].value = ConfidentialValue::from_amount(amount)?;
    Ok(tx_obj)
  }

  /// Update fee amount.
  ///
  /// # Arguments
  /// * `amount` - A satoshi amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, OutPoint, ConfidentialAsset, ConfidentialTransaction, TxInData, ConfidentialTxOutData};
  /// use std::str::FromStr;
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("ex1qjex3wgf33j9u0vqk6r4exa9xyr5t3z5c7saq0d").expect("Fail");
  /// let asset = ConfidentialAsset::from_str("0202020202020202020202020202020202020202020202020202020202020202").expect("Fail");
  /// let txout_list = [ConfidentialTxOutData::from_address(amount, &asset, &addr), ConfidentialTxOutData::from_fee(5000, &asset)];
  /// let tx = ConfidentialTransaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// let tx2 = tx.update_fee_amount(10000).expect("Fail");
  /// ```
  pub fn update_fee_amount(&self, amount: i64) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx = ope.update_fee_amount(&hex_from_bytes(&self.tx), amount)?;
    let index = ope.get_last_txout_index();
    let data = ope.get_tx_data(ope.get_last_tx())?;
    let mut tx_obj = ConfidentialTransaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txout_list[index as usize].value = ConfidentialValue::from_amount(amount)?;
    Ok(tx_obj)
  }

  /// Split txout.
  ///
  /// # Arguments
  /// * `index` - A txout index.
  /// * `txout_list` - txout list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{
  ///   Address, ConfidentialAsset, OutPoint, ConfidentialTransaction,
  ///   TxInData, ConfidentialTxOutData,
  /// };
  /// use std::str::FromStr;
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("ex1qjex3wgf33j9u0vqk6r4exa9xyr5t3z5c7saq0d").expect("Fail");
  /// let addr2 = Address::from_string("ex1qyewtv8juq97qyfcd0l3ctwsgsdnpdsgc4zmnkj").expect("Fail");
  /// let asset = ConfidentialAsset::from_str("0202020202020202020202020202020202020202020202020202020202020202").expect("Fail");
  /// let txout_list = [ConfidentialTxOutData::from_address(amount, &asset, &addr), ConfidentialTxOutData::from_fee(5000, &asset)];
  /// let split_txout_list = [ConfidentialTxOutData::from_address(10000, &asset, &addr2)];
  /// let tx = ConfidentialTransaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// let tx2 = tx.split_txout(0, &split_txout_list).expect("Fail");
  /// ```
  pub fn split_txout(
    &self,
    index: u32,
    txout_list: &[ConfidentialTxOutData],
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx = ope.split_txout(&hex_from_bytes(&self.tx), index, txout_list)?;
    let txout_list = ope.get_txout_list_cache();
    Ok(ConfidentialTransaction {
      tx,
      data: ope.get_last_tx_data().clone(),
      txin_list: self.txin_list.clone(),
      txout_list: txout_list.to_vec(),
      // txin_utxo_list: self.txin_utxo_list.clone(),
    })
  }

  /// Blind transaction.
  ///
  /// # Arguments
  /// * `utxos` - The utxo list.
  /// * `issuance_keys` - The utxo list.
  /// * `confidential_addresses` - The confidential address list. (for unset nonce)
  /// * `direct_confidential_key_list` - The confidential key list. (for unused confidential address)
  /// * `option` - A blinding option.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, BlindOption, ElementsUtxoData, IssuanceKeyMap, KeyIndexMap, OutPoint, ConfidentialAddress, ConfidentialAsset, ConfidentialTransaction, Pubkey, TxInData, ConfidentialTxOutData};
  /// use std::str::FromStr;
  /// let asset = ConfidentialAsset::from_str("0202020202020202020202020202020202020202020202020202020202020202").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount11: i64 = 50000;
  /// let amount21: i64 = 30000;
  /// let amount22: i64 = 15000;
  /// let amount23: i64 = 5000;
  /// let utxo1 = ElementsUtxoData::from_outpoint(&outpoint, amount11, &asset).expect("Fail");
  /// let txin_list = [TxInData::from_utxo(&utxo1.utxo)];
  /// let addr1 = Address::from_string("ex1q9jfn03582uzaer4dr4ptjc0lavhf4stedyyd8a").expect("Fail");
  /// let ct_key1 = Pubkey::from_str("03084316c0b2c90afa9242a5eb51f457b722ba08db4c19f9554c41d8cab5d907e4").expect("Fail");
  /// let addr2 = Address::from_string("ex1qyewtv8juq97qyfcd0l3ctwsgsdnpdsgc4zmnkj").expect("Fail");
  /// let ct_key2 = Pubkey::from_str("0304a3a881f2cd89e80b453879788155a6a7a71b60d262e23f9e94d67155282af6").expect("Fail");
  /// let txout_list = [ConfidentialTxOutData::from_address(amount21, &asset, &addr1), ConfidentialTxOutData::from_address(amount22, &asset, &addr2), ConfidentialTxOutData::from_fee(amount23, &asset)];
  /// let tx = ConfidentialTransaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// let ct_addr1 = ConfidentialAddress::new(&addr1, &ct_key1).expect("Fail");
  /// let ct_addr2 = ConfidentialAddress::new(&addr2, &ct_key2).expect("Fail");
  /// let ct_addr_list = [ct_addr1, ct_addr2];
  /// let option = BlindOption::default();
  /// let tx2 = tx.blind(
  ///   &[utxo1], &IssuanceKeyMap::default(), &ct_addr_list, &KeyIndexMap::default(), &option
  /// ).expect("Fail");
  /// ```
  pub fn blind(
    &self,
    utxos: &[ElementsUtxoData],
    issuance_keys: &IssuanceKeyMap,
    confidential_addresses: &[ConfidentialAddress],
    direct_confidential_key_list: &KeyIndexMap,
    option: &BlindOption,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let (tx, _, _) = ope.blind(
      &hex_from_bytes(&self.tx),
      utxos,
      issuance_keys,
      confidential_addresses,
      direct_confidential_key_list,
      option,
    )?;
    ConfidentialTransaction::from_slice(&tx)
  }

  /// Blind transaction.
  ///
  /// # Arguments
  /// * `utxos` - The utxo list.
  /// * `issuance_keys` - The utxo list.
  /// * `confidential_addresses` - The confidential address list. (for unset nonce)
  /// * `direct_confidential_key_list` - The confidential key list. (for unused confidential address)
  /// * `option` - A blinding option.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, BlindOption, ElementsUtxoData, IssuanceKeyMap, KeyIndexMap, OutPoint, ConfidentialAddress, ConfidentialAsset, ConfidentialTransaction, Pubkey, TxInData, ConfidentialTxOutData};
  /// use std::str::FromStr;
  /// let asset = ConfidentialAsset::from_str("0202020202020202020202020202020202020202020202020202020202020202").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount11: i64 = 50000;
  /// let amount21: i64 = 30000;
  /// let amount22: i64 = 15000;
  /// let amount23: i64 = 5000;
  /// let utxo1 = ElementsUtxoData::from_outpoint(&outpoint, amount11, &asset).expect("Fail");
  /// let txin_list = [TxInData::from_utxo(&utxo1.utxo)];
  /// let addr1 = Address::from_string("ex1q9jfn03582uzaer4dr4ptjc0lavhf4stedyyd8a").expect("Fail");
  /// let ct_key1 = Pubkey::from_str("03084316c0b2c90afa9242a5eb51f457b722ba08db4c19f9554c41d8cab5d907e4").expect("Fail");
  /// let addr2 = Address::from_string("ex1qyewtv8juq97qyfcd0l3ctwsgsdnpdsgc4zmnkj").expect("Fail");
  /// let ct_key2 = Pubkey::from_str("0304a3a881f2cd89e80b453879788155a6a7a71b60d262e23f9e94d67155282af6").expect("Fail");
  /// let txout_list = [ConfidentialTxOutData::from_address(amount21, &asset, &addr1), ConfidentialTxOutData::from_address(amount22, &asset, &addr2), ConfidentialTxOutData::from_fee(amount23, &asset)];
  /// let tx = ConfidentialTransaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// let ct_addr1 = ConfidentialAddress::new(&addr1, &ct_key1).expect("Fail");
  /// let ct_addr2 = ConfidentialAddress::new(&addr2, &ct_key2).expect("Fail");
  /// let ct_addr_list = [ct_addr1, ct_addr2];
  /// let option = BlindOption::default();
  /// let (tx2, blinder_list) = tx.blind_and_get_blinder(
  ///   &[utxo1], &IssuanceKeyMap::default(), &ct_addr_list, &KeyIndexMap::default(), &option
  /// ).expect("Fail");
  /// ```
  pub fn blind_and_get_blinder(
    &self,
    utxos: &[ElementsUtxoData],
    issuance_keys: &IssuanceKeyMap,
    confidential_addresses: &[ConfidentialAddress],
    direct_confidential_key_list: &KeyIndexMap,
    option: &BlindOption,
  ) -> Result<(ConfidentialTransaction, Vec<BlindData>), CfdError> {
    let mut opt = option.clone();
    opt.collect_blinder = true;
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let (tx, _, blinder) = ope.blind(
      &hex_from_bytes(&self.tx),
      utxos,
      issuance_keys,
      confidential_addresses,
      direct_confidential_key_list,
      &opt,
    )?;
    Ok((ConfidentialTransaction::from_slice(&tx)?, blinder))
  }

  /// Unblind transaction output.
  ///
  /// # Arguments
  /// * `index` - A transaction output index.
  /// * `blinding_key` - A blinding key.
  pub fn unblind_txout(&self, index: u32, blinding_key: &Privkey) -> Result<UnblindData, CfdError> {
    let ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    ope.unblind_txout(&hex_from_bytes(&self.tx), index, blinding_key)
  }

  /// Unblind transaction input issuance.
  ///
  /// # Arguments
  /// * `index` - A transaction input index.
  /// * `asset_blinding_key` - An asset blinding key.
  /// * `token_blinding_key` - A token blinding key.
  pub fn unblind_issuance(
    &self,
    index: u32,
    asset_blinding_key: &Privkey,
    token_blinding_key: &Privkey,
  ) -> Result<UnblindIssuanceData, CfdError> {
    let ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    ope.unblind_issuance(
      &hex_from_bytes(&self.tx),
      index,
      asset_blinding_key,
      token_blinding_key,
    )
  }

  /// Set issuance input and output.
  ///
  /// # Arguments
  /// * `outpoint` - An issuance outpoint.
  /// * `data` - A issuance input data.
  /// * `issuance_data` - (out) An issuance output data.
  pub fn set_issuance(
    &self,
    outpoint: &OutPoint,
    data: &IssuanceInputData,
    issuance_data: &mut IssuanceOutputData,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let out_data = ope.set_issuance(&hex_from_bytes(&self.tx), outpoint, data)?;
    *issuance_data = out_data;
    let tx = ope.get_last_tx();
    let tx_obj = ConfidentialTransaction {
      tx: byte_from_hex(tx)?,
      data: ope.get_last_tx_data().clone(),
      txin_list: ope.get_txin_list_cache().to_vec(),
      txout_list: ope.get_txout_list_cache().to_vec(),
    };
    Ok(tx_obj)
  }

  /// Set reissuance input and output.
  ///
  /// # Arguments
  /// * `outpoint` - An issuance outpoint.
  /// * `data` - A reissuance input data.
  /// * `output_data` - (out) An appended txout data.
  pub fn set_reissuance(
    &self,
    outpoint: &OutPoint,
    data: &ReissuanceInputData,
    output_data: &mut ConfidentialTxOutData,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let out_data = ope.set_reissuance(&hex_from_bytes(&self.tx), outpoint, data)?;
    *output_data = out_data;
    let tx = ope.get_last_tx();
    let tx_obj = ConfidentialTransaction {
      tx: byte_from_hex(tx)?,
      data: ope.get_last_tx_data().clone(),
      txin_list: ope.get_txin_list_cache().to_vec(),
      txout_list: ope.get_txout_list_cache().to_vec(),
    };
    Ok(tx_obj)
  }

  /// add pegin input.
  ///
  /// # Arguments
  /// * `outpoint` - An issuance outpoint.
  /// * `data` - A reissuance input data.
  /// * `output_data` - (out) An appended txout data.
  pub fn add_pegin_input(
    &self,
    outpoint: &OutPoint,
    data: &PeginInputData,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    ope.add_pegin_input(&hex_from_bytes(&self.tx), outpoint, data)?;
    Ok(ConfidentialTransaction {
      tx: byte_from_hex(ope.get_last_tx())?,
      data: ope.get_last_tx_data().clone(),
      txin_list: ope.get_txin_list_cache().to_vec(),
      txout_list: ope.get_txout_list_cache().to_vec(),
    })
  }

  /// add pegout output.
  ///
  /// # Arguments
  /// * `data` - A reissuance input data.
  /// * `output_data` - (out) An appended txout data.
  pub fn add_pegout_output(
    &self,
    data: &PegoutInputData,
    pegout_address: &mut Address,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let (tx_bytes, addr) = ope.add_pegout_output(&hex_from_bytes(&self.tx), data)?;
    *pegout_address = addr;
    Ok(ConfidentialTransaction {
      tx: tx_bytes,
      data: ope.get_last_tx_data().clone(),
      txin_list: ope.get_txin_list_cache().to_vec(),
      txout_list: ope.get_txout_list_cache().to_vec(),
    })
  }

  pub fn get_txin_index(&self, outpoint: &OutPoint) -> Result<u32, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    ope.get_txin_index_by_outpoint(&hex_from_bytes(&self.tx), outpoint)
  }

  pub fn get_txout_index_by_address(&self, address: &Address) -> Result<u32, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    ope.get_txout_index_by_address(&hex_from_bytes(&self.tx), address)
  }

  pub fn get_txout_index_by_script(&self, script: &Script) -> Result<u32, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    ope.get_txout_index_by_script(&hex_from_bytes(&self.tx), script)
  }

  pub fn get_txout_fee_index(&self) -> Result<u32, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    ope.get_txout_index_by_script(&hex_from_bytes(&self.tx), &Script::default())
  }

  pub fn get_txout_indexes_by_address(&self, address: &Address) -> Result<Vec<u32>, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    ope.get_txout_indexes_by_address(&hex_from_bytes(&self.tx), address)
  }

  pub fn get_txout_indexes_by_script(&self, script: &Script) -> Result<Vec<u32>, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    ope.get_txout_indexes_by_script(&hex_from_bytes(&self.tx), script)
  }

  /// Create signature hash by pubkey.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type. (pubkey hash only)
  /// * `pubkey` - A public key.
  /// * `sighash_type` - A ConfidentialTransaction input sighash-type.
  /// * `amount` - A ConfidentialTransaction input amount. (p2pkh is 0)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Pubkey, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash = tx.create_sighash_by_pubkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &pubkey,
  ///   &SigHashType::All,
  ///   &ConfidentialValue::from_amount(60000).expect("Fail")).expect("Fail");
  /// ```
  pub fn create_sighash_by_pubkey(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    sighash_type: &SigHashType,
    value: &ConfidentialValue,
  ) -> Result<Vec<u8>, CfdError> {
    let ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let option = SigHashOption {
      sighash_type: *sighash_type,
      amount: value.to_amount(),
      value_byte: match value.is_empty() {
        true => ByteData::default(),
        _ => value.as_byte_data(),
      },
      ..SigHashOption::default()
    };
    ope.create_sighash(
      &hex_from_bytes(&self.tx),
      outpoint,
      hash_type,
      pubkey,
      &Script::default(),
      &option,
    )
  }

  /// Create signature hash by redeem script.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type. (script hash only)
  /// * `redeem_script` - A redeem script.
  /// * `sighash_type` - A ConfidentialTransaction input sighash-type.
  /// * `amount` - A ConfidentialTransaction input amount. (p2pkh is 0)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Script, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash = tx.create_sighash_by_script(
  ///   &outpoint,
  ///   &HashType::P2wsh,
  ///   &script,
  ///   &SigHashType::All,
  ///   &ConfidentialValue::from_amount(60000).expect("Fail")).expect("Fail");
  /// ```
  pub fn create_sighash_by_script(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    redeem_script: &Script,
    sighash_type: &SigHashType,
    value: &ConfidentialValue,
  ) -> Result<Vec<u8>, CfdError> {
    let ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let option = SigHashOption {
      sighash_type: *sighash_type,
      amount: value.to_amount(),
      value_byte: match value.is_empty() {
        true => ByteData::default(),
        _ => value.as_byte_data(),
      },
      ..SigHashOption::default()
    };
    ope.create_sighash(
      &hex_from_bytes(&self.tx),
      outpoint,
      hash_type,
      &Pubkey::default(),
      redeem_script,
      &option,
    )
  }

  /// Add signature and pubkey into the ConfidentialTransaction.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type. (pubkey hash only)
  /// * `pubkey` - A public key using sign.
  /// * `signature` - A signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_pubkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &pubkey,
  ///   &sighash_type,
  ///   &ConfidentialValue::from_amount(60000).expect("Fail")).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type);
  /// let signed_tx = tx.add_pubkey_hash_sign(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &pubkey,
  ///   &signature,
  /// ).expect("Fail");
  /// ```
  pub fn add_pubkey_hash_sign(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    signature: &SignParameter,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::LiquidV1);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_pubkey_hash_sign(&tx_hex, outpoint, hash_type, pubkey, signature)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ConfidentialTxOperation::new(&Network::LiquidV1);
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = ConfidentialTransaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Sign with privkey.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type. (pubkey hash only)
  /// * `privkey` - A private key using sign.
  /// * `sighash_type` - A ConfidentialTransaction input sighash-type.
  /// * `amount` - A ConfidentialTransaction input amount. (p2pkh is 0)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let signed_tx = tx.sign_with_privkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &privkey,
  ///   &sighash_type,
  ///   &ConfidentialValue::from_amount(60000).expect("Fail")).expect("Fail");
  /// ```
  pub fn sign_with_privkey(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    privkey: &Privkey,
    sighash_type: &SigHashType,
    value: &ConfidentialValue,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx_hex = hex_from_bytes(&self.tx);
    let pubkey = privkey.get_pubkey()?;
    let key = KeyPair::new(privkey, &pubkey);
    let option = SigHashOption {
      sighash_type: *sighash_type,
      amount: value.to_amount(),
      value_byte: match value.is_empty() {
        true => ByteData::default(),
        _ => value.as_byte_data(),
      },
      ..SigHashOption::default()
    };
    let tx = ope.sign_with_privkey(&tx_hex, outpoint, hash_type, &key, &option, true)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = ConfidentialTransaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add multisig signatures and redeem script into the ConfidentialTransaction.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type. (script hash only)
  /// * `redeem_script` - A redeem script using sign.
  /// * `signature_list` - Multiple signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, Script, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_script(
  ///   &outpoint,
  ///   &HashType::P2wsh,
  ///   &script,
  ///   &sighash_type,
  ///   &ConfidentialValue::from_amount(60000).expect("Fail")).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type)
  ///   .set_related_pubkey(&pubkey);
  /// let signature_list = [signature];
  /// let signed_tx = tx.add_multisig_sign(
  ///   &outpoint,
  ///   &HashType::P2wsh,
  ///   &script,
  ///   &signature_list,
  /// ).expect("Fail");
  /// ```
  pub fn add_multisig_sign(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    redeem_script: &Script,
    signature_list: &[SignParameter],
  ) -> Result<ConfidentialTransaction, CfdError> {
    if signature_list.is_empty() {
      return Err(CfdError::IllegalArgument(
        "signature list is empty.".to_string(),
      ));
    }
    let mut ope = TransactionOperation::new(&Network::LiquidV1);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_multisig_sign(&tx_hex, outpoint, hash_type, redeem_script, signature_list)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ConfidentialTxOperation::new(&Network::LiquidV1);
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = ConfidentialTransaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add signature manually.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type.
  /// * `sign_data` - A signature or byte data.
  /// * `clear_stack` - Clear to already exist stack.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, SignParameter, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_pubkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &pubkey,
  ///   &sighash_type,
  ///   &ConfidentialValue::from_amount(60000).expect("Fail")).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type);
  /// let tx2 = tx.add_sign(&outpoint, &HashType::P2wpkh, &signature, true).expect("Fail");
  /// let pubkey_sign = SignParameter::from_slice(pubkey.to_slice());
  /// let signed_tx = tx2.add_sign(&outpoint, &HashType::P2wpkh, &pubkey_sign, false).expect("Fail");
  /// ```
  pub fn add_sign(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    sign_data: &SignParameter,
    clear_stack: bool,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::LiquidV1);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_sign(&tx_hex, outpoint, hash_type, sign_data, clear_stack)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ConfidentialTxOperation::new(&Network::LiquidV1);
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = ConfidentialTransaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add redeem script with sign.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type.
  /// * `sign_list` - A ConfidentialTransaction sign parameter list.
  /// * `redeem_script` - A redeem script.
  /// * `clear_stack` - Clear to already exist stack.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, Script, SignParameter, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_script(
  ///   &outpoint,
  ///   &HashType::P2wsh,
  ///   &script,
  ///   &sighash_type,
  ///   &ConfidentialValue::from_amount(60000).expect("Fail")).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type)
  ///   .set_related_pubkey(&pubkey);
  /// let empty_sig = SignParameter::from_slice(&[]);
  /// let tx2 = tx.add_sign(&outpoint, &HashType::P2wpkh, &empty_sig, true).expect("Fail");
  /// let tx3 = tx2.add_sign(&outpoint, &HashType::P2wpkh, &signature, false).expect("Fail");
  /// let signed_tx = tx3.add_script_hash_sign(&outpoint, &HashType::P2wsh, &[], &script, false).expect("Fail");
  /// ```
  pub fn add_script_hash_sign(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    sign_list: &[SignParameter],
    redeem_script: &Script,
    clear_stack: bool,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::LiquidV1);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_script_hash_sign(
      &tx_hex,
      outpoint,
      hash_type,
      sign_list,
      redeem_script,
      clear_stack,
    )?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ConfidentialTxOperation::new(&Network::LiquidV1);
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = ConfidentialTransaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Verify signature with pubkey.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type. (pubkey hash only)
  /// * `pubkey` - A public key using sign.
  /// * `signature` - A signature.
  /// * `value` - A ConfidentialTransaction input value.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let amount = ConfidentialValue::from_amount(60000).expect("Fail");
  /// let hash_type = HashType::P2wpkh;
  /// let sighash = tx.create_sighash_by_pubkey(&outpoint, &hash_type, &pubkey, &sighash_type, &amount).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// let verify = tx.verify_signature_by_pubkey(&outpoint, &hash_type, &pubkey, &signature, &amount).expect("Fail");
  /// ```
  pub fn verify_signature_by_pubkey(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    signature: &SignParameter,
    value: &ConfidentialValue,
  ) -> Result<bool, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    let option = SigHashOption {
      sighash_type: *signature.get_sighash_type(),
      amount: value.to_amount(),
      value_byte: match value.is_empty() {
        true => ByteData::default(),
        _ => value.as_byte_data(),
      },
      ..SigHashOption::default()
    };
    let key = HashTypeData::from_pubkey(pubkey);
    ope.verify_signature(
      &hex_from_bytes(&self.tx),
      outpoint,
      hash_type,
      signature,
      &key,
      &option,
    )
  }

  /// Verify signature with redeem script.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `hash_type` - A ConfidentialTransaction input hash type.
  /// * `pubkey` - A public key using sign.
  /// * `redeem_script` - A redeem script using locking script.
  /// * `signature` - A signature.
  /// * `value` - A ConfidentialTransaction input value.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, Script, SignParameter, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let hash_type = HashType::P2wsh;
  /// let amount = ConfidentialValue::from_amount(60000).expect("Fail");
  /// let sighash = tx.create_sighash_by_script(&outpoint, &hash_type, &script, &sighash_type, &amount).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_related_pubkey(&pubkey);
  /// let verify = tx.verify_signature_by_script(&outpoint, &hash_type, &pubkey, &script, &signature, &amount).expect("Fail");
  /// ```
  pub fn verify_signature_by_script(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    redeem_script: &Script,
    signature: &SignParameter,
    value: &ConfidentialValue,
  ) -> Result<bool, CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    let option = SigHashOption {
      sighash_type: *signature.get_sighash_type(),
      amount: value.to_amount(),
      value_byte: match value.is_empty() {
        true => ByteData::default(),
        _ => value.as_byte_data(),
      },
      ..SigHashOption::default()
    };
    let key = HashTypeData::new(pubkey, redeem_script);
    ope.verify_signature(
      &hex_from_bytes(&self.tx),
      outpoint,
      hash_type,
      signature,
      &key,
      &option,
    )
  }

  /// Verify sign with address.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `address` - A ConfidentialTransaction input address.
  /// * `value` - A ConfidentialTransaction input value.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, Amount, HashType, Network, OutPoint, Privkey, Pubkey, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let amount = ConfidentialValue::from_amount(60000).expect("Fail");
  /// let sighash = tx.create_sighash_by_pubkey(&outpoint, &HashType::P2wpkh, &pubkey, &sighash_type, &amount).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type);
  /// let signed_tx = tx.add_pubkey_hash_sign(&outpoint, &HashType::P2wpkh, &pubkey, &signature,
  /// ).expect("Fail");
  /// let addr = Address::p2wpkh(&pubkey, &Network::ElementsRegtest).expect("Fail");
  /// let is_verify = signed_tx.verify_sign_by_address(&outpoint, &addr, &amount).expect("Fail");
  /// ```
  pub fn verify_sign_by_address(
    &self,
    outpoint: &OutPoint,
    address: &Address,
    value: &ConfidentialValue,
  ) -> Result<(), CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    let option = SigHashOption {
      sighash_type: SigHashType::All,
      amount: value.to_amount(),
      value_byte: match value.is_empty() {
        true => ByteData::default(),
        _ => value.as_byte_data(),
      },
      ..SigHashOption::default()
    };
    ope.verify_sign(
      &hex_from_bytes(&self.tx),
      outpoint,
      address,
      address.get_address_type(),
      &Script::default(),
      &option,
    )
  }

  /// Verify sign with locking script.
  ///
  /// # Arguments
  /// * `outpoint` - A ConfidentialTransaction input out-point.
  /// * `locking_script` - A ConfidentialTransaction input locking script.
  /// * `hash_type` - A signed hash type.
  /// * `value` - A ConfidentialTransaction input value.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, Amount, HashType, Network, OutPoint, Privkey, Pubkey, SigHashType, ConfidentialTransaction, ConfidentialValue};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let amount = ConfidentialValue::from_amount(60000).expect("Fail");
  /// let sighash = tx.create_sighash_by_pubkey(&outpoint, &HashType::P2wpkh, &pubkey, &sighash_type, &amount).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type);
  /// let signed_tx = tx.add_pubkey_hash_sign(&outpoint, &HashType::P2wpkh, &pubkey, &signature,
  /// ).expect("Fail");
  /// let addr = Address::p2wpkh(&pubkey, &Network::ElementsRegtest).expect("Fail");
  /// let is_verify = signed_tx.verify_sign_by_script(&outpoint, addr.get_locking_script(), &addr.get_address_type().to_hash_type(), &amount).expect("Fail");
  /// ```
  pub fn verify_sign_by_script(
    &self,
    outpoint: &OutPoint,
    locking_script: &Script,
    hash_type: &HashType,
    value: &ConfidentialValue,
  ) -> Result<(), CfdError> {
    let ope = TransactionOperation::new(&Network::LiquidV1);
    let option = SigHashOption {
      sighash_type: SigHashType::All,
      amount: value.to_amount(),
      value_byte: match value.is_empty() {
        true => ByteData::default(),
        _ => value.as_byte_data(),
      },
      ..SigHashOption::default()
    };
    ope.verify_sign(
      &hex_from_bytes(&self.tx),
      outpoint,
      &Address::default(),
      &hash_type.to_address_type(),
      locking_script,
      &option,
    )
  }

  /// Estimate fee on the ConfidentialTransaction.
  ///
  /// # Arguments
  /// * `txin_list` - ConfidentialTransaction input utxo data.
  /// * `fee_rate` - A ConfidentialTransaction fee rate.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, Descriptor, Network, OutPoint, Pubkey, ConfidentialAsset, ConfidentialTransaction, ElementsUtxoData, FeeOption};
  /// use std::str::FromStr;
  /// let tx_str = "0200000000020a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff040100000000000000000000000000000000000000000000000000000000000000aa0100000000000007d000000100000000000000000000000000000000000000000000000000000000000000aa010000000000989680001600142c9337c6875705dc8ead1d42b961ffeb2e9ac1790100000000000000000000000000000000000000000000000000000000000000bb0100000000004c4b4000160014265cb61e5c017c02270d7fe385ba08836616c1180100000000000000000000000000000000000000000000000000000000000000bb0100000000002dc6c003e95214596e9291c6e596c324f62d84cfa5e48fb3383841c1dd7fefaa17ad640d160014964d1721318c8bc7b016d0eb9374a620e8b88a9800000000";
  /// let asset = ConfidentialAsset::from_str("aa00000000000000000000000000000000000000000000000000000000000000").expect("Fail");
  /// let asset2 = ConfidentialAsset::from_str("bb00000000000000000000000000000000000000000000000000000000000000").expect("Fail");
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint1 = OutPoint::from_str(
  ///   "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
  ///   0).expect("Fail");
  /// let outpoint2 = OutPoint::from_str(
  ///   "30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a",
  ///   0).expect("Fail");
  /// let descriptor = Descriptor::p2wpkh(&pubkey, &Network::LiquidV1).expect("Fail");
  /// let tx = ConfidentialTransaction::from_str(tx_str).expect("Fail");
  /// let utxo1 = ElementsUtxoData::from_descriptor(&outpoint1, 10002000, &asset, &descriptor).expect("Fail");
  /// let utxo2 = ElementsUtxoData::from_descriptor(&outpoint2, 8000000, &asset2, &descriptor).expect("Fail");
  /// let fee_rate = 0.11;
  /// let mut option = FeeOption::new(&Network::LiquidV1);
  /// option.fee_asset = asset.clone();
  /// let fee_data = tx.estimate_fee(&[utxo1, utxo2], fee_rate, &option).expect("Fee Fail");
  /// ```
  pub fn estimate_fee(
    &self,
    txin_list: &[ElementsUtxoData],
    fee_rate: f64,
    fee_param: &FeeOption,
  ) -> Result<FeeData, CfdError> {
    let ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    ope.estimate_fee(&hex_from_bytes(&self.tx), txin_list, fee_rate, fee_param)
  }

  /// Select utxo until target amount.
  ///
  /// # Arguments
  /// * `utxo_list` - Utxo data list.
  /// * `tx_fee_amount` - A ConfidentialTransaction fee amount.
  /// * `target_list` - A selection target list.
  /// * `fee_param` - A fee option parameter.
  pub fn select_coins(
    utxo_list: &[ElementsUtxoData],
    tx_fee_amount: i64,
    target_list: &[FundTargetOption],
    fee_param: &FeeOption,
  ) -> Result<ElementsCoinSelectionData, CfdError> {
    let ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    ope.select_coins(utxo_list, tx_fee_amount, target_list, fee_param)
  }

  /// Fund ConfidentialTransaction.
  ///
  /// # Arguments
  /// * `txin_list` - ConfidentialTransaction input utxo data list.
  /// * `utxo_list` - Utxo data list.
  /// * `target_list` - Selection target list.
  /// * `fee_param` - A fee option parameter.
  /// * `fund_data` - (output) A fund ConfidentialTransaction's response data.
  pub fn fund_raw_transaction(
    &self,
    txin_list: &[ElementsUtxoData],
    utxo_list: &[ElementsUtxoData],
    target_list: &[FundTargetOption],
    fee_param: &FeeOption,
    fund_data: &mut FundTransactionData,
  ) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let fund_result = ope.fund_raw_transaction(
      txin_list,
      utxo_list,
      &hex_from_bytes(&self.tx),
      target_list,
      fee_param,
    )?;
    let tx = ope.get_last_tx();
    let tx_obj = ConfidentialTransaction::from_str(tx)?;
    *fund_data = fund_result;
    Ok(tx_obj)
  }
}

impl FromStr for ConfidentialTransaction {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<ConfidentialTransaction, CfdError> {
    let mut ope = ConfidentialTxOperation::new(&Network::LiquidV1);
    let tx = ope.update(text, &[], &[])?;
    // let last_tx = ope.get_last_tx();
    // let mut ope2 = ope.clone();
    let data = ope.get_all_data(text)?;
    Ok(ConfidentialTransaction {
      tx,
      data,
      txin_list: ope.get_txin_list_cache().to_vec(),
      txout_list: ope.get_txout_list_cache().to_vec(),
    })
  }
}

impl Default for ConfidentialTransaction {
  fn default() -> ConfidentialTransaction {
    ConfidentialTransaction {
      tx: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec(),
      data: ConfidentialTxData::default(),
      txin_list: vec![],
      txout_list: vec![],
    }
  }
}

/// A container that operating ConfidentialTransaction base.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate) struct ConfidentialTxOperation {
  network: Network,
  last_tx: String,
  txin_list: Vec<ConfidentialTxIn>,
  txout_list: Vec<ConfidentialTxOut>,
  tx_data: ConfidentialTxData,
  last_txin_index: u32,
  last_txout_index: u32,
}

impl ConfidentialTxOperation {
  pub fn new(network: &Network) -> ConfidentialTxOperation {
    if !network.is_elements() {
      panic!("invalid network type.");
    }
    ConfidentialTxOperation {
      network: *network,
      last_tx: String::default(),
      txin_list: vec![],
      txout_list: vec![],
      tx_data: ConfidentialTxData::default(),
      last_txin_index: 0,
      last_txout_index: 0,
    }
  }

  pub fn get_last_tx(&self) -> &str {
    &self.last_tx
  }

  pub fn get_last_tx_data(&self) -> &ConfidentialTxData {
    &self.tx_data
  }

  pub fn get_last_txin_index(&self) -> u32 {
    self.last_txin_index
  }

  pub fn get_last_txout_index(&self) -> u32 {
    self.last_txout_index
  }

  pub fn blind(
    &mut self,
    tx: &str,
    utxos: &[ElementsUtxoData],
    issuance_keys: &IssuanceKeyMap,
    confidential_addresses: &[ConfidentialAddress],
    direct_confidential_key_list: &KeyIndexMap,
    option: &BlindOption,
  ) -> Result<(Vec<u8>, &String, Vec<BlindData>), CfdError> {
    // set_blind_tx_option
    let tx_str = alloc_c_string(tx)?;
    let empty_str = alloc_c_string("")?;
    let mut handle = ErrorHandle::new()?;
    let mut blind_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe { CfdInitializeBlindTx(handle.as_handle(), &mut blind_handle) };
    let result = match error_code {
      0 => {
        let ret = {
          for utxo in utxos {
            let _ret = {
              let mut asset_key = empty_str.clone();
              let mut token_key = empty_str.clone();
              let issuance_data = issuance_keys.get_value(&utxo.utxo.outpoint);
              if let Some(item) = issuance_data {
                if item.asset_blinding_key.valid() {
                  asset_key = alloc_c_string(&item.asset_blinding_key.to_hex())?;
                }
                if item.token_blinding_key.valid() {
                  token_key = alloc_c_string(&item.token_blinding_key.to_hex())?;
                }
              }
              let txid = alloc_c_string(&utxo.utxo.outpoint.get_txid().to_hex())?;
              let asset = alloc_c_string(&utxo.asset.get_unblind_asset()?)?;
              let abf = alloc_c_string(&utxo.asset_blind_factor.to_hex())?;
              let vbf = alloc_c_string(&utxo.amount_blind_factor.to_hex())?;
              let error_code = unsafe {
                CfdAddBlindTxInData(
                  handle.as_handle(),
                  blind_handle,
                  txid.as_ptr(),
                  utxo.utxo.outpoint.get_vout(),
                  asset.as_ptr(),
                  abf.as_ptr(),
                  vbf.as_ptr(),
                  utxo.utxo.amount,
                  asset_key.as_ptr(),
                  token_key.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          for ct_addr in confidential_addresses.iter() {
            let _ret = {
              let addr = alloc_c_string(&ct_addr.to_str())?;
              let error_code = unsafe {
                CfdAddBlindTxOutByAddress(handle.as_handle(), blind_handle, addr.as_ptr())
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          for index in direct_confidential_key_list.get_index_list() {
            let _ret = {
              let key = direct_confidential_key_list.get_value(index);
              let key_str = match key {
                Some(ct_key) => alloc_c_string(&ct_key.to_hex()),
                _ => alloc_c_string(""),
              }?;
              let error_code = unsafe {
                CfdAddBlindTxOutData(handle.as_handle(), blind_handle, index, key_str.as_ptr())
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          set_blind_tx_option(
            &handle,
            blind_handle,
            BLIND_OPT_MINIMUM_RANGE_VALUE,
            option.minimum_range_value,
          )?;
          set_blind_tx_option(
            &handle,
            blind_handle,
            BLIND_OPT_EXPONENT,
            option.exponent as i64,
          )?;
          set_blind_tx_option(
            &handle,
            blind_handle,
            BLIND_OPT_MINIMUM_BITS,
            option.minimum_bits as i64,
          )?;
          let collect_blinder = if option.collect_blinder { 1 } else { 0 };
          set_blind_tx_option(
            &handle,
            blind_handle,
            BLIND_OPT_COLLECT_BLINDER,
            collect_blinder as i64,
          )?;
          let mut output: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdFinalizeBlindTx(
              handle.as_handle(),
              blind_handle,
              tx_str.as_ptr(),
              &mut output,
            )
          };
          let mut result = match error_code {
            0 => {
              let output_tx = unsafe { collect_cstring_and_free(output) }?;
              self.last_tx = output_tx;
              Ok((byte_from_hex(&self.last_tx)?, &self.last_tx, vec![]))
            }
            _ => Err(handle.get_error(error_code)),
          }?;

          if option.collect_blinder {
            let mut blinder_list: Vec<BlindData> = vec![];
            let mut index: u32 = 0;
            while index < 0xffffffff {
              let data = {
                let mut vout: c_uint = 0;
                let mut asset: *mut c_char = ptr::null_mut();
                let mut value: c_longlong = 0;
                let mut asset_blinder: *mut c_char = ptr::null_mut();
                let mut value_blinder: *mut c_char = ptr::null_mut();
                let mut issuance_txid: *mut c_char = ptr::null_mut();
                let mut issuance_vout: u32 = 0;
                let mut is_issuance_asset = false;
                let mut is_issuance_token = false;
                let error_code = unsafe {
                  CfdGetBlindTxBlindData(
                    handle.as_handle(),
                    blind_handle,
                    index,
                    &mut vout,
                    &mut asset,
                    &mut value,
                    &mut asset_blinder,
                    &mut value_blinder,
                    &mut issuance_txid,
                    &mut issuance_vout,
                    &mut is_issuance_asset,
                    &mut is_issuance_token,
                  )
                };
                match error_code {
                  0 => {
                    let str_list = unsafe {
                      collect_multi_cstring_and_free(&[
                        asset,
                        asset_blinder,
                        value_blinder,
                        issuance_txid,
                      ])
                    }?;
                    let data = UnblindData {
                      asset: ConfidentialAsset::from_str(&str_list[0])?,
                      amount: ConfidentialValue::from_amount(value)?,
                      asset_blind_factor: BlindFactor::from_str(&str_list[1])?,
                      amount_blind_factor: BlindFactor::from_str(&str_list[2])?,
                    };
                    let issuance_outpoint = match str_list[3].len() {
                      64 => OutPoint::new(&Txid::from_str(&str_list[3])?, issuance_vout),
                      _ => OutPoint::default(),
                    };
                    Ok(BlindData::new(
                      vout,
                      &data,
                      &issuance_outpoint,
                      is_issuance_asset,
                      is_issuance_token,
                    ))
                  }
                  3 => {
                    // out of range error
                    index = 0xffffffff;
                    Ok(BlindData::default())
                  }
                  _ => Err(handle.get_error(error_code)),
                }
              }?;
              if index < 0xffffffff {
                blinder_list.push(data);
                index += 1;
              }
            }
            let (tx, tx_hex, _) = result;
            result = (tx, tx_hex, blinder_list);
          }
          Ok(result)
        };
        unsafe { CfdFreeBlindHandle(handle.as_handle(), blind_handle) };
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn unblind_txout(
    &self,
    tx: &str,
    index: u32,
    blinding_key: &Privkey,
  ) -> Result<UnblindData, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let privkey = alloc_c_string(&blinding_key.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut asset_value: c_longlong = 0;
    let mut asset: *mut c_char = ptr::null_mut();
    let mut asset_abf: *mut c_char = ptr::null_mut();
    let mut asset_vbf: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdUnblindTxOut(
        handle.as_handle(),
        tx_str.as_ptr(),
        index,
        privkey.as_ptr(),
        &mut asset,
        &mut asset_value,
        &mut asset_abf,
        &mut asset_vbf,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[asset, asset_abf, asset_vbf]) }?;
        let data = UnblindData {
          asset: ConfidentialAsset::from_str(&str_list[0])?,
          amount: ConfidentialValue::from_amount(asset_value)?,
          asset_blind_factor: BlindFactor::from_str(&str_list[1])?,
          amount_blind_factor: BlindFactor::from_str(&str_list[2])?,
        };
        Ok(data)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn unblind_issuance(
    &self,
    tx: &str,
    index: u32,
    asset_blinding_key: &Privkey,
    token_blinding_key: &Privkey,
  ) -> Result<UnblindIssuanceData, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let asset_key = alloc_c_string(&asset_blinding_key.to_hex())?;
    let token_key = alloc_c_string(&token_blinding_key.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut asset_value: c_longlong = 0;
    let mut token_value: c_longlong = 0;
    let mut asset: *mut c_char = ptr::null_mut();
    let mut asset_abf: *mut c_char = ptr::null_mut();
    let mut asset_vbf: *mut c_char = ptr::null_mut();
    let mut token: *mut c_char = ptr::null_mut();
    let mut token_abf: *mut c_char = ptr::null_mut();
    let mut token_vbf: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdUnblindIssuance(
        handle.as_handle(),
        tx_str.as_ptr(),
        index,
        asset_key.as_ptr(),
        token_key.as_ptr(),
        &mut asset,
        &mut asset_value,
        &mut asset_abf,
        &mut asset_vbf,
        &mut token,
        &mut token_value,
        &mut token_abf,
        &mut token_vbf,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe {
          collect_multi_cstring_and_free(&[
            asset, asset_abf, asset_vbf, token, token_abf, token_vbf,
          ])
        }?;
        let data = UnblindIssuanceData {
          asset_data: UnblindData {
            asset: ConfidentialAsset::from_str(&str_list[0])?,
            amount: ConfidentialValue::from_amount(asset_value)?,
            asset_blind_factor: BlindFactor::from_str(&str_list[1])?,
            amount_blind_factor: BlindFactor::from_str(&str_list[2])?,
          },
          token_data: UnblindData {
            asset: ConfidentialAsset::from_str(&str_list[3])?,
            amount: ConfidentialValue::from_amount(token_value)?,
            asset_blind_factor: BlindFactor::from_str(&str_list[4])?,
            amount_blind_factor: BlindFactor::from_str(&str_list[5])?,
          },
        };
        Ok(data)
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn set_issuance(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    data: &IssuanceInputData,
  ) -> Result<IssuanceOutputData, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let tx_result = {
        let output = self.set_issuance_internal(&handle, &tx_handle, outpoint, data)?;
        self.tx_data = self.get_all_data_internal(&handle, &tx_handle, &String::default())?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())?;
        Ok(output)
      };
      tx_handle.free_handle(&handle);
      tx_result
    };
    handle.free_handle();
    result
  }

  pub fn set_issuance_internal(
    &mut self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    outpoint: &OutPoint,
    data: &IssuanceInputData,
  ) -> Result<IssuanceOutputData, CfdError> {
    let asset_addr_str = match &data.asset_address {
      InputAddress::Addr(address) => address.to_str().to_string(),
      InputAddress::CtAddr(address) => address.to_str().to_string(),
    };
    let token_addr_str = match &data.token_address {
      InputAddress::Addr(address) => address.to_str().to_string(),
      InputAddress::CtAddr(address) => address.to_str().to_string(),
    };
    let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
    let contract_hash = alloc_c_string(&data.contract_hash.to_hex())?;
    let asset_address = alloc_c_string(&asset_addr_str)?;
    let asset_script = alloc_c_string(&data.asset_locking_script.to_hex())?;
    let token_address = alloc_c_string(&token_addr_str)?;
    let token_script = alloc_c_string(&data.token_locking_script.to_hex())?;
    let mut entropy: *mut c_char = ptr::null_mut();
    let mut asset: *mut c_char = ptr::null_mut();
    let mut token: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdSetIssueAsset(
        handle.as_handle(),
        tx_handle.as_handle(),
        txid.as_ptr(),
        outpoint.get_vout(),
        contract_hash.as_ptr(),
        data.asset_amount,
        asset_address.as_ptr(),
        asset_script.as_ptr(),
        data.token_amount,
        token_address.as_ptr(),
        token_script.as_ptr(),
        data.has_blind,
        &mut entropy,
        &mut asset,
        &mut token,
      )
    };
    match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[entropy, asset, token]) }?;
        let entropy_obj = BlindFactor::from_str(&str_list[0])?;
        let asset_obj = ConfidentialAsset::from_str(&str_list[1])?;
        let token_obj = ConfidentialAsset::from_str(&str_list[2])?;
        Ok(IssuanceOutputData {
          entropy: entropy_obj,
          asset: asset_obj,
          token: token_obj,
        })
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub fn set_reissuance(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    data: &ReissuanceInputData,
  ) -> Result<ConfidentialTxOutData, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let tx_result = {
        let output = self.set_reissuance_internal(&handle, &tx_handle, outpoint, data)?;
        self.tx_data = self.get_all_data_internal(&handle, &tx_handle, &String::default())?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())?;
        Ok(output)
      };
      tx_handle.free_handle(&handle);
      tx_result
    };
    handle.free_handle();
    result
  }

  pub fn set_reissuance_internal(
    &mut self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    outpoint: &OutPoint,
    data: &ReissuanceInputData,
  ) -> Result<ConfidentialTxOutData, CfdError> {
    let asset_addr_str = match &data.asset_address {
      InputAddress::Addr(address) => address.to_str().to_string(),
      InputAddress::CtAddr(address) => address.to_str().to_string(),
    };
    let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
    let nonce = alloc_c_string(&data.blinding_nonce.to_hex())?;
    let entropy_hex = alloc_c_string(&data.entropy.to_hex())?;
    let address = alloc_c_string(&asset_addr_str)?;
    let script = alloc_c_string(&data.asset_locking_script.to_hex())?;
    let mut asset: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdSetReissueAsset(
        handle.as_handle(),
        tx_handle.as_handle(),
        txid.as_ptr(),
        outpoint.get_vout(),
        data.asset_amount,
        nonce.as_ptr(),
        entropy_hex.as_ptr(),
        address.as_ptr(),
        script.as_ptr(),
        &mut asset,
      )
    };
    match error_code {
      0 => {
        let asset_str = unsafe { collect_cstring_and_free(asset) }?;
        let asset_obj = ConfidentialAsset::from_str(&asset_str)?;
        ConfidentialTxOutData::from_str(&asset_addr_str, &asset_obj, data.asset_amount)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub fn add_pegin_input(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    data: &PeginInputData,
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let tx_result = {
        self.add_pegin_input_internal(&handle, &tx_handle, outpoint, data)?;
        self.tx_data = self.get_all_data_internal(&handle, &tx_handle, &String::default())?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())
      };
      tx_handle.free_handle(&handle);
      tx_result
    };
    handle.free_handle();
    result
  }

  pub fn add_pegin_input_internal(
    &mut self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    outpoint: &OutPoint,
    data: &PeginInputData,
  ) -> Result<(), CfdError> {
    let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
    let asset = alloc_c_string(&data.asset.to_hex())?;
    let block_hash = alloc_c_string(&data.mainchain_genesis_block_hash.to_hex())?;
    let script = alloc_c_string(&data.claim_script.to_hex())?;
    let tx = alloc_c_string(&data.transaction.to_str())?;
    let txout_proof = alloc_c_string(&data.txout_proof.to_hex())?;
    let error_code = unsafe {
      CfdAddTxPeginInput(
        handle.as_handle(),
        tx_handle.as_handle(),
        txid.as_ptr(),
        outpoint.get_vout(),
        data.amount,
        asset.as_ptr(),
        block_hash.as_ptr(),
        script.as_ptr(),
        tx.as_ptr(),
        txout_proof.as_ptr(),
      )
    };
    match error_code {
      0 => Ok(()),
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub fn add_pegout_output(
    &mut self,
    tx: &str,
    data: &PegoutInputData,
  ) -> Result<(Vec<u8>, Address), CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let tx_result = {
        let addr = self.add_pegout_output_internal(&handle, &tx_handle, data)?;
        self.tx_data = self.get_all_data_internal(&handle, &tx_handle, &String::default())?;
        let tx_bytes = self.get_tx_internal(&handle, &tx_handle, &String::default())?;
        Ok((tx_bytes, addr))
      };
      tx_handle.free_handle(&handle);
      tx_result
    };
    handle.free_handle();
    result
  }

  pub fn add_pegout_output_internal(
    &mut self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    data: &PegoutInputData,
  ) -> Result<Address, CfdError> {
    let online_pubkey_obj = data.online_privkey.get_pubkey()?;
    let asset = alloc_c_string(&data.asset.to_hex())?;
    let online_key = alloc_c_string(&data.online_privkey.to_hex())?;
    let online_pubkey = alloc_c_string(&online_pubkey_obj.to_hex())?;
    let genesis_block_hash = alloc_c_string(&data.mainchain_genesis_block_hash.to_hex())?;
    let descriptor = alloc_c_string(&data.offline_output_descriptor)?;
    let whitelist = alloc_c_string(&data.whitelist.to_hex())?;
    let mut address: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdAddTxPegoutOutput(
        handle.as_handle(),
        tx_handle.as_handle(),
        asset.as_ptr(),
        data.amount,
        data.mainchain_network_type.to_c_value(),
        data.elements_network_type.to_c_value(),
        genesis_block_hash.as_ptr(),
        online_pubkey.as_ptr(),
        online_key.as_ptr(),
        descriptor.as_ptr(),
        data.bip32_counter,
        whitelist.as_ptr(),
        &mut address,
      )
    };
    match error_code {
      0 => {
        let addr_str = unsafe { collect_cstring_and_free(address) }?;
        Address::from_str(&addr_str)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub fn create(
    &mut self,
    version: u32,
    locktime: u32,
    txin_list: &[TxInData],
    txout_list: &[ConfidentialTxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    self.create_tx(version, locktime, "", txin_list, txout_list)
  }

  pub fn update(
    &mut self,
    tx: &str,
    txin_list: &[TxInData],
    txout_list: &[ConfidentialTxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    self.create_tx(0, 0, tx, txin_list, txout_list)
  }

  pub fn update_witness_stack(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    stack_index: u32,
    data: &ByteData,
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let tx_result = {
        TransactionOperation::update_witness_stack_internal(
          &CreateTxData::new(&self.network),
          &handle,
          &tx_handle,
          0,
          outpoint,
          stack_index,
          data,
        )?;
        self.get_txin_by_outpoint_internal(&handle, &tx_handle, &String::default(), outpoint)?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())
      }?;
      tx_handle.free_handle(&handle);
      tx_result
    };
    handle.free_handle();
    Ok(result)
  }

  pub fn update_pegin_witness_stack(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    stack_index: u32,
    data: &ByteData,
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let tx_result = {
        TransactionOperation::update_witness_stack_internal(
          &CreateTxData::new(&self.network),
          &handle,
          &tx_handle,
          1,
          outpoint,
          stack_index,
          data,
        )?;
        self.get_txin_by_outpoint_internal(&handle, &tx_handle, &String::default(), outpoint)?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())
      }?;
      tx_handle.free_handle(&handle);
      tx_result
    };
    handle.free_handle();
    Ok(result)
  }

  pub fn update_output_amount(
    &mut self,
    tx: &str,
    index: u32,
    amount: i64,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let mut handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdUpdateTxOutAmount(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        index,
        amount,
        &mut output,
      )
    };
    let result = match error_code {
      0 => {
        let output_obj = unsafe { collect_cstring_and_free(output) }?;
        self.last_tx = output_obj;
        Ok(byte_from_hex_unsafe(&self.last_tx))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn update_fee_amount(&mut self, tx: &str, amount: i64) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let mut handle = ErrorHandle::new()?;
    let result = {
      let index = {
        let mut index: c_uint = 0;
        let empty_str = alloc_c_string("")?;
        let error_code = unsafe {
          CfdGetTxOutIndex(
            handle.as_handle(),
            self.network.to_c_value(),
            tx_str.as_ptr(),
            empty_str.as_ptr(),
            empty_str.as_ptr(),
            &mut index,
          )
        };
        match error_code {
          0 => Ok(index),
          _ => Err(handle.get_error(error_code)),
        }
      }?;
      let mut output: *mut c_char = ptr::null_mut();
      let error_code = unsafe {
        CfdUpdateTxOutAmount(
          handle.as_handle(),
          self.network.to_c_value(),
          tx_str.as_ptr(),
          index,
          amount,
          &mut output,
        )
      };
      match error_code {
        0 => {
          let output_obj = unsafe { collect_cstring_and_free(output) }?;
          self.last_tx = output_obj;
          self.last_txout_index = index;
          Ok(byte_from_hex_unsafe(&self.last_tx))
        }
        _ => Err(handle.get_error(error_code)),
      }
    };
    handle.free_handle();
    result
  }

  pub fn split_txout(
    &mut self,
    tx: &str,
    index: u32,
    txout_list: &[ConfidentialTxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let split_result = {
        TransactionOperation::split_txout_internal(
          &self.network,
          &handle,
          &tx_handle,
          &String::default(),
          index,
          &txout_list,
        )?;
        self.tx_data = self.get_all_data_internal(&handle, &tx_handle, &String::default())?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())
      }?;
      tx_handle.free_handle(&handle);
      split_result
    };
    handle.free_handle();
    Ok(result)
  }

  pub fn get_all_data(&mut self, tx: &str) -> Result<ConfidentialTxData, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let tx_result = self.get_all_data_internal(&handle, &tx_handle, &String::default());
      tx_handle.free_handle(&handle);
      tx_result
    };
    handle.free_handle();
    result
  }

  fn get_all_data_internal(
    &mut self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
  ) -> Result<ConfidentialTxData, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let result = {
      let data = self.get_tx_data_internal(&handle, &tx_handle, tx)?;
      let in_count =
        TransactionOperation::get_count_internal(&self.network, &handle, &tx_handle, tx, true)?;
      let out_count =
        TransactionOperation::get_count_internal(&self.network, &handle, &tx_handle, tx, false)?;
      let in_indexes = ConfidentialTxOperation::create_index_list(in_count);
      let out_indexes = ConfidentialTxOperation::create_index_list(out_count);
      let in_data = self.get_tx_input_list_internal(&handle, &tx_handle, tx, &in_indexes)?;
      let out_data = self.get_tx_output_list_internal(&handle, &tx_handle, tx, &out_indexes)?;
      self.txin_list = in_data;
      self.txout_list = out_data;
      Ok(data)
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  fn create_index_list(index_count: u32) -> Vec<u32> {
    let mut indexes: Vec<u32> = vec![];
    if index_count == 0 {
      return indexes;
    }
    indexes.reserve(index_count as usize);
    let mut index = 0;
    while index < index_count {
      indexes.push(index);
      index += 1;
    }
    indexes
  }

  pub fn get_txin_list_cache(&self) -> &[ConfidentialTxIn] {
    &self.txin_list
  }
  pub fn get_txout_list_cache(&self) -> &[ConfidentialTxOut] {
    &self.txout_list
  }

  fn get_tx_internal(
    &mut self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let mut output: *mut c_char = ptr::null_mut();
    let result = {
      let error_code = unsafe {
        CfdFinalizeTransaction(handle.as_handle(), tx_data_handle.as_handle(), &mut output)
      };
      match error_code {
        0 => {
          let output_obj = unsafe { collect_cstring_and_free(output) }?;
          self.last_tx = output_obj;
          Ok(byte_from_hex_unsafe(&self.last_tx))
        }
        _ => Err(handle.get_error(error_code)),
      }
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  pub fn get_tx_data(&self, tx: &str) -> Result<ConfidentialTxData, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = self.get_tx_data_internal(&handle, &TxDataHandle::empty(), tx);
    handle.free_handle();
    result
  }

  pub fn get_tx_data_internal(
    &self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
  ) -> Result<ConfidentialTxData, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let mut data = ConfidentialTxData::default();
    let mut txid: *mut c_char = ptr::null_mut();
    let mut wtxid: *mut c_char = ptr::null_mut();
    let mut wit_hash: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetConfidentialTxInfoByHandle(
        handle.as_handle(),
        tx_data_handle.as_handle(),
        &mut txid,
        &mut wtxid,
        &mut wit_hash,
        &mut data.tx_data.size,
        &mut data.tx_data.vsize,
        &mut data.tx_data.weight,
        &mut data.tx_data.version,
        &mut data.tx_data.locktime,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[txid, wtxid, wit_hash]) }?;
        let txid_ret = Txid::from_str(&str_list[0])?;
        let wtxid_ret = Txid::from_str(&str_list[1])?;
        let wit_hash_ret = Txid::from_str(&str_list[2])?;
        data.tx_data.txid = txid_ret;
        data.tx_data.wtxid = wtxid_ret;
        data.wit_hash = wit_hash_ret;
        Ok(data)
      }
      _ => Err(handle.get_error(error_code)),
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  pub fn get_txin_by_outpoint(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
  ) -> Result<ConfidentialTxIn, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_data_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let list_result = {
        let index = {
          let mut index: c_uint = 0;
          let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
          let error_code = unsafe {
            CfdGetTxInIndexByHandle(
              handle.as_handle(),
              tx_data_handle.as_handle(),
              txid.as_ptr(),
              outpoint.get_vout(),
              &mut index,
            )
          };
          match error_code {
            0 => Ok(index),
            _ => Err(handle.get_error(error_code)),
          }
        }?;

        let indexes = vec![index];
        let list_result =
          self.get_tx_input_list_internal(&handle, &tx_data_handle, tx, &indexes)?;
        let data_result = self.get_tx_data_internal(&handle, &tx_data_handle, tx)?;
        self.tx_data = data_result;
        self.last_txin_index = index;
        if list_result.is_empty() {
          Err(CfdError::Internal("Failed to empty list.".to_string()))
        } else {
          Ok(list_result[0].clone())
        }
      };
      tx_data_handle.free_handle(&handle);
      list_result
    };
    handle.free_handle();
    result
  }

  pub fn get_txin_by_outpoint_internal(
    &mut self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
    outpoint: &OutPoint,
  ) -> Result<ConfidentialTxIn, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let list_result = {
      let index = {
        let mut index: c_uint = 0;
        let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
        let error_code = unsafe {
          CfdGetTxInIndexByHandle(
            handle.as_handle(),
            tx_data_handle.as_handle(),
            txid.as_ptr(),
            outpoint.get_vout(),
            &mut index,
          )
        };
        match error_code {
          0 => Ok(index),
          _ => Err(handle.get_error(error_code)),
        }
      }?;

      let indexes = vec![index];
      let list_result = self.get_tx_input_list_internal(&handle, &tx_data_handle, tx, &indexes)?;
      let data_result = self.get_tx_data_internal(&handle, &tx_data_handle, tx)?;
      self.tx_data = data_result;
      if list_result.is_empty() {
        Err(CfdError::Internal("Failed to empty list.".to_string()))
      } else {
        self.last_txin_index = index;
        self.txin_list = vec![list_result[0].clone()];
        Ok(list_result[0].clone())
      }
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    list_result
  }

  pub fn get_tx_input_list_internal(
    &self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
    indexes: &[u32],
  ) -> Result<Vec<ConfidentialTxIn>, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let mut list: Vec<ConfidentialTxIn> = vec![];
    list.reserve(indexes.len());

    let result = {
      for index in indexes {
        let item = {
          let mut data = ConfidentialTxIn::default();
          let mut txid: *mut c_char = ptr::null_mut();
          let mut script_sig: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdGetTxInByHandle(
              handle.as_handle(),
              tx_data_handle.as_handle(),
              *index,
              &mut txid,
              &mut data.outpoint.get_vout(),
              &mut data.sequence,
              &mut script_sig,
            )
          };
          match error_code {
            0 => {
              let str_list = unsafe { collect_multi_cstring_and_free(&[txid, script_sig]) }?;
              let txid_ret = Txid::from_str(&str_list[0])?;
              let script_ret = Script::from_hex(&str_list[1])?;
              let script_witness = TransactionOperation::get_tx_input_witness(
                &handle,
                &tx_data_handle,
                *index,
                WITNESS_STACK_TYPE_NORMAL,
              )?;
              let pegin_witness = TransactionOperation::get_tx_input_witness(
                &handle,
                &tx_data_handle,
                *index,
                WITNESS_STACK_TYPE_PEGIN,
              )?;
              let issuance = self.get_tx_input_issuance(&handle, &tx_data_handle, *index)?;
              data.outpoint = OutPoint::new(&txid_ret, data.outpoint.get_vout());
              data.script_sig = script_ret;
              data.script_witness = script_witness;
              data.pegin_witness = pegin_witness;
              data.issuance = issuance;
              Ok(data)
            }
            _ => Err(handle.get_error(error_code)),
          }
        }?;
        list.push(item);
      }
      if list.len() == indexes.len() {
        Ok(list)
      } else {
        Err(CfdError::Unknown(
          "Failed to get_tx_input_list.".to_string(),
        ))
      }
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  fn get_tx_output_list_internal(
    &self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
    indexes: &[u32],
  ) -> Result<Vec<ConfidentialTxOut>, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let mut list: Vec<ConfidentialTxOut> = vec![];
    list.reserve(indexes.len());

    let result = {
      for index in indexes {
        let item = {
          let mut data = ConfidentialTxOut::default();
          let mut locking_script: *mut c_char = ptr::null_mut();
          let mut amount: i64 = 0;
          let mut value: *mut c_char = ptr::null_mut();
          let mut asset: *mut c_char = ptr::null_mut();
          let mut nonce: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdGetConfidentialTxOutSimpleByHandle(
              handle.as_handle(),
              tx_data_handle.as_handle(),
              *index,
              &mut asset,
              &mut amount,
              &mut value,
              &mut nonce,
              &mut locking_script,
            )
          };
          match error_code {
            0 => {
              let str_list =
                unsafe { collect_multi_cstring_and_free(&[locking_script, asset, value, nonce]) }?;
              let script_obj = &str_list[0];
              let asset_hex = &str_list[1];
              let value_hex = &str_list[2];
              let nonce_hex = &str_list[3];
              data.locking_script = Script::from_hex(script_obj)?;
              data.asset = ConfidentialAsset::from_str(asset_hex)?;
              data.value = match value_hex.is_empty() {
                true => ConfidentialValue::from_amount(amount),
                _ => ConfidentialValue::from_str(value_hex),
              }?;
              data.nonce = ConfidentialNonce::from_str(nonce_hex)?;
              Ok(data)
            }
            _ => Err(handle.get_error(error_code)),
          }
        }?;
        list.push(item);
      }
      if list.len() == indexes.len() {
        Ok(list)
      } else {
        Err(CfdError::Unknown(
          "Failed to get_tx_output_list.".to_string(),
        ))
      }
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  pub fn create_sighash(
    &self,
    tx: &str,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    redeem_script: &Script,
    option: &SigHashOption,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
    let pubkey_str = alloc_c_string(&pubkey.to_hex())?;
    let script_str = alloc_c_string(&redeem_script.to_hex())?;
    let value_commitment = alloc_c_string(&option.value_byte.to_hex())?;
    let amount = option.amount;
    let sighash_type = option.sighash_type;
    let mut handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateConfidentialSighash(
        handle.as_handle(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.get_vout(),
        hash_type.to_c_value(),
        pubkey_str.as_ptr(),
        script_str.as_ptr(),
        amount,
        value_commitment.as_ptr(),
        sighash_type.to_c_value(),
        sighash_type.is_anyone_can_pay(),
        &mut output,
      )
    };
    let result = match error_code {
      0 => {
        let output_obj = unsafe { collect_cstring_and_free(output) }?;
        Ok(byte_from_hex_unsafe(&output_obj))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn sign_with_privkey(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    hash_type: &HashType,
    key: &KeyPair,
    option: &SigHashOption,
    has_grind_r: bool,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.get_txid().to_hex())?;
    let pubkey_hex = alloc_c_string(&key.to_pubkey().to_hex())?;
    let privkey_hex = alloc_c_string(&key.to_privkey().to_hex())?;
    let value_hex = alloc_c_string(&option.value_byte.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let sighash_type = option.sighash_type;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdAddConfidentialTxSignWithPrivkeySimple(
        handle.as_handle(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.get_vout(),
        hash_type.to_c_value(),
        pubkey_hex.as_ptr(),
        privkey_hex.as_ptr(),
        option.amount,
        value_hex.as_ptr(),
        sighash_type.to_c_value(),
        sighash_type.is_anyone_can_pay(),
        has_grind_r,
        &mut output,
      )
    };
    let result = match error_code {
      0 => {
        let output_obj = unsafe { collect_cstring_and_free(output) }?;
        self.last_tx = output_obj;
        Ok(byte_from_hex_unsafe(&self.last_tx))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn estimate_fee(
    &self,
    tx: &str,
    txin_list: &[ElementsUtxoData],
    fee_rate: f64,
    option: &FeeOption,
  ) -> Result<FeeData, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let fee_asset = alloc_c_string(&option.fee_asset.get_unblind_asset()?)?;
    let mut handle = ErrorHandle::new()?;
    let mut fee_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeEstimateFee(
        handle.as_handle(),
        &mut fee_handle,
        self.network.is_elements(),
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          for txin_data in txin_list {
            let _err = {
              let txid = alloc_c_string(&txin_data.utxo.outpoint.get_txid().to_hex())?;
              let descriptor = alloc_c_string(&txin_data.utxo.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&txin_data.utxo.scriptsig_template.to_hex())?;
              let asset = alloc_c_string(&txin_data.asset.get_unblind_asset()?)?;
              let fedpeg_script = alloc_c_string(&txin_data.option.fedpeg_script.to_hex())?;
              let error_code = unsafe {
                CfdAddTxInTemplateForEstimateFee(
                  handle.as_handle(),
                  fee_handle,
                  txid.as_ptr(),
                  txin_data.utxo.outpoint.get_vout(),
                  descriptor.as_ptr(),
                  asset.as_ptr(),
                  txin_data.option.is_issuance,
                  txin_data.option.is_blind_issuance,
                  txin_data.option.is_pegin,
                  txin_data.option.pegin_btc_tx_size,
                  fedpeg_script.as_ptr(),
                  sig_tmpl.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          set_fee_option(
            &handle,
            fee_handle,
            FEE_OPT_BLIND_EXPONENT,
            option.blind_exponent as i64,
          )?;
          set_fee_option(
            &handle,
            fee_handle,
            FEE_OPT_BLIND_MINIMUM_BITS,
            option.blind_minimum_bits as i64,
          )?;

          let mut fee_data = FeeData::default();
          let error_code = unsafe {
            CfdFinalizeEstimateFee(
              handle.as_handle(),
              fee_handle,
              tx_str.as_ptr(),
              fee_asset.as_ptr(),
              &mut fee_data.txout_fee,
              &mut fee_data.utxo_fee,
              option.is_blind,
              fee_rate,
            )
          };
          match error_code {
            0 => Ok(fee_data),
            _ => Err(handle.get_error(error_code)),
          }
        };
        unsafe {
          CfdFreeEstimateFeeHandle(handle.as_handle(), fee_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn select_coins(
    &self,
    utxo_list: &[ElementsUtxoData],
    tx_fee_amount: i64,
    target_list: &[FundTargetOption],
    fee_param: &FeeOption,
  ) -> Result<ElementsCoinSelectionData, CfdError> {
    let fee_asset = alloc_c_string(&fee_param.fee_asset.get_unblind_asset()?)?;
    let mut handle = ErrorHandle::new()?;
    let mut coin_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeCoinSelection(
        handle.as_handle(),
        utxo_list.len() as c_uint,
        target_list.len() as c_uint,
        fee_asset.as_ptr(),
        tx_fee_amount,
        fee_param.fee_rate,
        fee_param.long_term_fee_rate,
        fee_param.dust_fee_rate,
        fee_param.knapsack_min_change,
        &mut coin_handle,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          for (index, utxo_data) in utxo_list.iter().enumerate() {
            let _err = {
              let txid = alloc_c_string(&utxo_data.utxo.outpoint.get_txid().to_hex())?;
              let descriptor = alloc_c_string(&utxo_data.utxo.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&utxo_data.utxo.scriptsig_template.to_hex())?;
              let asset = alloc_c_string(&utxo_data.asset.get_unblind_asset()?)?;
              let error_code = unsafe {
                CfdAddCoinSelectionUtxoTemplate(
                  handle.as_handle(),
                  coin_handle,
                  index as c_int,
                  txid.as_ptr(),
                  utxo_data.utxo.outpoint.get_vout(),
                  utxo_data.utxo.amount,
                  asset.as_ptr(),
                  descriptor.as_ptr(),
                  sig_tmpl.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          for (index, target_data) in target_list.iter().enumerate() {
            let _ret = {
              let asset = alloc_c_string(&target_data.target_asset.get_unblind_asset()?)?;
              let error_code = unsafe {
                CfdAddCoinSelectionAmount(
                  handle.as_handle(),
                  coin_handle,
                  index as c_uint,
                  target_data.target_amount,
                  asset.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          set_coin_selection_option(
            &handle,
            coin_handle,
            COIN_OPT_BLIND_EXPONENT,
            fee_param.blind_exponent as i64,
          )?;
          set_coin_selection_option(
            &handle,
            coin_handle,
            COIN_OPT_BLIND_MINIMUM_BITS,
            fee_param.blind_minimum_bits as i64,
          )?;
          let utxo_fee_amount = {
            let mut utxo_fee_amount = 0;
            let error_code = unsafe {
              CfdFinalizeCoinSelection(handle.as_handle(), coin_handle, &mut utxo_fee_amount)
            };
            match error_code {
              0 => Ok(utxo_fee_amount),
              _ => Err(handle.get_error(error_code)),
            }
          }?;
          let mut select_utxo_list: Vec<ElementsUtxoData> = vec![];
          let mut indexes: Vec<i32> = vec![];
          indexes.reserve(utxo_list.len());
          let mut index: usize = 0;
          if utxo_fee_amount > 0 {
            while index < utxo_list.len() {
              let utxo_index = {
                let mut utxo_index = 0;
                let error_code = unsafe {
                  CfdGetSelectedCoinIndex(
                    handle.as_handle(),
                    coin_handle,
                    index as u32,
                    &mut utxo_index,
                  )
                };
                match error_code {
                  0 => {
                    if (utxo_index == -1) || (utxo_list.len() > (utxo_index as usize)) {
                      Ok(utxo_index)
                    } else {
                      Err(CfdError::Internal("utxoIndex maximum over.".to_string()))
                    }
                  }
                  _ => Err(handle.get_error(error_code)),
                }
              }?;
              if utxo_index < 0 {
                break;
              }
              indexes.push(utxo_index);
              index += 1;
            }
          }

          select_utxo_list.reserve(indexes.len());
          for utxo_index in indexes {
            select_utxo_list.push(utxo_list[utxo_index as usize].clone());
          }
          Ok(ElementsCoinSelectionData::new(
            select_utxo_list,
            utxo_fee_amount,
          ))
        };
        unsafe {
          CfdFreeCoinSelectionHandle(handle.as_handle(), coin_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn fund_raw_transaction(
    &mut self,
    txin_list: &[ElementsUtxoData],
    utxo_list: &[ElementsUtxoData],
    tx: &str,
    target_list: &[FundTargetOption],
    fee_param: &FeeOption,
  ) -> Result<FundTransactionData, CfdError> {
    let network = {
      let mut net = &self.network;
      for target in target_list {
        if target.reserved_ct_address.valid() {
          net = match target.reserved_ct_address.get_address().get_network_type() {
            Network::LiquidV1 | Network::ElementsRegtest => {
              target.reserved_ct_address.get_address().get_network_type()
            }
            _ => &self.network,
          };
          break;
        }
        if target.reserved_address.valid() {
          net = match target.reserved_address.get_network_type() {
            Network::LiquidV1 | Network::ElementsRegtest => {
              target.reserved_address.get_network_type()
            }
            _ => &self.network,
          };
          break;
        }
      }
      net
    };
    let tx_hex = alloc_c_string(tx)?;
    let fee_asset = alloc_c_string(&fee_param.fee_asset.get_unblind_asset()?)?;
    let mut handle = ErrorHandle::new()?;
    let mut fund_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeFundRawTx(
        handle.as_handle(),
        network.to_c_value(),
        target_list.len() as u32,
        fee_asset.as_ptr(),
        &mut fund_handle,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          for txin_data in txin_list {
            let _err = {
              let txid = alloc_c_string(&txin_data.utxo.outpoint.get_txid().to_hex())?;
              let descriptor = alloc_c_string(&txin_data.utxo.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&txin_data.utxo.scriptsig_template.to_hex())?;
              let asset = alloc_c_string(&txin_data.asset.get_unblind_asset()?)?;
              let fedpeg_script = alloc_c_string(&txin_data.option.fedpeg_script.to_hex())?;
              let error_code = unsafe {
                CfdAddTxInTemplateForFundRawTx(
                  handle.as_handle(),
                  fund_handle,
                  txid.as_ptr(),
                  txin_data.utxo.outpoint.get_vout(),
                  txin_data.utxo.amount,
                  descriptor.as_ptr(),
                  asset.as_ptr(),
                  txin_data.option.is_issuance,
                  txin_data.option.is_blind_issuance,
                  txin_data.option.is_pegin,
                  txin_data.option.pegin_btc_tx_size,
                  fedpeg_script.as_ptr(),
                  sig_tmpl.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          for utxo_data in utxo_list {
            let _err = {
              let txid = alloc_c_string(&utxo_data.utxo.outpoint.get_txid().to_hex())?;
              let descriptor = alloc_c_string(&utxo_data.utxo.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&utxo_data.utxo.scriptsig_template.to_hex())?;
              let asset = alloc_c_string(&utxo_data.asset.get_unblind_asset()?)?;
              let error_code = unsafe {
                CfdAddUtxoTemplateForFundRawTx(
                  handle.as_handle(),
                  fund_handle,
                  txid.as_ptr(),
                  utxo_data.utxo.outpoint.get_vout(),
                  utxo_data.utxo.amount,
                  descriptor.as_ptr(),
                  asset.as_ptr(),
                  sig_tmpl.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          for (index, target_data) in target_list.iter().enumerate() {
            let _ret = {
              let addr_str = match target_data.reserved_ct_address.valid() {
                true => target_data.reserved_ct_address.to_str(),
                _ => target_data.reserved_address.to_str(),
              };
              let addr = alloc_c_string(addr_str)?;
              let asset = alloc_c_string(&target_data.target_asset.get_unblind_asset()?)?;
              let error_code = unsafe {
                CfdAddTargetAmountForFundRawTx(
                  handle.as_handle(),
                  fund_handle,
                  index as u32,
                  target_data.target_amount,
                  asset.as_ptr(),
                  addr.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          set_fund_tx_option(
            &handle,
            fund_handle,
            FUND_OPT_DUST_FEE_RATE,
            FundOptionValue::Double(fee_param.dust_fee_rate),
          )?;
          set_fund_tx_option(
            &handle,
            fund_handle,
            FUND_OPT_LONG_TERM_FEE_RATE,
            FundOptionValue::Double(fee_param.long_term_fee_rate),
          )?;
          set_fund_tx_option(
            &handle,
            fund_handle,
            FUND_OPT_KNAPSACK_MIN_CHANGE,
            FundOptionValue::Long(fee_param.knapsack_min_change),
          )?;
          set_fund_tx_option(
            &handle,
            fund_handle,
            FUND_OPT_IS_BLIND,
            FundOptionValue::Bool(fee_param.is_blind),
          )?;
          set_fund_tx_option(
            &handle,
            fund_handle,
            FUND_OPT_BLIND_EXPONENT,
            FundOptionValue::Long(fee_param.blind_exponent),
          )?;
          set_fund_tx_option(
            &handle,
            fund_handle,
            FUND_OPT_BLIND_MINIMUM_BITS,
            FundOptionValue::Long(fee_param.blind_minimum_bits),
          )?;

          let mut tx_fee = 0;
          let mut append_txout_count = 0;
          let output_tx = {
            let mut output: *mut c_char = ptr::null_mut();
            let error_code = unsafe {
              CfdFinalizeFundRawTx(
                handle.as_handle(),
                fund_handle,
                tx_hex.as_ptr(),
                fee_param.fee_rate,
                &mut tx_fee,
                &mut append_txout_count,
                &mut output,
              )
            };
            match error_code {
              0 => unsafe { collect_cstring_and_free(output) },
              _ => Err(handle.get_error(error_code)),
            }
          }?;
          let mut used_addr_list: Vec<Address> = vec![];
          used_addr_list.reserve(append_txout_count as usize);
          let mut index = 0;
          while index < append_txout_count {
            let address = {
              let mut output: *mut c_char = ptr::null_mut();
              let error_code = unsafe {
                CfdGetAppendTxOutFundRawTx(handle.as_handle(), fund_handle, index, &mut output)
              };
              match error_code {
                0 => {
                  let addr_str = unsafe { collect_cstring_and_free(output) }?;
                  match ConfidentialAddress::parse(&addr_str) {
                    Ok(ct_addr) => Ok(ct_addr.get_address().clone()),
                    _ => Address::from_str(&addr_str),
                  }
                }
                _ => Err(handle.get_error(error_code)),
              }
            }?;
            used_addr_list.push(address);
            index += 1;
          }
          self.last_tx = output_tx;
          Ok(FundTransactionData::new(used_addr_list, tx_fee))
        };
        unsafe {
          CfdFreeFundRawTxHandle(handle.as_handle(), fund_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  fn get_tx_input_issuance(
    &self,
    handle: &ErrorHandle,
    tx_data_handle: &TxDataHandle,
    index: u32,
  ) -> Result<Issuance, CfdError> {
    let mut asset_amount: c_longlong = 0;
    let mut token_amount: c_longlong = 0;
    let mut entropy: *mut c_char = ptr::null_mut();
    let mut nonce: *mut c_char = ptr::null_mut();
    let mut asset_value: *mut c_char = ptr::null_mut();
    let mut token_value: *mut c_char = ptr::null_mut();
    let mut asset_range_proof: *mut c_char = ptr::null_mut();
    let mut token_range_proof: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetTxInIssuanceInfoByHandle(
        handle.as_handle(),
        tx_data_handle.as_handle(),
        index,
        &mut entropy,
        &mut nonce,
        &mut asset_amount,
        &mut asset_value,
        &mut token_amount,
        &mut token_value,
        &mut asset_range_proof,
        &mut token_range_proof,
      )
    };
    match error_code {
      0 => {
        let str_list = unsafe {
          collect_multi_cstring_and_free(&[
            entropy,
            nonce,
            asset_value,
            token_value,
            asset_range_proof,
            token_range_proof,
          ])
        }?;
        let issue_asset = match str_list[2].is_empty() {
          true => ConfidentialValue::from_amount(asset_amount),
          _ => ConfidentialValue::from_str(&str_list[2]),
        }?;
        let token = match str_list[3].is_empty() {
          true => ConfidentialValue::from_amount(token_amount),
          _ => ConfidentialValue::from_str(&str_list[3]),
        }?;
        let issuance = Issuance {
          asset_entropy: BlindFactor::from_str(&str_list[0])?,
          asset_blinding_nonce: BlindFactor::from_str(&str_list[1])?,
          asset_amount: issue_asset,
          inflation_keys: token,
          amount_range_proof: ByteData::from_str(&str_list[4])?,
          inflation_keys_range_proof: ByteData::from_str(&str_list[5])?,
        };
        Ok(issuance)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  fn create_tx(
    &mut self,
    version: u32,
    locktime: u32,
    tx: &str,
    txin_list: &[TxInData],
    txout_list: &[ConfidentialTxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let mut handle = ErrorHandle::new()?;
    let mut create_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeTransaction(
        handle.as_handle(),
        self.network.to_c_value(),
        version,
        locktime,
        tx_str.as_ptr(),
        &mut create_handle,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          for input in txin_list {
            let _err = {
              let txid = alloc_c_string(&input.outpoint.get_txid().to_hex())?;
              let error_code = unsafe {
                CfdAddTransactionInput(
                  handle.as_handle(),
                  create_handle,
                  txid.as_ptr(),
                  input.outpoint.get_vout(),
                  input.sequence,
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          for output in txout_list {
            let _err = {
              let address_str = alloc_c_string(output.get_address_str())?;
              let script = alloc_c_string(&output.locking_script.to_hex())?;
              let asset = alloc_c_string(&output.asset.get_unblind_asset()?)?;
              let nonce = alloc_c_string(&output.nonce.as_str())?;
              let error_code = unsafe {
                CfdAddConfidentialTxOutput(
                  handle.as_handle(),
                  create_handle,
                  output.amount,
                  address_str.as_ptr(),
                  script.as_ptr(),
                  asset.as_ptr(),
                  nonce.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          let mut output: *mut c_char = ptr::null_mut();
          let error_code =
            unsafe { CfdFinalizeTransaction(handle.as_handle(), create_handle, &mut output) };
          match error_code {
            0 => {
              let output_obj = unsafe { collect_cstring_and_free(output) }?;
              self.last_tx = output_obj;
              Ok(byte_from_hex_unsafe(&self.last_tx))
            }
            _ => Err(handle.get_error(error_code)),
          }
        };
        unsafe {
          CfdFreeTransactionHandle(handle.as_handle(), create_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }
}

pub(in crate) fn set_blind_tx_option(
  handle: &ErrorHandle,
  blind_handle: *const c_void,
  key: i32,
  value: i64,
) -> Result<(), CfdError> {
  let error_code = unsafe { CfdSetBlindTxOption(handle.as_handle(), blind_handle, key, value) };
  match error_code {
    0 => Ok(()),
    _ => Err(handle.get_error(error_code)),
  }
}

pub(in crate) fn set_coin_selection_option(
  handle: &ErrorHandle,
  coin_handle: *const c_void,
  key: i32,
  value: i64,
) -> Result<(), CfdError> {
  let error_code =
    unsafe { CfdSetOptionCoinSelection(handle.as_handle(), coin_handle, key, value, 0.0, false) };
  match error_code {
    0 => Ok(()),
    _ => Err(handle.get_error(error_code)),
  }
}

pub(in crate) fn set_fee_option(
  handle: &ErrorHandle,
  fee_handle: *const c_void,
  key: i32,
  value: i64,
) -> Result<(), CfdError> {
  let error_code =
    unsafe { CfdSetOptionEstimateFee(handle.as_handle(), fee_handle, key, value, 0.0, false) };
  match error_code {
    0 => Ok(()),
    _ => Err(handle.get_error(error_code)),
  }
}
