extern crate cfd_sys;
extern crate libc;

// use self::cfd_sys as ffi;
use self::libc::{c_char, c_int, c_uint, c_void};
use crate::common::{
  alloc_c_string, byte_from_hex_unsafe, collect_cstring_and_free, collect_multi_cstring_and_free,
  hex_from_bytes, Amount, ByteData, CfdError, ErrorHandle, Network, ReverseContainer,
};
use crate::confidential_address::ConfidentialAddress;
use crate::confidential_transaction::ConfidentialAsset;
use crate::descriptor::Descriptor;
use crate::key::{KeyPair, Privkey, Pubkey, SigHashType, SignParameter};
use crate::script::{Script, TAPROOT_HASH_SIZE};
use crate::{
  address::{Address, AddressType, HashType},
  SchnorrPubkey,
};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdAddCoinSelectionAmount, CfdAddCoinSelectionUtxoTemplate, CfdAddMultisigSignData,
  CfdAddMultisigSignDataToDer, CfdAddPubkeyHashSign, CfdAddScriptHashSign,
  CfdAddSignWithPrivkeyByHandle, CfdAddSignWithPrivkeySimple, CfdAddTaprootSignByHandle,
  CfdAddTargetAmountForFundRawTx, CfdAddTransactionInput, CfdAddTransactionOutput,
  CfdAddTxInTemplateForEstimateFee, CfdAddTxInTemplateForFundRawTx, CfdAddTxSign,
  CfdAddTxSignByHandle, CfdAddUtxoTemplateForFundRawTx, CfdCreateSighash, CfdCreateSighashByHandle,
  CfdFinalizeCoinSelection, CfdFinalizeEstimateFee, CfdFinalizeFundRawTx, CfdFinalizeMultisigSign,
  CfdFinalizeTransaction, CfdFreeCoinSelectionHandle, CfdFreeEstimateFeeHandle,
  CfdFreeFundRawTxHandle, CfdFreeMultisigSignHandle, CfdFreeTxDataHandle,
  CfdGetAppendTxOutFundRawTx, CfdGetSelectedCoinIndex, CfdGetTxInByHandle, CfdGetTxInCountByHandle,
  CfdGetTxInIndex, CfdGetTxInIndexByHandle, CfdGetTxInWitnessByHandle,
  CfdGetTxInWitnessCountByHandle, CfdGetTxInfoByHandle, CfdGetTxOutByHandle,
  CfdGetTxOutCountByHandle, CfdGetTxOutIndexByHandle, CfdInitializeCoinSelection,
  CfdInitializeEstimateFee, CfdInitializeFundRawTx, CfdInitializeMultisigSign,
  CfdInitializeTransaction, CfdInitializeTxDataHandle, CfdSetOptionFundRawTx,
  CfdSetTransactionUtxoData, CfdUpdateTxOutAmount, CfdVerifySignature, CfdVerifyTxSign,
  CfdVerifyTxSignByHandle, DEFAULT_BLIND_MINIMUM_BITS, FUND_OPT_DUST_FEE_RATE,
  FUND_OPT_KNAPSACK_MIN_CHANGE, FUND_OPT_LONG_TERM_FEE_RATE, WITNESS_STACK_TYPE_NORMAL,
};

// fund option
// const OPT_DUST_FEE_RATE: i32 = 2;
// const OPT_LONG_TERM_FEE_RATE: i32 = 3;
// const OPT_KNAPSACK_MIN_CHANGE: i32 = 4;

/// locktime final
pub const SEQUENCE_LOCK_TIME_FINAL: u32 = 0xffffffff;
/// disable locktime (deprecated)
#[deprecated(since = "0.3.0", note = "Please use the SEQUENCE_LOCK_TIME_FINAL")]
pub const SEQUENCE_LOCK_TIME_DISABLE: u32 = 0xffffffff;
/// enable locktime (maximum time)
pub const SEQUENCE_LOCK_TIME_ENABLE_MAX: u32 = 0xfffffffe;
/// array size of txid.
pub const TXID_SIZE: usize = 32;
/// OP_CODESEPARATOR position final
pub const CODE_SEPARATOR_POSITION_FINAL: u32 = 0xffffffff;

/// A container that stores a txid.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Txid {
  txid: ReverseContainer,
}

impl Txid {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `txid` - An unsigned 8bit slice that holds the txid.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Txid;
  /// let bytes = [2; 32];
  /// let data = Txid::from_slice(&bytes);
  /// ```
  pub fn from_slice(txid: &[u8; TXID_SIZE]) -> Txid {
    Txid {
      txid: ReverseContainer::from_slice(txid),
    }
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8; TXID_SIZE] {
    self.txid.to_slice()
  }

  pub fn to_hex(&self) -> String {
    self.txid.to_hex()
  }
}

impl FromStr for Txid {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Txid, CfdError> {
    let txid = ReverseContainer::from_str(text)?;
    Ok(Txid { txid })
  }
}

impl fmt::Display for Txid {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.to_hex())
  }
}

impl Default for Txid {
  fn default() -> Txid {
    Txid {
      txid: ReverseContainer::default(),
    }
  }
}

/// A container that stores a txid and vout.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct OutPoint {
  txid: Txid,
  vout: u32,
}

impl OutPoint {
  /// Create object.
  ///
  /// # Arguments
  /// * `txid` - A txid object.
  /// * `vout` - A unsigned 32bit transaction vout number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Txid, OutPoint};
  /// let bytes = [2; 32];
  /// let txid = Txid::from_slice(&bytes);
  /// let outpoint = OutPoint::new(&txid, 1);
  /// ```
  pub fn new(txid: &Txid, vout: u32) -> OutPoint {
    OutPoint {
      txid: txid.clone(),
      vout,
    }
  }

  /// Create object from txid string.
  ///
  /// # Arguments
  /// * `txid` - A txid string.
  /// * `vout` - A unsigned 32bit transaction vout number.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::OutPoint;
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// ```
  pub fn from_str(txid: &str, vout: u32) -> Result<OutPoint, CfdError> {
    let txid = Txid::from_str(txid)?;
    Ok(OutPoint { txid, vout })
  }

  #[inline]
  pub fn get_txid(&self) -> &Txid {
    &self.txid
  }

  #[inline]
  pub fn get_vout(&self) -> u32 {
    self.vout
  }
}

impl fmt::Display for OutPoint {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}:{}", &self.txid, self.vout)
  }
}

impl Default for OutPoint {
  fn default() -> OutPoint {
    OutPoint {
      txid: Txid::default(),
      vout: 0,
    }
  }
}

/// A container that stores witness stack.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ScriptWitness {
  pub witness_stack: Vec<ByteData>,
}

impl ScriptWitness {
  /// Create from witness stack byte array.
  ///
  /// # Arguments
  /// * `list` - Witness stack.
  pub fn new(list: &[ByteData]) -> ScriptWitness {
    ScriptWitness {
      witness_stack: list.to_vec(),
    }
  }

  pub fn get_stack(&self, index: u32) -> Result<&ByteData, CfdError> {
    match self.witness_stack.len() > index as usize {
      true => Ok(&self.witness_stack[index as usize]),
      _ => Err(CfdError::OutOfRange("index out of range.".to_string())),
    }
  }

  pub fn len(&self) -> usize {
    self.witness_stack.len()
  }

  pub fn is_empty(&self) -> bool {
    self.witness_stack.is_empty()
  }
}

impl fmt::Display for ScriptWitness {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "stack({})[", &self.len())?;

    let mut index = 0;
    while index < self.len() {
      if index == 0 {
        write!(f, "{}", &self.witness_stack[index])?;
      } else {
        write!(f, ", {}", &self.witness_stack[index])?;
      }
      index += 1;
    }
    write!(f, "]")
  }
}

impl Default for ScriptWitness {
  fn default() -> ScriptWitness {
    ScriptWitness {
      witness_stack: vec![],
    }
  }
}

/// A container that stores utxo information.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UtxoData {
  pub outpoint: OutPoint,
  pub amount: i64,
  pub descriptor: Descriptor,
  pub scriptsig_template: Script,
}

impl UtxoData {
  /// Create from out-point.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{OutPoint, UtxoData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let utxo = UtxoData::from_outpoint(&outpoint, amount);
  /// ```
  pub fn from_outpoint(outpoint: &OutPoint, amount: i64) -> UtxoData {
    UtxoData {
      outpoint: outpoint.clone(),
      amount,
      descriptor: Descriptor::default(),
      scriptsig_template: Script::default(),
    }
  }

  /// Create from descriptor.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  /// * `descriptor` - An output descriptor.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, OutPoint, UtxoData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  /// let descriptor = Descriptor::new(desc_str, &Network::Testnet).expect("Fail");
  /// let utxo = UtxoData::from_descriptor(&outpoint, amount, &descriptor);
  /// ```
  pub fn from_descriptor(outpoint: &OutPoint, amount: i64, descriptor: &Descriptor) -> UtxoData {
    UtxoData {
      outpoint: outpoint.clone(),
      amount,
      descriptor: descriptor.clone(),
      scriptsig_template: Script::default(),
    }
  }

  /// Create from address.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  /// * `address` - An address.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Network, OutPoint, UtxoData, Address, Pubkey};
  /// use std::str::FromStr;
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let pubkey = Pubkey::from_str(&"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").expect("Fail");
  /// let address = Address::p2pkh(&pubkey, &Network::Testnet).expect("Fail");
  /// let utxo = UtxoData::from_address(&outpoint, amount, &address);
  /// ```
  pub fn from_address(
    outpoint: &OutPoint,
    amount: i64,
    address: &Address,
  ) -> Result<UtxoData, CfdError> {
    Ok(UtxoData {
      outpoint: outpoint.clone(),
      amount,
      descriptor: Descriptor::address(address)?,
      scriptsig_template: Script::default(),
    })
  }

  /// Create from locking script.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  /// * `locking_script` - A locking script.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Network, OutPoint, UtxoData, Script};
  /// use std::str::FromStr;
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let script = Script::from_hex("5120c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").expect("Fail");
  /// let utxo = UtxoData::from_locking_script(&outpoint, amount, &script, &Network::Testnet);
  /// ```
  pub fn from_locking_script(
    outpoint: &OutPoint,
    amount: i64,
    locking_script: &Script,
    network: &Network,
  ) -> Result<UtxoData, CfdError> {
    Ok(UtxoData {
      outpoint: outpoint.clone(),
      amount,
      descriptor: Descriptor::raw_script(locking_script, network)?,
      scriptsig_template: Script::default(),
    })
  }

  /// Create object.
  ///
  /// # Arguments
  /// * `outpoint` - A txid string.
  /// * `amount` - A satoshi amount.
  /// * `descriptor` - An output descriptor.
  /// * `scriptsig_template` - A script template for calculating script hash signed size.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Descriptor, Network, OutPoint, Script, UtxoData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let amount: i64 = 50000;
  /// let desc_str = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
  /// let descriptor = Descriptor::new(desc_str, &Network::Testnet).expect("Fail");
  /// let script = Script::default();
  /// let utxo = UtxoData::new(&outpoint, amount, &descriptor, &script);
  /// ```
  pub fn new(
    outpoint: &OutPoint,
    amount: i64,
    descriptor: &Descriptor,
    scriptsig_template: &Script,
  ) -> UtxoData {
    UtxoData {
      outpoint: outpoint.clone(),
      amount,
      descriptor: descriptor.clone(),
      scriptsig_template: scriptsig_template.clone(),
    }
  }

  pub fn get_amount(&self) -> Amount {
    Amount::new(self.amount)
  }
}

impl fmt::Display for UtxoData {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "utxo({}, amount: {})[", &self.outpoint, self.amount)
  }
}

impl Default for UtxoData {
  fn default() -> UtxoData {
    UtxoData {
      outpoint: OutPoint::default(),
      amount: 0,
      descriptor: Descriptor::default(),
      scriptsig_template: Script::default(),
    }
  }
}

/// A container that stores coin selection data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CoinSelectionData {
  pub select_utxo_list: Vec<UtxoData>,
  pub utxo_fee_amount: i64,
}

impl CoinSelectionData {
  pub fn new(select_utxo_list: Vec<UtxoData>, utxo_fee_amount: i64) -> CoinSelectionData {
    CoinSelectionData {
      select_utxo_list,
      utxo_fee_amount,
    }
  }

  pub fn get_total_amount(&self) -> i64 {
    let mut total = 0;
    for utxo in self.select_utxo_list.iter() {
      total += utxo.amount;
    }
    total
  }
}

impl Default for CoinSelectionData {
  fn default() -> CoinSelectionData {
    CoinSelectionData {
      select_utxo_list: vec![],
      utxo_fee_amount: 0,
    }
  }
}

/// A container that stores transaction fee.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FeeData {
  /// tx outputs and tx base fee.
  pub txout_fee: i64,
  /// utxo (tx inputs) fee.
  pub utxo_fee: i64,
}

impl FeeData {
  pub fn new(txout_fee: i64, utxo_fee: i64) -> FeeData {
    FeeData {
      txout_fee,
      utxo_fee,
    }
  }

  pub fn get_total_fee(&self) -> i64 {
    self.txout_fee + self.utxo_fee
  }
}

impl fmt::Display for FeeData {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "fee[tx:{}, utxo:{}]", &self.txout_fee, self.utxo_fee)
  }
}

impl Default for FeeData {
  fn default() -> FeeData {
    FeeData::new(0, 0)
  }
}

/// A container that stores transaction fee.
#[derive(Debug, PartialEq, Clone)]
pub struct FeeOption {
  pub fee_rate: f64,
  pub long_term_fee_rate: f64,
  pub dust_fee_rate: f64,
  pub knapsack_min_change: i64,
  pub is_blind: bool,
  pub blind_exponent: i64,
  pub blind_minimum_bits: i64,
  pub fee_asset: ConfidentialAsset,
}

impl FeeOption {
  pub fn new(network: &Network) -> FeeOption {
    match network {
      Network::LiquidV1 | Network::ElementsRegtest => FeeOption {
        fee_rate: 0.11,
        long_term_fee_rate: 1.0,
        dust_fee_rate: 3.0,
        knapsack_min_change: -1,
        is_blind: true,
        blind_exponent: 0,
        blind_minimum_bits: DEFAULT_BLIND_MINIMUM_BITS as i64,
        fee_asset: ConfidentialAsset::default(),
      },
      _ => FeeOption {
        fee_rate: 2.0,
        long_term_fee_rate: 20.0,
        dust_fee_rate: 3.0,
        knapsack_min_change: -1,
        is_blind: false,
        blind_exponent: 0,
        blind_minimum_bits: 0,
        fee_asset: ConfidentialAsset::default(),
      },
    }
  }
}

impl Default for FeeOption {
  fn default() -> FeeOption {
    FeeOption::new(&Network::Mainnet)
  }
}

/// A container that stores fund raw transaction option.
#[derive(Debug, PartialEq, Clone)]
pub struct FundTargetOption {
  pub target_amount: i64,
  pub target_asset: ConfidentialAsset,
  pub reserved_address: Address,
  pub reserved_ct_address: ConfidentialAddress,
}

impl FundTargetOption {
  pub fn from_amount(amount: i64, address: &Address) -> FundTargetOption {
    FundTargetOption {
      target_amount: amount,
      target_asset: ConfidentialAsset::default(),
      reserved_address: address.clone(),
      reserved_ct_address: ConfidentialAddress::default(),
    }
  }

  pub fn from_asset(amount: i64, asset: &ConfidentialAsset, address: &Address) -> FundTargetOption {
    FundTargetOption {
      target_amount: amount,
      target_asset: asset.clone(),
      reserved_address: address.clone(),
      reserved_ct_address: ConfidentialAddress::default(),
    }
  }

  pub fn from_asset_and_address(
    amount: i64,
    asset: &ConfidentialAsset,
    ct_address: &ConfidentialAddress,
  ) -> FundTargetOption {
    FundTargetOption {
      target_amount: amount,
      target_asset: asset.clone(),
      reserved_address: Address::default(),
      reserved_ct_address: ct_address.clone(),
    }
  }
}

impl Default for FundTargetOption {
  fn default() -> FundTargetOption {
    FundTargetOption {
      target_amount: 0,
      target_asset: ConfidentialAsset::default(),
      reserved_address: Address::default(),
      reserved_ct_address: ConfidentialAddress::default(),
    }
  }
}

/// A container that stores fund transaction data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FundTransactionData {
  pub reserved_address_list: Vec<Address>,
  pub fee_amount: i64,
}

impl FundTransactionData {
  pub fn new(reserved_address_list: Vec<Address>, fee_amount: i64) -> FundTransactionData {
    FundTransactionData {
      reserved_address_list,
      fee_amount,
    }
  }
}

impl Default for FundTransactionData {
  fn default() -> FundTransactionData {
    FundTransactionData {
      reserved_address_list: vec![],
      fee_amount: 0,
    }
  }
}

/// A container that stores transaction data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxData {
  pub txid: Txid,
  pub wtxid: Txid,
  pub size: u32,
  pub vsize: u32,
  pub weight: u32,
  pub version: u32,
  pub locktime: u32,
}

impl Default for TxData {
  fn default() -> TxData {
    // default txid: version=2, locktime=0
    let txid_value =
      match Txid::from_str("4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a") {
        Ok(_txid) => _txid,
        _ => Txid::default(),
      };
    TxData {
      txid: txid_value.clone(),
      wtxid: txid_value,
      size: 10,
      vsize: 10,
      weight: 40,
      version: 2,
      locktime: 0,
    }
  }
}

/// A container that stores transaction input data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxInData {
  pub outpoint: OutPoint,
  pub sequence: u32,
  pub script_sig: Script,
}

impl TxInData {
  pub fn new(outpoint: &OutPoint) -> TxInData {
    TxInData {
      outpoint: outpoint.clone(),
      sequence: SEQUENCE_LOCK_TIME_FINAL,
      script_sig: Script::default(),
    }
  }

  pub fn from_utxo(utxo: &UtxoData) -> TxInData {
    TxInData {
      outpoint: utxo.outpoint.clone(),
      sequence: SEQUENCE_LOCK_TIME_FINAL,
      script_sig: Script::default(),
    }
  }
}

/// A container that stores transaction output data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxOutData {
  pub amount: i64,
  pub address: Address,
  pub locking_script: Script,
  pub asset: String,
}

impl TxOutData {
  pub fn from_address(amount: i64, address: &Address) -> TxOutData {
    TxOutData {
      amount,
      address: address.clone(),
      locking_script: Script::default(),
      asset: String::default(),
    }
  }
}

/// A container that stores transaction input.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxIn {
  pub outpoint: OutPoint,
  pub sequence: u32,
  pub script_sig: Script,
  pub script_witness: ScriptWitness,
}

impl TxIn {
  pub fn from_data_list(list: &[TxInData]) -> Vec<TxIn> {
    let mut output: Vec<TxIn> = vec![];
    output.reserve(list.len());
    for item in list {
      output.push(TxIn {
        outpoint: item.outpoint.clone(),
        sequence: item.sequence,
        script_sig: item.script_sig.clone(),
        script_witness: ScriptWitness::default(),
      });
    }
    output
  }
}

impl Default for TxIn {
  fn default() -> TxIn {
    TxIn {
      outpoint: OutPoint::default(),
      sequence: SEQUENCE_LOCK_TIME_FINAL,
      script_sig: Script::default(),
      script_witness: ScriptWitness::default(),
    }
  }
}

/// A container that stores transaction output.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxOut {
  pub amount: i64,
  pub locking_script: Script,
}

impl TxOut {
  pub fn from_data_list(list: &[TxOutData]) -> Vec<TxOut> {
    let mut output: Vec<TxOut> = vec![];
    output.reserve(list.len());
    for item in list {
      let script = if item.address.valid() {
        item.address.get_locking_script()
      } else {
        &item.locking_script
      };
      output.push(TxOut {
        amount: item.amount,
        locking_script: script.clone(),
      });
    }
    output
  }
}

impl Default for TxOut {
  fn default() -> TxOut {
    TxOut {
      amount: 0,
      locking_script: Script::default(),
    }
  }
}

/// A container that stores bitcoin transaction.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Transaction {
  tx: Vec<u8>,
  data: TxData,
  txin_list: Vec<TxIn>,
  txout_list: Vec<TxOut>,
  txin_utxo_list: Vec<UtxoData>,
}

impl Transaction {
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
    &self.data.txid
  }

  pub fn get_info(&self) -> &TxData {
    &self.data
  }

  pub fn get_txin_list(&self) -> &[TxIn] {
    &self.txin_list
  }

  pub fn get_txout_list(&self) -> &[TxOut] {
    &self.txout_list
  }

  /// Create initial empty transaction.
  ///
  /// # Arguments
  /// * `version` - A transaction version.
  /// * `locktime` - A transaction locktime.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Transaction;
  /// let tx = Transaction::new(2, 0).expect("Fail");
  /// ```
  pub fn new(version: u32, locktime: u32) -> Result<Transaction, CfdError> {
    Transaction::create_tx(version, locktime, &[], &[])
  }

  /// Get transaction from bytes.
  ///
  /// # Arguments
  /// * `tx` - A transaction byte array.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::Transaction;
  /// let tx = Transaction::new(2, 0).expect("Fail");
  /// let tx2 = Transaction::from_slice(tx.to_bytes()).expect("Fail");
  /// ```
  pub fn from_slice(tx: &[u8]) -> Result<Transaction, CfdError> {
    let hex = hex_from_bytes(tx);
    Transaction::from_str(&hex)
  }

  /// Create initial transaction.
  ///
  /// # Arguments
  /// * `version` - A transaction version.
  /// * `locktime` - A transaction locktime.
  /// * `txin_list` - Transaction input list.
  /// * `txout_list` - Transaction output list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, OutPoint, Transaction, TxInData, TxOutData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("bc1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4jcdzrv").expect("Fail");
  /// let txout_list = [TxOutData::from_address(amount, &addr)];
  /// let tx = Transaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// ```
  pub fn create_tx(
    version: u32,
    locktime: u32,
    txin_list: &[TxInData],
    txout_list: &[TxOutData],
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx = ope.create(version, locktime, txin_list, txout_list)?;
    let data = ope.get_tx_data(ope.get_last_tx())?;
    Ok(Transaction {
      tx,
      data,
      txin_list: TxIn::from_data_list(txin_list),
      txout_list: TxOut::from_data_list(txout_list),
      ..Transaction::default()
    })
  }

  /// Append to transaction.
  ///
  /// # Arguments
  /// * `txin_list` - Transaction input list.
  /// * `txout_list` - Transaction output list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, OutPoint, Transaction, TxInData, TxOutData};
  /// let tx = Transaction::new(2, 0).expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("bc1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4jcdzrv").expect("Fail");
  /// let txout_list = [TxOutData::from_address(amount, &addr)];
  /// let tx2 = tx.append_data(&txin_list, &txout_list).expect("Fail");
  /// ```
  pub fn append_data(
    &self,
    txin_list: &[TxInData],
    txout_list: &[TxOutData],
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx = ope.update(&hex_from_bytes(&self.tx), txin_list, txout_list)?;
    let last_tx = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let data = ope2.get_all_data(last_tx)?;
    Ok(Transaction {
      tx,
      data,
      txin_list: ope2.get_txin_list_cache().to_vec(),
      txout_list: ope2.get_txout_list_cache().to_vec(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    })
  }

  /// Append utxo data to transaction.
  ///
  /// # Arguments
  /// * `utxo_list` - Transaction input's utxo list.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, OutPoint, Transaction, TxInData, TxOutData, UtxoData};
  /// let tx = Transaction::new(2, 0).expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("bc1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4jcdzrv").expect("Fail");
  /// let txout_list = [TxOutData::from_address(amount, &addr)];
  /// let tx2 = tx.append_data(&txin_list, &txout_list).expect("Fail");
  /// let utxo = UtxoData::from_address(&outpoint, amount, &addr).expect("Fail");
  /// let tx3 = tx2.append_utxo_list(&[utxo]).expect("Fail");
  /// ```
  pub fn append_utxo_list(&self, utxo_list: &[UtxoData]) -> Result<Transaction, CfdError> {
    let mut utxos = self.txin_utxo_list.clone();
    for utxo in utxo_list.to_vec() {
      let mut is_find = false;
      for txin in &self.txin_list {
        if txin.outpoint == utxo.outpoint {
          is_find = true;
          break;
        }
      }
      if is_find {
        utxos.push(utxo);
      }
    }
    Ok(Transaction {
      tx: self.tx.clone(),
      data: self.data.clone(),
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: utxos,
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
  /// use cfd_rust::{Address, OutPoint, Transaction, TxInData, TxOutData};
  /// let outpoint = OutPoint::from_str(
  ///   "0202020202020202020202020202020202020202020202020202020202020202",
  ///   1).expect("Fail");
  /// let txin_list = [TxInData::new(&outpoint)];
  /// let amount: i64 = 50000;
  /// let addr = Address::from_string("bc1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4jcdzrv").expect("Fail");
  /// let txout_list = [TxOutData::from_address(amount, &addr)];
  /// let tx = Transaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  /// let tx2 = tx.update_amount(0, 60000).expect("Fail");
  /// ```
  pub fn update_amount(&self, index: u32, amount: i64) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx = ope.update_output_amount(&hex_from_bytes(&self.tx), index, amount)?;
    let data = ope.get_tx_data(ope.get_last_tx())?;
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txout_list[index as usize].amount = amount;
    Ok(tx_obj)
  }

  pub fn get_txin_index(&self, outpoint: &OutPoint) -> Result<u32, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    ope.get_txin_index_by_outpoint(&hex_from_bytes(&self.tx), outpoint)
  }

  pub fn get_txout_index_by_address(&self, address: &Address) -> Result<u32, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    ope.get_txout_index_by_address(&hex_from_bytes(&self.tx), address)
  }

  pub fn get_txout_index_by_script(&self, script: &Script) -> Result<u32, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    ope.get_txout_index_by_script(&hex_from_bytes(&self.tx), script)
  }

  /// Create signature hash by pubkey.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type. (pubkey hash only)
  /// * `pubkey` - A public key.
  /// * `sighash_type` - A transaction input sighash-type.
  /// * `amount` - A transaction input amount. (p2pkh is 0)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Pubkey, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash = tx.create_sighash_by_pubkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &pubkey,
  ///   &SigHashType::All,
  ///   &Amount::new(60000)).expect("Fail");
  /// ```
  pub fn create_sighash_by_pubkey(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    sighash_type: &SigHashType,
    amount: &Amount,
  ) -> Result<Vec<u8>, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::new(*sighash_type, amount.as_satoshi_amount());
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
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type. (script hash only)
  /// * `redeem_script` - A redeem script.
  /// * `sighash_type` - A transaction input sighash-type.
  /// * `amount` - A transaction input amount. (p2pkh is 0)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Script, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash = tx.create_sighash_by_script(
  ///   &outpoint,
  ///   &HashType::P2wsh,
  ///   &script,
  ///   &SigHashType::All,
  ///   &Amount::new(60000)).expect("Fail");
  /// ```
  pub fn create_sighash_by_script(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    redeem_script: &Script,
    sighash_type: &SigHashType,
    amount: &Amount,
  ) -> Result<Vec<u8>, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::new(*sighash_type, amount.as_satoshi_amount());
    ope.create_sighash(
      &hex_from_bytes(&self.tx),
      outpoint,
      hash_type,
      &Pubkey::default(),
      redeem_script,
      &option,
    )
  }

  /// Get signature hash by pubkey.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `pubkey` - A public key.
  /// * `sighash_type` - A transaction input sighash-type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Pubkey, SigHashType, Transaction, Descriptor, UtxoData, Network, Address};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey1 = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint1 = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let outpoint2 = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let addr2 = Address::from_string("bc1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4jcdzrv").expect("Fail");
  /// let amount1: i64 = 2000000000;
  /// let amount2: i64 = 505000;
  /// let desc1 = Descriptor::p2wpkh(&pubkey1, &Network::Mainnet).expect("Fail");
  /// let utxo1 = UtxoData::from_descriptor(&outpoint1, amount1, &desc1);
  /// let utxo2 = UtxoData::from_address(&outpoint2, amount2, &addr2).expect("Fail");
  /// let tx2 = tx.append_utxo_list(&[utxo1, utxo2]).expect("Fail");
  /// let sighash = tx2.get_sighash_by_pubkey(&outpoint1, &pubkey1, &SigHashType::All).expect("Fail");
  /// ```
  pub fn get_sighash_by_pubkey(
    &self,
    outpoint: &OutPoint,
    pubkey: &Pubkey,
    sighash_type: &SigHashType,
  ) -> Result<Vec<u8>, CfdError> {
    if self.txin_utxo_list.is_empty() {
      return Err(CfdError::IllegalState(
        "Empty txin utxo list. Please call append_utxo_list".to_string(),
      ));
    }
    let ope = TransactionOperation::create_instance(&Network::Mainnet, &self.txin_utxo_list);
    let option = SigHashOption::new(*sighash_type, 0);
    ope.get_sighash(
      &hex_from_bytes(&self.tx),
      outpoint,
      &pubkey.to_hex(),
      &Script::default(),
      &option,
    )
  }

  /// Get signature hash by schnorr pubkey.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `schnorr_pubkey` - A schnorr public key.
  /// * `sighash_type` - A transaction input sighash-type.
  /// * `annex` - An annex bytes.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Pubkey, SchnorrPubkey, SigHashType, Transaction, Descriptor, UtxoData, Network, Address};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey1 = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let pubkey2 = SchnorrPubkey::from_str("d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint1 = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let outpoint2 = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let addr2 = Address::taproot(&pubkey2, &Network::Mainnet).expect("Fail");
  /// let amount1: i64 = 2000000000;
  /// let amount2: i64 = 505000;
  /// let desc1 = Descriptor::p2wpkh(&pubkey1, &Network::Mainnet).expect("Fail");
  /// let utxo1 = UtxoData::from_descriptor(&outpoint1, amount1, &desc1);
  /// let utxo2 = UtxoData::from_address(&outpoint2, amount2, &addr2).expect("Fail");
  /// let tx2 = tx.append_utxo_list(&[utxo1, utxo2]).expect("Fail");
  /// let annex: Vec<u8> = vec![];
  /// let sighash = tx2.get_sighash_by_schnorr_pubkey(&outpoint2, &pubkey2, &SigHashType::Default, &annex).expect("Fail");
  /// ```
  pub fn get_sighash_by_schnorr_pubkey(
    &self,
    outpoint: &OutPoint,
    schnorr_pubkey: &SchnorrPubkey,
    sighash_type: &SigHashType,
    annex: &[u8],
  ) -> Result<Vec<u8>, CfdError> {
    if self.txin_utxo_list.is_empty() {
      return Err(CfdError::IllegalState(
        "Empty txin utxo list. Please call append_utxo_list".to_string(),
      ));
    }
    let ope = TransactionOperation::create_instance(&Network::Mainnet, &self.txin_utxo_list);
    let mut option = SigHashOption::new(*sighash_type, 0);
    option.annex = annex.to_vec();
    ope.get_sighash(
      &hex_from_bytes(&self.tx),
      outpoint,
      &schnorr_pubkey.to_hex(),
      &Script::default(),
      &option,
    )
  }

  /// Get signature hash by redeem script.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `redeem_script` - A redeem script.
  /// * `sighash_type` - A transaction input sighash-type.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Pubkey, Script, SigHashType, Transaction, Descriptor, UtxoData, Network, Address};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey1 = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let outpoint1 = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let outpoint2 = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let addr2 = Address::p2wsh(&script, &Network::Mainnet).expect("Fail");
  /// let amount1: i64 = 2000000000;
  /// let amount2: i64 = 505000;
  /// let desc1 = Descriptor::p2wpkh(&pubkey1, &Network::Mainnet).expect("Fail");
  /// let utxo1 = UtxoData::from_descriptor(&outpoint1, amount1, &desc1);
  /// let utxo2 = UtxoData::from_address(&outpoint2, amount2, &addr2).expect("Fail");
  /// let tx2 = tx.append_utxo_list(&[utxo1, utxo2]).expect("Fail");
  /// let sighash = tx2.get_sighash_by_script(&outpoint2, &script, &SigHashType::Default).expect("Fail");
  /// ```
  pub fn get_sighash_by_script(
    &self,
    outpoint: &OutPoint,
    redeem_script: &Script,
    sighash_type: &SigHashType,
  ) -> Result<Vec<u8>, CfdError> {
    if self.txin_utxo_list.is_empty() {
      return Err(CfdError::IllegalState(
        "Empty txin utxo list. Please call append_utxo_list".to_string(),
      ));
    }
    let ope = TransactionOperation::create_instance(&Network::Mainnet, &self.txin_utxo_list);
    let option = SigHashOption::new(*sighash_type, 0);
    ope.get_sighash(
      &hex_from_bytes(&self.tx),
      outpoint,
      &String::default(),
      &redeem_script,
      &option,
    )
  }

  /// Get signature hash by tapscript.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `tapscript` - A tapscript.
  /// * `sighash_type` - A transaction input sighash-type.
  /// * `code_separator_position` - A OP_CODESEPARATOR position. default is `CODE_SEPARATOR_POSITION_FINAL`.
  /// * `annex` - An annex bytes.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Pubkey, Script, SigHashType, Transaction, Descriptor, UtxoData, Network, Address, SchnorrPubkey, TapBranch, CODE_SEPARATOR_POSITION_FINAL};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey1 = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let schnorr_pubkey = SchnorrPubkey::from_str("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb").expect("Fail");
  /// let script = Script::from_asm(&format!("{} OP_CHECKSIG", schnorr_pubkey.to_hex())).expect("Fail");
  /// let outpoint1 = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let outpoint2 = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tree = TapBranch::from_tapscript(&script).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let (_, addr2, _) = tree.get_tweaked_pubkey(&schnorr_pubkey, &Network::Mainnet).expect("Fail");
  /// let tapleaf_hash = tree.get_tapleaf_hash().expect("Fail");
  /// let amount1: i64 = 2000000000;
  /// let amount2: i64 = 505000;
  /// let desc1 = Descriptor::p2wpkh(&pubkey1, &Network::Mainnet).expect("Fail");
  /// let utxo1 = UtxoData::from_descriptor(&outpoint1, amount1, &desc1);
  /// let utxo2 = UtxoData::from_address(&outpoint2, amount2, &addr2).expect("Fail");
  /// let tx2 = tx.append_utxo_list(&[utxo1, utxo2]).expect("Fail");
  /// let sighash = tx2.get_sighash_by_tapscript(&outpoint2, &tapleaf_hash, &SigHashType::Default, CODE_SEPARATOR_POSITION_FINAL, &[]).expect("Fail");
  /// ```
  pub fn get_sighash_by_tapscript(
    &self,
    outpoint: &OutPoint,
    tapleaf_hash: &[u8; TAPROOT_HASH_SIZE],
    sighash_type: &SigHashType,
    code_separator_position: u32,
    annex: &[u8],
  ) -> Result<Vec<u8>, CfdError> {
    if self.txin_utxo_list.is_empty() {
      return Err(CfdError::IllegalState(
        "Empty txin utxo list. Please call append_utxo_list".to_string(),
      ));
    }
    let ope = TransactionOperation::create_instance(&Network::Mainnet, &self.txin_utxo_list);
    let mut option = SigHashOption::new(*sighash_type, 0);
    option.annex = annex.to_vec();
    option.code_separator_pos = code_separator_position;
    option.tap_leaf_hash = *tapleaf_hash;
    ope.get_sighash(
      &hex_from_bytes(&self.tx),
      outpoint,
      &String::default(),
      &Script::default(),
      &option,
    )
  }

  /// Add signature and pubkey into the transaction.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type. (pubkey hash only)
  /// * `pubkey` - A public key using sign.
  /// * `signature` - A signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_pubkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &pubkey,
  ///   &sighash_type,
  ///   &Amount::new(60000)).expect("Fail");
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
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_pubkey_hash_sign(&tx_hex, outpoint, hash_type, pubkey, signature)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add taproot schnorr signature into the transaction.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `signature` - A schnorr signature. Please set SigHashType.
  /// * `annex` - An annex bytes.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, SchnorrPubkey, SigHashType, Transaction, SchnorrUtil, ByteData};
  /// use std::str::FromStr;
  /// let tx_str = "020000000116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000";
  /// let pubkey = SchnorrPubkey::from_str("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "2fea883042440d030ca5929814ead927075a8f52fef5f4720fa3cec2e475d916",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = ByteData::from_str("e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02").expect("Fail");
  /// let privkey = Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27").expect("Fail");
  /// let util = SchnorrUtil::new();
  /// let aux_rand = ByteData::from_str("f5f4720fa3ead927075a8f52fecec2e40d030ca575d9162fea88304244929814").expect("Fail");
  /// let sig = util.sign(&sighash, &privkey, &aux_rand).expect("Fail");
  /// let signature = sig.get_sign_parameter(&sighash_type);
  /// let signed_tx = tx.add_taproot_signature(&outpoint, &signature, &[]).expect("Fail");
  /// ```
  pub fn add_taproot_signature(
    &self,
    outpoint: &OutPoint,
    signature: &SignParameter,
    annex: &[u8],
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let list = vec![signature.clone()];
    let tx = ope.add_taproot_sign(
      &tx_hex,
      outpoint,
      &list,
      &Script::default(),
      &ByteData::default(),
      annex,
    )?;
    let index = ope.get_last_txin_index();
    let data = ope.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = ope.get_txin_list_cache()[0].clone();
    Ok(tx_obj)
  }

  /// Sign with privkey.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type. (pubkey hash only)
  /// * `privkey` - A private key using sign.
  /// * `sighash_type` - A transaction input sighash-type.
  /// * `amount` - A transaction input amount. (p2pkh is 0)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let signed_tx = tx.sign_with_privkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &privkey,
  ///   &sighash_type,
  ///   &Amount::new(60000)).expect("Fail");
  /// ```
  pub fn sign_with_privkey(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    privkey: &Privkey,
    sighash_type: &SigHashType,
    amount: &Amount,
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let pubkey = privkey.get_pubkey()?;
    let key = KeyPair::new(privkey, &pubkey);
    let option = SigHashOption::new(*sighash_type, amount.as_satoshi_amount());
    let tx = ope.sign_with_privkey(&tx_hex, outpoint, hash_type, &key, &option, true)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Sign with privkey by utxo data.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `privkey` - A private key using sign.
  /// * `sighash_type` - A transaction input sighash-type.
  /// * `aux_rand` - An aux random bytes. (32-byte)
  /// * `annex` - An annex bytes.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, Address, Network, OutPoint, Privkey, SchnorrPubkey, SigHashType, Transaction, UtxoData};
  /// use std::str::FromStr;
  /// let privkey =
  ///   Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
  ///   .expect("Fail");
  /// let (pubkey, _) = SchnorrPubkey::from_privkey(&privkey).expect("Fail");
  /// let tx_hex = "020000000116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000";
  /// let addr = Address::taproot(&pubkey, &Network::Testnet).expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "2fea883042440d030ca5929814ead927075a8f52fef5f4720fa3cec2e475d916", 0).expect("Fail");
  /// let utxos = [UtxoData::from_locking_script(
  ///   &outpoint, 2499999000, addr.get_locking_script(), &Network::Mainnet).expect("Fail"),
  /// ];
  /// let sighash_type = SigHashType::All;
  /// let mut tx = Transaction::from_str(tx_hex).expect("Fail");
  /// tx = tx.append_utxo_list(&utxos).expect("Fail");
  /// tx = tx.sign_with_privkey_by_utxo_list(&outpoint, &privkey, &sighash_type, &[], &[]).expect("Fail");
  /// ```
  pub fn sign_with_privkey_by_utxo_list(
    &self,
    outpoint: &OutPoint,
    privkey: &Privkey,
    sighash_type: &SigHashType,
    aux_rand: &[u8],
    annex: &[u8],
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::create_instance(&Network::Mainnet, &self.txin_utxo_list);
    let tx_hex = hex_from_bytes(&self.tx);
    let mut option = SigHashOption::new(*sighash_type, 0);
    option.annex = annex.to_vec();
    option.aux_rand = aux_rand.to_vec();
    let tx = ope.sign_with_privkey_by_utxo_list(&tx_hex, outpoint, &privkey, &option, true)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add multisig signatures and redeem script into the transaction.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type. (script hash only)
  /// * `redeem_script` - A redeem script using sign.
  /// * `signature_list` - Multiple signature.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, Script, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_script(
  ///   &outpoint,
  ///   &HashType::P2wsh,
  ///   &script,
  ///   &sighash_type,
  ///   &Amount::new(60000)).expect("Fail");
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
  ) -> Result<Transaction, CfdError> {
    if signature_list.is_empty() {
      return Err(CfdError::IllegalArgument(
        "signature list is empty.".to_string(),
      ));
    }
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_multisig_sign(&tx_hex, outpoint, hash_type, redeem_script, signature_list)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add signature manually.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type.
  /// * `sign_data` - A signature or byte data.
  /// * `clear_stack` - Clear to already exist stack.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, SignParameter, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_pubkey(
  ///   &outpoint,
  ///   &HashType::P2wpkh,
  ///   &pubkey,
  ///   &sighash_type,
  ///   &Amount::new(60000)).expect("Fail");
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
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_sign(&tx_hex, outpoint, hash_type, sign_data, clear_stack)?;
    let new_tx_hex = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add redeem script with sign.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type.
  /// * `sign_list` - A transaction sign parameter list.
  /// * `redeem_script` - A redeem script.
  /// * `clear_stack` - Clear to already exist stack.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, Script, SignParameter, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let sighash = tx.create_sighash_by_script(
  ///   &outpoint,
  ///   &HashType::P2wsh,
  ///   &script,
  ///   &sighash_type,
  ///   &Amount::new(60000)).expect("Fail");
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
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
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
    let mut ope2 = ope.clone();
    let new_txin = ope2.get_txin_by_outpoint(&new_tx_hex, outpoint)?;
    let index = ope2.get_last_txin_index();
    let data = ope2.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  /// Add tapscript with sign.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `sign_list` - A transaction sign parameter list.
  /// * `tapscript` - A tapscript.
  /// * `control_block` - A control block.
  /// * `annex` - An annex bytes.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{OutPoint, Script, Transaction, Network, SchnorrPubkey, TapBranch};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let schnorr_pubkey = SchnorrPubkey::from_str("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tree = TapBranch::from_tapscript(&script).expect("Fail");
  /// let (_, _, control_block) = tree.get_tweaked_pubkey(&schnorr_pubkey, &Network::Mainnet).expect("Fail");
  /// let tapleaf_hash = tree.get_tapleaf_hash().expect("Fail");
  /// let mut tx = Transaction::from_str(tx_str).expect("Fail");
  /// tx = tx.add_tapscript_sign(&outpoint, &[], &script, &control_block, &[]).expect("Fail");
  /// ```
  pub fn add_tapscript_sign(
    &self,
    outpoint: &OutPoint,
    sign_list: &[SignParameter],
    tapscript: &Script,
    control_block: &ByteData,
    annex: &[u8],
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let tx = ope.add_taproot_sign(
      &tx_hex,
      outpoint,
      sign_list,
      tapscript,
      control_block,
      annex,
    )?;
    let index = ope.get_last_txin_index();
    let data = ope.get_last_tx_data().clone();
    let mut tx_obj = Transaction {
      tx,
      data,
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
      txin_utxo_list: self.txin_utxo_list.clone(),
    };
    tx_obj.txin_list[index as usize] = ope.get_txin_list_cache()[0].clone();
    Ok(tx_obj)
  }

  /// Verify signature with pubkey.
  ///
  /// # Arguments
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type. (pubkey hash only)
  /// * `pubkey` - A public key using sign.
  /// * `signature` - A signature.
  /// * `amount` - A transaction input amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let amount = Amount::new(60000);
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
    amount: &Amount,
  ) -> Result<bool, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::new(*signature.get_sighash_type(), amount.as_satoshi_amount());
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
  /// * `outpoint` - A transaction input out-point.
  /// * `hash_type` - A transaction input hash type.
  /// * `pubkey` - A public key using sign.
  /// * `redeem_script` - A redeem script using locking script.
  /// * `signature` - A signature.
  /// * `amount` - A transaction input amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, HashType, OutPoint, Privkey, Pubkey, Script, SignParameter, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let script = Script::from_hex("512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae").expect("Fail");
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1",
  ///   1).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let hash_type = HashType::P2wsh;
  /// let amount = Amount::new(60000);
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
    amount: &Amount,
  ) -> Result<bool, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::new(*signature.get_sighash_type(), amount.as_satoshi_amount());
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
  /// * `outpoint` - A transaction input out-point.
  /// * `address` - A transaction input address.
  /// * `amount` - A transaction input amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, Amount, HashType, Network, OutPoint, Privkey, Pubkey, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let amount = Amount::new(60000);
  /// let sighash = tx.create_sighash_by_pubkey(&outpoint, &HashType::P2wpkh, &pubkey, &sighash_type, &amount).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type);
  /// let signed_tx = tx.add_pubkey_hash_sign(&outpoint, &HashType::P2wpkh, &pubkey, &signature,
  /// ).expect("Fail");
  /// let addr = Address::p2wpkh(&pubkey, &Network::Testnet).expect("Fail");
  /// let is_verify = signed_tx.verify_sign_by_address(&outpoint, &addr, &amount).expect("Fail");
  /// ```
  pub fn verify_sign_by_address(
    &self,
    outpoint: &OutPoint,
    address: &Address,
    amount: &Amount,
  ) -> Result<(), CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::from_amount(amount.as_satoshi_amount());
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
  /// * `outpoint` - A transaction input out-point.
  /// * `locking_script` - A transaction input locking script.
  /// * `hash_type` - A signed hash type.
  /// * `amount` - A transaction input amount.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Address, Amount, HashType, Network, OutPoint, Privkey, Pubkey, SigHashType, Transaction};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let sighash_type = SigHashType::All;
  /// let amount = Amount::new(60000);
  /// let sighash = tx.create_sighash_by_pubkey(&outpoint, &HashType::P2wpkh, &pubkey, &sighash_type, &amount).expect("Fail");
  /// let privkey = Privkey::from_wif("cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG").expect("Fail");
  /// let mut signature = privkey.calculate_ec_signature(&sighash, true).expect("Fail");
  /// signature = signature.set_signature_hash(&sighash_type);
  /// let signed_tx = tx.add_pubkey_hash_sign(&outpoint, &HashType::P2wpkh, &pubkey, &signature,
  /// ).expect("Fail");
  /// let addr = Address::p2wpkh(&pubkey, &Network::Testnet).expect("Fail");
  /// let is_verify = signed_tx.verify_sign_by_script(&outpoint, addr.get_locking_script(), &addr.get_address_type().to_hash_type(), &amount).expect("Fail");
  /// ```
  pub fn verify_sign_by_script(
    &self,
    outpoint: &OutPoint,
    locking_script: &Script,
    hash_type: &HashType,
    amount: &Amount,
  ) -> Result<(), CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::from_amount(amount.as_satoshi_amount());
    ope.verify_sign(
      &hex_from_bytes(&self.tx),
      outpoint,
      &Address::default(),
      &hash_type.to_address_type(),
      locking_script,
      &option,
    )
  }

  pub fn verify_sign_by_utxo_list(&self, outpoint: &OutPoint) -> Result<(), CfdError> {
    let ope =
      TransactionOperation::create_instance(&Network::Mainnet, &self.txin_utxo_list.clone());
    ope.verify_sign_by_utxo_list(&hex_from_bytes(&self.tx), outpoint)
  }

  /// Estimate fee on the transaction.
  ///
  /// # Arguments
  /// * `txin_list` - Transaction input utxo data.
  /// * `fee_rate` - A transaction fee rate.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Amount, Descriptor, Network, OutPoint, Pubkey, Transaction, UtxoData};
  /// use std::str::FromStr;
  /// let tx_str = "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000";
  /// let pubkey = Pubkey::from_str("03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b").expect("Fail");
  /// let outpoint = OutPoint::from_str(
  ///   "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd",
  ///   0).expect("Fail");
  /// let descriptor = Descriptor::p2wpkh(&pubkey, &Network::Mainnet).expect("Fail");
  /// let tx = Transaction::from_str(tx_str).expect("Fail");
  /// let amount = Amount::new(60000);
  /// let utxo = UtxoData::from_descriptor(&outpoint, amount.as_satoshi_amount(), &descriptor);
  /// let fee_rate = 20.0;
  /// let fee_data = tx.estimate_fee(&[utxo], fee_rate).expect("Fail");
  /// ```
  pub fn estimate_fee(&self, txin_list: &[UtxoData], fee_rate: f64) -> Result<FeeData, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    ope.estimate_fee(&hex_from_bytes(&self.tx), txin_list, fee_rate)
  }

  /// Select utxo until target amount.
  ///
  /// # Arguments
  /// * `utxo_list` - Utxo data list.
  /// * `tx_fee_amount` - A transaction fee amount.
  /// * `target_amount` - A selection amount.
  /// * `fee_param` - A fee option parameter.
  pub fn select_coins(
    utxo_list: &[UtxoData],
    tx_fee_amount: i64,
    target_amount: i64,
    fee_param: &FeeOption,
  ) -> Result<CoinSelectionData, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    ope.select_coins(utxo_list, tx_fee_amount, target_amount, fee_param)
  }

  /// Fund transaction.
  ///
  /// # Arguments
  /// * `txin_list` - Transaction input utxo data list.
  /// * `utxo_list` - Utxo data list.
  /// * `target_data` - A selection target data.
  /// * `fee_param` - A fee option parameter.
  /// * `fund_data` - (output) A fund transaction's response data.
  pub fn fund_raw_transaction(
    &self,
    txin_list: &[UtxoData],
    utxo_list: &[UtxoData],
    target_data: &FundTargetOption,
    fee_param: &FeeOption,
    fund_data: &mut FundTransactionData,
  ) -> Result<Transaction, CfdError> {
    let (fund_result, tx) = {
      let mut ope = TransactionOperation::new(&Network::Mainnet);
      let (fund_ret, tx_str) = ope.fund_raw_transaction(
        txin_list,
        utxo_list,
        &hex_from_bytes(&self.tx),
        target_data,
        fee_param,
      )?;
      Ok((fund_ret, tx_str))
    }?;
    let tx_obj = Transaction::from_str(&tx)?;
    *fund_data = fund_result;
    Ok(tx_obj)
  }
}

impl FromStr for Transaction {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx = ope.update(text, &[], &[])?;
    let last_tx = ope.get_last_tx();
    let mut ope2 = ope.clone();
    let data = ope2.get_all_data(last_tx)?;
    Ok(Transaction {
      tx,
      data,
      txin_list: ope2.get_txin_list_cache().to_vec(),
      txout_list: ope2.get_txout_list_cache().to_vec(),
      txin_utxo_list: ope2.txin_utxo_list.clone(),
    })
  }
}

impl Default for Transaction {
  fn default() -> Transaction {
    Transaction {
      tx: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec(),
      data: TxData::default(),
      txin_list: vec![],
      txout_list: vec![],
      txin_utxo_list: vec![],
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate) struct SigHashOption {
  pub sighash_type: SigHashType,
  pub amount: i64,
  pub value_byte: ByteData,
  pub aux_rand: Vec<u8>,
  pub annex: Vec<u8>,
  pub tap_leaf_hash: [u8; TAPROOT_HASH_SIZE],
  pub code_separator_pos: u32,
}

impl SigHashOption {
  pub fn new(sighash_type: SigHashType, amount: i64) -> SigHashOption {
    SigHashOption {
      sighash_type,
      amount,
      ..SigHashOption::default()
    }
  }

  pub fn from_amount(amount: i64) -> SigHashOption {
    SigHashOption {
      amount,
      ..SigHashOption::default()
    }
  }
}

impl Default for SigHashOption {
  fn default() -> SigHashOption {
    SigHashOption {
      sighash_type: SigHashType::All,
      amount: 0,
      value_byte: ByteData::default(),
      aux_rand: vec![],
      annex: vec![],
      tap_leaf_hash: [0; 32],
      code_separator_pos: 0xffffffff,
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate) struct HashTypeData {
  pub pubkey: Pubkey,
  pub script: Script,
}

impl HashTypeData {
  pub fn new(pubkey: &Pubkey, script: &Script) -> HashTypeData {
    HashTypeData {
      pubkey: pubkey.clone(),
      script: script.clone(),
    }
  }

  pub fn from_pubkey(pubkey: &Pubkey) -> HashTypeData {
    HashTypeData {
      pubkey: pubkey.clone(),
      script: Script::default(),
    }
  }
}

/// A container that operating transaction base.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate) struct TransactionOperation {
  network: Network,
  last_tx: String,
  txin_list: Vec<TxIn>,
  txout_list: Vec<TxOut>,
  txin_utxo_list: Vec<UtxoData>,
  tx_data: TxData,
  last_txin_index: u32,
}

impl TransactionOperation {
  pub fn new(network: &Network) -> TransactionOperation {
    TransactionOperation {
      network: *network,
      ..TransactionOperation::default()
    }
  }

  pub fn create_instance(network: &Network, utxo_list: &[UtxoData]) -> TransactionOperation {
    TransactionOperation {
      network: *network,
      txin_utxo_list: utxo_list.to_vec(),
      ..TransactionOperation::default()
    }
  }

  pub fn get_last_tx(&self) -> &str {
    &self.last_tx
  }

  pub fn get_last_tx_data(&self) -> &TxData {
    &self.tx_data
  }

  pub fn get_last_txin_index(&self) -> u32 {
    self.last_txin_index
  }

  pub fn create(
    &mut self,
    version: u32,
    locktime: u32,
    txin_list: &[TxInData],
    txout_list: &[TxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    self.create_tx(version, locktime, "", txin_list, txout_list)
  }

  pub fn update(
    &mut self,
    tx: &str,
    txin_list: &[TxInData],
    txout_list: &[TxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    self.create_tx(0, 0, tx, txin_list, txout_list)
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

  pub fn get_all_data(&mut self, tx: &str) -> Result<TxData, CfdError> {
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
  ) -> Result<TxData, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let result = {
      let data = self.get_tx_data_internal(&handle, &tx_data_handle, tx)?;
      let in_count = Self::get_count_internal(&self.network, &handle, &tx_data_handle, tx, true)?;
      let out_count = Self::get_count_internal(&self.network, &handle, &tx_data_handle, tx, false)?;
      let in_indexes = TransactionOperation::create_index_list(in_count);
      let out_indexes = TransactionOperation::create_index_list(out_count);
      let in_data = self.get_tx_input_list_internal(&handle, &tx_data_handle, tx, &in_indexes)?;
      let out_data =
        self.get_tx_output_list_internal(&handle, &tx_data_handle, tx, &out_indexes)?;
      self.txin_list = in_data;
      self.txout_list = out_data;
      Ok(data)
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
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

  pub fn get_txin_list_cache(&self) -> &[TxIn] {
    &self.txin_list
  }
  pub fn get_txout_list_cache(&self) -> &[TxOut] {
    &self.txout_list
  }

  pub fn get_tx_data(&self, tx: &str) -> Result<TxData, CfdError> {
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
  ) -> Result<TxData, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let mut data: TxData = TxData::default();
    let mut txid: *mut c_char = ptr::null_mut();
    let mut wtxid: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetTxInfoByHandle(
        handle.as_handle(),
        tx_data_handle.as_handle(),
        &mut txid,
        &mut wtxid,
        &mut data.size,
        &mut data.vsize,
        &mut data.weight,
        &mut data.version,
        &mut data.locktime,
      )
    };
    let result = match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[txid, wtxid]) }?;
        let txid_ret = Txid::from_str(&str_list[0])?;
        let wtxid_ret = Txid::from_str(&str_list[1])?;
        data.txid = txid_ret;
        data.wtxid = wtxid_ret;
        Ok(data)
      }
      _ => Err(handle.get_error(error_code)),
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  pub fn get_txin_by_outpoint(&mut self, tx: &str, outpoint: &OutPoint) -> Result<TxIn, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_data_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let list_result = {
        let index = {
          let mut index: c_uint = 0;
          let txid = alloc_c_string(&outpoint.txid.to_hex())?;
          let error_code = unsafe {
            CfdGetTxInIndexByHandle(
              handle.as_handle(),
              tx_data_handle.as_handle(),
              txid.as_ptr(),
              outpoint.vout,
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
  ) -> Result<TxIn, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let list_result = {
      let index = {
        let mut index: c_uint = 0;
        let txid = alloc_c_string(&outpoint.txid.to_hex())?;
        let error_code = unsafe {
          CfdGetTxInIndexByHandle(
            handle.as_handle(),
            tx_data_handle.as_handle(),
            txid.as_ptr(),
            outpoint.vout,
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
  ) -> Result<Vec<TxIn>, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let mut list: Vec<TxIn> = vec![];
    list.reserve(indexes.len());

    let result = {
      for index in indexes {
        let item = {
          let mut data: TxIn = TxIn::default();
          let mut txid: *mut c_char = ptr::null_mut();
          let mut script_sig: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdGetTxInByHandle(
              handle.as_handle(),
              tx_data_handle.as_handle(),
              *index,
              &mut txid,
              &mut data.outpoint.vout,
              &mut data.sequence,
              &mut script_sig,
            )
          };
          match error_code {
            0 => {
              let str_list = unsafe { collect_multi_cstring_and_free(&[txid, script_sig]) }?;
              let txid_ret = Txid::from_str(&str_list[0])?;
              let script_ret = Script::from_hex(&str_list[1])?;
              let script_witness = Self::get_tx_input_witness(
                &handle,
                &tx_data_handle,
                *index,
                WITNESS_STACK_TYPE_NORMAL,
              )?;
              data.outpoint.txid = txid_ret;
              data.script_sig = script_ret;
              data.script_witness = script_witness;
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
  ) -> Result<Vec<TxOut>, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let mut list: Vec<TxOut> = vec![];
    list.reserve(indexes.len());

    let result = {
      for index in indexes {
        let item = {
          let mut data: TxOut = TxOut::default();
          let mut locking_script: *mut c_char = ptr::null_mut();
          let mut asset: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdGetTxOutByHandle(
              handle.as_handle(),
              tx_data_handle.as_handle(),
              *index,
              &mut data.amount,
              &mut locking_script,
              &mut asset,
            )
          };
          match error_code {
            0 => {
              let str_list = unsafe { collect_multi_cstring_and_free(&[locking_script, asset]) }?;
              let script_obj = &str_list[0];
              data.locking_script = Script::from_hex(script_obj)?;
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

  /*
  pub fn get_count(&self, tx: &str, is_target_input: bool) -> Result<u32, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = self.get_count_internal(
      &handle, &TxDataHandle::empty(), tx, is_target_input);
    handle.free_handle();
    result
  }
  */

  pub fn get_count_internal(
    network: &Network,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
    is_target_input: bool,
  ) -> Result<u32, CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, network, tx)?,
    };
    let mut count: c_uint = 0;
    let error_code = unsafe {
      if is_target_input {
        CfdGetTxInCountByHandle(handle.as_handle(), tx_data_handle.as_handle(), &mut count)
      } else {
        CfdGetTxOutCountByHandle(handle.as_handle(), tx_data_handle.as_handle(), &mut count)
      }
    };
    let result = match error_code {
      0 => Ok(count),
      _ => Err(handle.get_error(error_code)),
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  pub fn get_txin_index_by_outpoint(&self, tx: &str, outpoint: &OutPoint) -> Result<u32, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut index: c_uint = 0;
    let error_code = unsafe {
      CfdGetTxInIndex(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        &mut index,
      )
    };
    let result = match error_code {
      0 => Ok(index),
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn get_txout_index_by_address(&self, tx: &str, address: &Address) -> Result<u32, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let result = Self::get_txout_index(&handle, &tx_handle, address, &Script::default());
      tx_handle.free_handle(&handle);
      result
    };
    handle.free_handle();
    result
  }

  pub fn get_txout_index_by_script(
    &self,
    tx: &str,
    locking_script: &Script,
  ) -> Result<u32, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let result = Self::get_txout_index(&handle, &tx_handle, &Address::default(), locking_script);
      tx_handle.free_handle(&handle);
      result
    };
    handle.free_handle();
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
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let pubkey_str = alloc_c_string(&pubkey.to_hex())?;
    let script_str = alloc_c_string(&redeem_script.to_hex())?;
    let amount = option.amount;
    let sighash_type = option.sighash_type;
    let mut handle = ErrorHandle::new()?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdCreateSighash(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        hash_type.to_c_value(),
        pubkey_str.as_ptr(),
        script_str.as_ptr(),
        amount,
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

  pub fn get_sighash(
    &self,
    tx: &str,
    outpoint: &OutPoint,
    pubkey: &str,
    redeem_script: &Script,
    option: &SigHashOption,
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let result = {
        self.set_utxo_list(&handle, &tx_handle, &String::default())?;
        let txid = alloc_c_string(&outpoint.txid.to_hex())?;
        let pubkey_str = alloc_c_string(&pubkey)?;
        let script_str = alloc_c_string(&redeem_script.to_hex())?;
        let tapleaf_hash = alloc_c_string(&hex_from_bytes(&option.tap_leaf_hash))?;
        let annex = alloc_c_string(&ByteData::from_slice(&option.annex).to_hex())?;
        let sighash_type = option.sighash_type;
        let mut output: *mut c_char = ptr::null_mut();
        let error_code = unsafe {
          CfdCreateSighashByHandle(
            handle.as_handle(),
            tx_handle.as_handle(),
            txid.as_ptr(),
            outpoint.vout,
            sighash_type.to_c_value(),
            sighash_type.is_anyone_can_pay(),
            pubkey_str.as_ptr(),
            script_str.as_ptr(),
            tapleaf_hash.as_ptr(),
            option.code_separator_pos,
            annex.as_ptr(),
            &mut output,
          )
        };
        match error_code {
          0 => {
            let output_obj = unsafe { collect_cstring_and_free(output) }?;
            Ok(byte_from_hex_unsafe(&output_obj))
          }
          _ => Err(handle.get_error(error_code)),
        }
      };
      tx_handle.free_handle(&handle);
      result
    };
    handle.free_handle();
    result
  }

  pub fn add_sign(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    hash_type: &HashType,
    sign_data: &SignParameter,
    clear_stack: bool,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let sign_data_hex = alloc_c_string(&sign_data.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let sighash_type = sign_data.get_sighash_type();
    let use_der_encoded = match sign_data.to_slice().len() <= 65 {
      true => sign_data.can_use_der_encode(),
      _ => false,
    };
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdAddTxSign(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        hash_type.to_c_value(),
        sign_data_hex.as_ptr(),
        use_der_encoded,
        sighash_type.to_c_value(),
        sighash_type.is_anyone_can_pay(),
        clear_stack,
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

  pub fn add_pubkey_hash_sign(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    signature: &SignParameter,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let pubkey_hex = alloc_c_string(&pubkey.to_hex())?;
    let signature_hex = alloc_c_string(&signature.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let sighash_type = signature.get_sighash_type();
    let use_der_encoded = match signature.to_slice().len() <= 65 {
      true => signature.can_use_der_encode(),
      _ => false,
    };
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdAddPubkeyHashSign(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        hash_type.to_c_value(),
        pubkey_hex.as_ptr(),
        signature_hex.as_ptr(),
        use_der_encoded,
        sighash_type.to_c_value(),
        sighash_type.is_anyone_can_pay(),
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

  pub fn add_script_hash_sign(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    hash_type: &HashType,
    sign_list: &[SignParameter],
    redeem_script: &Script,
    clear_stack: bool,
  ) -> Result<Vec<u8>, CfdError> {
    let mut temp_tx = tx;
    let mut temp_clear_stack = clear_stack;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let script_hex = alloc_c_string(&redeem_script.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let result = {
      let mut tx_hex;
      for sign_data in sign_list {
        tx_hex = {
          let tx_str = alloc_c_string(temp_tx)?;
          let sign_data_hex = alloc_c_string(&sign_data.to_hex())?;
          let use_der_encoded = match sign_data.to_slice().len() <= 65 {
            true => sign_data.can_use_der_encode(),
            _ => false,
          };
          let sighash_type = sign_data.get_sighash_type();
          let mut output: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdAddTxSign(
              handle.as_handle(),
              self.network.to_c_value(),
              tx_str.as_ptr(),
              txid.as_ptr(),
              outpoint.vout,
              hash_type.to_c_value(),
              sign_data_hex.as_ptr(),
              use_der_encoded,
              sighash_type.to_c_value(),
              sighash_type.is_anyone_can_pay(),
              temp_clear_stack,
              &mut output,
            )
          };
          match error_code {
            0 => unsafe { collect_cstring_and_free(output) },
            _ => Err(handle.get_error(error_code)),
          }
        }?;
        temp_tx = &tx_hex;
        temp_clear_stack = false;
      }
      let tx_str = alloc_c_string(temp_tx)?;
      let mut output: *mut c_char = ptr::null_mut();
      let error_code = unsafe {
        CfdAddScriptHashSign(
          handle.as_handle(),
          self.network.to_c_value(),
          tx_str.as_ptr(),
          txid.as_ptr(),
          outpoint.vout,
          hash_type.to_c_value(),
          script_hex.as_ptr(),
          temp_clear_stack,
          &mut output,
        )
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
    handle.free_handle();
    result
  }

  pub fn add_taproot_sign(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    sign_list: &[SignParameter],
    tapscript: &Script,
    control_block: &ByteData,
    annex: &[u8],
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let result = {
        let txid = alloc_c_string(&outpoint.txid.to_hex())?;
        let mut signature = String::default();
        if tapscript.is_empty() && sign_list.len() == 1 {
          let sig = sign_list[0].append_taproot_sighash_type()?;
          signature = sig.to_hex();
        } else {
          let mut clear_flag = true;
          for sign_data in sign_list {
            {
              let sig = sign_data.append_taproot_sighash_type()?;
              let sig_str = alloc_c_string(&sig.to_hex())?;
              let error_code = unsafe {
                CfdAddTxSignByHandle(
                  handle.as_handle(),
                  tx_handle.as_handle(),
                  txid.as_ptr(),
                  outpoint.vout,
                  HashType::Taproot.to_c_value(),
                  sig_str.as_ptr(),
                  false,
                  0,
                  false,
                  clear_flag,
                )
              };
              clear_flag = false;
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?
          }
        }
        {
          let sig_str = alloc_c_string(&signature)?;
          let script_str = alloc_c_string(&tapscript.to_hex())?;
          let control_block_str = alloc_c_string(&control_block.to_hex())?;
          let annex_str = alloc_c_string(&ByteData::from_slice(annex).to_hex())?;
          let error_code = unsafe {
            CfdAddTaprootSignByHandle(
              handle.as_handle(),
              tx_handle.as_handle(),
              txid.as_ptr(),
              outpoint.vout,
              sig_str.as_ptr(),
              script_str.as_ptr(),
              control_block_str.as_ptr(),
              annex_str.as_ptr(),
            )
          };
          if error_code != 0 {
            Err(handle.get_error(error_code))
          } else {
            Ok(())
          }
        }?;
        self.get_txin_by_outpoint_internal(&handle, &tx_handle, &String::default(), outpoint)?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())
      };
      tx_handle.free_handle(&handle);
      result
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
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let pubkey_hex = alloc_c_string(&key.to_pubkey().to_hex())?;
    let privkey_hex = alloc_c_string(&key.to_privkey().to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let sighash_type = option.sighash_type;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdAddSignWithPrivkeySimple(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        hash_type.to_c_value(),
        pubkey_hex.as_ptr(),
        privkey_hex.as_ptr(),
        option.amount,
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

  pub fn sign_with_privkey_by_utxo_list(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    key: &Privkey,
    option: &SigHashOption,
    has_grind_r: bool,
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let result = {
        self.set_utxo_list(&handle, &tx_handle, &String::default())?;
        {
          let txid = alloc_c_string(&outpoint.txid.to_hex())?;
          let privkey_hex = alloc_c_string(&key.to_hex())?;
          let annex = alloc_c_string(&ByteData::from_slice(&option.annex).to_hex())?;
          let aux_rand = alloc_c_string(&ByteData::from_slice(&option.aux_rand).to_hex())?;
          let sighash_type = option.sighash_type;
          let error_code = unsafe {
            CfdAddSignWithPrivkeyByHandle(
              handle.as_handle(),
              tx_handle.as_handle(),
              txid.as_ptr(),
              outpoint.vout,
              privkey_hex.as_ptr(),
              sighash_type.to_c_value(),
              sighash_type.is_anyone_can_pay(),
              has_grind_r,
              aux_rand.as_ptr(),
              annex.as_ptr(),
            )
          };
          match error_code {
            0 => Ok(()),
            _ => Err(handle.get_error(error_code)),
          }
        }?;
        self.get_txin_by_outpoint_internal(&handle, &tx_handle, &String::default(), outpoint)?;
        self.get_tx_internal(&handle, &tx_handle, &String::default())
      };
      tx_handle.free_handle(&handle);
      result
    };
    handle.free_handle();
    result
  }

  pub fn add_multisig_sign(
    &mut self,
    tx: &str,
    outpoint: &OutPoint,
    hash_type: &HashType,
    redeem_script: &Script,
    signature_list: &[SignParameter],
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let script_hex = alloc_c_string(&redeem_script.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let mut multisig_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe { CfdInitializeMultisigSign(handle.as_handle(), &mut multisig_handle) };
    let result = match error_code {
      0 => {
        let ret = {
          for sign_data in signature_list {
            let _err = {
              let signature = alloc_c_string(&sign_data.to_hex())?;
              let related_pubkey = alloc_c_string(&sign_data.get_related_pubkey().to_hex())?;
              let sighash_type = sign_data.get_sighash_type();
              let use_der_encoded = match sign_data.to_slice().len() <= 65 {
                true => sign_data.can_use_der_encode(),
                _ => false,
              };
              let error_code = unsafe {
                if use_der_encoded {
                  CfdAddMultisigSignDataToDer(
                    handle.as_handle(),
                    multisig_handle,
                    signature.as_ptr(),
                    sighash_type.to_c_value(),
                    sighash_type.is_anyone_can_pay(),
                    related_pubkey.as_ptr(),
                  )
                } else {
                  CfdAddMultisigSignData(
                    handle.as_handle(),
                    multisig_handle,
                    signature.as_ptr(),
                    related_pubkey.as_ptr(),
                  )
                }
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          let mut output: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdFinalizeMultisigSign(
              handle.as_handle(),
              multisig_handle,
              self.network.to_c_value(),
              tx_str.as_ptr(),
              txid.as_ptr(),
              outpoint.vout,
              hash_type.to_c_value(),
              script_hex.as_ptr(),
              &mut output,
            )
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
        unsafe {
          CfdFreeMultisigSignHandle(handle.as_handle(), multisig_handle);
        }
        ret
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn verify_signature(
    &self,
    tx: &str,
    outpoint: &OutPoint,
    hash_type: &HashType,
    sign_data: &SignParameter,
    key: &HashTypeData,
    option: &SigHashOption,
  ) -> Result<bool, CfdError> {
    let sig_data = match sign_data.len() {
      64 | 65 => Ok(sign_data.to_hex()),
      _ => {
        let der_decoded = sign_data.to_der_decode()?;
        Ok(der_decoded.to_hex())
      }
    }?;
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let signature = alloc_c_string(&sig_data)?;
    let pubkey_hex = alloc_c_string(&key.pubkey.to_hex())?;
    let script_hex = alloc_c_string(&key.script.to_hex())?;
    let value_byte_hex = alloc_c_string(&option.value_byte.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let sighash_type = sign_data.get_sighash_type();
    let error_code = unsafe {
      CfdVerifySignature(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        signature.as_ptr(),
        hash_type.to_c_value(),
        pubkey_hex.as_ptr(),
        script_hex.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        sighash_type.to_c_value(),
        sighash_type.is_anyone_can_pay(),
        option.amount,
        value_byte_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(true),
      7 => Ok(false),
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn verify_sign(
    &self,
    tx: &str,
    outpoint: &OutPoint,
    address: &Address,
    address_type: &AddressType,
    locking_script: &Script,
    option: &SigHashOption,
  ) -> Result<(), CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let address_str = alloc_c_string(address.to_str())?;
    let script_hex = alloc_c_string(&locking_script.to_hex())?;
    let value_byte_hex = alloc_c_string(&option.value_byte.to_hex())?;
    let mut handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifyTxSign(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        address_str.as_ptr(),
        address_type.to_c_value(),
        script_hex.as_ptr(),
        option.amount,
        value_byte_hex.as_ptr(),
      )
    };
    let result = match error_code {
      0 => Ok(()),
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn verify_sign_by_utxo_list(&self, tx: &str, outpoint: &OutPoint) -> Result<(), CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::new(&handle, &self.network, tx)?;
      let result = {
        self.set_utxo_list(&handle, &tx_handle, &String::default())?;
        self.verify_sign_by_handle(&handle, &tx_handle, &String::default(), outpoint)
      };
      tx_handle.free_handle(&handle);
      result
    };
    handle.free_handle();
    result
  }

  fn set_utxo_list(
    &self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
  ) -> Result<(), CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };

    let result = {
      for utxo in self.txin_utxo_list.as_slice() {
        {
          let txid = alloc_c_string(&utxo.outpoint.txid.to_hex())?;
          let commitment = alloc_c_string(&String::default())?;
          let descriptor = alloc_c_string(utxo.descriptor.to_str())?;
          let address = alloc_c_string(&String::default())?;
          let asset = alloc_c_string(&String::default())?;
          let script_template = alloc_c_string(&utxo.scriptsig_template.to_hex())?;
          let error_code = unsafe {
            CfdSetTransactionUtxoData(
              handle.as_handle(),
              tx_data_handle.as_handle(),
              txid.as_ptr(),
              utxo.outpoint.vout,
              utxo.amount,
              commitment.as_ptr(),
              descriptor.as_ptr(),
              address.as_ptr(),
              asset.as_ptr(),
              script_template.as_ptr(),
              false,
            )
          };
          match error_code {
            0 => Ok(()),
            _ => Err(handle.get_error(error_code)),
          }
        }?;
      }
      Ok(())
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  fn verify_sign_by_handle(
    &self,
    handle: &ErrorHandle,
    tx_handle: &TxDataHandle,
    tx: &str,
    outpoint: &OutPoint,
  ) -> Result<(), CfdError> {
    let tx_data_handle = match tx_handle.is_null() {
      false => tx_handle.clone(),
      _ => TxDataHandle::new(&handle, &self.network, tx)?,
    };
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let error_code = unsafe {
      CfdVerifyTxSignByHandle(
        handle.as_handle(),
        tx_data_handle.as_handle(),
        txid.as_ptr(),
        outpoint.vout,
      )
    };
    let result = match error_code {
      0 => Ok(()),
      _ => Err(handle.get_error(error_code)),
    };
    if tx_handle.is_null() {
      tx_data_handle.free_handle(&handle);
    }
    result
  }

  pub fn estimate_fee(
    &self,
    tx: &str,
    txin_list: &[UtxoData],
    fee_rate: f64,
  ) -> Result<FeeData, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let empty_str = alloc_c_string("")?;
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
              let txid = alloc_c_string(&txin_data.outpoint.txid.to_hex())?;
              let descriptor = alloc_c_string(&txin_data.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&txin_data.scriptsig_template.to_hex())?;
              let error_code = unsafe {
                CfdAddTxInTemplateForEstimateFee(
                  handle.as_handle(),
                  fee_handle,
                  txid.as_ptr(),
                  txin_data.outpoint.vout,
                  descriptor.as_ptr(),
                  empty_str.as_ptr(),
                  false,
                  false,
                  false,
                  0,
                  empty_str.as_ptr(),
                  sig_tmpl.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          let mut fee_data = FeeData::default();
          let error_code = unsafe {
            CfdFinalizeEstimateFee(
              handle.as_handle(),
              fee_handle,
              tx_str.as_ptr(),
              empty_str.as_ptr(),
              &mut fee_data.txout_fee,
              &mut fee_data.utxo_fee,
              false,
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
    utxo_list: &[UtxoData],
    tx_fee_amount: i64,
    target_amount: i64,
    fee_param: &FeeOption,
  ) -> Result<CoinSelectionData, CfdError> {
    let empty_str = alloc_c_string("")?;
    let mut handle = ErrorHandle::new()?;
    let mut coin_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeCoinSelection(
        handle.as_handle(),
        utxo_list.len() as c_uint,
        1,
        empty_str.as_ptr(),
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
              let txid = alloc_c_string(&utxo_data.outpoint.txid.to_hex())?;
              let descriptor = alloc_c_string(&utxo_data.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&utxo_data.scriptsig_template.to_hex())?;
              let error_code = unsafe {
                CfdAddCoinSelectionUtxoTemplate(
                  handle.as_handle(),
                  coin_handle,
                  index as i32,
                  txid.as_ptr(),
                  utxo_data.outpoint.vout,
                  utxo_data.amount,
                  empty_str.as_ptr(),
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
          let _ret = {
            let error_code = unsafe {
              CfdAddCoinSelectionAmount(
                handle.as_handle(),
                coin_handle,
                0,
                target_amount,
                empty_str.as_ptr(),
              )
            };
            match error_code {
              0 => Ok(()),
              _ => Err(handle.get_error(error_code)),
            }
          }?;
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
          let mut select_utxo_list: Vec<UtxoData> = vec![];
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
          Ok(CoinSelectionData::new(select_utxo_list, utxo_fee_amount))
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
    txin_list: &[UtxoData],
    utxo_list: &[UtxoData],
    tx: &str,
    target_data: &FundTargetOption,
    fee_param: &FeeOption,
  ) -> Result<(FundTransactionData, String), CfdError> {
    let network = match target_data.reserved_address.valid() {
      true => match target_data.reserved_address.get_network_type() {
        Network::Mainnet | Network::Testnet | Network::Regtest => {
          target_data.reserved_address.get_network_type()
        }
        _ => &Network::Mainnet,
      },
      _ => &Network::Mainnet,
    };
    let empty_str = alloc_c_string("")?;
    let tx_hex = alloc_c_string(tx)?;
    let mut handle = ErrorHandle::new()?;
    let mut fund_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeFundRawTx(
        handle.as_handle(),
        network.to_c_value(),
        1,
        empty_str.as_ptr(),
        &mut fund_handle,
      )
    };
    let result = match error_code {
      0 => {
        let ret = {
          for txin_data in txin_list {
            let _err = {
              let txid = alloc_c_string(&txin_data.outpoint.txid.to_hex())?;
              let descriptor = alloc_c_string(&txin_data.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&txin_data.scriptsig_template.to_hex())?;
              let error_code = unsafe {
                CfdAddTxInTemplateForFundRawTx(
                  handle.as_handle(),
                  fund_handle,
                  txid.as_ptr(),
                  txin_data.outpoint.vout,
                  txin_data.amount,
                  descriptor.as_ptr(),
                  empty_str.as_ptr(),
                  false,
                  false,
                  false,
                  0,
                  empty_str.as_ptr(),
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
              let txid = alloc_c_string(&utxo_data.outpoint.txid.to_hex())?;
              let descriptor = alloc_c_string(&utxo_data.descriptor.to_str())?;
              let sig_tmpl = alloc_c_string(&utxo_data.scriptsig_template.to_hex())?;
              let error_code = unsafe {
                CfdAddUtxoTemplateForFundRawTx(
                  handle.as_handle(),
                  fund_handle,
                  txid.as_ptr(),
                  utxo_data.outpoint.vout,
                  utxo_data.amount,
                  descriptor.as_ptr(),
                  empty_str.as_ptr(),
                  sig_tmpl.as_ptr(),
                )
              };
              match error_code {
                0 => Ok(()),
                _ => Err(handle.get_error(error_code)),
              }
            }?;
          }
          let _ret = {
            let addr = alloc_c_string(target_data.reserved_address.to_str())?;
            let error_code = unsafe {
              CfdAddTargetAmountForFundRawTx(
                handle.as_handle(),
                fund_handle,
                0,
                target_data.target_amount,
                empty_str.as_ptr(),
                addr.as_ptr(),
              )
            };
            match error_code {
              0 => Ok(()),
              _ => Err(handle.get_error(error_code)),
            }
          }?;

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
                  Address::from_str(&addr_str)
                }
                _ => Err(handle.get_error(error_code)),
              }
            }?;
            used_addr_list.push(address);
            index += 1;
          }
          self.last_tx = output_tx.clone();
          Ok((FundTransactionData::new(used_addr_list, tx_fee), output_tx))
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

  pub fn get_tx_input_witness(
    handle: &ErrorHandle,
    tx_data_handle: &TxDataHandle,
    index: u32,
    stack_type: c_int,
  ) -> Result<ScriptWitness, CfdError> {
    let mut count: c_uint = 0;
    let error_code = unsafe {
      CfdGetTxInWitnessCountByHandle(
        handle.as_handle(),
        tx_data_handle.as_handle(),
        stack_type,
        index,
        &mut count,
      )
    };
    match error_code {
      0 => {
        let mut list: Vec<ByteData> = vec![];
        let mut stack_index = 0;
        while stack_index < count {
          let stack_bytes = {
            let mut stack_data: *mut c_char = ptr::null_mut();
            let error_code = unsafe {
              CfdGetTxInWitnessByHandle(
                handle.as_handle(),
                tx_data_handle.as_handle(),
                stack_type,
                index,
                stack_index,
                &mut stack_data,
              )
            };
            match error_code {
              0 => {
                let data_obj = unsafe { collect_cstring_and_free(stack_data) }?;
                ByteData::from_str(&data_obj)
              }
              _ => Err(handle.get_error(error_code)),
            }
          }?;
          list.push(stack_bytes);
          stack_index += 1;
        }
        if list.len() == count as usize {
          Ok(ScriptWitness::new(&list))
        } else {
          Err(CfdError::Unknown(
            "Failed to get_tx_input_witness.".to_string(),
          ))
        }
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  fn get_txout_index(
    handle: &ErrorHandle,
    tx_data_handle: &TxDataHandle,
    address: &Address,
    locking_script: &Script,
  ) -> Result<u32, CfdError> {
    let addr = alloc_c_string(address.to_str())?;
    let script = alloc_c_string(&locking_script.to_hex())?;
    let mut index: c_uint = 0;
    let error_code = unsafe {
      CfdGetTxOutIndexByHandle(
        handle.as_handle(),
        tx_data_handle.as_handle(),
        addr.as_ptr(),
        script.as_ptr(),
        &mut index,
      )
    };
    match error_code {
      0 => Ok(index),
      _ => Err(handle.get_error(error_code)),
    }
  }

  fn create_tx(
    &mut self,
    version: u32,
    locktime: u32,
    tx: &str,
    txin_list: &[TxInData],
    txout_list: &[TxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let tx_handle = TxDataHandle::create(&handle, &self.network, version, locktime, tx)?;
      let ret = {
        for input in txin_list {
          let _err = {
            let txid = alloc_c_string(&input.outpoint.txid.to_hex())?;
            let error_code = unsafe {
              CfdAddTransactionInput(
                handle.as_handle(),
                tx_handle.as_handle(),
                txid.as_ptr(),
                input.outpoint.vout,
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
            let address = alloc_c_string(output.address.to_str())?;
            let script = alloc_c_string(&output.locking_script.to_hex())?;
            let asset = alloc_c_string(&output.asset)?;
            let error_code = unsafe {
              CfdAddTransactionOutput(
                handle.as_handle(),
                tx_handle.as_handle(),
                output.amount,
                address.as_ptr(),
                script.as_ptr(),
                asset.as_ptr(),
              )
            };
            match error_code {
              0 => Ok(()),
              _ => Err(handle.get_error(error_code)),
            }
          }?;
        }
        self.get_tx_internal(&handle, &tx_handle, &String::default())
      };
      tx_handle.free_handle(&handle);
      ret
    };
    handle.free_handle();
    result
  }
}

impl Default for TransactionOperation {
  fn default() -> TransactionOperation {
    TransactionOperation {
      network: Network::Mainnet,
      last_tx: String::default(),
      txin_list: vec![],
      txout_list: vec![],
      txin_utxo_list: vec![],
      tx_data: TxData::default(),
      last_txin_index: 0,
    }
  }
}

/// A container that tx data handler.
#[derive(Debug, Clone)]
pub(in crate) struct TxDataHandle {
  tx_handle: *mut c_void,
}

impl TxDataHandle {
  pub fn new(handle: &ErrorHandle, network: &Network, tx: &str) -> Result<TxDataHandle, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let mut tx_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeTxDataHandle(
        handle.as_handle(),
        network.to_c_value(),
        tx_str.as_ptr(),
        &mut tx_handle,
      )
    };
    match error_code {
      0 => Ok(TxDataHandle { tx_handle }),
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub fn create(
    handle: &ErrorHandle,
    network: &Network,
    version: u32,
    locktime: u32,
    tx: &str,
  ) -> Result<TxDataHandle, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let mut tx_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeTransaction(
        handle.as_handle(),
        network.to_c_value(),
        version,
        locktime,
        tx_str.as_ptr(),
        &mut tx_handle,
      )
    };
    match error_code {
      0 => Ok(TxDataHandle { tx_handle }),
      _ => Err(handle.get_error(error_code)),
    }
  }

  #[inline]
  pub fn as_handle(&self) -> *const c_void {
    self.tx_handle
  }

  pub fn free_handle(&self, handle: &ErrorHandle) {
    unsafe {
      CfdFreeTxDataHandle(handle.as_handle(), self.tx_handle);
    }
  }

  pub fn empty() -> TxDataHandle {
    TxDataHandle {
      tx_handle: ptr::null_mut(),
    }
  }

  pub fn is_null(&self) -> bool {
    self.tx_handle.is_null()
  }
}

#[derive(Debug, PartialEq, Clone)]
pub(in crate) enum FundOptionValue {
  Long(i64),
  Double(f64),
  Bool(bool),
}

pub(in crate) fn set_fund_tx_option(
  handle: &ErrorHandle,
  fund_handle: *const c_void,
  key: i32,
  value: FundOptionValue,
) -> Result<(), CfdError> {
  let mut longlong_value = 0;
  let mut float_value = 0.0;
  let mut is_bool = false;
  match value {
    FundOptionValue::Long(value) => longlong_value = value,
    FundOptionValue::Double(value) => float_value = value,
    FundOptionValue::Bool(value) => is_bool = value,
  }
  let error_code = unsafe {
    CfdSetOptionFundRawTx(
      handle.as_handle(),
      fund_handle,
      key,
      longlong_value,
      float_value,
      is_bool,
    )
  };
  match error_code {
    0 => Ok(()),
    _ => Err(handle.get_error(error_code)),
  }
}
