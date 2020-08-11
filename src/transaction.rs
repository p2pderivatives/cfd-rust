extern crate cfd_sys;
extern crate libc;

// use self::cfd_sys as ffi;
use self::libc::{c_char, c_uint, c_void};
use crate::address::{Address, HashType};
use crate::common::{
  alloc_c_string, byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free,
  collect_multi_cstring_and_free, hex_from_bytes, Amount, ByteData, CfdError, ErrorHandle, Network,
};
use crate::descriptor::Descriptor;
use crate::key::{KeyPair, Privkey, Pubkey, SigHashType, SignParameter};
use crate::script::Script;
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdAddMultisigSignData, CfdAddMultisigSignDataToDer, CfdAddPubkeyHashSign, CfdAddScriptHashSign,
  CfdAddSignWithPrivkeySimple, CfdAddTransactionInput, CfdAddTransactionOutput, CfdAddTxSign,
  CfdCreateSighash, CfdFinalizeMultisigSign, CfdFinalizeTransaction, CfdFreeMultisigSignHandle,
  CfdFreeTransactionHandle, CfdGetTxIn, CfdGetTxInCount, CfdGetTxInIndex, CfdGetTxInWitness,
  CfdGetTxInWitnessCount, CfdGetTxInfo, CfdGetTxOut, CfdGetTxOutCount, CfdGetTxOutIndex,
  CfdInitializeMultisigSign, CfdInitializeTransaction, CfdUpdateTxOutAmount, CfdVerifySignature,
  CfdVerifyTxSign,
};

/// disable locktime
pub const SEQUENCE_LOCK_TIME_DISABLE: u32 = 0xffffffff;
/// enable locktime (maximum time)
pub const SEQUENCE_LOCK_TIME_ENABLE_MAX: u32 = 0xfffffffe;

pub const TXID_SIZE: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid {
  txid: [u8; TXID_SIZE],
}

impl Txid {
  pub fn from_slice(txid: &[u8; TXID_SIZE]) -> Txid {
    Txid { txid: *txid }
  }

  #[inline]
  pub fn to_slice(&self) -> &[u8; TXID_SIZE] {
    &self.txid
  }

  pub fn to_hex(&self) -> String {
    let byte_data = ByteData::from_slice_reverse(&self.txid);
    byte_data.to_hex()
  }
}

impl FromStr for Txid {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Txid, CfdError> {
    let bytes = byte_from_hex(text)?;
    if bytes.len() != TXID_SIZE {
      Err(CfdError::IllegalArgument(
        "invalid txid length.".to_string(),
      ))
    } else {
      let byte_data = ByteData::from_slice_reverse(&bytes);
      let reverse_bytes = byte_data.to_slice();
      let mut txid = Txid::default();
      let result = slice_as_array!(&reverse_bytes, [u8; TXID_SIZE]);
      if let Some(value) = result {
        txid.txid = *value;
      }
      Ok(txid)
    }
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
      txid: [0; TXID_SIZE],
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OutPoint {
  txid: Txid,
  vout: u32,
}

impl OutPoint {
  pub fn new(txid: &Txid, vout: u32) -> OutPoint {
    OutPoint {
      txid: txid.clone(),
      vout,
    }
  }

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ScriptWitness {
  pub witness_stack: Vec<ByteData>,
}

impl ScriptWitness {
  pub fn new(list: &[ByteData]) -> ScriptWitness {
    ScriptWitness {
      witness_stack: list.to_vec(),
    }
  }

  pub fn get_stack(&self, index: u32) -> Result<&ByteData, CfdError> {
    match self.witness_stack.len() <= index as usize {
      true => Err(CfdError::IllegalArgument("invalid index.".to_string())),
      _ => Ok(&self.witness_stack[index as usize]),
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UtxoData {
  pub outpoint: OutPoint,
  pub amount: i64,
  pub descriptor: Descriptor,
  pub scriptsig_template: Script,
}

impl UtxoData {
  pub fn from_outpoint(outpoint: &OutPoint, amount: i64) -> UtxoData {
    UtxoData {
      outpoint: outpoint.clone(),
      amount,
      descriptor: Descriptor::default(),
      scriptsig_template: Script::default(),
    }
  }
  pub fn from_descriptor(outpoint: &OutPoint, amount: i64, descriptor: &Descriptor) -> UtxoData {
    UtxoData {
      outpoint: outpoint.clone(),
      amount,
      descriptor: descriptor.clone(),
      scriptsig_template: Script::default(),
    }
  }
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
    TxData {
      txid: Txid::default(),
      wtxid: Txid::default(),
      size: 10,
      vsize: 10,
      weight: 40,
      version: 2,
      locktime: 0,
    }
  }
}

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
      sequence: SEQUENCE_LOCK_TIME_DISABLE,
      script_sig: Script::default(),
    }
  }
}

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
      sequence: SEQUENCE_LOCK_TIME_DISABLE,
      script_sig: Script::default(),
      script_witness: ScriptWitness::default(),
    }
  }
}

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Transaction {
  tx: Vec<u8>,
  data: TxData,
  txin_list: Vec<TxIn>,
  txout_list: Vec<TxOut>,
}

impl Transaction {
  pub fn to_str(&self) -> String {
    hex_from_bytes(&self.tx)
  }
  pub fn to_bytes(&self) -> &[u8] {
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

  pub fn new(version: u32, locktime: u32) -> Result<Transaction, CfdError> {
    Transaction::create_tx(version, locktime, &[], &[])
  }

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
    })
  }

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
    })
  }

  pub fn update_amount(&self, index: u32, amount: i64) -> Result<Transaction, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let tx = ope.update_output_amount(&hex_from_bytes(&self.tx), index, amount)?;
    let mut tx_obj = Transaction {
      tx,
      data: self.data.clone(),
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
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

  pub fn add_pubkey_hash_sign(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    pubkey: &Pubkey,
    signature: &SignParameter,
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let index = ope.get_txin_index_by_outpoint(&tx_hex, outpoint)?;
    let tx = ope.add_pubkey_hash_sign(&tx_hex, outpoint, hash_type, pubkey, signature)?;
    let new_tx_hex = ope.get_last_tx();
    let new_txin = ope.get_tx_input(&new_tx_hex, index)?;
    let mut tx_obj = Transaction {
      tx,
      data: self.data.clone(),
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

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
    let index = ope.get_txin_index_by_outpoint(&tx_hex, outpoint)?;
    let pubkey = privkey.get_pubkey()?;
    let key = KeyPair::new(privkey, &pubkey);
    let option = SigHashOption::new(*sighash_type, amount.as_satoshi_amount());
    let tx = ope.sign_with_privkey(&tx_hex, outpoint, hash_type, &key, &option, true)?;
    let new_tx_hex = ope.get_last_tx();
    let new_txin = ope.get_tx_input(&new_tx_hex, index)?;
    let mut tx_obj = Transaction {
      tx,
      data: self.data.clone(),
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

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
    let index = ope.get_txin_index_by_outpoint(&tx_hex, outpoint)?;
    let tx = ope.add_multisig_sign(&tx_hex, outpoint, hash_type, redeem_script, signature_list)?;
    let new_tx_hex = ope.get_last_tx();
    let new_txin = ope.get_tx_input(&new_tx_hex, index)?;
    let mut tx_obj = Transaction {
      tx,
      data: self.data.clone(),
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  pub fn add_sign(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    sign_data: &SignParameter,
    clear_stack: bool,
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let index = ope.get_txin_index_by_outpoint(&tx_hex, outpoint)?;
    let tx = ope.add_sign(&tx_hex, outpoint, hash_type, sign_data, clear_stack)?;
    let new_tx_hex = ope.get_last_tx();
    let new_txin = ope.get_tx_input(&new_tx_hex, index)?;
    let mut tx_obj = Transaction {
      tx,
      data: self.data.clone(),
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

  pub fn add_script_hash_sign(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    redeem_script: &Script,
    clear_stack: bool,
  ) -> Result<Transaction, CfdError> {
    let mut ope = TransactionOperation::new(&Network::Mainnet);
    let tx_hex = hex_from_bytes(&self.tx);
    let index = ope.get_txin_index_by_outpoint(&tx_hex, outpoint)?;
    let tx = ope.add_script_hash_sign(&tx_hex, outpoint, hash_type, redeem_script, clear_stack)?;
    let new_tx_hex = ope.get_last_tx();
    let new_txin = ope.get_tx_input(&new_tx_hex, index)?;
    let mut tx_obj = Transaction {
      tx,
      data: self.data.clone(),
      txin_list: self.txin_list.clone(),
      txout_list: self.txout_list.clone(),
    };
    tx_obj.txin_list[index as usize] = new_txin;
    Ok(tx_obj)
  }

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

  pub fn verify_signature_by_script(
    &self,
    outpoint: &OutPoint,
    hash_type: &HashType,
    redeem_script: &Script,
    signature: &SignParameter,
    amount: &Amount,
  ) -> Result<bool, CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::new(*signature.get_sighash_type(), amount.as_satoshi_amount());
    let key = HashTypeData::from_script(redeem_script);
    ope.verify_signature(
      &hex_from_bytes(&self.tx),
      outpoint,
      hash_type,
      signature,
      &key,
      &option,
    )
  }

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
      &Script::default(),
      &option,
    )
  }

  pub fn verify_sign_by_script(
    &self,
    outpoint: &OutPoint,
    locking_script: &Script,
    amount: &Amount,
  ) -> Result<(), CfdError> {
    let ope = TransactionOperation::new(&Network::Mainnet);
    let option = SigHashOption::from_amount(amount.as_satoshi_amount());
    ope.verify_sign(
      &hex_from_bytes(&self.tx),
      outpoint,
      &Address::default(),
      locking_script,
      &option,
    )
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
    })
  }
}

impl Default for Transaction {
  fn default() -> Transaction {
    match Transaction::new(2, 0) {
      Ok(tx) => tx,
      _ => Transaction {
        tx: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec(),
        data: TxData::default(),
        txin_list: vec![],
        txout_list: vec![],
      },
    }
  }
}

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub struct CoinSelectionUtil {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate) struct SigHashOption {
  sighash_type: SigHashType,
  amount: i64,
  value_byte: ByteData,
}

impl SigHashOption {
  pub fn new(sighash_type: SigHashType, amount: i64) -> SigHashOption {
    SigHashOption {
      sighash_type,
      amount,
      value_byte: ByteData::default(),
    }
  }

  pub fn from_amount(amount: i64) -> SigHashOption {
    SigHashOption {
      sighash_type: SigHashType::All,
      amount,
      value_byte: ByteData::default(),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate) struct HashTypeData {
  pubkey: Pubkey,
  script: Script,
}

impl HashTypeData {
  pub fn from_pubkey(pubkey: &Pubkey) -> HashTypeData {
    HashTypeData {
      pubkey: pubkey.clone(),
      script: Script::default(),
    }
  }

  pub fn from_script(script: &Script) -> HashTypeData {
    HashTypeData {
      pubkey: Pubkey::default(),
      script: script.clone(),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate) struct TransactionOperation {
  network: Network,
  last_tx: String,
  txin_list: Vec<TxIn>,
  txout_list: Vec<TxOut>,
}

impl TransactionOperation {
  pub fn new(network: &Network) -> TransactionOperation {
    TransactionOperation {
      network: *network,
      last_tx: String::default(),
      txin_list: vec![],
      txout_list: vec![],
    }
  }

  pub fn get_last_tx(&self) -> &str {
    &self.last_tx
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
    &self,
    tx: &str,
    index: u32,
    amount: i64,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let handle = ErrorHandle::new()?;
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
        Ok(byte_from_hex_unsafe(&output_obj))
      }
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn get_all_data(&mut self, tx: &str) -> Result<TxData, CfdError> {
    let data = self.get_tx_data(tx)?;
    let in_count = self.get_count(tx, true)?;
    let out_count = self.get_count(tx, false)?;
    let in_indexes = TransactionOperation::create_index_list(in_count);
    let out_indexes = TransactionOperation::create_index_list(out_count);

    let in_data = self.get_tx_input_list(tx, &in_indexes)?;
    let out_data = self.get_tx_output_list(tx, &out_indexes)?;
    self.txin_list = in_data;
    self.txout_list = out_data;
    Ok(data)
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
    let tx_str = alloc_c_string(tx)?;
    let handle = ErrorHandle::new()?;
    let mut data: TxData = TxData::default();
    let mut txid: *mut c_char = ptr::null_mut();
    let mut wtxid: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetTxInfo(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
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
    handle.free_handle();
    result
  }

  pub fn get_tx_input(&self, tx: &str, index: u32) -> Result<TxIn, CfdError> {
    let indexes = vec![index];
    let list = self.get_tx_input_list(tx, &indexes)?;
    if list.is_empty() {
      Err(CfdError::Internal("Failed to empty list.".to_string()))
    } else {
      Ok(list[0].clone())
    }
  }

  pub fn get_tx_input_list(&self, tx: &str, indexes: &[u32]) -> Result<Vec<TxIn>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let handle = ErrorHandle::new()?;
    let mut list: Vec<TxIn> = vec![];
    list.reserve(indexes.len());

    let result = {
      for index in indexes {
        let item = {
          let mut data: TxIn = TxIn::default();
          let mut txid: *mut c_char = ptr::null_mut();
          let mut script_sig: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdGetTxIn(
              handle.as_handle(),
              self.network.to_c_value(),
              tx_str.as_ptr(),
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
              let script_witness = self.get_tx_input_witness(&handle, &tx_str, *index)?;
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
    handle.free_handle();
    result
  }

  /*
  pub fn get_tx_output(&self, tx: &str, index: u32) -> Result<TxOut, CfdError> {
    let indexes = vec![index];
    let result = self.get_tx_output_list(tx, &indexes);
    if let Err(e) = result {
      Err(e)
    } else {
      let list = result.unwrap();
      if list.is_empty() {
        Err(CfdError::Internal("Failed to empty list.".to_string()))
      } else {
        Ok(list[0].clone())
      }
    }
  }
  */

  pub fn get_tx_output_list(&self, tx: &str, indexes: &[u32]) -> Result<Vec<TxOut>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let handle = ErrorHandle::new()?;
    let mut list: Vec<TxOut> = vec![];
    list.reserve(indexes.len());

    let result = {
      for index in indexes {
        let item = {
          let mut data: TxOut = TxOut::default();
          let mut locking_script: *mut c_char = ptr::null_mut();
          let error_code = unsafe {
            CfdGetTxOut(
              handle.as_handle(),
              self.network.to_c_value(),
              tx_str.as_ptr(),
              *index,
              &mut data.amount,
              &mut locking_script,
            )
          };
          match error_code {
            0 => {
              let script_obj = unsafe { collect_cstring_and_free(locking_script) }?;
              data.locking_script = Script::from_hex(&script_obj)?;
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
    handle.free_handle();
    result
  }

  pub fn get_count(&self, tx: &str, is_target_input: bool) -> Result<u32, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let handle = ErrorHandle::new()?;
    let mut count: c_uint = 0;
    let error_code = unsafe {
      if is_target_input {
        CfdGetTxInCount(
          handle.as_handle(),
          self.network.to_c_value(),
          tx_str.as_ptr(),
          &mut count,
        )
      } else {
        CfdGetTxOutCount(
          handle.as_handle(),
          self.network.to_c_value(),
          tx_str.as_ptr(),
          &mut count,
        )
      }
    };
    let result = match error_code {
      0 => Ok(count),
      _ => Err(handle.get_error(error_code)),
    };
    handle.free_handle();
    result
  }

  pub fn get_txin_index_by_outpoint(&self, tx: &str, outpoint: &OutPoint) -> Result<u32, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let handle = ErrorHandle::new()?;
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
    self.get_txout_index(tx, address, &Script::default())
  }

  pub fn get_txout_index_by_script(
    &self,
    tx: &str,
    locking_script: &Script,
  ) -> Result<u32, CfdError> {
    self.get_txout_index(tx, &Address::default(), locking_script)
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
    let handle = ErrorHandle::new()?;
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
    let handle = ErrorHandle::new()?;
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
        sign_data.can_use_der_encode(),
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
    let handle = ErrorHandle::new()?;
    let sighash_type = signature.get_sighash_type();
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
        signature.can_use_der_encode(),
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
    redeem_script: &Script,
    clear_stack: bool,
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let script_hex = alloc_c_string(&redeem_script.to_hex())?;
    let handle = ErrorHandle::new()?;
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
    let handle = ErrorHandle::new()?;
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
    let handle = ErrorHandle::new()?;
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
              let error_code = unsafe {
                if sign_data.can_use_der_encode() {
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
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let signature = alloc_c_string(&sign_data.to_hex())?;
    let pubkey_hex = alloc_c_string(&key.pubkey.to_hex())?;
    let script_hex = alloc_c_string(&key.script.to_hex())?;
    let value_byte_hex = alloc_c_string(&option.value_byte.to_hex())?;
    let handle = ErrorHandle::new()?;
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
    locking_script: &Script,
    option: &SigHashOption,
  ) -> Result<(), CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let txid = alloc_c_string(&outpoint.txid.to_hex())?;
    let address_str = alloc_c_string(address.to_str())?;
    let script_hex = alloc_c_string(&locking_script.to_hex())?;
    let value_byte_hex = alloc_c_string(&option.value_byte.to_hex())?;
    let handle = ErrorHandle::new()?;
    let error_code = unsafe {
      CfdVerifyTxSign(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        txid.as_ptr(),
        outpoint.vout,
        address_str.as_ptr(),
        address.get_address_type().to_c_value(),
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

  fn get_tx_input_witness(
    &self,
    handle: &ErrorHandle,
    tx: &CString,
    index: u32,
  ) -> Result<ScriptWitness, CfdError> {
    let mut count: c_uint = 0;
    let error_code = unsafe {
      CfdGetTxInWitnessCount(
        handle.as_handle(),
        self.network.to_c_value(),
        tx.as_ptr(),
        index,
        &mut count,
      )
    };
    let result = match error_code {
      0 => {
        let mut list: Vec<ByteData> = vec![];
        let mut stack_index = 0;
        while stack_index < count {
          let stack_bytes = {
            let mut stack_data: *mut c_char = ptr::null_mut();
            let error_code = unsafe {
              CfdGetTxInWitness(
                handle.as_handle(),
                self.network.to_c_value(),
                tx.as_ptr(),
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
    };
    result
  }

  fn get_txout_index(
    &self,
    tx: &str,
    address: &Address,
    locking_script: &Script,
  ) -> Result<u32, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let addr = alloc_c_string(address.to_str())?;
    let script = alloc_c_string(&locking_script.to_hex())?;
    let handle = ErrorHandle::new()?;
    let mut index: c_uint = 0;
    let error_code = unsafe {
      CfdGetTxOutIndex(
        handle.as_handle(),
        self.network.to_c_value(),
        tx_str.as_ptr(),
        addr.as_ptr(),
        script.as_ptr(),
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

  fn create_tx(
    &mut self,
    version: u32,
    locktime: u32,
    tx: &str,
    txin_list: &[TxInData],
    txout_list: &[TxOutData],
  ) -> Result<Vec<u8>, CfdError> {
    let tx_str = alloc_c_string(tx)?;
    let handle = ErrorHandle::new()?;
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
              let txid = alloc_c_string(&input.outpoint.txid.to_hex())?;
              let error_code = unsafe {
                CfdAddTransactionInput(
                  handle.as_handle(),
                  create_handle,
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
                  create_handle,
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
