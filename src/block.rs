extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_uint, c_void};
use crate::common::{
  alloc_c_string, byte_from_hex, collect_cstring_and_free, collect_multi_cstring_and_free,
  hex_from_bytes, ErrorHandle,
};
use crate::{
  common::{ByteData, CfdError, Network},
  transaction::{BlockHash, Transaction, Txid},
};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdFreeBlockHandle, CfdGetBlockHash, CfdGetBlockHeaderData, CfdGetTransactionFromBlock,
  CfdGetTxCountInBlock, CfdGetTxOutProof, CfdGetTxidFromBlock, CfdInitializeBlockHandle,
};

/// A container that stores a bitcoin block header.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlockHeader {
  pub version: u32,
  pub prev_block_hash: BlockHash,
  pub merkle_root: BlockHash,
  pub time: u32,
  pub bits: u32,
  pub nonce: u32,
}

impl Default for BlockHeader {
  fn default() -> BlockHeader {
    BlockHeader {
      version: 0,
      prev_block_hash: BlockHash::default(),
      merkle_root: BlockHash::default(),
      time: 0,
      bits: 0,
      nonce: 0,
    }
  }
}
/// A container that stores a bitcoin block.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Block {
  buffer: Vec<u8>,
  hash: BlockHash,
  header: BlockHeader,
  txid_list: Vec<Txid>,
}

impl Block {
  /// Generate from slice.
  ///
  /// # Arguments
  /// * `data` - An unsigned 8bit slice that holds the byte data.
  #[inline]
  pub fn from_slice(data: &[u8]) -> Result<Block, CfdError> {
    Block::parse(data, &Network::Mainnet)
  }

  /// Generate from ByteData.
  ///
  /// # Arguments
  /// * `data` - An unsigned 8bit slice that holds the byte data.
  #[inline]
  pub fn from_data(data: &ByteData) -> Result<Block, CfdError> {
    Block::from_slice(data.to_slice())
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

  /// Get the block hash
  pub fn get_hash(&self) -> &BlockHash {
    &self.hash
  }

  /// Get the block header.
  pub fn get_header(&self) -> &BlockHeader {
    &self.header
  }

  /// Get txid list from block.
  pub fn get_txid_list(&self) -> &Vec<Txid> {
    &self.txid_list
  }

  /// Get tx count in block.
  pub fn get_tx_count(&self) -> usize {
    self.txid_list.len()
  }

  /// Exist txid in block
  ///
  /// # Arguments
  /// * `txid` - A transaction id.
  pub fn exist_txid(&self, txid: &Txid) -> bool {
    for temp_txid in &self.txid_list {
      if temp_txid == txid {
        return true;
      }
    }
    false
  }

  #[inline]
  pub fn is_empty(&self) -> bool {
    self.buffer.is_empty()
  }

  /// Get a transaction from block.
  ///
  /// # Arguments
  /// * `txid` - A transaction id.
  pub fn get_transaction(&self, txid: &Txid) -> Result<Transaction, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let hex_str = hex_from_bytes(&self.buffer);
      let block_handle = BlockHandle::new(&handle, &Network::Mainnet, &hex_str)?;
      let block_result = Block::get_transaction_internal(&handle, &block_handle, txid)?;
      block_handle.free_handle(&handle);
      block_result
    };
    handle.free_handle();
    Ok(result)
  }

  /// Get a txoutproof.
  ///
  /// # Arguments
  /// * `txid` - A transaction id.
  pub fn get_txoutproof(&self, txid: &Txid) -> Result<ByteData, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let hex_str = hex_from_bytes(&self.buffer);
      let block_handle = BlockHandle::new(&handle, &Network::Mainnet, &hex_str)?;
      let block_result = Block::get_txoutproof_internal(&handle, &block_handle, txid)?;
      block_handle.free_handle(&handle);
      block_result
    };
    handle.free_handle();
    Ok(result)
  }

  /// Get transaction and txoutproof.
  ///
  /// # Arguments
  /// * `txid` - A transaction id.
  pub fn get_tx_data(&self, txid: &Txid) -> Result<(Transaction, ByteData), CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let hex_str = hex_from_bytes(&self.buffer);
      let block_handle = BlockHandle::new(&handle, &Network::Mainnet, &hex_str)?;
      let block_result = {
        let tx = Block::get_transaction_internal(&handle, &block_handle, txid)?;
        let txoutproof = Block::get_txoutproof_internal(&handle, &block_handle, txid)?;
        Ok((tx, txoutproof))
      }?;
      block_handle.free_handle(&handle);
      block_result
    };
    handle.free_handle();
    Ok(result)
  }

  #[inline]
  pub(in crate) fn parse(data: &[u8], network: &Network) -> Result<Block, CfdError> {
    let mut handle = ErrorHandle::new()?;
    let result = {
      let hex_str = hex_from_bytes(data);
      let block_handle = BlockHandle::new(&handle, network, &hex_str)?;
      let block_result = {
        let hash = Block::get_hash_internal(&handle, &block_handle)?;
        let header = Block::get_header_internal(&handle, &block_handle)?;
        let txid_list = Block::get_txid_list_internal(&handle, &block_handle)?;
        Ok(Block {
          buffer: data.to_vec(),
          hash,
          header,
          txid_list,
        })
      }?;
      block_handle.free_handle(&handle);
      block_result
    };
    handle.free_handle();
    Ok(result)
  }

  pub(in crate) fn get_hash_internal(
    handle: &ErrorHandle,
    block_handle: &BlockHandle,
  ) -> Result<BlockHash, CfdError> {
    let mut hash: *mut c_char = ptr::null_mut();
    let error_code =
      unsafe { CfdGetBlockHash(handle.as_handle(), block_handle.as_handle(), &mut hash) };
    match error_code {
      0 => {
        let block_hash = unsafe { collect_cstring_and_free(hash) }?;
        Ok(BlockHash::from_str(&block_hash)?)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub(in crate) fn get_header_internal(
    handle: &ErrorHandle,
    block_handle: &BlockHandle,
  ) -> Result<BlockHeader, CfdError> {
    let mut version = 0;
    let mut time = 0;
    let mut bits = 0;
    let mut nonce = 0;
    let mut prev_block_hash: *mut c_char = ptr::null_mut();
    let mut merkle_root: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetBlockHeaderData(
        handle.as_handle(),
        block_handle.as_handle(),
        &mut version,
        &mut prev_block_hash,
        &mut merkle_root,
        &mut time,
        &mut bits,
        &mut nonce,
      )
    };
    match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[prev_block_hash, merkle_root]) }?;
        let prev_hash = BlockHash::from_str(&str_list[0])?;
        let merkle_root_obj = BlockHash::from_str(&str_list[1])?;
        Ok(BlockHeader {
          version,
          prev_block_hash: prev_hash,
          merkle_root: merkle_root_obj,
          time,
          bits,
          nonce,
        })
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub(in crate) fn get_txid_list_internal(
    handle: &ErrorHandle,
    block_handle: &BlockHandle,
  ) -> Result<Vec<Txid>, CfdError> {
    let tx_count = {
      let mut count = 0;
      let error_code =
        unsafe { CfdGetTxCountInBlock(handle.as_handle(), block_handle.as_handle(), &mut count) };
      match error_code {
        0 => Ok(count),
        _ => Err(handle.get_error(error_code)),
      }
    }?;

    let mut list: Vec<Txid> = vec![];
    let mut index = 0;
    while index < tx_count {
      let txid = {
        let mut txid_str: *mut c_char = ptr::null_mut();
        let error_code = unsafe {
          CfdGetTxidFromBlock(
            handle.as_handle(),
            block_handle.as_handle(),
            index as c_uint,
            &mut txid_str,
          )
        };
        match error_code {
          0 => {
            let txid_hex = unsafe { collect_cstring_and_free(txid_str) }?;
            Ok(Txid::from_str(&txid_hex)?)
          }
          _ => Err(handle.get_error(error_code)),
        }
      }?;
      list.push(txid);
      index += 1;
    }
    Ok(list)
  }

  pub(in crate) fn get_transaction_internal(
    handle: &ErrorHandle,
    block_handle: &BlockHandle,
    txid: &Txid,
  ) -> Result<Transaction, CfdError> {
    let txid_hex = alloc_c_string(&txid.to_hex())?;
    let mut tx_hex: *mut c_char = ptr::null_mut();
    let error_code: i32 = unsafe {
      CfdGetTransactionFromBlock(
        handle.as_handle(),
        block_handle.as_handle(),
        txid_hex.as_ptr(),
        &mut tx_hex,
      )
    };
    match error_code {
      0 => {
        let tx = unsafe { collect_cstring_and_free(tx_hex) }?;
        Ok(Transaction::from_str(&tx)?)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub(in crate) fn get_txoutproof_internal(
    handle: &ErrorHandle,
    block_handle: &BlockHandle,
    txid: &Txid,
  ) -> Result<ByteData, CfdError> {
    let txid_hex = alloc_c_string(&txid.to_hex())?;
    let mut proof: *mut c_char = ptr::null_mut();
    let error_code: i32 = unsafe {
      CfdGetTxOutProof(
        handle.as_handle(),
        block_handle.as_handle(),
        txid_hex.as_ptr(),
        &mut proof,
      )
    };
    match error_code {
      0 => {
        let txoutproof = unsafe { collect_cstring_and_free(proof) }?;
        Ok(ByteData::from_str(&txoutproof)?)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }
}

impl FromStr for Block {
  type Err = CfdError;
  fn from_str(text: &str) -> Result<Block, CfdError> {
    let buf = byte_from_hex(text)?;
    Block::from_slice(&buf)
  }
}

impl Default for Block {
  fn default() -> Block {
    Block {
      buffer: vec![],
      hash: BlockHash::default(),
      header: BlockHeader::default(),
      txid_list: vec![],
    }
  }
}

impl fmt::Display for Block {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Block[{}]", &self.hash.to_hex())
  }
}

/// A container that tx data handler.
#[derive(Debug, Clone)]
pub(in crate) struct BlockHandle {
  block_handle: *mut c_void,
}

impl BlockHandle {
  pub fn new(
    handle: &ErrorHandle,
    network: &Network,
    block: &str,
  ) -> Result<BlockHandle, CfdError> {
    let block_str = alloc_c_string(block)?;
    let mut block_handle: *mut c_void = ptr::null_mut();
    let error_code = unsafe {
      CfdInitializeBlockHandle(
        handle.as_handle(),
        network.to_c_value(),
        block_str.as_ptr(),
        &mut block_handle,
      )
    };
    match error_code {
      0 => Ok(BlockHandle { block_handle }),
      _ => Err(handle.get_error(error_code)),
    }
  }

  #[inline]
  pub fn as_handle(&self) -> *const c_void {
    self.block_handle
  }

  pub fn free_handle(&self, handle: &ErrorHandle) {
    unsafe {
      CfdFreeBlockHandle(handle.as_handle(), self.block_handle);
    }
  }
}
