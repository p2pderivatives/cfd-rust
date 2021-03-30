extern crate cfd_sys;
extern crate libc;

use self::libc::{c_char, c_int, c_uchar, c_uint, c_void};
use crate::common::{
  alloc_c_string, byte_from_hex, byte_from_hex_unsafe, collect_cstring_and_free,
  collect_multi_cstring_and_free, copy_array_32byte, hex_from_bytes, ErrorHandle,
};
use crate::{
  address::Address,
  common::{ByteData, CfdError, Network},
  key::{Privkey, Pubkey},
  schnorr::SchnorrPubkey,
};
use std::fmt;
use std::ptr;
use std::result::Result::{Err, Ok};
use std::str::FromStr;

use self::cfd_sys::{
  CfdAddMultisigScriptData, CfdAddTapBranchByScriptTreeString, CfdConvertScriptAsmToHex,
  CfdFinalizeMultisigScript, CfdFreeMultisigScriptHandle, CfdFreeScriptItemHandle,
  CfdFreeTaprootScriptTreeHandle, CfdGetBaseTapLeaf, CfdGetScriptItem, CfdGetTapBranchCount,
  CfdGetTapBranchData, CfdGetTapBranchHandle, CfdGetTaprootScriptTreeHash,
  CfdGetTaprootScriptTreeSrting, CfdGetTaprootTweakedPrivkey, CfdInitializeMultisigScript,
  CfdInitializeTaprootScriptTree, CfdParseScript, CfdSetScriptTreeFromString,
  CfdSetTapScriptByWitnessStack,
};

/// taproot hash size.
pub const TAPROOT_HASH_SIZE: usize = 32;
/// tapscript leaf version
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

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
    let mut handle = ErrorHandle::new()?;
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
    let mut handle = ErrorHandle::new()?;
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

    let mut handle = ErrorHandle::new()?;
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

/// A container that stores a taproot script tree branch.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TapBranch {
  /// top branch hash.
  hash: [u8; TAPROOT_HASH_SIZE],
  /// root tapscript.
  tapscript: Script,
  /// tapscript tree string (cfd format).
  tree_str: String,
  /// tapscript control node list.
  target_nodes: Vec<[u8; TAPROOT_HASH_SIZE]>,
}

impl TapBranch {
  /// Create TapBranch from tapscript. (tapleaf)
  ///
  /// # Arguments
  /// * `tapscript` - A tapscript.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{Script, TapBranch};
  /// use std::str::FromStr;
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_tapscript(&script).expect("Fail");
  /// ```
  pub fn from_tapscript(tapscript: &Script) -> Result<TapBranch, CfdError> {
    let arr: Vec<[u8; TAPROOT_HASH_SIZE]> = vec![];
    TapBranch::from_string_by_tapscript(&format!("tl({})", tapscript.to_hex()), &tapscript, &arr)
  }

  /// Create TapBranch from branch hash only.
  /// This object is branch only. (not tapleaf)
  ///
  /// # Arguments
  /// * `hash` - A tapbranch hash.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ByteData, TapBranch};
  /// use std::str::FromStr;
  /// let hash = ByteData::from_str("06b46c960d6824f0da5af71d9ecc55714de5b2d2da51be60bd12c77df20a20df").expect("Fail").to_32byte_array();
  /// let tree = TapBranch::from_branch_hash(&hash);
  /// ```
  pub fn from_branch_hash(hash: &[u8; TAPROOT_HASH_SIZE]) -> TapBranch {
    TapBranch {
      hash: *hash,
      tree_str: hex_from_bytes(hash),
      ..TapBranch::default()
    }
  }

  /// Create TapBranch from tree string.
  /// This object is branch only. (not tapleaf)
  ///
  /// # Arguments
  /// * `tree_str` - A script tree string. (cfd format)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::TapBranch;
  /// let tree = TapBranch::from_string(&"{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}").expect("Fail");
  /// ```
  pub fn from_string(tree_str: &str) -> Result<TapBranch, CfdError> {
    let arr: Vec<[u8; TAPROOT_HASH_SIZE]> = vec![];
    TapBranch::from_string_by_tapscript(tree_str, &Script::default(), &arr)
  }

  /// Create TapBranch from control block and tapscript. (tapleaf)
  ///
  /// # Arguments
  /// * `control_block` - A control block.
  /// * `tapscript` - A tapscript.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{ByteData, TapBranch, Script};
  /// use std::str::FromStr;
  /// let control_block = ByteData::from_str("c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb06b46c960d6824f0da5af71d9ecc55714de5b2d2da51be60bd12c77df20a20df").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_control_block(&control_block.to_slice(), &script);
  /// ```
  pub fn from_control_block(
    control_block: &[u8],
    tapscript: &Script,
  ) -> Result<(TapBranch, SchnorrPubkey), CfdError> {
    let handle = ScriptTreeHandle::new()?;
    let script_str = alloc_c_string(&tapscript.to_hex())?;
    let control_block_str = alloc_c_string(&hex_from_bytes(control_block))?;
    let mut output: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdSetTapScriptByWitnessStack(
        handle.as_handle(),
        handle.as_tree_handle(),
        control_block_str.as_ptr(),
        script_str.as_ptr(),
        &mut output,
      )
    };
    match error_code {
      0 => {
        let pubkey_str = unsafe { collect_cstring_and_free(output) }?;
        let schnorr_pubkey = SchnorrPubkey::from_str(&pubkey_str)?;
        let nodes: Vec<[u8; 32]> = vec![];
        let branch = Self::get_branch_data(&handle, &tapscript, &nodes)?;
        Ok((branch, schnorr_pubkey))
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  /// Create TapBranch from tapscript and tree string. (tapleaf)
  ///
  /// # Arguments
  /// * `tree_str` - A script tree string. (cfd format)
  /// * `tapscript` - A tapscript.
  /// * `target_nodes` - A tapscript target node list. (branch hash list)
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, Script, ByteData};
  /// use std::str::FromStr;
  /// let tree_str = "{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}";
  /// let hash_bytes = ByteData::from_str("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_string_by_tapscript(
  ///   tree_str, &script, &[hash_bytes.to_32byte_array()]).expect("Fail");
  /// ```
  pub fn from_string_by_tapscript(
    tree_str: &str,
    tapscript: &Script,
    target_nodes: &[[u8; TAPROOT_HASH_SIZE]],
  ) -> Result<TapBranch, CfdError> {
    let handle = ScriptTreeHandle::new()?;
    Self::load_by_tree_string(&handle, tree_str, tapscript, target_nodes)?;
    let nodes: Vec<[u8; 32]> = vec![];
    Self::get_branch_data(&handle, &tapscript, &nodes)
  }

  fn load_by_tree_string(
    handle: &ScriptTreeHandle,
    tree_str: &str,
    tapscript: &Script,
    target_nodes: &[[u8; TAPROOT_HASH_SIZE]],
  ) -> Result<(), CfdError> {
    let mut target_nodes_str = String::default();
    for node in target_nodes {
      target_nodes_str += &hex_from_bytes(node);
    }
    let leaf_version: u8 = TAPSCRIPT_LEAF_VERSION;
    let script_str = alloc_c_string(&tapscript.to_hex())?;
    let tree_string = alloc_c_string(&tree_str)?;
    let control_nodes = alloc_c_string(&target_nodes_str)?;
    let error_code = unsafe {
      CfdSetScriptTreeFromString(
        handle.as_handle(),
        handle.as_tree_handle(),
        tree_string.as_ptr(),
        script_str.as_ptr(),
        leaf_version,
        control_nodes.as_ptr(),
      )
    };
    match error_code {
      0 => Ok(()),
      _ => Err(handle.get_error(error_code)),
    }
  }

  /// Add tapleaf to tapbranch.
  ///
  /// # Arguments
  /// * `tapscript` - A tapscript.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, Script};
  /// let tree_str = "{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}";
  /// let mut tree = TapBranch::from_string(tree_str).expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// tree.add_by_tapleaf(&script).expect("Fail");
  /// ```
  pub fn add_by_tapleaf(&mut self, tapscript: &Script) -> Result<(), CfdError> {
    self.add_by_tree_string(&format!("tl({})", tapscript.to_hex()))
  }

  /// Add tapbranch to tapbranch.
  ///
  /// # Arguments
  /// * `branch` - A tapbranch.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::TapBranch;
  /// let tree_str = "tl(51)";
  /// let mut tree = TapBranch::from_string(tree_str).expect("Fail");
  /// let brach_str = "{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}";
  /// let branch = TapBranch::from_string(brach_str).expect("Fail");
  /// tree.add_by_tapbranch(&branch).expect("Fail");
  /// ```
  pub fn add_by_tapbranch(&mut self, branch: &TapBranch) -> Result<(), CfdError> {
    self.add_by_tree_string(branch.to_str())
  }

  /// Add tapbranch hash to tapbranch.
  ///
  /// # Arguments
  /// * `hash` - A tapbranch hash.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, ByteData};
  /// use std::str::FromStr;
  /// let tree_str = "tl(51)";
  /// let mut tree = TapBranch::from_string(tree_str).expect("Fail");
  /// let hash_bytes = ByteData::from_str("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086").expect("Fail");
  /// tree.add_by_tapbranch_hash(&hash_bytes.to_32byte_array()).expect("Fail");
  /// ```
  pub fn add_by_tapbranch_hash(&mut self, hash: &[u8; TAPROOT_HASH_SIZE]) -> Result<(), CfdError> {
    self.add_by_tree_string(&hex_from_bytes(hash))
  }

  /// Add tree string to tapbranch.
  ///
  /// # Arguments
  /// * `tree_str` - A tree string.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::TapBranch;
  /// let tree_str = "tl(51)";
  /// let mut tree = TapBranch::from_string(tree_str).expect("Fail");
  /// let brach_str = "{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}";
  /// tree.add_by_tree_string(&brach_str).expect("Fail");
  /// ```
  pub fn add_by_tree_string(&mut self, tree_str: &str) -> Result<(), CfdError> {
    let handle = ScriptTreeHandle::new()?;
    Self::load_by_tree_string(&handle, &self.tree_str, &self.tapscript, &self.target_nodes)?;
    let tree_string = alloc_c_string(&tree_str)?;
    let error_code = unsafe {
      CfdAddTapBranchByScriptTreeString(
        handle.as_handle(),
        handle.as_tree_handle(),
        tree_string.as_ptr(),
      )
    };
    match error_code {
      0 => {
        let nodes = self.target_nodes.clone();
        let branch = Self::get_branch_data(&handle, &self.tapscript, &nodes)?;
        self.hash = branch.hash;
        self.tree_str = branch.tree_str;
        if !self.tapscript.is_empty() {
          self.target_nodes = branch.target_nodes;
        }
        Ok(())
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  /// Get branch data.
  ///
  /// # Arguments
  /// * `index` - A branch index (from leaf). start is zero. maximum is `get_branch_count() - 1`.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, Script, ByteData};
  /// use std::str::FromStr;
  /// let tree_str = "{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}";
  /// let hash_bytes = ByteData::from_str("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_string_by_tapscript(
  ///   tree_str, &script, &[hash_bytes.to_32byte_array()]).expect("Fail");
  /// let max_count = tree.get_branch_count().expect("Fail");
  /// let branch = tree.get_branch(max_count - 1).expect("Fail");
  /// ```
  pub fn get_branch(&self, index: u8) -> Result<TapBranch, CfdError> {
    let handle = ScriptTreeHandle::new()?;
    Self::load_by_tree_string(&handle, &self.tree_str, &self.tapscript, &self.target_nodes)?;
    let branch_handle = ScriptTreeHandle::create_sub_branch(&handle, index)?;
    let nodes: Vec<[u8; 32]> = vec![];
    Self::get_branch_data(&branch_handle, &Script::default(), &nodes)
  }

  /// Get the count of contains branch.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, Script, ByteData};
  /// use std::str::FromStr;
  /// let tree_str = "{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}";
  /// let hash_bytes = ByteData::from_str("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_string_by_tapscript(
  ///   tree_str, &script, &[hash_bytes.to_32byte_array()]).expect("Fail");
  /// let max_count = tree.get_branch_count().expect("Fail");
  /// ```
  pub fn get_branch_count(&self) -> Result<u8, CfdError> {
    if !self.tapscript.is_empty() {
      return Ok(self.target_nodes.len() as u8);
    }
    let handle = ScriptTreeHandle::new()?;
    Self::load_by_tree_string(&handle, &self.tree_str, &self.tapscript, &self.target_nodes)?;
    Self::get_branch_count_internal(&handle)
  }

  /// Get a tapleaf hash.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, Script, ByteData};
  /// use std::str::FromStr;
  /// let tree_str = "{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}";
  /// let hash_bytes = ByteData::from_str("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_string_by_tapscript(
  ///   tree_str, &script, &[hash_bytes.to_32byte_array()]).expect("Fail");
  /// let tapleaf_hash = tree.get_tapleaf_hash().expect("Fail");
  /// ```
  pub fn get_tapleaf_hash(&self) -> Result<[u8; 32], CfdError> {
    if self.tapscript.is_empty() {
      return Err(CfdError::IllegalArgument(
        "This branch has not tapscript.".to_string(),
      ));
    }
    let handle = ScriptTreeHandle::new()?;
    Self::load_by_tree_string(&handle, &self.tree_str, &self.tapscript, &self.target_nodes)?;

    let mut tapscript: *mut c_char = ptr::null_mut();
    let mut tap_leaf_hash: *mut c_char = ptr::null_mut();
    let mut leaf_version: c_uchar = 0;
    let error_code = unsafe {
      CfdGetBaseTapLeaf(
        handle.as_handle(),
        handle.as_tree_handle(),
        &mut leaf_version,
        &mut tapscript,
        &mut tap_leaf_hash,
      )
    };
    match error_code {
      0 => {
        let str_list = unsafe { collect_multi_cstring_and_free(&[tapscript, tap_leaf_hash]) }?;
        let hash = copy_array_32byte(&byte_from_hex_unsafe(&str_list[1]));
        Ok(hash)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  /// Get a tweaked pubkey for taproot.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, Script, ByteData, SchnorrPubkey, Network};
  /// use std::str::FromStr;
  /// let schnorr_pubkey = SchnorrPubkey::from_str("1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb").expect("Fail");
  /// let tree_str = "{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}";
  /// let hash_bytes = ByteData::from_str("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_string_by_tapscript(
  ///   tree_str, &script, &[hash_bytes.to_32byte_array()]).expect("Fail");
  /// let (witness_program_hash, address, control_block) = tree.get_tweaked_pubkey(
  ///   &schnorr_pubkey, &Network::Mainnet).expect("Fail");
  /// ```
  pub fn get_tweaked_pubkey(
    &self,
    schnorr_pubkey: &SchnorrPubkey,
    network: &Network,
  ) -> Result<(SchnorrPubkey, Address, ByteData), CfdError> {
    let handle = ScriptTreeHandle::new()?;
    Self::load_by_tree_string(&handle, &self.tree_str, &self.tapscript, &self.target_nodes)?;
    let internal_pubkey = alloc_c_string(&schnorr_pubkey.to_hex())?;
    let mut hash: *mut c_char = ptr::null_mut();
    let mut tap_leaf_hash: *mut c_char = ptr::null_mut();
    let mut control_block: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetTaprootScriptTreeHash(
        handle.as_handle(),
        handle.as_tree_handle(),
        internal_pubkey.as_ptr(),
        &mut hash,
        &mut tap_leaf_hash,
        &mut control_block,
      )
    };
    match error_code {
      0 => {
        let str_list =
          unsafe { collect_multi_cstring_and_free(&[hash, tap_leaf_hash, control_block]) }?;
        let pubkey = SchnorrPubkey::from_str(&str_list[0])?;
        let control_block_data = ByteData::from_str(&str_list[2])?;
        let addr = Address::taproot(&pubkey, network)?;
        Ok((pubkey, addr, control_block_data))
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  /// Get a tweaked pubkey for taproot.
  ///
  /// # Example
  ///
  /// ```
  /// use cfd_rust::{TapBranch, Script, ByteData, Privkey, Network};
  /// use std::str::FromStr;
  /// let privkey = Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27").expect("Fail");
  /// let tree_str = "{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}";
  /// let hash_bytes = ByteData::from_str("aaf9ea4cbd2f4606a31a35d563fa371bc630d9d7bcc50f62d064a3d84e0e3086").expect("Fail");
  /// let script = Script::from_asm("OP_TRUE").expect("Fail");
  /// let tree = TapBranch::from_string_by_tapscript(
  ///   tree_str, &script, &[hash_bytes.to_32byte_array()]).expect("Fail");
  /// let tweaked_privkey = tree.get_tweaked_privkey(&privkey).expect("Fail");
  /// ```
  pub fn get_tweaked_privkey(&self, privkey: &Privkey) -> Result<Privkey, CfdError> {
    let handle = ScriptTreeHandle::new()?;
    Self::load_by_tree_string(&handle, &self.tree_str, &self.tapscript, &self.target_nodes)?;
    let internal_privkey = alloc_c_string(&privkey.to_hex())?;
    let mut tweaked_privkey: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetTaprootTweakedPrivkey(
        handle.as_handle(),
        handle.as_tree_handle(),
        internal_privkey.as_ptr(),
        &mut tweaked_privkey,
      )
    };
    match error_code {
      0 => {
        let privkey_str = unsafe { collect_cstring_and_free(tweaked_privkey) }?;
        Privkey::from_str(&privkey_str)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }

  pub fn get_top_branch_hash(&self) -> &[u8; TAPROOT_HASH_SIZE] {
    &self.hash
  }

  pub fn get_top_branch_hash_data(&self) -> ByteData {
    ByteData::from_slice(&self.hash)
  }

  pub fn get_tapscript(&self) -> &Script {
    &self.tapscript
  }

  pub fn to_str(&self) -> &str {
    &self.tree_str
  }

  pub fn get_target_nodes(&self) -> &Vec<[u8; TAPROOT_HASH_SIZE]> {
    &self.target_nodes
  }

  fn get_branch_count_internal(handle: &ScriptTreeHandle) -> Result<u8, CfdError> {
    let mut count: c_uint = 0;
    let error_code =
      unsafe { CfdGetTapBranchCount(handle.as_handle(), handle.as_tree_handle(), &mut count) };
    match error_code {
      0 => Ok(count as u8),
      _ => Err(handle.get_error(error_code)),
    }
  }

  fn get_branch_data(
    handle: &ScriptTreeHandle,
    root_tapscript: &Script,
    nodes: &[[u8; 32]],
  ) -> Result<TapBranch, CfdError> {
    let mut branch = TapBranch::default();
    let count = Self::get_branch_count_internal(&handle)?;
    if count == 0 {
      let mut tapscript: *mut c_char = ptr::null_mut();
      let mut tap_leaf_hash: *mut c_char = ptr::null_mut();
      let mut leaf_version: c_uchar = 0;
      let error_code = unsafe {
        CfdGetBaseTapLeaf(
          handle.as_handle(),
          handle.as_tree_handle(),
          &mut leaf_version,
          &mut tapscript,
          &mut tap_leaf_hash,
        )
      };
      match error_code {
        0 => {
          let str_list = unsafe { collect_multi_cstring_and_free(&[tapscript, tap_leaf_hash]) }?;
          if !str_list[1].is_empty() {
            branch.hash = copy_array_32byte(&byte_from_hex_unsafe(&str_list[1]));
          }
          Ok(())
        }
        _ => Err(handle.get_error(error_code)),
      }?;
    } else {
      let mut branch_hash: *mut c_char = ptr::null_mut();
      let mut tapscript: *mut c_char = ptr::null_mut();
      let mut leaf_version: c_uchar = 0;
      let mut depth_by_leaf_or_end: c_uchar = 0;
      let index = count - 1;
      let error_code = unsafe {
        CfdGetTapBranchData(
          handle.as_handle(),
          handle.as_tree_handle(),
          index,
          true,
          &mut branch_hash,
          &mut leaf_version,
          &mut tapscript,
          &mut depth_by_leaf_or_end,
        )
      };
      match error_code {
        0 => {
          let str_list = unsafe { collect_multi_cstring_and_free(&[branch_hash, tapscript]) }?;
          if !str_list[0].is_empty() {
            branch.hash = copy_array_32byte(&byte_from_hex_unsafe(&str_list[0]));
          }
          Ok(())
        }
        _ => Err(handle.get_error(error_code)),
      }?;
    }
    if count != 0 && !root_tapscript.is_empty() {
      let mut index: u8 = nodes.len() as u8;
      for node in nodes {
        branch.target_nodes.push(*node);
      }
      while index < count {
        let mut branch_hash: *mut c_char = ptr::null_mut();
        let mut tapscript: *mut c_char = ptr::null_mut();
        let mut leaf_version: c_uchar = 0;
        let mut depth_by_leaf_or_end: c_uchar = 0;
        let error_code = unsafe {
          CfdGetTapBranchData(
            handle.as_handle(),
            handle.as_tree_handle(),
            index,
            false,
            &mut branch_hash,
            &mut leaf_version,
            &mut tapscript,
            &mut depth_by_leaf_or_end,
          )
        };
        match error_code {
          0 => {
            let str_list = unsafe { collect_multi_cstring_and_free(&[branch_hash, tapscript]) }?;
            if !str_list[0].is_empty() {
              branch
                .target_nodes
                .push(copy_array_32byte(&byte_from_hex_unsafe(&str_list[0])));
            }
            Ok(())
          }
          _ => Err(handle.get_error(error_code)),
        }?;
        index += 1;
      }
    }

    let mut tree_str: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetTaprootScriptTreeSrting(handle.as_handle(), handle.as_tree_handle(), &mut tree_str)
    };
    match error_code {
      0 => {
        branch.tree_str = unsafe { collect_cstring_and_free(tree_str) }?;
        branch.tapscript = root_tapscript.clone();
        Ok(branch)
      }
      _ => Err(handle.get_error(error_code)),
    }
  }
}

impl Default for TapBranch {
  fn default() -> TapBranch {
    TapBranch {
      hash: [0; TAPROOT_HASH_SIZE],
      tapscript: Script::default(),
      tree_str: String::default(),
      target_nodes: vec![],
    }
  }
}

impl fmt::Display for TapBranch {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "TapBranch[{}]", &self.tree_str)
  }
}

impl FromStr for TapBranch {
  type Err = CfdError;
  fn from_str(string: &str) -> Result<TapBranch, CfdError> {
    TapBranch::from_string(string)
  }
}

/// A container that tree handler.
#[derive(Debug)]
pub(in crate) struct ScriptTreeHandle {
  handle: ErrorHandle,
  tree_handle: *mut c_void,
}

impl ScriptTreeHandle {
  pub fn new() -> Result<ScriptTreeHandle, CfdError> {
    let mut tree_hdl = ScriptTreeHandle {
      handle: ErrorHandle::new()?,
      tree_handle: ptr::null_mut(),
    };
    let mut tree_handle: *mut c_void = ptr::null_mut();
    let error_code =
      unsafe { CfdInitializeTaprootScriptTree(tree_hdl.handle.as_handle(), &mut tree_handle) };
    match error_code {
      0 => {
        tree_hdl.tree_handle = tree_handle;
        Ok(tree_hdl)
      }
      _ => {
        let err = tree_hdl.handle.get_error(error_code);
        tree_hdl.handle.free_handle();
        Err(err)
      }
    }
  }

  pub fn create_sub_branch(
    handle: &ScriptTreeHandle,
    index: u8,
  ) -> Result<ScriptTreeHandle, CfdError> {
    let mut tree_hdl = ScriptTreeHandle {
      handle: ErrorHandle::new()?,
      tree_handle: ptr::null_mut(),
    };
    let mut tree_handle: *mut c_void = ptr::null_mut();
    let mut branch_hash: *mut c_char = ptr::null_mut();
    let error_code = unsafe {
      CfdGetTapBranchHandle(
        tree_hdl.handle.as_handle(),
        handle.as_tree_handle(),
        index,
        &mut branch_hash,
        &mut tree_handle,
      )
    };
    match error_code {
      0 => {
        if !branch_hash.is_null() {
          unsafe {
            libc::free(branch_hash as *mut libc::c_void);
          };
        }
        tree_hdl.tree_handle = tree_handle;
        Ok(tree_hdl)
      }
      _ => {
        let err = tree_hdl.handle.get_error(error_code);
        tree_hdl.handle.free_handle();
        Err(err)
      }
    }
  }

  #[inline]
  pub fn as_tree_handle(&self) -> *const c_void {
    self.tree_handle
  }

  #[inline]
  pub fn as_handle(&self) -> *const c_void {
    self.handle.as_handle()
  }

  pub fn get_error(&self, error_code: c_int) -> CfdError {
    self.handle.get_error(error_code)
  }

  pub fn free_handle(&mut self) {
    if !self.tree_handle.is_null() {
      unsafe {
        CfdFreeTaprootScriptTreeHandle(self.handle.as_handle(), self.tree_handle);
      }
      self.tree_handle = ptr::null_mut();
      self.handle.free_handle();
    }
  }

  #[inline]
  pub fn is_null(&self) -> bool {
    self.tree_handle.is_null()
  }
}

impl Drop for ScriptTreeHandle {
  fn drop(&mut self) {
    if !self.is_null() {
      self.free_handle();
    }
  }
}
