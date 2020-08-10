extern crate cfd_rust;
extern crate sha2;

use std::str::FromStr;

#[cfg(test)]
mod tests {
  use super::*;
  use cfd_rust::{Privkey, Pubkey, SignParameter};
  use sha2::{Digest, Sha256};

  #[test]
  fn pubkey() {
    // default
    let pubkey_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
    let pubkey_ret = Pubkey::from_str(pubkey_str);
    assert!(pubkey_ret.is_ok(), "err: \"{}\"", pubkey_ret.unwrap_err());
    let pubkey = pubkey_ret.unwrap();
    assert_eq!(pubkey_str, pubkey.to_hex());
    assert_eq!(true, pubkey.valid());
    // combine
    // compress/uncompress
    // tweak/negate
  }

  #[test]
  fn combine_multiple_messages_test() {
    const K_ORACLE_NUM: usize = 3;

    let oracle_privkey_str = "0000000000000000000000000000000000000000000000000000000000000001";
    let privkey_ret = Privkey::from_str(oracle_privkey_str);
    assert!(privkey_ret.is_ok(), "err: \"{}\"", privkey_ret.unwrap_err());
    let oracle_privkey = privkey_ret.unwrap();
    let pubkey_ret = oracle_privkey.get_pubkey();
    assert!(pubkey_ret.is_ok(), "err: \"{}\"", pubkey_ret.unwrap_err());
    let oracle_pubkey = pubkey_ret.unwrap();

    // Arrange
    let mut oracle_k_values: Vec<Privkey> = vec![];
    let oracle_k_value_str_list = &[
      "0000000000000000000000000000000000000000000000000000000000000002",
      "0000000000000000000000000000000000000000000000000000000000000003",
      "0000000000000000000000000000000000000000000000000000000000000004",
    ];
    for k_value in oracle_k_value_str_list {
      let oracle_k_value_ret = Privkey::from_str(*k_value);
      assert!(
        oracle_k_value_ret.is_ok(),
        "err: \"{}\"",
        oracle_k_value_ret.unwrap_err()
      );
      oracle_k_values.push(oracle_k_value_ret.unwrap());
    }
    let messages = [b"W", b"I", b"N"];
    let local_fund_privkey_str = "0000000000000000000000000000000000000000000000000000000000000006";
    let local_fund_privkey_ret = Privkey::from_str(local_fund_privkey_str);
    assert!(
      local_fund_privkey_ret.is_ok(),
      "err: \"{}\"",
      local_fund_privkey_ret.unwrap_err()
    );
    let local_fund_privkey = local_fund_privkey_ret.unwrap();
    let local_fund_pubkey_ret = local_fund_privkey.get_pubkey();
    assert!(
      local_fund_pubkey_ret.is_ok(),
      "err: \"{}\"",
      local_fund_pubkey_ret.unwrap_err()
    );
    let local_fund_pubkey = local_fund_pubkey_ret.unwrap();

    let local_sweep_privkey_str =
      "0000000000000000000000000000000000000000000000000000000000000006";
    let local_sweep_privkey_ret = Privkey::from_str(local_sweep_privkey_str);
    assert!(
      local_sweep_privkey_ret.is_ok(),
      "err: \"{}\"",
      local_sweep_privkey_ret.unwrap_err()
    );
    let local_sweep_privkey_obj = local_sweep_privkey_ret.unwrap();
    // std::string local_sweep_privkey_str = local_sweep_privkey_obj.GetHex();
    // const char* local_sweep_privkey = local_sweep_privkey_str.c_str();
    let local_sweep_pubkey_ret = local_sweep_privkey_obj.get_pubkey();
    assert!(
      local_sweep_pubkey_ret.is_ok(),
      "err: \"{}\"",
      local_sweep_pubkey_ret.unwrap_err()
    );
    let local_sweep_pubkey = local_sweep_pubkey_ret.unwrap();
    // const char* local_sweep_pubkey = local_sweep_pubkey_str.c_str();

    let mut oracle_r_points: Vec<Pubkey> = vec![];
    for k_value in &oracle_k_values {
      let nonce_ret = k_value.get_schnorr_public_nonce();
      assert!(nonce_ret.is_ok(), "err: \"{}\"", nonce_ret.unwrap_err());
      oracle_r_points.push(nonce_ret.unwrap());
    }

    // Act
    let mut signatures: Vec<SignParameter> = vec![];
    let mut index: usize = 0;
    while index < K_ORACLE_NUM {
      let message = messages[index];
      let hash = {
        let mut hash_obj = Sha256::new();
        hash_obj.update(*message);
        hash_obj.finalize()
      };
      let signature_ret = oracle_privkey
        .calculate_schnorr_signature_with_nonce(oracle_k_values[index].to_slice(), hash.as_slice());
      assert!(
        signature_ret.is_ok(),
        "err: \"{}\"",
        signature_ret.unwrap_err()
      );
      signatures.push(signature_ret.unwrap());
      index += 1;
    }

    let mut pubkey_list: Vec<Pubkey> = vec![];
    index = 0;
    while index < K_ORACLE_NUM {
      let message = messages[index];
      let hash = {
        let mut hash_obj = Sha256::new();
        hash_obj.update(*message);
        hash_obj.finalize()
      };
      let pubkey_ret = oracle_pubkey.get_schnorr_pubkey(&oracle_r_points[index], hash.as_slice());
      assert!(pubkey_ret.is_ok(), "err: \"{}\"", pubkey_ret.unwrap_err());
      pubkey_list.push(pubkey_ret.unwrap());
      index += 1;
    }

    let committed_key = {
      let combine_ret = Pubkey::combine(&pubkey_list);
      assert!(combine_ret.is_ok(), "err: \"{}\"", combine_ret.unwrap_err());
      combine_ret.unwrap()
    };
    let combine_pubkey = {
      let combine_pubkey_ret = Pubkey::combine(&[local_fund_pubkey, committed_key]);
      assert!(
        combine_pubkey_ret.is_ok(),
        "err: \"{}\"",
        combine_pubkey_ret.unwrap_err()
      );
      combine_pubkey_ret.unwrap()
    };
    let hash_privkey = {
      let hash = {
        let mut hash_obj = Sha256::new();
        hash_obj.update(local_sweep_pubkey.to_slice());
        hash_obj.finalize()
      };
      let privkey_ret = Privkey::from_slice(hash.as_slice());
      assert!(privkey_ret.is_ok(), "err: \"{}\"", privkey_ret.unwrap_err());
      privkey_ret.unwrap()
    };
    let hash_pubkey = {
      let pubkey_ret = hash_privkey.get_pubkey();
      assert!(pubkey_ret.is_ok(), "err: \"{}\"", pubkey_ret.unwrap_err());
      pubkey_ret.unwrap()
    };
    let combined_pubkey = {
      let combine_pubkey_ret = Pubkey::combine(&[combine_pubkey, hash_pubkey]);
      assert!(
        combine_pubkey_ret.is_ok(),
        "err: \"{}\"",
        combine_pubkey_ret.unwrap_err()
      );
      combine_pubkey_ret.unwrap()
    };

    // auto tweak_priv = DlcUtil::GetTweakedPrivkey(signatures, local_fund_privkey,
    //                                              local_sweep_pubkey);
    let tweaked_key = {
      let mut target_tweaked_key: Privkey = local_fund_privkey;
      index = 0;
      while index < K_ORACLE_NUM {
        let signature = &signatures[index];
        let privkey_ret = target_tweaked_key.tweak_add(signature.to_slice());
        assert!(privkey_ret.is_ok(), "err: \"{}\"", privkey_ret.unwrap_err());
        target_tweaked_key = privkey_ret.unwrap();
        index += 1;
      }
      target_tweaked_key
    };
    let tweak_priv = {
      let privkey_ret = tweaked_key.tweak_add(hash_privkey.to_slice());
      assert!(privkey_ret.is_ok(), "err: \"{}\"", privkey_ret.unwrap_err());
      privkey_ret.unwrap()
    };

    let tweak_pub = {
      let pubkey_ret = tweak_priv.get_pubkey();
      assert!(pubkey_ret.is_ok(), "err: \"{}\"", pubkey_ret.unwrap_err());
      pubkey_ret.unwrap()
    };
    assert_eq!(combined_pubkey.to_string(), tweak_pub.to_string());
    assert_eq!(
      "03bbf2453fbd2ca029574213fb4314285023c6592cc6c1e9956a6eecf861fde3f9",
      tweak_pub.to_string()
    );
  }
}
