extern crate cfd_rust;

use cfd_rust::{Address, Network, Pubkey, Script};
use std::str;
use str::FromStr;

fn main() {
  let pubkey_str: &str = "036b67e1bd3bd3efbc37fdc738ab159a4aa527057eae12a0c4b07d3132580dcdfd";
  let key_obj = Pubkey::from_str(pubkey_str);
  if let Err(ret) = key_obj {
    println!("{}", ret);
    return;
  }

  let pubkey = key_obj.unwrap();
  println!("pubkey hex: {}", pubkey.to_hex());
  let uncompress_key_obj = pubkey.uncompress();
  if let Err(ret) = uncompress_key_obj {
    println!("{}", ret);
    return;
  }
  let uncompress_key = uncompress_key_obj.unwrap();
  println!("uncompressed pubkey hex: {}", uncompress_key.to_hex());

  let pubkey2_str: &str = "039bdf440048b8ddaf982aa8c73abd9828014f885abc7f2a3c28f31a1b09f7d022";
  let pubkey3_str: &str = "022d5eca86e918ee9b1e8d8166520c86fb9f7285f561af861ac0f34ec101a260e4";
  let key2_obj = Pubkey::from_str(pubkey2_str);
  let key3_obj = Pubkey::from_str(pubkey3_str);
  if let Err(ret) = key2_obj {
    println!("{}", ret);
    return;
  }
  if let Err(ret) = key3_obj {
    println!("{}", ret);
    return;
  }
  let pubkey2 = key2_obj.unwrap();
  let pubkey3 = key3_obj.unwrap();
  println!("pubkey2 hex: {}", pubkey2.to_hex());
  println!("pubkey3 hex: {}", pubkey3.to_hex());
  let pubkey_list: Vec<Pubkey> = vec![pubkey.clone(), pubkey2, pubkey3];
  //let pubkey_list: Vec<Pubkey> = vec![pubkey];

  let multisig_obj = Script::multisig(2, &pubkey_list);
  if let Err(ret) = multisig_obj {
    println!("{}", ret);
    return;
  }
  let multisig = multisig_obj.unwrap();
  println!("multisig hex: {}", multisig.to_hex());
  println!("multisig asm: {}", multisig.to_asm());

  let addr_obj = Address::p2wpkh(&pubkey, &Network::Mainnet);
  if let Err(ret) = addr_obj {
    println!("{}", ret);
  } else {
    let addr = addr_obj.unwrap();
    println!("address: {}", addr.to_str());
  }
}
