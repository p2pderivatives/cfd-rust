extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{Address, Network, Pubkey};
  use std::str::FromStr;

  #[test]
  fn address() {
    let pubkey_str: &str = "036b67e1bd3bd3efbc37fdc738ab159a4aa527057eae12a0c4b07d3132580dcdfd";
    let key_obj = Pubkey::from_str(pubkey_str);
    assert!(key_obj.is_ok(), "err: \"{}\"", key_obj.unwrap_err());
    let pubkey = key_obj.unwrap();
    let addr_obj = Address::p2wpkh(&pubkey, &Network::Regtest);
    assert!(addr_obj.is_ok(), "err: \"{}\"", addr_obj.unwrap_err());
    let address = addr_obj.unwrap();
    let addr = address.to_str();
    assert_eq!("bcrt1q576jgpgewxwu205cpjq4s4j5tprxlq38l7kd85", addr);
  }
}
