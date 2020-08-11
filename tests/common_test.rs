extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{Amount, ByteData, Network};
  use std::str::FromStr;

  #[test]
  fn amount() {
    let amount_btc: f64 = 1234.56789012;
    let amount = Amount::from_btc(amount_btc);
    let amount_satoshi = amount.as_satoshi_amount();
    assert_eq!(123456789012, amount_satoshi);
  }

  #[test]
  fn byte_data() {
    let byte_hex = "0123456789abcdef0123";
    let byte_obj_ret = ByteData::from_str(byte_hex);
    assert!(
      byte_obj_ret.is_ok(),
      "err: \"{}\"",
      byte_obj_ret.unwrap_err()
    );
    let byte_obj = byte_obj_ret.unwrap();
    assert_eq!(byte_hex, byte_obj.to_hex());
    let byte_serialize_ret = byte_obj.serialize();
    assert!(
      byte_serialize_ret.is_ok(),
      "err: \"{}\"",
      byte_serialize_ret.unwrap_err()
    );
    let serialized = byte_serialize_ret.unwrap();
    assert_eq!("0a0123456789abcdef0123", serialized.to_hex());
  }

  #[test]
  fn network() {
    let mainnet = Network::Mainnet;
    assert_eq!("Mainnet", mainnet.to_string());
    let regtest = Network::Regtest;
    assert_eq!("Regtest", regtest.to_string());
  }
}
