extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{
    Address, Amount, ExtPrivkey, HashType, Network, OutPoint, SigHashType, SignParameter,
    Transaction, TxInData, TxOutData,
  };
  use std::str::FromStr;

  #[test]
  fn create_raw_transaction_test() {
    // based: cfd-csharp
    let network_type = Network::Regtest;
    let xpriv: &str = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
    let privkey_ret = ExtPrivkey::new(xpriv);
    assert!(privkey_ret.is_ok(), "err: \"{}\"", privkey_ret.unwrap_err());
    let privkey = privkey_ret.unwrap();
    let derive_key_1_ret = privkey.derive_from_number(1, false);
    assert!(
      derive_key_1_ret.is_ok(),
      "err: \"{}\"",
      derive_key_1_ret.unwrap_err()
    );
    let derive_key_2_ret = privkey.derive_from_number(2, false);
    assert!(
      derive_key_2_ret.is_ok(),
      "err: \"{}\"",
      derive_key_2_ret.unwrap_err()
    );
    let derive_key_3_ret = privkey.derive_from_number(3, false);
    assert!(
      derive_key_3_ret.is_ok(),
      "err: \"{}\"",
      derive_key_3_ret.unwrap_err()
    );
    let child_xpriv_1 = derive_key_1_ret.unwrap();
    let child_xpriv_2 = derive_key_2_ret.unwrap();
    let child_xpriv_3 = derive_key_3_ret.unwrap();
    let child_pubkey_1_ret = child_xpriv_1.get_privkey().get_pubkey();
    assert!(
      child_pubkey_1_ret.is_ok(),
      "err: \"{}\"",
      child_pubkey_1_ret.unwrap_err()
    );
    let child_pubkey_2_ret = child_xpriv_2.get_privkey().get_pubkey();
    assert!(
      child_pubkey_2_ret.is_ok(),
      "err: \"{}\"",
      child_pubkey_2_ret.unwrap_err()
    );
    let child_pubkey_3_ret = child_xpriv_3.get_privkey().get_pubkey();
    assert!(
      child_pubkey_3_ret.is_ok(),
      "err: \"{}\"",
      child_pubkey_3_ret.unwrap_err()
    );

    let child_pubkey_1 = child_pubkey_1_ret.unwrap();
    let child_pubkey_2 = child_pubkey_2_ret.unwrap();
    let child_pubkey_3 = child_pubkey_3_ret.unwrap();

    let addr1_ret = Address::p2wpkh(&child_pubkey_1, &network_type);
    let addr2_ret = Address::p2wpkh(&child_pubkey_2, &network_type);
    let addr3_ret = Address::p2wpkh(&child_pubkey_3, &network_type);
    assert!(addr1_ret.is_ok(), "err: \"{}\"", addr1_ret.unwrap_err());
    assert!(addr2_ret.is_ok(), "err: \"{}\"", addr2_ret.unwrap_err());
    assert!(addr3_ret.is_ok(), "err: \"{}\"", addr3_ret.unwrap_err());
    let addr1 = addr1_ret.unwrap();
    let addr2 = addr2_ret.unwrap();
    let addr3 = addr3_ret.unwrap();

    let outpoint1_ret = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      2,
    );
    let outpoint2_ret = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      3,
    );
    assert!(
      outpoint1_ret.is_ok(),
      "err: \"{}\"",
      outpoint1_ret.unwrap_err()
    );
    assert!(
      outpoint2_ret.is_ok(),
      "err: \"{}\"",
      outpoint2_ret.unwrap_err()
    );
    let outpoint1 = outpoint1_ret.unwrap();
    let outpoint2 = outpoint2_ret.unwrap();
    let txin_list = vec![TxInData::new(&outpoint1), TxInData::new(&outpoint2)];
    let txout_data = vec![
      TxOutData::from_address(10000, &addr1),
      TxOutData::from_address(10000, &addr2),
    ];
    let tx_ret = Transaction::create_tx(2, 0, &txin_list, &txout_data);
    assert!(tx_ret.is_ok(), "err: \"{}\"", tx_ret.unwrap_err());
    let append_txouts = vec![TxOutData::from_address(50000, &addr3)];
    let empty_input_list: Vec<TxInData> = vec![];
    let tx_ret2 = tx_ret
      .unwrap()
      .append_data(&empty_input_list, &append_txouts);
    assert!(tx_ret2.is_ok(), "err: \"{}\"", tx_ret2.unwrap_err());
    let mut tx = tx_ret2.unwrap();
    assert_eq!("020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000",
    tx.to_str());

    assert_eq!(2, tx.get_txin_list().len());
    assert_eq!(3, tx.get_txout_list().len());
    let child_xpriv_11_ret = privkey.derive_from_number(11, false);
    assert!(
      child_xpriv_11_ret.is_ok(),
      "err: \"{}\"",
      child_xpriv_11_ret.unwrap_err()
    );
    let child_xpriv_11 = child_xpriv_11_ret.unwrap();
    let privkey1 = child_xpriv_11.get_privkey();
    let pubkey1_ret = privkey1.get_pubkey();
    assert!(pubkey1_ret.is_ok(), "err: \"{}\"", pubkey1_ret.unwrap_err());
    let pubkey1 = pubkey1_ret.unwrap();
    let sighash_type = SigHashType::All;
    let amount = Amount::new(50000);
    let sighash_ret = tx.create_sighash_by_pubkey(
      &outpoint1,
      &HashType::P2wpkh,
      &pubkey1,
      &sighash_type,
      &amount,
    );
    assert!(sighash_ret.is_ok(), "err: \"{}\"", sighash_ret.unwrap_err());
    let sighash = sighash_ret.unwrap();
    let signature_ret = privkey1.calculate_ec_signature(&sighash, true);
    assert!(
      signature_ret.is_ok(),
      "err: \"{}\"",
      signature_ret.unwrap_err()
    );
    let signature = signature_ret.unwrap().set_use_der_encode(&sighash_type);

    let tx_ret3 = tx.add_sign(&outpoint1, &HashType::P2wpkh, &signature, true);
    assert!(tx_ret3.is_ok(), "err: \"{}\"", tx_ret3.unwrap_err());
    tx = tx_ret3.unwrap();
    let pubkey_info = SignParameter::from_slice(pubkey1.to_slice());
    let tx_ret4 = tx.add_sign(&outpoint1, &HashType::P2wpkh, &pubkey_info, false);
    assert!(tx_ret4.is_ok(), "err: \"{}\"", tx_ret4.unwrap_err());
    tx = tx_ret4.unwrap();
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000", tx.to_str());

    let addr11_ret = Address::p2wpkh(&pubkey1, &network_type);
    assert!(addr11_ret.is_ok(), "err: \"{}\"", addr11_ret.unwrap_err());
    let addr11 = addr11_ret.unwrap();
    let verify_ret = tx.verify_sign_by_address(&outpoint1, &addr11, &amount);
    assert!(verify_ret.is_ok(), "err: \"{}\"", verify_ret.unwrap_err());
    let is_verify = verify_ret.unwrap();
    assert_eq!(true, is_verify);
  }

  #[test]
  fn transaction_sign_pubkey_test() {
    // based: cfd-csharp
    let network_type = Network::Regtest;
    let xpriv: &str = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
    let privkey_ret = ExtPrivkey::new(xpriv);
    assert!(privkey_ret.is_ok(), "err: \"{}\"", privkey_ret.unwrap_err());
    let privkey = privkey_ret.unwrap();

    let outpoint1_ret = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      2,
    );
    assert!(
      outpoint1_ret.is_ok(),
      "err: \"{}\"",
      outpoint1_ret.unwrap_err()
    );
    let outpoint1 = outpoint1_ret.unwrap();
    let base_tx_str = "020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000";
    let tx_ret = Transaction::from_str(base_tx_str);
    assert!(tx_ret.is_ok(), "err: \"{}\"", tx_ret.unwrap_err());
    let mut tx = tx_ret.unwrap();

    assert_eq!(2, tx.get_txin_list().len());
    assert_eq!(3, tx.get_txout_list().len());
    let child_xpriv_11_ret = privkey.derive_from_number(11, false);
    assert!(
      child_xpriv_11_ret.is_ok(),
      "err: \"{}\"",
      child_xpriv_11_ret.unwrap_err()
    );
    let child_xpriv_11 = child_xpriv_11_ret.unwrap();
    let privkey1 = child_xpriv_11.get_privkey();
    let pubkey1_ret = privkey1.get_pubkey();
    assert!(pubkey1_ret.is_ok(), "err: \"{}\"", pubkey1_ret.unwrap_err());
    let pubkey1 = pubkey1_ret.unwrap();
    let sighash_type = SigHashType::All;
    let amount = Amount::new(50000);
    let sighash_ret = tx.create_sighash_by_pubkey(
      &outpoint1,
      &HashType::P2wpkh,
      &pubkey1,
      &sighash_type,
      &amount,
    );
    assert!(sighash_ret.is_ok(), "err: \"{}\"", sighash_ret.unwrap_err());
    let sighash = sighash_ret.unwrap();
    let signature_ret = privkey1.calculate_ec_signature(&sighash, true);
    assert!(
      signature_ret.is_ok(),
      "err: \"{}\"",
      signature_ret.unwrap_err()
    );
    let signature = signature_ret.unwrap().set_use_der_encode(&sighash_type);

    let tx_ret3 = tx.add_pubkey_hash_sign(&outpoint1, &HashType::P2wpkh, &pubkey1, &signature);
    assert!(tx_ret3.is_ok(), "err: \"{}\"", tx_ret3.unwrap_err());
    tx = tx_ret3.unwrap();
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000", tx.to_str());

    let addr11_ret = Address::p2wpkh(&pubkey1, &network_type);
    assert!(addr11_ret.is_ok(), "err: \"{}\"", addr11_ret.unwrap_err());
    let addr11 = addr11_ret.unwrap();
    let verify_ret = tx.verify_sign_by_address(&outpoint1, &addr11, &amount);
    assert!(verify_ret.is_ok(), "err: \"{}\"", verify_ret.unwrap_err());
    let is_verify = verify_ret.unwrap();
    assert_eq!(true, is_verify);
  }

  #[test]
  fn transaction_sign_privkey_test() {
    // based: cfd-csharp
    // let network_type = Network::Regtest;
    let xpriv: &str = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
    let privkey_ret = ExtPrivkey::new(xpriv);
    assert!(privkey_ret.is_ok(), "err: \"{}\"", privkey_ret.unwrap_err());
    let privkey = privkey_ret.unwrap();

    let outpoint1_ret = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      2,
    );
    assert!(
      outpoint1_ret.is_ok(),
      "err: \"{}\"",
      outpoint1_ret.unwrap_err()
    );
    let outpoint1 = outpoint1_ret.unwrap();
    let base_tx_str = "020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000";
    let tx_ret = Transaction::from_str(base_tx_str);
    assert!(tx_ret.is_ok(), "err: \"{}\"", tx_ret.unwrap_err());
    let mut tx = tx_ret.unwrap();

    assert_eq!(2, tx.get_txin_list().len());
    assert_eq!(3, tx.get_txout_list().len());
    let child_xpriv_11_ret = privkey.derive_from_number(11, false);
    assert!(
      child_xpriv_11_ret.is_ok(),
      "err: \"{}\"",
      child_xpriv_11_ret.unwrap_err()
    );
    let child_xpriv_11 = child_xpriv_11_ret.unwrap();
    let privkey1 = child_xpriv_11.get_privkey();
    let sighash_type = SigHashType::All;
    let amount = Amount::new(50000);
    let tx_ret3 = tx.sign_with_privkey(
      &outpoint1,
      &HashType::P2wpkh,
      &privkey1,
      &sighash_type,
      &amount,
    );
    assert!(tx_ret3.is_ok(), "err: \"{}\"", tx_ret3.unwrap_err());
    tx = tx_ret3.unwrap();
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000", tx.to_str());
  }
}
