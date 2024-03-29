extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{
    Address, Amount, ByteData, Descriptor, ExtPrivkey, ExtPubkey, FeeOption, FundTargetOption,
    FundTransactionData, HashType, Network, OutPoint, Privkey, Pubkey, SchnorrPubkey, SchnorrUtil,
    Script, SigHashType, SignParameter, TapBranch, Transaction, TxInData, TxOutData, Txid,
    UtxoData, CODE_SEPARATOR_POSITION_FINAL,
  };
  use std::str::FromStr;

  #[test]
  fn transaction_constructor_test() {
    let tx1 = Transaction::new(2, 0).expect("Fail");
    let tx2 = Transaction::from_str(&tx1.to_str()).expect("Fail");
    let tx3 = Transaction::from_slice(tx1.to_slice()).expect("Fail");
    assert_eq!("02000000000000000000", tx1.to_str());
    assert_eq!(tx1.to_str(), tx2.to_str());
    assert_eq!(tx1.to_str(), tx3.to_str());
  }

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
    assert_eq!((), is_verify);

    let is_verify2 = tx
      .verify_sign_by_script(
        &outpoint1,
        addr11.get_locking_script(),
        &HashType::P2wpkh,
        &amount,
      )
      .expect("Fail");
    assert_eq!((), is_verify2);

    let verify_sig = tx
      .verify_signature_by_pubkey(&outpoint1, &HashType::P2wpkh, &pubkey1, &signature, &amount)
      .expect("Fail");
    assert!(verify_sig);
  }

  #[test]
  fn get_tx_info_test() {
    let privkey = ExtPrivkey::new("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV").expect("Fail");
    let addr1 = Address::p2wpkh(
      privkey
        .derive_pubkey_from_number(1, false)
        .expect("Fail")
        .get_pubkey(),
      &Network::Regtest,
    )
    .expect("Fail");
    let addr2 = Address::p2wpkh(
      privkey
        .derive_pubkey_from_number(2, false)
        .expect("Fail")
        .get_pubkey(),
      &Network::Regtest,
    )
    .expect("Fail");
    let addr3 = Address::p2wpkh(
      privkey
        .derive_pubkey_from_number(3, false)
        .expect("Fail")
        .get_pubkey(),
      &Network::Regtest,
    )
    .expect("Fail");

    let outpoint1 = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      2,
    )
    .expect("Fail");
    let outpoint2 = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      3,
    )
    .expect("Fail");
    let txins = [TxInData::new(&outpoint1), TxInData::new(&outpoint2)];
    let txouts = [
      TxOutData::from_address(10000, &addr1),
      TxOutData::from_address(10000, &addr2),
    ];
    let mut tx = Transaction::create_tx(2, 0, &txins, &txouts).expect("Fail");
    tx = tx
      .append_data(&[], &[TxOutData::from_address(50000, &addr3)])
      .expect("Fail");
    let tx_base = tx.clone();
    assert_eq!("020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000",
    tx_base.to_str());

    let ext_privkey1 = privkey.derive_from_number(11, false).expect("Fail");
    let privkey1 = ext_privkey1.get_privkey();
    let sighash_type = SigHashType::All;
    let amount = Amount::new(50000);
    tx = tx
      .sign_with_privkey(
        &outpoint1,
        &HashType::P2wpkh,
        privkey1,
        &sighash_type,
        &amount,
      )
      .expect("Fail");
    // output.WriteLine("tx:\n" + tx.ToHexString());
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000",
      tx.to_str());

    let txid = tx.as_txid();
    assert_eq!(
      "67e1878d1621e77e166bed9d726bff27b2afcde9eb3dbb1ae3088d0387f40be4",
      txid.to_hex()
    );
    let info = tx.get_info();
    let wtxid = &info.wtxid;
    assert_eq!(
      "24c66461b4b38c750fa4528d0cf3aea9a13d3156c0a73cfd6fca6958523b97f7",
      wtxid.to_hex()
    );
    assert_eq!(295, info.size);
    assert_eq!(213, info.vsize);
    assert_eq!(850, info.weight);
    assert_eq!(2, info.version);
    assert_eq!(0, info.locktime);

    assert_eq!(2, tx.get_txin_list().len());
    assert_eq!(3, tx.get_txout_list().len());
    assert_eq!(1, tx.get_txin_index(&outpoint2).expect("Fail"));
    assert_eq!(2, tx.get_txout_index_by_address(&addr3).expect("Fail"));
    assert_eq!(
      1,
      tx.get_txout_index_by_script(addr2.get_locking_script())
        .expect("Fail")
    );

    assert!(outpoint2.eq(&tx.get_txin_list()[1].outpoint));
    assert!(addr2
      .get_locking_script()
      .eq(&tx.get_txout_list()[1].locking_script));
  }

  #[test]
  fn update_amount_test() {
    let mut tx = Transaction::from_str("0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000").expect("Fail");
    tx = tx.update_amount(1, 76543210).expect("Fail");
    assert_eq!("0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688aceaf48f04000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000",
      tx.to_str());
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
      privkey1,
      &sighash_type,
      &amount,
    );
    assert!(tx_ret3.is_ok(), "err: \"{}\"", tx_ret3.unwrap_err());
    tx = tx_ret3.unwrap();
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000", tx.to_str());
  }

  #[test]
  fn multisig_sign_test() {
    let privkey = ExtPrivkey::new("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV").expect("Fail");
    let mut tx = Transaction::from_str("020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000").expect("Fail");
    let outpoint2 = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      3,
    )
    .expect("Fail");
    let amount = Amount::new(25000);

    let ext_privkey21 = privkey.derive_from_number(21, false).expect("Fail");
    let ext_privkey22 = privkey.derive_from_number(22, false).expect("Fail");
    let ext_privkey23 = privkey.derive_from_number(23, false).expect("Fail");
    let privkey21 = ext_privkey21.get_privkey();
    let privkey22 = ext_privkey22.get_privkey();
    let privkey23 = ext_privkey23.get_privkey();
    let pubkey21 = privkey21.get_pubkey().expect("Fail");
    let pubkey22 = privkey22.get_pubkey().expect("Fail");
    let pubkey23 = privkey23.get_pubkey().expect("Fail");
    let multisig_script =
      Script::multisig(2, &[pubkey21, pubkey22.clone(), pubkey23.clone()]).expect("Fail");
    let sighash_type = SigHashType::All;
    let sighash = tx
      .create_sighash_by_script(
        &outpoint2,
        &HashType::P2shP2wsh,
        &multisig_script,
        &sighash_type,
        &amount,
      )
      .expect("Fail");
    let mut sig22 = privkey22
      .calculate_ec_signature(&sighash, true)
      .expect("Fail");
    let mut sig23 = privkey23
      .calculate_ec_signature(&sighash, true)
      .expect("Fail");
    sig22 = sig22
      .set_use_der_encode(&sighash_type)
      .set_related_pubkey(&pubkey22);
    sig23 = sig23
      .set_use_der_encode(&sighash_type)
      .set_related_pubkey(&pubkey23);
    tx = tx
      .add_multisig_sign(
        &outpoint2,
        &HashType::P2shP2wsh,
        &multisig_script,
        &[sig22.clone(), sig23],
      )
      .expect("Fail");
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff0100000000000000000000000000000000000000000000000000000000000000030000002322002064a0e02e723ce71d8f18441a39bedd5cefc9c5411c3045614c34bba1a8fbd94fffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c0004004730440220749cbe5080a3ce49c2a89f897be537b2b5449b75c64b57030dea1859b22c183f02200573f5be5170bfe4ca617edec0eb021638dd78b90209bbd8eede8a9e8138a32c01473044022019105df75884ff34111282f32c22986db295596983a87bf0df1d16905b4f9a50022075f8a2c8e3335a4265265b428df185fb045d9614ed1b08929bfa9f3f9d294a72016952210334bd4f1bab7f3e6f6bfc4a4aeaa890b858a9a146c6bd6bc5a3fbc00a12524ca72103ff743075c59596729d74b79694ca99b2c57bed6a77a06871b123b6e0d729823021036759d0dc7623e781de940a9bc9162f69c6ad68cc5be1c748e960ae4613e658e053ae00000000",
      tx.to_str());

    let is_verify = tx
      .verify_signature_by_script(
        &outpoint2,
        &HashType::P2shP2wsh,
        &pubkey22,
        &multisig_script,
        &sig22,
        &amount,
      )
      .expect("Fail");
    assert!(is_verify);
  }

  #[test]
  fn script_sign_test() {
    let privkey = ExtPrivkey::new("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV").expect("Fail");
    let mut tx = Transaction::from_str("020000000201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c00000000").expect("Fail");
    let outpoint2 = OutPoint::from_str(
      "0000000000000000000000000000000000000000000000000000000000000001",
      3,
    )
    .expect("Fail");
    let amount = Amount::new(25000);

    let ext_privkey21 = privkey.derive_from_number(21, false).expect("Fail");
    let ext_privkey22 = privkey.derive_from_number(22, false).expect("Fail");
    let ext_privkey23 = privkey.derive_from_number(23, false).expect("Fail");
    let privkey21 = ext_privkey21.get_privkey();
    let privkey22 = ext_privkey22.get_privkey();
    let privkey23 = ext_privkey23.get_privkey();
    let pubkey21 = privkey21.get_pubkey().expect("Fail");
    let pubkey22 = privkey22.get_pubkey().expect("Fail");
    let pubkey23 = privkey23.get_pubkey().expect("Fail");
    let multisig_script =
      Script::multisig(2, &[pubkey21, pubkey22.clone(), pubkey23.clone()]).expect("Fail");
    let sighash_type = SigHashType::All;
    let sighash = tx
      .create_sighash_by_script(
        &outpoint2,
        &HashType::P2shP2wsh,
        &multisig_script,
        &sighash_type,
        &amount,
      )
      .expect("Fail");
    let mut sig22 = privkey22
      .calculate_ec_signature(&sighash, true)
      .expect("Fail");
    let mut sig23 = privkey23
      .calculate_ec_signature(&sighash, true)
      .expect("Fail");
    sig22 = sig22
      .set_use_der_encode(&sighash_type)
      .set_related_pubkey(&pubkey22);
    sig23 = sig23
      .set_use_der_encode(&sighash_type)
      .set_related_pubkey(&pubkey23);

    tx = tx
      .add_script_hash_sign(
        &outpoint2,
        &HashType::P2shP2wsh,
        &[SignParameter::from_slice(&[]), sig22, sig23],
        &multisig_script,
        true,
      )
      .expect("Fail");
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff0100000000000000000000000000000000000000000000000000000000000000030000002322002064a0e02e723ce71d8f18441a39bedd5cefc9c5411c3045614c34bba1a8fbd94fffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c0004004730440220749cbe5080a3ce49c2a89f897be537b2b5449b75c64b57030dea1859b22c183f02200573f5be5170bfe4ca617edec0eb021638dd78b90209bbd8eede8a9e8138a32c01473044022019105df75884ff34111282f32c22986db295596983a87bf0df1d16905b4f9a50022075f8a2c8e3335a4265265b428df185fb045d9614ed1b08929bfa9f3f9d294a72016952210334bd4f1bab7f3e6f6bfc4a4aeaa890b858a9a146c6bd6bc5a3fbc00a12524ca72103ff743075c59596729d74b79694ca99b2c57bed6a77a06871b123b6e0d729823021036759d0dc7623e781de940a9bc9162f69c6ad68cc5be1c748e960ae4613e658e053ae00000000",
      tx.to_str());
  }

  #[test]
  fn verify_pkh_test() {
    let tx = Transaction::from_str("01000000019c53cb2a6118530aaa345b799aeb7e4e5055de41ac5b2dd2ce47419624c57b580000000000ffffffff0130ea052a010000001976a9143cadb10040e9e7002bbd9d0620f5f79c05603ffd88ac00000000").expect("Fail");
    let outpoint = OutPoint::from_str(
      "587bc524964147ced22d5bac41de55504e7eeb9a795b34aa0a5318612acb539c",
      0,
    )
    .expect("Fail");
    let hash_type = HashType::P2pkh;
    let pubkey =
      Pubkey::from_str("02f56451fc1fd9040652ff9a700cf914ad1df1c8f9e82f3fe96ca01b6cd47293ef")
        .expect("Fail");
    let signature = SignParameter::from_str("3c1cffcc8908ab1911303f102c41e5c677488346851288360b0d309ab99557207ac2c9c6aec9d8bae187a1eea843dda423edff216c568efad231e4249c77ffe1").expect("Fail").set_use_der_encode(&SigHashType::All);
    let verify = tx
      .verify_signature_by_pubkey(
        &outpoint,
        &hash_type,
        &pubkey,
        &signature,
        &Amount::default(),
      )
      .expect("Fail");
    assert!(verify);
  }

  #[test]
  fn transaction_estimate_fee_test() {
    let network = Network::Mainnet;
    // p2sh-p2wpkh
    let utxos = get_bitcoin_bnb_utxo_list(&Network::Mainnet);
    let key = ExtPubkey::new("xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy").expect("Fail");
    let set_addr1 = Address::p2wpkh(
      key.derive_from_number(11).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let set_addr2 = Address::p2wpkh(
      key.derive_from_number(12).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");

    // amount = 85062500 + 39062500 = 124125000
    let amount = utxos[1].amount + utxos[2].amount;
    let fee_amount = 5000;
    let amount1 = 100000000;
    let amount2 = amount - amount1 - fee_amount;
    let tx = Transaction::create_tx(
      2,
      0,
      &[
        TxInData::new(&utxos[1].outpoint),
        TxInData::new(&utxos[2].outpoint),
      ],
      &[
        TxOutData::from_address(amount1, &set_addr1),
        TxOutData::from_address(amount2, &set_addr2),
      ],
    )
    .expect("Fail");

    let fee_data = tx
      .estimate_fee(&[utxos[1].clone(), utxos[2].clone()], 10.0)
      .expect("Fail");
    assert_eq!(740, fee_data.txout_fee);
    assert_eq!(1830, fee_data.utxo_fee);
  }

  #[test]
  fn fund_raw_transaction_test() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_bnb_utxo_list(&Network::Mainnet);
    let key = ExtPubkey::new("xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy").expect("Fail");
    let set_addr1 = Address::p2wpkh(
      key.derive_from_number(11).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let set_addr2 = Address::p2wpkh(
      key.derive_from_number(12).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");

    let tx = Transaction::create_tx(
      2,
      0,
      &[],
      &[
        TxOutData::from_address(10000000, &set_addr1),
        TxOutData::from_address(4000000, &set_addr2),
      ],
    )
    .expect("Fail");

    let addr1 = Address::p2wpkh(
      key.derive_from_number(1).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let target_data = FundTargetOption::from_amount(0, &addr1);
    let mut fee_option = FeeOption::new(&network);
    fee_option.fee_rate = 20.0;
    let mut fund_data = FundTransactionData::default();
    let fund_tx = tx
      .fund_raw_transaction(&[], &utxos, &target_data, &fee_option, &mut fund_data)
      .expect("Fail");

    assert_eq!("02000000010af4768e14f820cb9063f55833b5999119e53390ecf4bf181842909b11d0974d0000000000ffffffff0380969800000000001600144352a1a6e86311f22274f7ebb2746de21b09b15d00093d00000000001600148beaaac4654cf4ebd8e46ca5062b0e7fb3e7470c947f19000000000016001478eb9fc2c9e1cdf633ecb646858ba862b21384ab00000000",
    fund_tx.to_str());
    assert_eq!(addr1.to_str(), fund_data.reserved_address_list[0].to_str());
    assert_eq!(3940, fund_data.fee_amount);
  }

  #[test]
  fn fund_raw_transaction_exist_txin_test() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_bnb_utxo_list(&Network::Mainnet);
    let key = ExtPubkey::new("xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy").expect("Fail");
    let set_addr1 = Address::p2wpkh(
      key.derive_from_number(11).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let set_addr2 = Address::p2wpkh(
      key.derive_from_number(12).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");

    // amount = 85062500 + 39062500 = 124125000
    let amount1 = 100000000;
    let amount2 = 100000000;
    let mut tx = Transaction::create_tx(
      2,
      0,
      &[
        TxInData::new(&utxos[1].outpoint),
        TxInData::new(&utxos[2].outpoint),
      ],
      &[
        TxOutData::from_address(amount1, &set_addr1),
        TxOutData::from_address(amount2, &set_addr2),
      ],
    )
    .expect("Fail");

    let input_utxos = [utxos[1].clone(), utxos[2].clone()];
    let addr1 = Address::p2wpkh(
      key.derive_from_number(1).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let target_data = FundTargetOption::from_amount(0, &addr1);
    let mut fee_option = FeeOption::new(&network);
    fee_option.fee_rate = 20.0;
    fee_option.long_term_fee_rate = 20.0;
    fee_option.dust_fee_rate = -1.0;
    fee_option.knapsack_min_change = -1;
    let mut fund_data = FundTransactionData::default();
    tx = tx
      .fund_raw_transaction(
        &input_utxos,
        &utxos,
        &target_data,
        &fee_option,
        &mut fund_data,
      )
      .expect("Fail");

    assert_eq!("02000000030a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff0a9bf51e0ac499391efd9426e2c909901edd74a97d2378b49c8832c491ad1e9e0000000000ffffffff0a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0300e1f505000000001600144352a1a6e86311f22274f7ebb2746de21b09b15d00e1f505000000001600148beaaac4654cf4ebd8e46ca5062b0e7fb3e7470c9030b8040000000016001478eb9fc2c9e1cdf633ecb646858ba862b21384ab00000000",
    tx.to_str());
    assert_eq!(addr1.to_str(), fund_data.reserved_address_list[0].to_str());
    assert_eq!(7580, fund_data.fee_amount);

    let fee_utxos = [utxos[1].clone(), utxos[2].clone(), utxos[0].clone()];
    let fee_data = tx
      .estimate_fee(&fee_utxos, fee_option.fee_rate)
      .expect("Fail");
    assert_eq!(7580, fee_data.txout_fee + fee_data.utxo_fee);
    assert_eq!(2100, fee_data.txout_fee);
    assert_eq!(5480, fee_data.utxo_fee);
  }

  #[test]
  fn fund_raw_transaction_regtest_address_test() {
    let network = Network::Regtest;
    let utxos = get_bitcoin_bnb_utxo_list(&network);
    let key = ExtPubkey::new("xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy").expect("Fail");
    let set_addr1 = Address::p2wpkh(
      key.derive_from_number(11).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let set_addr2 = Address::p2wpkh(
      key.derive_from_number(12).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");

    let tx = Transaction::create_tx(
      2,
      0,
      &[],
      &[
        TxOutData::from_address(10000000, &set_addr1),
        TxOutData::from_address(4000000, &set_addr2),
      ],
    )
    .expect("Fail");

    let addr1 = Address::p2wpkh(
      key.derive_from_number(1).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let target_data = FundTargetOption::from_amount(0, &addr1);
    let mut fee_option = FeeOption::new(&network);
    fee_option.fee_rate = 20.0;
    let mut fund_data = FundTransactionData::default();
    let fund_tx = tx
      .fund_raw_transaction(&[], &utxos, &target_data, &fee_option, &mut fund_data)
      .expect("Fail");

    assert_eq!("02000000010af4768e14f820cb9063f55833b5999119e53390ecf4bf181842909b11d0974d0000000000ffffffff0380969800000000001600144352a1a6e86311f22274f7ebb2746de21b09b15d00093d00000000001600148beaaac4654cf4ebd8e46ca5062b0e7fb3e7470c947f19000000000016001478eb9fc2c9e1cdf633ecb646858ba862b21384ab00000000",
    fund_tx.to_str());
    assert_eq!(addr1.to_str(), fund_data.reserved_address_list[0].to_str());
    assert_eq!(3940, fund_data.fee_amount);
  }

  fn get_bitcoin_bnb_utxo_list(network: &Network) -> Vec<UtxoData> {
    let desc = "sh(wpkh([ef735203/0'/0'/7']022c2409fbf657ba25d97bb3dab5426d20677b774d4fc7bd3bfac27ff96ada3dd1))#4z2vy08x";
    let descriptor = Descriptor::new(desc, network).expect("Fail");
    vec![
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
          0,
        )
        .expect("Fail"),
        155062500,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a",
          0,
        )
        .expect("Fail"),
        85062500,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "9e1ead91c432889cb478237da974dd1e9009c9e22694fd1e3999c40a1ef59b0a",
          0,
        )
        .expect("Fail"),
        39062500,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "8f4af7ee42e62a3d32f25ca56f618fb2f5df3d4c3a9c59e2c3646c5535a3d40a",
          0,
        )
        .expect("Fail"),
        61062500,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "4d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a",
          0,
        )
        .expect("Fail"),
        15675000,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "b9720ed2265a4ced42425bffdb4ef90a473b4106811a802fce53f7c57487fa0b",
          0,
        )
        .expect("Fail"),
        14938590,
        &descriptor,
      ),
    ]
  }

  fn get_bitcoin_utxo_list() -> Vec<UtxoData> {
    let network = &Network::Mainnet;
    let desc =
      "wpkh([ef735203/0'/0'/7']022c2409fbf657ba25d97bb3dab5426d20677b774d4fc7bd3bfac27ff96ada3dd1)";
    let descriptor = Descriptor::new(desc, network).expect("Fail");
    vec![
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
          0,
        )
        .expect("Fail"),
        312500000,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a",
          0,
        )
        .expect("Fail"),
        78125000,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "9e1ead91c432889cb478237da974dd1e9009c9e22694fd1e3999c40a1ef59b0a",
          0,
        )
        .expect("Fail"),
        1250000000,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "8f4af7ee42e62a3d32f25ca56f618fb2f5df3d4c3a9c59e2c3646c5535a3d40a",
          0,
        )
        .expect("Fail"),
        39062500,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "4d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a",
          0,
        )
        .expect("Fail"),
        156250000,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "b9720ed2265a4ced42425bffdb4ef90a473b4106811a802fce53f7c57487fa0b",
          0,
        )
        .expect("Fail"),
        2500000000,
        &descriptor,
      ),
      UtxoData::from_descriptor(
        &OutPoint::from_str(
          "0f093988839178ea5895431241cb4400fb31dd7b665a1a93cbd372336c717e0c",
          0,
        )
        .expect("Fail"),
        5000000000,
        &descriptor,
      ),
    ]
  }

  #[test]
  fn select_coins_test01() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_list = Transaction::select_coins(&utxos, 0, 0, &fee_param).expect("Fail");
    assert!(selected_list.select_utxo_list.is_empty());
    assert_eq!(0, selected_list.utxo_fee_amount);
  }

  #[test]
  fn select_coins_test02() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 39059180, &fee_param).expect("Fail");
    assert_eq!(1, selected_list.select_utxo_list.len());
    assert_eq!(1380, selected_list.utxo_fee_amount);
    assert_eq!(39062500, selected_list.get_total_amount());
    assert_eq!(39062500, selected_list.select_utxo_list[0].amount);
  }

  #[test]
  fn select_coins_test03() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 119154360, &fee_param).expect("Fail");
    assert_eq!(1, selected_list.select_utxo_list.len());
    assert_eq!(1380, selected_list.utxo_fee_amount);
    assert_eq!(156250000, selected_list.get_total_amount());
    assert_eq!(156250000, selected_list.select_utxo_list[0].amount);
  }

  #[test]
  fn select_coins_test04() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 120000000, &fee_param).expect("Fail");
    assert_eq!(1, selected_list.select_utxo_list.len());
    assert_eq!(1380, selected_list.utxo_fee_amount);
    assert_eq!(156250000, selected_list.get_total_amount());
    assert_eq!(156250000, selected_list.select_utxo_list[0].amount);
  }

  #[test]
  fn select_coins_test05() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 220000000, &fee_param).expect("Fail");
    assert_eq!(2, selected_list.select_utxo_list.len());
    assert_eq!(2760, selected_list.utxo_fee_amount);
    assert_eq!(234375000, selected_list.get_total_amount());
    assert_eq!(156250000, selected_list.select_utxo_list[0].amount);
    assert_eq!(78125000, selected_list.select_utxo_list[1].amount);
  }

  #[test]
  fn select_coins_test06() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 460000000, &fee_param).expect("Fail");
    assert_eq!(2, selected_list.select_utxo_list.len());
    assert_eq!(2760, selected_list.utxo_fee_amount);
    assert_eq!(468750000, selected_list.get_total_amount());
    assert_eq!(312500000, selected_list.select_utxo_list[0].amount);
    assert_eq!(156250000, selected_list.select_utxo_list[1].amount);
  }

  #[test]
  fn select_coins_test07() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 468700000, &fee_param).expect("Fail");
    assert_eq!(1, selected_list.select_utxo_list.len());
    assert_eq!(1380, selected_list.utxo_fee_amount);
    assert_eq!(1250000000, selected_list.get_total_amount());
    assert_eq!(1250000000, selected_list.select_utxo_list[0].amount);
  }

  #[test]
  fn select_coins_test08() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    fee_param.knapsack_min_change = 0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 468700000, &fee_param).expect("Fail");
    assert_eq!(2, selected_list.select_utxo_list.len());
    assert_eq!(2760, selected_list.utxo_fee_amount);
    assert_eq!(468750000, selected_list.get_total_amount());
    assert_eq!(312500000, selected_list.select_utxo_list[0].amount);
    assert_eq!(156250000, selected_list.select_utxo_list[1].amount);
  }

  #[test]
  fn select_coins_test11() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_bnb_utxo_list(&network);
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 2.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 99998500, &fee_param).expect("Fail");
    assert_eq!(2, selected_list.select_utxo_list.len());
    assert_eq!(368, selected_list.utxo_fee_amount);
    assert_eq!(100001090, selected_list.get_total_amount());
    assert_eq!(85062500, selected_list.select_utxo_list[0].amount);
    assert_eq!(14938590, selected_list.select_utxo_list[1].amount);
  }

  #[test]
  fn select_coins_test12() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_bnb_utxo_list(&network);
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 2.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 155060800, &fee_param).expect("Fail");
    assert_eq!(1, selected_list.select_utxo_list.len());
    assert_eq!(184, selected_list.utxo_fee_amount);
    assert_eq!(155062500, selected_list.get_total_amount());
    assert_eq!(155062500, selected_list.select_utxo_list[0].amount);
  }

  #[test]
  fn select_coins_test13() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_bnb_utxo_list(&network);
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 1.0;
    let selected_list =
      Transaction::select_coins(&utxos, 1500, 114040000, &fee_param).expect("Fail");
    assert_eq!(3, selected_list.select_utxo_list.len());
    assert_eq!(276, selected_list.utxo_fee_amount);
    assert_eq!(115063590, selected_list.get_total_amount());
    assert_eq!(61062500, selected_list.select_utxo_list[0].amount);
    assert_eq!(39062500, selected_list.select_utxo_list[1].amount);
    assert_eq!(14938590, selected_list.select_utxo_list[2].amount);
  }

  #[test]
  fn select_coins_error_test01() {
    let network = Network::Mainnet;
    let utxos = vec![];
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_result = Transaction::select_coins(&utxos, 1500, 100000000, &fee_param);
    assert!(selected_result.is_err(), "not error.");
    let err_obj = selected_result.unwrap_err();
    let err_msg = format!("{}", err_obj);
    assert_eq!(
      "[IllegalState]: Failed to select coin. Not enough utxos.",
      err_msg
    );
    // TODO: Should I check if the utxo list is empty?
  }

  #[test]
  fn select_coins_error_test02() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_utxo_list();
    let mut fee_param = FeeOption::new(&network);
    fee_param.fee_rate = 20.0;
    let selected_result = Transaction::select_coins(&utxos, 1500, 9500000000, &fee_param);
    assert!(selected_result.is_err(), "not error.");
    let err_obj = selected_result.unwrap_err();
    let err_msg = format!("{}", err_obj);
    assert_eq!(
      "[IllegalState]: Failed to select coin. Not enough utxos.",
      err_msg
    );
  }

  #[test]
  fn taproot_schnorr_sign_test01() {
    let privkey =
      Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
        .expect("Fail");
    let (pubkey, _) = SchnorrPubkey::from_privkey(&privkey).expect("Fail");
    assert_eq!(
      "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      pubkey.to_hex()
    );

    let addr = Address::taproot(&pubkey, &Network::Testnet).expect("Fail");
    assert_eq!(
      "tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6",
      addr.to_str()
    );

    let tx_hex = "020000000116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000";

    let utxos = [UtxoData::from_locking_script(
      &OutPoint::new(
        &Txid::from_str("2fea883042440d030ca5929814ead927075a8f52fef5f4720fa3cec2e475d916")
          .expect("Fail"),
        0,
      ),
      2499999000,
      addr.get_locking_script(),
      &Network::Mainnet,
    )
    .expect("Fail")];
    let outpoint = utxos[0].outpoint.clone();

    let mut tx = Transaction::from_str(tx_hex).expect("Fail");
    let fee_data = tx.estimate_fee(&utxos, 2.0).expect("Fail");
    assert_eq!(202, fee_data.get_total_fee());

    tx = tx.append_utxo_list(&utxos).expect("Fail");

    let sighash_type = SigHashType::All;
    let annex = vec![];
    let sighash = tx
      .get_sighash_by_schnorr_pubkey(&outpoint, &pubkey, &sighash_type, &annex)
      .expect("Fail");
    let sighash_bytes = ByteData::from_slice(&sighash);
    assert_eq!(
      "e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02",
      sighash_bytes.to_hex()
    );

    let util = SchnorrUtil::new();
    let aux_rand = ByteData::default();
    let signature = util
      .sign(&sighash_bytes, &privkey, &aux_rand)
      .expect("Fail");
    let sig = signature.get_sign_parameter(&sighash_type);
    assert_eq!("61f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f20872", sig.to_hex());

    tx = tx
      .add_taproot_signature(&outpoint, &sig, &annex)
      .expect("Fail");
    assert_eq!("0200000000010116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d5014161f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f208720100000000", tx.to_str());

    tx.verify_sign_by_utxo_list(&outpoint).expect("Fail");

    // verify signature
    let is_verify = util
      .verify(&signature, &sighash_bytes, &pubkey)
      .expect("Fail");
    assert!(is_verify);
  }

  #[test]
  fn taproot_schnorr_sign_test02() {
    let privkey =
      Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
        .expect("Fail");
    let (pubkey, _) = SchnorrPubkey::from_privkey(&privkey).expect("Fail");
    assert_eq!(
      "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      pubkey.to_hex()
    );

    let tx_hex = "020000000116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000";

    let addr = Address::taproot(&pubkey, &Network::Testnet).expect("Fail");
    assert_eq!(
      "tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6",
      addr.to_str()
    );

    let utxos = [UtxoData::from_locking_script(
      &OutPoint::new(
        &Txid::from_str("2fea883042440d030ca5929814ead927075a8f52fef5f4720fa3cec2e475d916")
          .expect("Fail"),
        0,
      ),
      2499999000,
      addr.get_locking_script(),
      &Network::Mainnet,
    )
    .expect("Fail")];
    let outpoint = utxos[0].outpoint.clone();

    let mut tx = Transaction::from_str(tx_hex).expect("Fail");

    tx = tx.append_utxo_list(&utxos).expect("Fail");

    let sighash_type = SigHashType::All;
    tx = tx
      .sign_with_privkey_by_utxo_list(&outpoint, &privkey, &sighash_type, &[], &[])
      .expect("Fail");
    assert_eq!("0200000000010116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d5014161f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f208720100000000", tx.to_str());

    tx.verify_sign_by_utxo_list(&outpoint).expect("Fail");
  }

  #[test]
  fn tapscript_sign_test01() {
    let privkey =
      Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
        .expect("Fail");
    let (pubkey, _) = SchnorrPubkey::from_privkey(&privkey).expect("Fail");
    assert_eq!(
      "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      pubkey.to_hex()
    );

    let script_checksig =
      Script::from_asm(&format!("{} OP_CHECKSIG", pubkey.to_hex())).expect("Fail");

    let mut tree = TapBranch::from_tapscript(&script_checksig).expect("Fail");
    tree
      .add_by_tapbranch_hash(
        &ByteData::from_str("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d")
          .expect("Fail")
          .to_32byte_array(),
      )
      .expect("Fail");
    tree
      .add_by_tapbranch_hash(
        &ByteData::from_str("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54")
          .expect("Fail")
          .to_32byte_array(),
      )
      .expect("Fail");

    let (tweaked_pubkey, addr, control_block) = tree
      .get_tweaked_pubkey(&pubkey, &Network::Mainnet)
      .expect("Fail");
    assert_eq!(
      "3dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2",
      tweaked_pubkey.to_hex()
    );
    assert_eq!(
      "bc1p8hh955u8526hjqhn5m5a5pmhymgecmxgerrmqj70tgvhk25mq8fqw77n40",
      addr.to_str()
    );
    assert_eq!(
    "c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54",
    control_block.to_hex());
    let tapleaf_hash = tree.get_tapleaf_hash().expect("Fail");
    assert_eq!(
      "dfc43ba9fc5f8a9e1b6d6a50600c704bb9e41b741d9ed6de6559a53d2f38e513",
      ByteData::from_slice(&tapleaf_hash).to_hex()
    );
    let tweaked_privkey = tree.get_tweaked_privkey(&privkey).expect("Fail");
    assert_eq!(
      "a7d17bee0b6313cf864a1ac6f203aafd74a40703ffc050f66517e4f83ff41a03",
      tweaked_privkey.to_hex()
    );

    let tx_hex = "02000000015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000";
    let utxos = [UtxoData::from_locking_script(
      &OutPoint::new(
        &Txid::from_str("195d6c18afaa6c33dcc2da86c6c0cd3f93ec2b44e4c8e9be00c7000eafa1805b")
          .expect("Fail"),
        0,
      ),
      2499999000,
      addr.get_locking_script(),
      &Network::Mainnet,
    )
    .expect("Fail")];
    let outpoint = utxos[0].outpoint.clone();

    let mut tx = Transaction::from_str(tx_hex).expect("Fail");
    let fee_data = tx.estimate_fee(&utxos, 2.0).expect("Fail");
    assert_eq!(202, fee_data.get_total_fee());

    tx = tx.append_utxo_list(&utxos).expect("Fail");

    let sighash_type = SigHashType::All;
    let annex = vec![];
    let sighash = tx
      .get_sighash_by_tapscript(
        &outpoint,
        &tapleaf_hash,
        &sighash_type,
        CODE_SEPARATOR_POSITION_FINAL,
        &annex,
      )
      .expect("Fail");
    let sighash_bytes = ByteData::from_slice(&sighash);
    assert_eq!(
      "80e53eaee13048aee9c6c13fa5a8529aad7fe2c362bfc16f1e2affc71f591d36",
      sighash_bytes.to_hex()
    );

    let util = SchnorrUtil::new();
    let aux_rand = ByteData::default();
    let signature = util
      .sign(&sighash_bytes, &privkey, &aux_rand)
      .expect("Fail");
    let sig = signature.get_sign_parameter(&sighash_type);
    assert_eq!("f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee9", sig.to_hex());

    tx = tx
      .add_tapscript_sign(&outpoint, &[sig], &script_checksig, &control_block, &annex)
      .expect("Fail");
    assert_eq!("020000000001015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee90122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5400000000", tx.to_str());

    let err_info = tx.verify_sign_by_utxo_list(&outpoint).expect_err("Fail");
    assert_eq!(
      "[IllegalState]: The script analysis of tapscript is not supported.",
      err_info.to_string()
    );
    // The script analysis of tapscript is not supported.

    // verify signature
    let is_verify = util
      .verify(&signature, &sighash_bytes, &pubkey)
      .expect("Fail");
    assert!(is_verify);
  }

  #[test]
  fn split_txout_test() {
    let mut tx = Transaction::from_str("0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0118f50295000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb00000000").expect("Fail");
    tx = tx
      .split_txout(
        0,
        &[TxOutData::from_address(
          499999000,
          &Address::from_str("bc1qz33wef9ehrvd7c64p27jf5xtvn50946xfzpxx4").expect("Fail"),
        )],
      )
      .expect("Fail");
    assert_eq!("0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0200943577000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb1861cd1d000000001600141462eca4b9b8d8df63550abd24d0cb64e8f2d74600000000",
      tx.to_str());

    tx = Transaction::from_str("0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0118f50295000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb00000000").expect("Fail");
    tx = tx
      .split_txout(
        0,
        &[
          TxOutData::from_locking_script(
            400000000,
            &Script::from_hex("00141462eca4b9b8d8df63550abd24d0cb64e8f2d746").expect("Fail"),
          ),
          TxOutData::from_locking_script(
            99999000,
            &Script::from_hex("0014164e985d0fc92c927a66c0cbaf78e6ea389629d5").expect("Fail"),
          ),
        ],
      )
      .expect("Fail");
    assert_eq!("0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0300943577000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb0084d717000000001600141462eca4b9b8d8df63550abd24d0cb64e8f2d74618ddf50500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000",
      tx.to_str());
  }

  #[test]
  fn update_txin_sequence_test() {
    let mut tx = Transaction::from_str("02000000000101ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0118f50295000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb02473044022018b10265080f8c491c43595000461a19212239fea9ee4c6fd26498f358b1760d0220223c1389ac26a2ed5f77ad73240af2fa6eb30ef5d19520026c2f7b7e817592530121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c4400000000").expect("Fail");
    tx = tx
      .update_txin_sequence(
        &OutPoint::from_str(
          "1f9866dc0a19c427347c2db0b5910bdc2c20b78fa9f74f8756b21db890dba8ff",
          0,
        )
        .expect("Fail"),
        4294967294,
      )
      .expect("Fail");
    assert_eq!(
      "02000000000101ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000feffffff0118f50295000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb02473044022018b10265080f8c491c43595000461a19212239fea9ee4c6fd26498f358b1760d0220223c1389ac26a2ed5f77ad73240af2fa6eb30ef5d19520026c2f7b7e817592530121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c4400000000",
      tx.to_str());
  }

  #[test]
  fn update_witness_stack_test() {
    let mut tx = Transaction::from_str("020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad800000000").expect("Fail");
    tx = tx
      .update_witness_stack(
        &OutPoint::from_str(
          "ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c",
          0,
        )
        .expect("Fail"),
        1,
        &ByteData::from_str("03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79")
          .expect("Fail"),
      )
      .expect("Fail");
    assert_eq!(
      "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf7900000000",
      tx.to_str());
  }

  #[test]
  fn get_txout_index_test() {
    let tx = Transaction::from_str(
      "02000000034cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff81ddd34c6c0c32544e3b89f5e24c6cd7afca62f2b5069281ac9fced6251191d20000000000ffffffff81ddd34c6c0c32544e3b89f5e24c6cd7afca62f2b5069281ac9fced6251191d20100000000ffffffff040200000000000000220020c5ae4ff17cec055e964b573601328f3f879fa441e53ef88acdfd4d8e8df429ef406f400100000000220020ea5a7208cddfbc20dd93e12bf29deb00b68c056382a502446c9c5b55490954d215cd5b0700000000220020f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a42406f400100000000220020ea5a7208cddfbc20dd93e12bf29deb00b68c056382a502446c9c5b55490954d200000000").expect("Fail");
    let indexes = tx
      .get_txout_indexes_by_address(
        &Address::from_str("bc1qafd8yzxdm77zphvnuy4l980tqzmgcptrs2jsy3rvn3d42jgf2nfqc4zt4j")
          .expect("Fail"),
      )
      .expect("Fail");
    assert_eq!(2, indexes.len());
    if indexes.len() == 2 {
      assert_eq!(1, indexes[0]);
      assert_eq!(3, indexes[1]);
    }
  }
}
