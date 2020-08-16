extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{
    Address, Amount, Descriptor, ExtPrivkey, ExtPubkey, FeeOption, FundTargetOption,
    FundTransactionData, HashType, Network, OutPoint, SigHashType, SignParameter, Transaction,
    TxInData, TxOutData, UtxoData,
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
    assert_eq!((), is_verify);
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
      &privkey1,
      &sighash_type,
      &amount,
    );
    assert!(tx_ret3.is_ok(), "err: \"{}\"", tx_ret3.unwrap_err());
    tx = tx_ret3.unwrap();
    assert_eq!("0200000000010201000000000000000000000000000000000000000000000000000000000000000200000000ffffffff01000000000000000000000000000000000000000000000000000000000000000300000000ffffffff0310270000000000001600148b756cbd98f4f55e985f80437a619d47f0732a941027000000000000160014c0a3dd0b7c1b3281be91112e16ce931dbac2a97950c3000000000000160014ad3abd3c325e40e20d89aa054dd980b97494f16c02473044022034db802aad655cd9be589075fc8ef325b6ffb8c24e5b27eb87bde8ad38f5fd7a0220364c916c8e8fc0adf714d7148cd1c6dc6f3e67d55471e57233b1870c65ec2727012103782f0ea892d7000e5f0f82b6ff283382a76500137a542bb0a616530094a8f54c0000000000", tx.to_str());
  }

  #[test]
  fn transaction_estimate_fee_test() {
    let network = Network::Mainnet;
    // p2sh-p2wpkh
    let utxos = get_bitcoin_bnb_utxo_list(&Network::Mainnet);
    let key = ExtPubkey::new("xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy").expect("Fail");
    let set_addr1 = Address::p2wpkh(
      &key.derive_from_number(11).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let set_addr2 = Address::p2wpkh(
      &key.derive_from_number(12).expect("Fail").get_pubkey(),
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
    assert_eq!(720, fee_data.tx_fee);
    assert_eq!(1800, fee_data.utxo_fee);
  }

  #[test]
  fn fund_raw_transaction_test() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_bnb_utxo_list(&Network::Mainnet);
    let key = ExtPubkey::new("xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy").expect("Fail");
    let set_addr1 = Address::p2wpkh(
      &key.derive_from_number(11).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let set_addr2 = Address::p2wpkh(
      &key.derive_from_number(12).expect("Fail").get_pubkey(),
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
      &key.derive_from_number(1).expect("Fail").get_pubkey(),
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

    assert_eq!("02000000010af4768e14f820cb9063f55833b5999119e53390ecf4bf181842909b11d0974d0000000000ffffffff0380969800000000001600144352a1a6e86311f22274f7ebb2746de21b09b15d00093d00000000001600148beaaac4654cf4ebd8e46ca5062b0e7fb3e7470ce47f19000000000016001478eb9fc2c9e1cdf633ecb646858ba862b21384ab00000000",
    fund_tx.to_str());
    assert_eq!(addr1.to_str(), fund_data.reserved_address_list[0].to_str());
    assert_eq!(3860, fund_data.fee_amount);
  }

  #[test]
  fn fund_raw_transaction_exist_txin_test() {
    let network = Network::Mainnet;
    let utxos = get_bitcoin_bnb_utxo_list(&Network::Mainnet);
    let key = ExtPubkey::new("xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy").expect("Fail");
    let set_addr1 = Address::p2wpkh(
      &key.derive_from_number(11).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");
    let set_addr2 = Address::p2wpkh(
      &key.derive_from_number(12).expect("Fail").get_pubkey(),
      &network,
    )
    .expect("Fail");

    // amount = 85062500 + 39062500 = 124125000
    let amount1 = 100000000;
    let amount2 = 100000000;
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

    let input_utxos = [utxos[1].clone(), utxos[2].clone()];
    let addr1 = Address::p2wpkh(
      &key.derive_from_number(1).expect("Fail").get_pubkey(),
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
    let fund_tx = tx
      .fund_raw_transaction(
        &input_utxos,
        &utxos,
        &target_data,
        &fee_option,
        &mut fund_data,
      )
      .expect("Fail");

    assert_eq!("02000000030a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000ffffffff0a9bf51e0ac499391efd9426e2c909901edd74a97d2378b49c8832c491ad1e9e0000000000ffffffff0a503dbd4f8f2b064c70e048b21f93fe4584174478abf5f44747932cd21da87c0000000000ffffffff0300e1f505000000001600144352a1a6e86311f22274f7ebb2746de21b09b15d00e1f505000000001600148beaaac4654cf4ebd8e46ca5062b0e7fb3e7470c0831b8040000000016001478eb9fc2c9e1cdf633ecb646858ba862b21384ab00000000",
    fund_tx.to_str());
    assert_eq!(addr1.to_str(), fund_data.reserved_address_list[0].to_str());
    assert_eq!(7460, fund_data.fee_amount);

    let fee_utxos = [utxos[1].clone(), utxos[2].clone(), utxos[0].clone()];
    let fee_data = fund_tx
      .estimate_fee(&fee_utxos, fee_option.fee_rate)
      .expect("Fail");
    assert_eq!(7460, fee_data.tx_fee + fee_data.utxo_fee);
    assert_eq!(2060, fee_data.tx_fee);
    assert_eq!(5400, fee_data.utxo_fee);
  }

  fn get_bitcoin_bnb_utxo_list(network: &Network) -> Vec<UtxoData> {
    let desc = "sh(wpkh([ef735203/0'/0'/7']022c2409fbf657ba25d97bb3dab5426d20677b774d4fc7bd3bfac27ff96ada3dd1))#4z2vy08x";
    let descriptor = Descriptor::new(desc, &network).expect("Fail");
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
    let descriptor = Descriptor::new(desc, &network).expect("Fail");
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
    assert_eq!(true, selected_list.select_utxo_list.is_empty());
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
    assert_eq!(1360, selected_list.utxo_fee_amount);
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
    assert_eq!(1360, selected_list.utxo_fee_amount);
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
    assert_eq!(1360, selected_list.utxo_fee_amount);
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
    assert_eq!(2720, selected_list.utxo_fee_amount);
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
    assert_eq!(2720, selected_list.utxo_fee_amount);
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
    assert_eq!(1360, selected_list.utxo_fee_amount);
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
    assert_eq!(2720, selected_list.utxo_fee_amount);
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
    assert_eq!(360, selected_list.utxo_fee_amount);
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
    assert_eq!(180, selected_list.utxo_fee_amount);
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
    assert_eq!(270, selected_list.utxo_fee_amount);
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
}
