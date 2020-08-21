extern crate cfd_rust;

use cfd_rust::{
  Descriptor, ExtPrivkey, Network, OutPoint, SigHashType, Transaction, TxInData, TxOutData, Txid,
  UtxoData,
};
use std::{str::FromStr, time::Instant};

const XPRIV: &str = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";

fn main() {
  const MAX: i32 = 2;
  let network = Network::Regtest;
  let utxos = get_utxos(&network, 10000);

  let mut index = 0;
  while index < MAX {
    let start = Instant::now();
    let tx = create_dummy_tx(&utxos);
    let end = start.elapsed();
    index += 1;
    println!(
      "count {:03}: {}.{:03} sec",
      index,
      end.as_secs(),
      end.subsec_millis()
    );
    if index == MAX {
      // println!("tx hex: {}", tx.to_str());
      println!("txid: {}", tx.as_txid().to_hex());
    }
  }
}

fn create_dummy_tx(utxos: &[UtxoData]) -> Transaction {
  let mut txin_list: Vec<TxInData> = vec![];
  let mut txout_list: Vec<TxOutData> = vec![];
  txin_list.reserve(utxos.len());
  txout_list.reserve(utxos.len() - 1);
  for utxo in utxos {
    let txin = TxInData::new(&utxo.outpoint);
    txin_list.push(txin);
  }
  for utxo in utxos {
    let addr = utxo.descriptor.get_address();
    let txout = TxOutData::from_address(10000, addr);
    txout_list.push(txout);
    if txout_list.len() == (utxos.len() - 1) {
      break;
    }
  }

  let tx_start = Instant::now();
  let mut tx = Transaction::create_tx(2, 0, &txin_list, &txout_list).expect("Fail");
  let tx_end = tx_start.elapsed();
  println!(
    "    createTx: {}.{:03} sec",
    tx_end.as_secs(),
    tx_end.subsec_millis()
  );

  let base_xpriv = ExtPrivkey::new(XPRIV).expect("Fail");
  let s_start = Instant::now();
  for (index, utxo) in utxos.iter().enumerate() {
    let derive_key = base_xpriv
      .derive_from_number(index as u32, false)
      .expect("Fail");
    let s1_start = Instant::now();
    tx = tx
      .sign_with_privkey(
        &utxo.outpoint,
        utxo.descriptor.get_hash_type(),
        derive_key.get_privkey(),
        &SigHashType::All,
        &utxo.get_amount(),
      )
      .expect("Fail");
    let s1_end = s1_start.elapsed();
    if index == 0 {
      println!(
        "    SignTxSignle: {}.{:03} sec",
        s1_end.as_secs(),
        s1_end.subsec_millis()
      );
    }
  }
  let s_end = s_start.elapsed();
  println!(
    "    SignTx All: {}.{:03} sec",
    s_end.as_secs(),
    s_end.subsec_millis()
  );
  tx
}

fn get_utxos(network: &Network, amount: i64) -> Vec<UtxoData> {
  const UTXO_NUM: usize = 255;

  let base_xpriv = ExtPrivkey::new(XPRIV).expect("Fail");
  let mut list: Vec<UtxoData> = vec![];
  let mut index = 0;
  list.reserve(UTXO_NUM);
  while index < UTXO_NUM {
    let txid = Txid::from_str("06c77d5d356b2a0f1015edd4d49b78337c925b8de09ca51777390fcb88744d20")
      .expect("Fail");
    let derive_key = base_xpriv
      .derive_pubkey_from_number(index as u32, false)
      .expect("Fail");
    let desc = Descriptor::p2wpkh(derive_key.get_pubkey(), network).expect("Fail");
    let utxo = UtxoData::from_descriptor(&OutPoint::new(&txid, index as u32), amount, &desc);
    list.push(utxo);
    index += 1;
  }
  list
}
