extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{ByteData, ExtPrivkey, ExtPubkey, HDWallet, MnemonicLanguage, Network, Pubkey};
  use std::str::FromStr;

  #[test]
  fn ext_pubkey_test() {
    // default
    let empty_key = ExtPubkey::default();
    assert_eq!(false, empty_key.valid());
    // fail
    let extkey_fail = ExtPubkey::new("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV");
    assert!(extkey_fail.is_err(), "err: \"{}\"", extkey_fail.unwrap());
    // default
    let extkey = ExtPubkey::new("xpub6DsNDJWpxZBXsbWsCy1VeBY8xf6hZBgznDTXSnp3FregxWoWfGsvtQ9j5wBJNPebZXD5YmhpQBV7nVjhUsUgkG9R7yE31mh6sVh2w854a1o").expect("Fail");
    assert_eq!("0488b21e", extkey.get_version().to_hex());
    assert_eq!("2da711a5", extkey.get_fingerprint().to_hex());
    assert_eq!(4, extkey.get_depth());
    assert_eq!(Network::Mainnet, *extkey.get_network_type());
    assert_eq!(0, extkey.get_child_number());
    assert_eq!(
      "038746b92b722894e533dbbda3fb7fa673da00f4b309bf98a2cf586c27100004b0",
      extkey.get_pubkey().to_hex()
    );
    assert_eq!(true, extkey.valid());
    // create
    let extkey2 = ExtPubkey::from_parent_info(
      Network::Testnet,
      Pubkey::from_str("02ca30dbb25a2cf96344a04ae2144fb28a17f006c34cfb973b9f21623db27c5cd3")
        .expect("Fail"),
      Pubkey::from_str("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3")
        .expect("Fail"),
      ByteData::from_str("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e")
        .expect("Fail"),
      4,
      44,
    )
    .expect("Fail");
    assert_eq!("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", extkey2.to_str());
    let extkey3 = ExtPubkey::create(
      Network::Testnet,
      ByteData::from_str("a53a8ff3").expect("Fail"),
      Pubkey::from_str("03f1e767c0555ce0105b2a76d0f8b19b6d33a147f82f75a05c4c09580c39694fd3")
        .expect("Fail"),
      ByteData::from_str("839fb0d66f1887db167cdc530ab98e871d8b017ebcb198568874b6c98516364e")
        .expect("Fail"),
      4,
      44,
    )
    .expect("Fail");
    assert_eq!("tpubDF7yNiHQHdfns9Mc3XM7PYcS2dqrPqcit3FLkebvHxS4atZxifANou2KTvpQQQP82ANDCkPc5MPQZ28pjYGgmDXGy1iyzaiX6MTBv8i4cua", extkey3.to_str());
    // derive
    let derive_key1 = extkey.derive_from_number(2).expect("Fail");
    assert_eq!("xpub6GhE9zHjXPRXqD8Yo5HnrwQ1a76iBuG47vjwfK6Tv2nMJoufvTCqCmbqiKSXaXdZcHLXHNWd4zJbLViypjJyH2d9X9zdgz9xEq7YCeR8tqm", derive_key1.to_str());
    let derive_key2 = extkey.derive_from_number_list(&[2, 1]).expect("Fail");
    assert_eq!("xpub6JiJLsQXD8vDSxVM8zZKKEYSdqHpsb87t6JQxpX381CVJusM9iV75gQnyKjuAHUN1MywMbx9oDXWF7RNgWFch515pMvNfygwJHKmFrWSZbM", derive_key2.to_str());
    let derive_key3 = extkey.derive_from_path("2/1").expect("Fail");
    assert_eq!("xpub6JiJLsQXD8vDSxVM8zZKKEYSdqHpsb87t6JQxpX381CVJusM9iV75gQnyKjuAHUN1MywMbx9oDXWF7RNgWFch515pMvNfygwJHKmFrWSZbM", derive_key3.to_str());
  }

  #[test]
  fn ext_privkey_test() {
    // empty
    let empty_key = ExtPrivkey::default();
    assert_eq!(false, empty_key.valid());
    // fail
    let extkey_fail = ExtPrivkey::new("xpub6DsNDJWpxZBXsbWsCy1VeBY8xf6hZBgznDTXSnp3FregxWoWfGsvtQ9j5wBJNPebZXD5YmhpQBV7nVjhUsUgkG9R7yE31mh6sVh2w854a1o");
    assert!(extkey_fail.is_err(), "err: \"{}\"", extkey_fail.unwrap());
    // default
    let extkey = ExtPrivkey::new("xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV").expect("Fail");
    assert_eq!("0488ade4", extkey.get_version().to_hex());
    assert_eq!("2da711a5", extkey.get_fingerprint().to_hex());
    assert_eq!(4, extkey.get_depth());
    assert_eq!(Network::Mainnet, *extkey.get_network_type());
    assert_eq!(0, extkey.get_child_number());
    assert_eq!(
      "28009126a24557d32ff2c5da21850dd06529f34faed53b4a3552b5ed4bda35d5",
      extkey.get_chain_code().to_hex()
    );
    assert_eq!(
      "73a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c",
      extkey.get_privkey().to_hex()
    );
    assert_eq!(true, extkey.valid());
    // derive
    let derive_key1 = extkey.derive_from_number(2, true).expect("Fail");
    assert_eq!(
      "xprvA3hskUkz2gQCmQEoZPrH3geqUaaH4vBfcehVQNDN6aw1G7M5unTbL2C653WMouTyV8zMMbYEC9FDvMSiNpg62aYW41hYDbjCRX7HBofefmS",
      derive_key1.to_str()
    );
    assert_eq!(0x80000002, derive_key1.get_child_number());
    let derive_key2 = extkey
      .derive_from_number_list(&[0x80000002, 1])
      .expect("Fail");
    assert_eq!(
      "xprvA5ZRPgxRULFxnCKMkfYdCARkQQbzc9h84vM2n2xFwyHaBdfdQHBecTR284s1seKTfuokaJjb9YcMJQLTmWszAyVG7j3ApPjNjk19CDVD2wR",
      derive_key2.to_str()
    );
    let derive_key3 = extkey.derive_from_path("2'/1").expect("Fail");
    assert_eq!(
      "xprvA5ZRPgxRULFxnCKMkfYdCARkQQbzc9h84vM2n2xFwyHaBdfdQHBecTR284s1seKTfuokaJjb9YcMJQLTmWszAyVG7j3ApPjNjk19CDVD2wR",
      derive_key3.to_str()
    );
    assert_eq!(1, derive_key3.get_child_number());
    // pubkey
    let ext_pubkey = extkey.get_ext_pubkey().expect("Fail");
    assert_eq!(
      "xpub6DsNDJWpxZBXsbWsCy1VeBY8xf6hZBgznDTXSnp3FregxWoWfGsvtQ9j5wBJNPebZXD5YmhpQBV7nVjhUsUgkG9R7yE31mh6sVh2w854a1o",
      ext_pubkey.to_str()
    );
    // derive pubkey
    let derive_pubkey1 = extkey.derive_pubkey_from_number(2, true).expect("Fail");
    assert_eq!(
      "xpub6GhE9zHss3xVytKGfRPHQpba2cQmUNuWysd6CkcyevTz8ugETKmqspWZvJHVS27yfUSrWhqrcD9nYuW73xGiZePtabCaUhqo2Gjk6ik98ap",
      derive_pubkey1.to_str()
    );
    let derive_pubkey2 = extkey
      .derive_pubkey_from_number_list(&[0x80000002, 1])
      .expect("Fail");
    assert_eq!(
      "xpub6JYmoCVKJhpFzgPprh5dZJNUxSSV1cQyS9GdaRMsWJpZ4RzmwpVuAFjVyLyw98qq9GpxqWPxLiy6bDptaYVA3RJNiUQPCNKPApxXTiPLLuc",
      derive_pubkey2.to_str()
    );
    let derive_pubkey3 = extkey.derive_pubkey_from_path("2'/1").expect("Fail");
    assert_eq!(
      "xpub6JYmoCVKJhpFzgPprh5dZJNUxSSV1cQyS9GdaRMsWJpZ4RzmwpVuAFjVyLyw98qq9GpxqWPxLiy6bDptaYVA3RJNiUQPCNKPApxXTiPLLuc",
      derive_pubkey3.to_str()
    );
  }

  #[test]
  fn hdwallet_test() {
    let word_list_en = HDWallet::mnemonic_word_list_en().expect("Fail");
    assert_eq!(2048, word_list_en.len());
    assert_eq!("ability", word_list_en[1]);
    let word_list_ja = HDWallet::mnemonic_word_list(MnemonicLanguage::JP).expect("Fail");
    assert_eq!(2048, word_list_ja.len());
    assert_eq!("あいさつ", word_list_ja[1]);

    let mnemonic_from_entropy =
      HDWallet::mnemonic_from_entropy(&[1; 32], MnemonicLanguage::EN).expect("Fail");
    assert_eq!("absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic", mnemonic_from_entropy);
    let entropy = HDWallet::entropy_from_mnemonic(
    "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic",
    MnemonicLanguage::EN,
    ).expect("Fail");
    assert_eq!(
      "0101010101010101010101010101010101010101010101010101010101010101",
      ByteData::from_slice(&entropy).to_hex()
    );

    let wallet = HDWallet::from_mnemonic(
      "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic",
      MnemonicLanguage::EN,
    ).expect("Fail");
    assert_eq!(
      "5191159cd9532cfd352d7a9bc4d91ad82e502ac7be0ddec134ea13172a4f256115d9c04f763395529673fd5d9baa5c83f191bdaa0b66c2f6a1a155b9859eb83d",
      ByteData::from_slice(wallet.to_seed()).to_hex()
    );
    let wallet_ph = HDWallet::from_mnemonic_passphrase(
      "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic",
      MnemonicLanguage::EN,
      "pass",
    ).expect("Fail");
    assert_eq!(
      "7f26c3bb2af5ada9232e790ee117a7d6b25142a95bea799163a28044e0123ccb60ca06680011b9bbc332a80e2e3e32fdf66eb5306f5609669235211e79636f23",
      ByteData::from_slice(wallet_ph.to_seed()).to_hex()
    );

    let seed1 = HDWallet::from_mnemonic_passphrase(
      "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
      MnemonicLanguage::EN,
      "TREZOR",
    ).expect("Fail");
    assert_eq!(
      "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
      ByteData::from_slice(seed1.to_seed()).to_hex()
    );

    let seed2 = HDWallet::from_mnemonic(
      "まぜる　むかし　じぶん　そえん　くつした　このよ　とおる　えもじ　おじさん　ねむたい　しいん　せすじ　のれん　ゆうめい　ときおり",
      MnemonicLanguage::JP,
    ).expect("Fail");
    assert_eq!(
      "4d2cd52f3ad39dc913d5a90e91163d7af4c9f11d727b273be269a404d2a23546243f8adb5009200d037900c76a3a8fc69c13afaa8084c4c85d3515232785fd54",
      ByteData::from_slice(seed2.to_seed()).to_hex()
    );
    let entropy_jp = HDWallet::entropy_from_mnemonic(
    "まぜる　むかし　じぶん　そえん　くつした　このよ　とおる　えもじ　おじさん　ねむたい　しいん　せすじ　のれん　ゆうめい　ときおり",
    MnemonicLanguage::JP,
    ).expect("Fail");
    assert_eq!(
      "e11cf99abf03d2a5e998e523373d87ba8bf1e2a9",
      ByteData::from_slice(&entropy_jp).to_hex()
    );

    let wallet2 = HDWallet::from_slice(wallet.to_seed()).expect("Fail");
    assert_eq!(wallet.to_seed(), wallet2.to_seed());
    let extkey = wallet.get_privkey(&Network::Testnet).expect("Fail");
    assert_eq!("tprv8ZgxMBicQKsPf5HXdKpB8XR3b2QzaC5CTe7VCKzkBoS8xF1d3yCooGzVkKFd3UCCiBQnpL9UMJxzwTxfEQ9st97yAEN2PM2LjieSKtTqBnT", extkey.to_str());
    let derive_key1 = wallet
      .get_privkey_from_path(&Network::Testnet, "2'/1")
      .expect("Fail");
    assert_eq!("tprv8eXXNCKgrrgdmooe14Ecwa7ScsHzRfDykwPE2nXdBwpYVGUuoYnjXbFBthwnYwFknqzGHCTqmbbB6qtsSfuJuA8EoMza8vKcofWtZeUR55J", derive_key1.to_str());
    let derive_key2 = wallet
      .get_privkey_from_number(&Network::Testnet, 2, true)
      .expect("Fail");
    assert_eq!("tprv8bgW4LxMphWtcAZf9TwSvweUjtonWym1SddJ12wLkSCGNb81yFxBu9VZQF7hER2HzUBEj4X9FkpqvZwuToZNCcqjiCC5aDnqwesT5SByPDi", derive_key2.to_str());
    let derive_key3 = wallet
      .get_privkey_from_number_list(&Network::Testnet, &[0x80000002, 1])
      .expect("Fail");
    assert_eq!("tprv8eXXNCKgrrgdmooe14Ecwa7ScsHzRfDykwPE2nXdBwpYVGUuoYnjXbFBthwnYwFknqzGHCTqmbbB6qtsSfuJuA8EoMza8vKcofWtZeUR55J", derive_key3.to_str());
    let ext_pubkey = wallet.get_pubkey(&Network::Testnet).expect("Fail");
    assert_eq!("tpubD6NzVbkrYhZ4YYKKWyUmXw5AA3vvjXG72wiGUr33c5EXnjGPgN2PymcMvV7xZqaWF2pTDoEM1yUyc4EK2GPt5HZ4fFnDiFsJs7qLyV1EWS6", ext_pubkey.to_str());
    let derive_pubkey1 = wallet
      .get_pubkey_from_path(&Network::Testnet, "2'/1")
      .expect("Fail");
    assert_eq!("tpubDBDZWcMw1ENJfGqRthuDLymZBtovazQtLEz1KJZvcDcwKkjgRwcKi5s44sCtksb3NCbBishZnTTCNnpB32FQCKmAevUkzh7Zd7akdF3C7s7", derive_pubkey1.to_str());
    let derive_pubkey2 = wallet
      .get_pubkey_from_number(&Network::Testnet, 2, true)
      .expect("Fail");
    assert_eq!("tpubD8NYCkzby5CZVdbT37c3LMJbJvKigJwv1wE5HYyeAhzfD5Nnbemn5e7RaPQRfRNVy2eu6HXPimK2bhNSyxtswBbnMNKNN6SR4rdLMTr6ut2", derive_pubkey2.to_str());
    let derive_pubkey3 = wallet
      .get_pubkey_from_number_list(&Network::Testnet, &[0x80000002, 1])
      .expect("Fail");
    assert_eq!("tpubDBDZWcMw1ENJfGqRthuDLymZBtovazQtLEz1KJZvcDcwKkjgRwcKi5s44sCtksb3NCbBishZnTTCNnpB32FQCKmAevUkzh7Zd7akdF3C7s7", derive_pubkey3.to_str());
  }
}
