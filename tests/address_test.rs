extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{Address, AddressType, Network, Pubkey, Script};
  use std::str::FromStr;

  #[test]
  fn address_test() {
    // default
    let empty_addr = Address::default();
    assert_eq!(false, empty_addr.valid());
    // default: bitcoin
    let pubkey =
      Pubkey::from_str("036b67e1bd3bd3efbc37fdc738ab159a4aa527057eae12a0c4b07d3132580dcdfd")
        .expect("Fail");
    let address = Address::p2wpkh(&pubkey, &Network::Regtest).expect("Fail");
    assert_eq!(
      "bcrt1q576jgpgewxwu205cpjq4s4j5tprxlq38l7kd85",
      address.to_str()
    );
    assert_eq!(AddressType::P2wpkhAddress, *address.get_address_type());
    assert_eq!(
      "0014a7b5240519719dc53e980c8158565458466f8227",
      address.get_locking_script().to_hex()
    );
    // default: elements
    let pubkey_elm =
      Pubkey::from_str("031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1")
        .expect("Fail");
    let address_elm = Address::p2wpkh(&pubkey_elm, &Network::ElementsRegtest).expect("Fail");
    assert_eq!(
      "ert1q7jm5vw5cunpy3lkvwdl3sr3qfm794xd4zr6z3k",
      address_elm.to_str()
    );
    assert_eq!(
      "0014f4b7463a98e4c248fecc737f180e204efc5a99b5",
      address_elm.get_locking_script().to_hex()
    );
    assert_eq!(AddressType::P2wpkhAddress, *address_elm.get_address_type());
    // from locking script
    let locking_script =
      Script::from_hex("0014a7b5240519719dc53e980c8158565458466f8227").expect("Fail");
    let from_script_addr =
      Address::from_locking_script(&locking_script, &Network::Regtest).expect("Fail");
    assert_eq!(
      "bcrt1q576jgpgewxwu205cpjq4s4j5tprxlq38l7kd85",
      from_script_addr.to_str()
    );
    // p2sh-segwit
    let p2sh_segwit_addr =
      Address::p2sh_p2wpkh(&pubkey_elm, &Network::ElementsRegtest).expect("Fail");
    assert_eq!(
      "XBsZoa2ueqj8TJA52KzNrHGtjzAeqTf6DS",
      p2sh_segwit_addr.to_str()
    );
    assert_eq!(
      "a91405bc4d5d12925f008cef06ba387ade16a49d7a3187",
      p2sh_segwit_addr.get_locking_script().to_hex()
    );
    assert_eq!(
      "0014f4b7463a98e4c248fecc737f180e204efc5a99b5",
      p2sh_segwit_addr
        .get_p2sh_wrapped_script()
        .expect("Fail")
        .to_hex(),
    );
    assert_eq!(
      AddressType::P2shP2wpkhAddress,
      *p2sh_segwit_addr.get_address_type()
    );
    let p2sh_script =
      Script::from_hex("a91405bc4d5d12925f008cef06ba387ade16a49d7a3187").expect("fail");
    let p2sh_addr = Address::from_locking_script(&p2sh_script, &Network::ElementsRegtest)
      .expect("Fail")
      .update_address_type(&AddressType::P2shP2wpkhAddress);
    assert_eq!(
      AddressType::P2shP2wpkhAddress,
      *p2sh_addr.get_address_type()
    );
    assert_eq!("XBsZoa2ueqj8TJA52KzNrHGtjzAeqTf6DS", p2sh_addr.to_str());
    assert_eq!(
      "a91405bc4d5d12925f008cef06ba387ade16a49d7a3187",
      p2sh_addr.get_locking_script().to_hex()
    );
    assert_eq!(true, p2sh_addr.valid());

    // get_multisig_addresses
    let multisig_script = Script::from_hex("522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae").expect("fail");
    let addr_list = Address::get_multisig_addresses(
      &multisig_script,
      &AddressType::P2wpkhAddress,
      &Network::Regtest,
    )
    .expect("Fail");
    assert_eq!(3, addr_list.len());
    assert_eq!(
      "bcrt1qakhjg9r4zgumw2m986sqftwrzz34yt3hlhtkzm",
      addr_list[0].get_address().to_str()
    );
    assert_eq!(
      "02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0",
      addr_list[0].get_pubkey().to_str()
    );
    assert_eq!(
      "bcrt1qfxspr7tm55sd4vrr7vym44va46esmcgpa70rxe",
      addr_list[1].get_address().to_str()
    );
    assert_eq!(
      "0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c",
      addr_list[1].get_pubkey().to_str()
    );
    assert_eq!(
      "bcrt1qlwmuy4kyap9u3p6cf4xxq49de82yv8j4cz72ln",
      addr_list[2].get_address().to_str()
    );
    assert_eq!(
      "024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82",
      addr_list[2].get_pubkey().to_str()
    );

    // pubkey hash
    let addr_p2pkh = Address::p2pkh(&pubkey, &Network::Testnet).expect("Fail");
    assert_eq!("mvoi8y19XmPDjwmKx2eRVrAqQznNutRBvF", addr_p2pkh.to_str());
    let addr_p2sh_p2wpkh = Address::p2sh_p2wpkh(&pubkey, &Network::Testnet).expect("Fail");
    assert_eq!(
      "2NAZJVxJyRZj7nG37FbpY412S1y9nCbDsYw",
      addr_p2sh_p2wpkh.to_str()
    );
    let addr_p2wpkh = Address::p2wpkh(&pubkey, &Network::Testnet).expect("Fail");
    assert_eq!(
      "tb1q576jgpgewxwu205cpjq4s4j5tprxlq38ah0qsa",
      addr_p2wpkh.to_str()
    );

    // script hash
    let addr_p2sh = Address::p2sh(&multisig_script, &Network::Testnet).expect("Fail");
    assert_eq!("2Mzzv5LBSNMrgnGN4W1Rbn2HUumHcrjUoVd", addr_p2sh.to_str());
    let addr_p2sh_p2wsh = Address::p2sh_p2wsh(&multisig_script, &Network::Testnet).expect("Fail");
    assert_eq!(
      "2NAhuZ3dT39ubb4FFwT2Ft3eNiYsLv9rT5y",
      addr_p2sh_p2wsh.to_str()
    );
    let addr_p2wsh = Address::p2wsh(&multisig_script, &Network::Testnet).expect("Fail");
    assert_eq!(
      "tb1q35e8e0lppzr5c322quaujy9tcg3wd89wrxremfk6val0f6y232cs93nx0t",
      addr_p2wsh.to_str()
    );
  }
}
