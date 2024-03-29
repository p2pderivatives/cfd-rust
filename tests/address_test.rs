extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{
    Address, AddressType, HashType, Network, Pubkey, SchnorrPubkey, Script, WitnessVersion,
  };
  use std::str::FromStr;

  #[test]
  fn address_test() {
    // default
    let empty_addr = Address::default();
    assert!(!empty_addr.valid());
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
    assert!(p2sh_addr.valid());

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

    // taproot
    let addr_taproot1 =
      Address::from_str("tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6")
        .expect("Fail");
    assert_eq!(
      "tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6",
      addr_taproot1.to_str()
    );
    assert_eq!(&Network::Testnet, addr_taproot1.get_network_type());
    assert_eq!(
      &AddressType::TaprootAddress,
      addr_taproot1.get_address_type()
    );
    assert_eq!(
      WitnessVersion::Version1,
      addr_taproot1.get_witness_version()
    );
    assert_eq!(
      "51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      addr_taproot1.get_locking_script().to_hex()
    );
    assert_eq!(
      "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      addr_taproot1.get_hash().to_hex()
    );
    let spk = SchnorrPubkey::from_slice(addr_taproot1.get_hash().to_slice()).expect("Fail");
    let addr_taproot2 = Address::taproot(&spk, &Network::Testnet).expect("Fail");
    assert_eq!(
      "tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6",
      addr_taproot2.to_str()
    );

    let fedpeg_script = Script::from_hex("522102baae8e066e4f2a1da4b731017697bb8fcacc60e4569f3ec27bc31cf3fb13246221026bccd050e8ecf7a702bc9fb63205cfdf278a22ba8b1f1d3ca3d8e5b38465a9702103430d354b89d1fbe43eb54ea138a4aee1076e4c54f4c805f62f9cee965351a1d053ae").expect("Fail");
    let pegin_pubkey =
      Pubkey::from_str("027592aab5d43618dda13fba71e3993cd7517a712d3da49664c06ee1bd3d1f70af")
        .expect("Fail");
    let pegin_addr_data = Address::pegin_by_pubkey(
      &fedpeg_script,
      &pegin_pubkey,
      &HashType::P2shP2wsh,
      &Network::Mainnet,
    )
    .expect("Fail");
    assert_eq!(
      "39cTKhjjh9YWDQT5hhSRkQwjvmpc4d1C7k",
      pegin_addr_data.address.to_str()
    );
    assert_eq!(
      "0014925d4028880bd0c9d68fbc7fc7dfee976698629c",
      pegin_addr_data.claim_script.to_hex()
    );
    assert_eq!("522103e3b215b75e015a5948efb043079d325a90e68b19112211ae3c1ff62366d441732102779396d5c2348c33bcbdcfd87bf59646ccbebc94bacf4750a9c5245dd297213021036416a1c936d3dc84747d5e544c200578cccfb6ec62dda48df79a0a6a8c7e63fa53ae",
    pegin_addr_data.tweaked_fedpeg_script.to_hex());

    let redeem_script = Script::from_hex("522103a7bd50beb3aff9238336285c0a790169eca90b7ad807abc4b64897ca1f6dedb621039cbaf938d050dd2582e4c2f56d1f75cfc9d165f2f3270532363d9871fb7be14252ae").expect("Fail");
    let pegin_addr_data2 = Address::pegin_by_script(
      &fedpeg_script,
      &redeem_script,
      &HashType::P2shP2wsh,
      &Network::Mainnet,
    )
    .expect("Fail");
    assert_eq!(
      "3DZHAW3TmdwfGuJTGKatD7XpCNJvnX6GiE",
      pegin_addr_data2.address.to_str()
    );
    assert_eq!(
      "0020c45384fa00fe363ed60968fff46541c89bc1766686c279ffdf0a335b80cad728",
      pegin_addr_data2.claim_script.to_hex()
    );
    assert_eq!("52210272d86fcc18fc129a3fe72ed268356735a176f01ba1bb6b5a6e5181735570fca021021909156e0a206a5a8f47bee2418eebd6db0ecae9b4810d761117fa7891f86f7021026e90023fe74aff9f5a26c76ca88eb19fd4477ae43cebb9d2e81e197961b263b753ae",
    pegin_addr_data2.tweaked_fedpeg_script.to_hex());

    let desc1 = "wpkh(tpubDASgDECJvTMzUgS7GkSCxQAAWPveW7BeTPSvbi1wpUe1Mq1v743FRw1i7vTavjAb3D3Y8geCTYw2ezgiVS7SFXDXS6NpZmvr6XPjPvg632y)";
    let (pegout_addr, base_desc) = Address::pegout(Network::Regtest, desc1, 0).expect("Fail");
    assert_eq!(
      "bcrt1qa77w63m523kq82z4fn3d5f7qxqxfm4pmdthkdf",
      pegout_addr.to_str()
    );
    assert_eq!("wpkh(tpubDASgDECJvTMzUgS7GkSCxQAAWPveW7BeTPSvbi1wpUe1Mq1v743FRw1i7vTavjAb3D3Y8geCTYw2ezgiVS7SFXDXS6NpZmvr6XPjPvg632y)",
    base_desc);

    let pegout_pubkey2 = "xpub67v4wfueMiZVkc7UbutFgPiptQw4kkNs89ooNMrwht8xEjnZZim1rNZHhEdrLejB99fiBdnWNNAB8hmUK7tCo5Ua6UtHzwVLj2Bzpch7vB2";
    let (pegout_addr2, base_desc2) =
      Address::pegout(Network::Mainnet, pegout_pubkey2, 0).expect("Fail");
    assert_eq!("1MMxsm4QG8NRHqaFZaUTFQQ9c9dEHUPWnD", pegout_addr2.to_str());
    assert_eq!("pkh(xpub67v4wfueMiZVkc7UbutFgPiptQw4kkNs89ooNMrwht8xEjnZZim1rNZHhEdrLejB99fiBdnWNNAB8hmUK7tCo5Ua6UtHzwVLj2Bzpch7vB2)",
    base_desc2);
  }
}
