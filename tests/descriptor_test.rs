extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{Descriptor, DescriptorKeyType, HashType, Network};

  #[test]
  fn descriptor_pkh_test() {
    let desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#8fhd9pwu",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2pkh, descriptor.get_hash_type());
    assert_eq!(
      "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_DUP OP_HASH160 06afd46bcdfd22ef94ac122aa11f241244a37ecc OP_EQUALVERIFY OP_CHECKSIG",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(true, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Public, key_data.get_type());
    assert_eq!(
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_wpkh_test() {
    let desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#8zl0zxma",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2wpkh, descriptor.get_hash_type());
    assert_eq!(
      "bc1q0ht9tyks4vh7p5p904t340cr9nvahy7u3re7zg",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_0 7dd65592d0ab2fe0d0257d571abf032cd9db93dc",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(true, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Public, key_data.get_type());
    assert_eq!(
      "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_sh_wpkh_test() {
    let desc = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))#qkrrc7je",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2shP2wpkh, descriptor.get_hash_type());
    assert_eq!(
      "3LKyvRN6SmYXGBNn8fcQvYxW9MGKtwcinN",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_HASH160 cc6ffbc0bf31af759451068f90ba7a0272b6b332 OP_EQUAL",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(true, descriptor.has_key_hash());
    assert_eq!(2, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(DescriptorKeyType::Public, *key_data.get_type());
    assert_eq!(
      "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_sh_multi_test() {
    let desc = "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "sh(multi(2,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))#y9zthqta",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2sh, descriptor.get_hash_type());
    assert_eq!(
      "3GtEB3yg3r5de2cDJG48SkQwxfxJumKQdN",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_HASH160 a6a8b030a38762f4c1f5cbe387b61a3c5da5cd26 OP_EQUAL",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(
      "5221022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a012103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe52ae",
      descriptor.get_redeem_script().expect("Fail").to_hex()
    );
    assert_eq!(
      "OP_2 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe OP_2 OP_CHECKMULTISIG",
      descriptor.get_redeem_script().expect("Fail").to_asm()
    );
    assert_eq!(true, descriptor.has_multisig());
    assert_eq!(true, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
    let key_list = descriptor.get_multisig_key_list().expect("Fail");
    assert_eq!(2, key_list.len());
    assert_eq!(&DescriptorKeyType::Public, key_list[0].get_type());
    assert_eq!(
      "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
      key_list[0].get_pubkey().to_str()
    );
    assert_eq!(&DescriptorKeyType::Public, key_list[1].get_type());
    assert_eq!(
      "03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
      key_list[1].get_pubkey().to_str()
    );
  }

  #[test]
  fn descriptor_wsh_multi_test() {
    let desc = "wsh(multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(desc.to_owned() + "#en3tu306", descriptor.to_str());
    assert_eq!(&HashType::P2wsh, descriptor.get_hash_type());
    assert_eq!(
      "bc1qwu7hp9vckakyuw6htsy244qxtztrlyez4l7qlrpg68v6drgvj39qn4zazc",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_0 773d709598b76c4e3b575c08aad40658963f9322affc0f8c28d1d9a68d0c944a",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!("522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c72103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb2103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a53ae",
      descriptor.get_redeem_script().expect("Fail").to_hex());
    assert_eq!("OP_2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb 03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a OP_3 OP_CHECKMULTISIG",
    descriptor.get_redeem_script().expect("Fail").to_asm());
    assert_eq!(1, descriptor.get_script_list().len());
    assert_eq!(true, descriptor.has_multisig());
    assert_eq!(true, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    let key_list = descriptor.get_multisig_key_list().expect("Fail");
    assert_eq!(3, key_list.len());
    assert_eq!(
      "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
      key_list[0].get_pubkey().to_hex()
    );
    assert_eq!(
      "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
      key_list[1].get_pubkey().to_hex()
    );
  }

  #[test]
  fn descriptor_sh_wsh_multi_test() {
    let desc = "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "sh(wsh(multi(1,03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8,03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e)))#ks05yr6p",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2shP2wsh, descriptor.get_hash_type());
    assert_eq!(
      "3Hd7YQStg9gYpEt6hgK14ZHUABxSURzeuQ",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_HASH160 aec509e284f909f769bb7dda299a717c87cc97ac OP_EQUAL",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(
      "512103f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa82103499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e42102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e53ae",
      descriptor.get_redeem_script().expect("Fail").to_hex()
    );
    assert_eq!(
      "OP_1 03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8 03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e OP_3 OP_CHECKMULTISIG",
      descriptor.get_redeem_script().expect("Fail").to_asm()
    );
    assert_eq!(true, descriptor.has_multisig());
    assert_eq!(true, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(2, descriptor.get_script_list().len());
    let key_list = descriptor.get_multisig_key_list().expect("Fail");
    assert_eq!(3, key_list.len());
    assert_eq!(&DescriptorKeyType::Public, key_list[0].get_type());
    assert_eq!(
      "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
      key_list[0].get_pubkey().to_str()
    );
    assert_eq!(&DescriptorKeyType::Public, key_list[1].get_type());
    assert_eq!(
      "03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4",
      key_list[1].get_pubkey().to_str()
    );
    assert_eq!(&DescriptorKeyType::Public, key_list[2].get_type());
    assert_eq!(
      "02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
      key_list[2].get_pubkey().to_str()
    );
  }

  #[test]
  fn descriptor_addr_test() {
    let desc = "addr(bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9)";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "addr(bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9)#6rmdcqux",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2wsh, descriptor.get_hash_type());
    assert_eq!(
      "bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_0 c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
  }

  #[test]
  fn descriptor_raw_test() {
    let desc = "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "raw(6a4c4f54686973204f505f52455455524e207472616e73616374696f6e206f7574707574207761732063726561746564206279206d6f646966696564206372656174657261777472616e73616374696f6e2e)#zf2avljj",
      descriptor.to_str()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
  }

  #[test]
  fn descriptor_combo_test() {
    let desc = "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "combo(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#lq9sf04s",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2wpkh, descriptor.get_hash_type());
    assert_eq!(
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_0 751e76e8199196d454941c45d1b3a323f1433bd6",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(true, descriptor.has_key_hash());
    assert_eq!(4, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Public, key_data.get_type());
    assert_eq!(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_sh_wsh_pkh_test() {
    let desc = "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))#2wtr0ej5",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2shP2wsh, descriptor.get_hash_type());
    assert_eq!(
      "39XGHYpYmJV9sGFoGHZeU2rLkY6r1MJ6C1",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_HASH160 55e8d5e8ee4f3604aba23c71c2684fa0a56a3a12 OP_EQUAL",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(
      "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac",
      descriptor.get_redeem_script().expect("Fail").to_hex()
    );
    assert_eq!(
      "OP_DUP OP_HASH160 c42e7ef92fdb603af844d064faad95db9bcdfd3d OP_EQUALVERIFY OP_CHECKSIG",
      descriptor.get_redeem_script().expect("Fail").to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(true, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(3, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Public, key_data.get_type());
    assert_eq!(
      "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_pkh_ext_pubkey_test() {
    let desc = "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/2)#kczqajcv",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2pkh, descriptor.get_hash_type());
    assert_eq!(
      "1PdNaNxbyQvHW5QHuAZenMGVHrrRaJuZDJ",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_DUP OP_HASH160 f833c08f02389c451ae35ec797fccf7f396616bf OP_EQUALVERIFY OP_CHECKSIG",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(true, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Bip32, key_data.get_type());
    assert_eq!(
      "xpub6D4BDPcEgbv6wqbZ5Vfp1MUpa5tieyHKAoJCFjcUJpzSc9BV92TpCM85m3jfth6jfKA7LWFiip8zp8RuARjoLjkD13Z8cb9VdyMm3MMdTcA",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_pkh_ext_pubkey_derive_test() {
    let desc = "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/*)";
    let descriptor =
      Descriptor::with_derive_bip32path(desc, "2/3", &Network::Mainnet).expect("Fail");
    assert_eq!(
      "pkh(xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/1/*)#8nhtvxel",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2pkh, descriptor.get_hash_type());
    assert_eq!(
      "1Jh92Cjae6Kt8JXnkonohX36EWK7Du5ZMP",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_DUP OP_HASH160 c21178dfb721039b6936b167657cd31ab60b1bbd OP_EQUALVERIFY OP_CHECKSIG",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(true, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Bip32, key_data.get_type());
    assert_eq!(
      "xpub6FMiTLEY5GgpKy1f9Vr2x5w25cs9eBtCMq6xJYPo8bWaFD11MrPxmBPoxqWTL2wninua6fwXuRyc5nAcg7RU3DebapJhaW8xXJWoFNpRN6s",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_sh_miniscript_test() {
    let desc = "sh(or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305))))";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "sh(or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305))))#ueuxphxk",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2sh, descriptor.get_hash_type());
    assert_eq!(
      "38WFPv9fne2UeFxVkGMhLkamMadH8j6s1c",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_HASH160 4abf8cfc94ae837bf59965e0c74d02a611ec1329 OP_EQUAL",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(
      "OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6 OP_EQUAL OP_IFDUP OP_NOTIF OP_IF 499999999 OP_CHECKLOCKTIMEVERIFY OP_0NOTEQUAL OP_ELSE OP_0 OP_ENDIF OP_NOTIF OP_0 OP_ELSE 4194305 OP_CHECKSEQUENCEVERIFY OP_ENDIF OP_ENDIF",
      descriptor.get_redeem_script().expect("Fail").to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(true, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
  }

  #[test]
  fn descriptor_wsh_miniscript_test() {
    let desc = "wsh(thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)))";
    let descriptor = Descriptor::new(desc, &Network::Mainnet).expect("Fail");
    assert_eq!(
      "wsh(thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)))#pv8ptztg",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2wsh, descriptor.get_hash_type());
    assert_eq!(
      "bc1qdfky9a3dh8atpy0l47fsuz5ywergnrfztcddjnl5xgnwyqvqh8gschn2ch",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_0 6a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(
      "OP_2 03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7 036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00 OP_2 OP_CHECKMULTISIG OP_TOALTSTACK OP_1 036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00 OP_1 OP_CHECKMULTISIG OP_FROMALTSTACK OP_ADD OP_TOALTSTACK 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01 OP_CHECKSIG OP_FROMALTSTACK OP_ADD OP_2 OP_EQUAL",
      descriptor.get_redeem_script().expect("Fail").to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(true, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(1, descriptor.get_script_list().len());
  }

  #[test]
  fn descriptor_sh_wsh_miniscript_derive_test() {
    let desc = "sh(wsh(c:or_i(andor(c:pk_h(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*),pk_h(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))))";
    let descriptor =
      Descriptor::with_derive_bip32path(desc, "44", &Network::Mainnet).expect("Fail");
    assert_eq!(
      "sh(wsh(c:or_i(andor(c:pk_h(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*),pk_h(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))))#cpx6as23",
      descriptor.to_str()
    );
    assert_eq!(&HashType::P2shP2wsh, descriptor.get_hash_type());
    assert_eq!(
      "3GyYN9WnJBoMn8M5tuqVcFJq1BvbAcdPAt",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_HASH160 a7a9f411001e3e3db96d7f02fc9ab1d0dc6aa691 OP_EQUAL",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(
      "OP_IF OP_DUP OP_HASH160 520e6e72bcd5b616bc744092139bd759c31d6bbe OP_EQUALVERIFY OP_CHECKSIG OP_NOTIF OP_DUP OP_HASH160 06afd46bcdfd22ef94ac122aa11f241244a37ecc OP_EQUALVERIFY OP_ELSE OP_DUP OP_HASH160 5ab62f0be26fe9d6205a155403f33e2ad2d31efe OP_EQUALVERIFY OP_ENDIF OP_ELSE 02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e OP_ENDIF OP_CHECKSIG",
      descriptor.get_redeem_script().expect("Fail").to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(true, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(2, descriptor.get_script_list().len());
  }

  #[test]
  fn descriptor_taproot_schnorr_test() {
    let desc = "tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a)";
    let descriptor = Descriptor::new(desc, &Network::Regtest).expect("Fail");
    assert_eq!(
      "tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a)#mavrnmjy",
      descriptor.to_str()
    );
    assert_eq!(&HashType::Taproot, descriptor.get_hash_type());
    assert_eq!(
      "bcrt1paag57xhtzja2dnzh4vex37ejnjj5p3yy2nmlgem3a4e3ud962gdqqctzwn",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_1 ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(true, descriptor.has_taproot());
    assert_eq!(1, descriptor.get_script_list().len());
    assert_eq!("", descriptor.get_script_tree().to_str());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Schnorr, key_data.get_type());
    assert_eq!(
      "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_taproot_xpub_derive_test() {
    let desc = "tr([bd16bee5/0]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*)";
    let descriptor = Descriptor::with_derive_bip32path(desc, "1", &Network::Mainnet).expect("Fail");
    assert_eq!(
      "tr([bd16bee5/0]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*)#aa0v9ye4",
      descriptor.to_str()
    );
    assert_eq!(&HashType::Taproot, descriptor.get_hash_type());
    assert_eq!(
      "bc1p33h4j4kre3e9r4yrl35rlgrtyt2w9hw8f94zty9vacmvfgcnlqtq0txdxt",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_1 8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(true, descriptor.has_taproot());
    assert_eq!(1, descriptor.get_script_list().len());
    assert_eq!("", descriptor.get_script_tree().to_str());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Bip32, key_data.get_type());
    assert_eq!(
      "xpub6EKMC2gSMfKgSwn7V9VZn7x1MvoeeVzSmmtSJ4z2L2d6R4WxvdQMouokypZHVp4fgKycrrQnGr6WJ5ED5jG9Q9FiA1q5gKYUc8u6JHJhdo8",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_taproot_tapscript_single_test() {
    let desc = "tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a,c:pk_k(8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816))";
    let descriptor = Descriptor::new(desc, &Network::Regtest).expect("Fail");
    assert_eq!(
      "tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a,c:pk_k(8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816))#agrnj9m2",
      descriptor.to_str()
    );
    assert_eq!(&HashType::Taproot, descriptor.get_hash_type());
    assert_eq!(
      "bcrt1p2druqmxfa49j9ph0ea8d9y4gzrhy2x7u2zj0p2622d9r7k28v02s6x9jx3",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_1 5347c06cc9ed4b2286efcf4ed292a810ee451bdc50a4f0ab4a534a3f594763d5",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(true, descriptor.has_taproot());
    assert_eq!(1, descriptor.get_script_list().len());
    assert_eq!(
      "tl(208c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816ac)",
      descriptor.get_script_tree().to_str()
    );
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Schnorr, key_data.get_type());
    assert_eq!(
      "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a",
      key_data.to_str()
    );
  }

  #[test]
  fn descriptor_taproot_tapscript_tapbranch_test() {
    let desc = "tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a,{c:pk_k(8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816),{c:pk_k([bd16bee5/0]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),thresh(2,c:pk_k(5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))}})";
    let descriptor = Descriptor::with_derive_bip32path(desc, "1", &Network::Regtest).expect("Fail");
    assert_eq!(
      "tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a,{c:pk_k(8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816),{c:pk_k([bd16bee5/0]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),thresh(2,c:pk_k(5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))}})#7ezsl729",
      descriptor.to_str()
    );
    assert_eq!(&HashType::Taproot, descriptor.get_hash_type());
    assert_eq!(
      "bcrt1pfuqf4j7ceyzmu3rsmude93ctu948r565hf2ucrn9z7zn7a7hjegskj3rsv",
      descriptor.get_address().to_str()
    );
    assert_eq!(
      "OP_1 4f009acbd8c905be4470df1b92c70be16a71d354ba55cc0e6517853f77d79651",
      descriptor.get_address().get_locking_script().to_asm()
    );
    assert_eq!(false, descriptor.has_multisig());
    assert_eq!(false, descriptor.has_script_hash());
    assert_eq!(false, descriptor.has_key_hash());
    assert_eq!(true, descriptor.has_taproot());
    assert_eq!(1, descriptor.get_script_list().len());
    assert_eq!(
      "{tl(208c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816ac),{tl(208c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816ac),tl(205cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bcac7c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87936b82012088a914dd69735817e0e3f6f826a9238dc2e291184f0131876c935287)}}",
      descriptor.get_script_tree().to_str()
    );
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Schnorr, key_data.get_type());
    assert_eq!(
      "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a",
      key_data.to_str()
    );
  }
}
