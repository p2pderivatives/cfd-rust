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
    assert_eq!(1, descriptor.get_script_list().len());
    let key_data = descriptor.get_key_data().expect("fail");
    assert_eq!(&DescriptorKeyType::Public, key_data.get_type());
    assert_eq!(
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      key_data.to_str()
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
    assert_eq!(3, descriptor.get_multisig_key_list().expect("Fail").len());
    assert_eq!(
      "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
      descriptor.get_multisig_key_list().expect("Fail")[0]
        .get_pubkey()
        .to_hex()
    );
    assert_eq!(
      "03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
      descriptor.get_multisig_key_list().expect("Fail")[1]
        .get_pubkey()
        .to_hex()
    );
  }
}
