extern crate cfd_rust;
extern crate sha2;

#[cfg(test)]
mod tests {
  use cfd_rust::{ByteData, Network, Privkey, Pubkey, SigHashType, SignParameter};
  use std::str::FromStr;

  #[test]
  fn pubkey_test() {
    // default
    let pubkey_str = "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1";
    let pubkey_ret = Pubkey::from_str(pubkey_str);
    assert!(pubkey_ret.is_ok(), "err: \"{}\"", pubkey_ret.unwrap_err());
    let pubkey = pubkey_ret.unwrap();
    assert_eq!(pubkey_str, pubkey.to_hex());
    assert!(pubkey.valid());
    let pubkey_empty = Pubkey::default();
    assert!(!pubkey_empty.valid());
    // from_slice
    let pubkey1 =
      Pubkey::from_str("031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1")
        .expect("Fail");
    let pubkey2 = Pubkey::from_slice(pubkey1.to_slice()).expect("Fail");
    assert_eq!(
      "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1",
      pubkey2.to_hex()
    );
    // combine
    let comb_pubkey1 =
      Pubkey::from_str("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9")
        .expect("Fail");
    let comb_pubkey2 =
      Pubkey::from_str("0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe")
        .expect("Fail");
    let combine_key = Pubkey::combine(&[comb_pubkey1, comb_pubkey2]).expect("Fail");
    assert!(combine_key.valid());
    assert_eq!(
      "022a66efd1ea9b1ad3acfcc62a5ce8c756fa6fc3917fce3d4952a8701244ed1049",
      combine_key.to_hex()
    );
    // compress/uncompress
    let uncompress_pubkey1 =
    Pubkey::from_str("076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73")
      .expect("Fail");
    let comp_pubkey1 =
      Pubkey::from_str("036468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955")
        .expect("Fail");
    let comp_pubkey2 = uncompress_pubkey1.compress().expect("Fail");
    let uncompress_pubkey2 = comp_pubkey1.uncompress().expect("Fail");
    assert_eq!(
        "046468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73",
        uncompress_pubkey2.to_hex()
      );
    assert_eq!(comp_pubkey1.to_hex(), comp_pubkey2.to_hex());
    // tweak/negate
    let pubkey3 =
      Pubkey::from_str("03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9")
        .expect("Fail");
    let tweak =
      ByteData::from_str("98430d10471cf697e2661e31ceb8720750b59a85374290e175799ba5dd06508e")
        .expect("Fail");
    let tweak_add = pubkey3.tweak_add(tweak.to_slice()).expect("Fail");
    assert_eq!(
      "02b05cf99a2f556177a38f5108445472316e87eb4f5b243d79d7e5829d3d53babc",
      tweak_add.to_hex()
    );
    let tweak_mul = pubkey3.tweak_mul(tweak.to_slice()).expect("Fail");
    assert_eq!(
      "0305d10e760a529d0523e98892d2deff59b91593a0d670bd82271cfa627c9e7e18",
      tweak_mul.to_hex()
    );
    let negate = pubkey3.negate().expect("Fail");
    assert_eq!(
      "02662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9",
      negate.to_hex()
    );
    // Verify ec-sig
    let pubkey_ec =
      Pubkey::from_str("031777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb")
        .expect("Fail");
    let sighash =
      ByteData::from_str("2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e")
        .expect("Fail");
    let signature = ByteData::from_str("0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c").expect("Fail");
    let bad_signature = ByteData::from_str("0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f").expect("Fail");
    let verify1 = pubkey_ec
      .verify_ec_signature(sighash.to_slice(), signature.to_slice())
      .expect("Fail");
    assert!(verify1);
    let verify2 = pubkey_ec
      .verify_ec_signature(sighash.to_slice(), bad_signature.to_slice())
      .expect("Fail");
    assert!(!verify2);
  }

  #[test]
  fn privkey_test() {
    // default
    let empty_key = Privkey::default();
    assert!(!empty_key.valid());
    let key = Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
      .expect("fail");
    assert_eq!(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27",
      key.to_hex()
    );
    assert!(key.valid());
    let wif =
      Privkey::from_wif("5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23").expect("fail");
    assert_eq!(
      "305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27",
      wif.to_hex()
    );
    assert_eq!(
      "5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23",
      wif.to_wif()
    );
    assert_eq!(Network::Mainnet, *wif.to_network());
    assert!(!wif.is_compressed_pubkey());
    assert!(wif.valid());
    // generate
    let gen_key = Privkey::generate(&Network::Testnet, true).expect("Fail");
    assert!(gen_key.valid());
    // get_wif
    let wif_base =
      Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
        .expect("Fail");
    let wif1 = wif_base
      .generate_wif(&Network::Mainnet, false)
      .expect("Fail");
    assert_eq!("5JBb5A38fjjeBnngkvRmCsXN6EY4w8jWvckik3hDvYQMcddGY23", wif1);
    let wif2 = wif_base
      .generate_wif(&Network::Mainnet, true)
      .expect("Fail");
    assert_eq!("KxqjPLtQqydD8d6eUrpJ7Q1266k8Mw8f5eoyEztY3Kc5z4f2RQTG", wif2);
    let wif3 = wif_base
      .generate_wif(&Network::Testnet, false)
      .expect("Fail");
    assert_eq!("91xDetrgFxon9rHyPGKg5U5Kjttn6JGiGZcfpg3jGH9QPd4tmrm", wif3);
    let wif4 = wif_base
      .generate_wif(&Network::Testnet, true)
      .expect("Fail");
    assert_eq!("cPCirFtGH3KUJ4ZusGdRUiW5iL3Y2PEM9gxSMRM3YSG6Eon9heJj", wif4);
    let wif3_privkey = Privkey::from_str(&wif3).expect("Fail");
    let wif3_pubkey = wif3_privkey.get_pubkey().expect("Fail");
    assert_eq!("041777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb78885d348051c6fbd31ac749eb5646481f6d8d9c36f8d157712ca054046a9b8b", wif3_pubkey.to_str());
    // tweak/negate
    let privkey3 =
      Privkey::from_str("036b13c5a0dd9935fe175b2b9ff86585c231e734b2148149d788a941f1f4f566")
        .expect("Fail");
    let tweak =
      ByteData::from_str("98430d10471cf697e2661e31ceb8720750b59a85374290e175799ba5dd06508e")
        .expect("Fail");
    let tweak_add = privkey3.tweak_add(tweak.to_slice()).expect("Fail");
    assert_eq!(
      "9bae20d5e7fa8fcde07d795d6eb0d78d12e781b9e957122b4d0244e7cefb45f4",
      tweak_add.to_hex()
    );
    let tweak_mul = privkey3.tweak_mul(tweak.to_slice()).expect("Fail");
    assert_eq!(
      "aa71b12accba23b49761a7521e661f07a7e5742ac48cf708b8f9497b3a72a957",
      tweak_mul.to_hex()
    );
    let negate = privkey3.negate().expect("Fail");
    assert_eq!(
      "fc94ec3a5f2266ca01e8a4d460079a78f87cf5b1fd341ef1e849b54ade414bdb",
      negate.to_hex()
    );
    // calc ec-sig
    let privkey_ec =
      Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
        .expect("Fail");
    let sighash =
      ByteData::from_str("2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e")
        .expect("Fail");
    let signature = privkey_ec
      .calculate_ec_signature(sighash.to_slice(), true)
      .expect("Fail");
    assert_eq!("0e68b55347fe37338beb3c28920267c5915a0c474d1dcafc65b087b9b3819cae6ae5e8fb12d669a63127abb4724070f8bd232a9efe3704e6544296a843a64f2c", signature.to_hex());
  }

  #[test]
  fn sign_parameter_test() {
    // normalize
    let sign_param = SignParameter::from_str("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5f67f6cf81a19873091aa7c9578fa2e96490e9bfc78ae7e9798004e8252c06287").expect("Fail");
    let normalized_sig = sign_param.normalize().expect("Fail");
    assert_eq!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee509809307e5e678cf6e55836a8705d16871a040ea369a21a427d2100a7d75deba", normalized_sig.to_hex());
    // der-encode
    let signature = SignParameter::from_str("773420c0ded41a55b1f1205cfb632f08f3f911a53e7338a0dac73ec6cbe3ca471907434d046185abedc5afddc2761a642bccc70af6d22b46394f1d04a8b24226").expect("Fail");
    let der_encoded_sig = signature.to_der_encode().expect("Fail");
    assert_eq!("30440220773420c0ded41a55b1f1205cfb632f08f3f911a53e7338a0dac73ec6cbe3ca4702201907434d046185abedc5afddc2761a642bccc70af6d22b46394f1d04a8b2422601", der_encoded_sig.to_hex());
    let der_decoded_sig = der_encoded_sig.to_der_decode().expect("Fail");
    assert_eq!("773420c0ded41a55b1f1205cfb632f08f3f911a53e7338a0dac73ec6cbe3ca471907434d046185abedc5afddc2761a642bccc70af6d22b46394f1d04a8b24226", der_decoded_sig.to_hex());

    // sighash rangeproof test
    let sighashtype_array = vec![
      // SigHashType::Default, // unuse der encode.
      SigHashType::All,
      SigHashType::None,
      SigHashType::Single,
      SigHashType::AllPlusAnyoneCanPay,
      SigHashType::NonePlusAnyoneCanPay,
      SigHashType::SinglePlusAnyoneCanPay,
      SigHashType::AllPlusRangeproof,
      SigHashType::NonePlusRangeproof,
      SigHashType::SinglePlusRangeproof,
      SigHashType::AllPlusAnyoneCanPayRangeproof,
      SigHashType::NonePlusAnyoneCanPayRangeproof,
      SigHashType::SinglePlusAnyoneCanPayRangeproof,
    ];
    let sig_str = "773420c0ded41a55b1f1205cfb632f08f3f911a53e7338a0dac73ec6cbe3ca471907434d046185abedc5afddc2761a642bccc70af6d22b46394f1d04a8b24226";
    for sighash_type2 in sighashtype_array {
      let signature2 = SignParameter::from_str(sig_str)
        .expect("Fail")
        .set_signature_hash(&sighash_type2);
      let der_encoded_sig2 = signature2.to_der_encode().expect("Fail");
      let der_decoded_sig2 = der_encoded_sig2.to_der_decode().expect("Fail");
      assert_eq!(sig_str, der_decoded_sig2.to_hex());
      assert_eq!(&sighash_type2, der_decoded_sig2.get_sighash_type());
    }
  }
}
