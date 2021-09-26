extern crate cfd_rust;
extern crate sha2;

#[cfg(test)]
mod tests {
  use cfd_rust::{
    AdaptorProof, AdaptorSignature, ByteData, EcdsaAdaptorUtil, Privkey, Pubkey, SchnorrPubkey,
    SchnorrSignature, SchnorrUtil,
  };
  use std::str::FromStr;

  #[test]
  fn ecdsa_adaptor_test() {
    // default
    let msg =
      ByteData::from_str("024bdd11f2144e825db05759bdd9041367a420fad14b665fd08af5b42056e5e2")
        .expect("Fail");
    let adaptor =
      Pubkey::from_str("038d48057fc4ce150482114d43201b333bf3706f3cd527e8767ceb4b443ab5d349")
        .expect("Fail");
    let sk = Privkey::from_str("90ac0d5dc0a1a9ab352afb02005a5cc6c4df0da61d8149d729ff50db9b5a5215")
      .expect("Fail");
    let pubkey =
      Pubkey::from_str("03490cec9a53cd8f2f664aea61922f26ee920c42d2489778bb7c9d9ece44d149a7")
        .expect("Fail");
    let adaptor_sig =
    AdaptorSignature::from_str("00cbe0859638c3600ea1872ed7a55b8182a251969f59d7d2da6bd4afedf25f5021a49956234cbbbbede8ca72e0113319c84921bf1224897a6abd89dc96b9c5b208").expect("Fail");
    let adaptor_proof =
    AdaptorProof::from_str("00b02472be1ba09f5675488e841a10878b38c798ca63eff3650c8e311e3e2ebe2e3b6fee5654580a91cc5149a71bf25bcbeae63dea3ac5ad157a0ab7373c3011d0fc2592a07f719c5fc1323f935569ecd010db62f045e965cc1d564eb42cce8d6d").expect("Fail");

    let adaptor_sig2 =
    AdaptorSignature::from_str("01099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f47bb90e2ad6630900b69f55674c8ad74a419e6ce113c10a21a79345a6e47bc74c1").expect("Fail");
    // let sig_der = ByteData::from_str("30440220099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f4702204d13456e98d8989043fd4674302ce90c432e2f8bb0269f02c72aafec60b72de101").expect("Fail");
    let expect_sig = ByteData::from_str("099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f474d13456e98d8989043fd4674302ce90c432e2f8bb0269f02c72aafec60b72de1").expect("Fail");
    let secret =
      Privkey::from_str("475697a71a74ff3f2a8f150534e9b67d4b0b6561fab86fcaa51f8c9d6c9db8c6")
        .expect("Fail");

    let obj = EcdsaAdaptorUtil::new();
    let pair = obj.sign(&msg, &sk, &adaptor).expect("Fail");
    assert_eq!(adaptor_sig.to_hex(), pair.signature.to_hex());
    assert_eq!(adaptor_proof.to_hex(), pair.proof.to_hex());

    let is_verify = obj
      .verify(&pair.signature, &pair.proof, &adaptor, &msg, &pubkey)
      .expect("Fail");
    assert!(is_verify);

    let signature = obj.adapt(&adaptor_sig2, &secret).expect("Fail");
    assert_eq!(expect_sig.to_hex(), signature.to_hex());

    let adaptor_secret = obj
      .extract_secret(&adaptor_sig2, &signature, &adaptor)
      .expect("Fail");
    assert_eq!(secret.to_hex(), adaptor_secret.to_hex());
  }

  #[test]
  fn schnorr_util_test() {
    // default
    let msg =
      ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614")
        .expect("Fail");
    let sk = Privkey::from_str("688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef")
      .expect("Fail");
    let pubkey =
      SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
        .expect("Fail");
    let aux_rand =
      ByteData::from_str("02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab")
        .expect("Fail");
    let nonce =
      SchnorrPubkey::from_str("8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe")
        .expect("Fail");
    let schnorr_nonce =
      SchnorrPubkey::from_str("f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547")
        .expect("Fail");
    let signature =
    SchnorrSignature::from_str("6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8").expect("Fail");

    let obj = SchnorrUtil::new();
    let sig1 = obj.sign(&msg, &sk, &aux_rand).expect("Fail");
    assert_eq!(signature.to_hex(), sig1.to_hex());

    let expected_sig =
    "5da618c1936ec728e5ccff29207f1680dcf4146370bdcfab0039951b91e3637a958e91d68537d1f6f19687cec1fd5db1d83da56ef3ade1f3c611babd7d08af42";
    let sig2 = obj
      .sign_with_nonce(&msg, &sk, &nonce.as_key().expect("Fail"))
      .expect("Fail");
    assert_eq!(expected_sig, sig2.to_hex());

    let expected_sig_point = "03735acf82eef9da1540efb07a68251d5476dabb11ac77054924eccbb4121885e8";
    let sig_point = obj
      .compute_sig_point(&msg, &schnorr_nonce, &pubkey)
      .expect("Fail");
    assert_eq!(expected_sig_point, sig_point.to_hex());

    let is_verify = obj.verify(&sig1, &msg, &pubkey).expect("Fail");
    assert!(is_verify);

    let expected_nonce = "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee";
    let expected_privkey = "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8";
    assert_eq!(expected_nonce, sig1.as_nonce().to_hex());
    assert_eq!(expected_privkey, sig1.as_key().to_hex());
  }

  #[test]
  fn schnorr_pubkey_test() {
    // default
    let tweak =
      ByteData::from_str("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614")
        .expect("Fail");
    let sk = Privkey::from_str("688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef")
      .expect("Fail");
    let pk = Pubkey::from_str("03b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
      .expect("Fail");
    let pubkey =
      SchnorrPubkey::from_str("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
        .expect("Fail");
    let exp_tweaked_pk =
      SchnorrPubkey::from_str("1fc8e882e34cc7942a15f39ffaebcbdf58a19239bcb17b7f5aa88e0eb808f906")
        .expect("Fail");
    let exp_tweaked_sk =
      Privkey::from_str("7bf7c9ba025ca01b698d3e9b3e40efce2774f8a388f8c390550481e1407b2a25")
        .expect("Fail");

    let (schnorr_pubkey, parity) = SchnorrPubkey::from_privkey(&sk).expect("Fail");
    assert_eq!(pubkey.to_hex(), schnorr_pubkey.to_hex());
    assert!(parity);

    let (schnorr_pubkey, parity) = SchnorrPubkey::from_pubkey(&pk).expect("Fail");
    assert_eq!(pubkey.to_hex(), schnorr_pubkey.to_hex());
    assert!(parity);

    let (tweaked_pubkey, tweaked_parity) = pubkey.tweak_add(tweak.to_slice()).expect("Fail");
    assert_eq!(exp_tweaked_pk.to_hex(), tweaked_pubkey.to_hex());
    assert!(tweaked_parity);

    let gen_key_ret =
      SchnorrPubkey::get_tweak_add_from_privkey(&sk, tweak.to_slice()).expect("Fail");
    let (tweaked_pubkey, tweaked_parity, tweaked_privkey) = gen_key_ret;
    assert_eq!(exp_tweaked_pk.to_hex(), tweaked_pubkey.to_hex());
    assert!(tweaked_parity);
    assert_eq!(exp_tweaked_sk.to_hex(), tweaked_privkey.to_hex());

    let is_valid = tweaked_pubkey
      .is_tweaked(true, &pubkey, tweak.to_slice())
      .expect("Fail");
    assert!(is_valid);
    let is_valid = tweaked_pubkey
      .is_tweaked(false, &pubkey, tweak.to_slice())
      .expect("Fail");
    assert!(!is_valid);
  }
}
