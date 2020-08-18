extern crate cfd_rust;
extern crate sha2;

#[cfg(test)]
mod tests {
  use cfd_rust::{Pubkey, Script};
  use std::str::FromStr;

  #[test]
  fn script_test() {
    // default
    let multisig_script = Script::from_hex("522102522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0210340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c21024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b8253ae").expect("Fail");
    assert_eq!("OP_2 02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0 0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c 024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82 OP_3 OP_CHECKMULTISIG", multisig_script.to_asm());
    let copy_script = Script::from_asm(multisig_script.to_asm()).expect("Fail");
    assert_eq!(multisig_script.to_asm(), copy_script.to_asm());
    let copy2_script = Script::from_slice(multisig_script.to_slice()).expect("Fail");
    assert_eq!(multisig_script.to_asm(), copy2_script.to_asm());
    let str_list = [
      "OP_2",
      "02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0",
      "0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c",
      "024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82",
      "OP_3",
      "OP_CHECKMULTISIG",
    ];
    let from_list_script = Script::from_strings(&str_list).expect("Fail");
    assert_eq!(multisig_script.to_asm(), from_list_script.to_asm());
    let string_list = [
      str_list[0].to_string(),
      str_list[1].to_string(),
      str_list[2].to_string(),
      str_list[3].to_string(),
      str_list[4].to_string(),
      str_list[5].to_string(),
    ];
    let str_list_script = Script::from_str_array(&string_list).expect("Fail");
    assert_eq!(multisig_script.to_asm(), str_list_script.to_asm());
    // multisig
    let pubkey1 =
      Pubkey::from_str("02522952c3fc2a53a8651b08ce10988b7506a3b40a5c26f9648a911be33e73e1a0")
        .expect("Fail");
    let pubkey2 =
      Pubkey::from_str("0340b52ae45bc1be5de083f1730fe537374e219c4836400623741d2a874e60590c")
        .expect("Fail");
    let pubkey3 =
      Pubkey::from_str("024a3477bc8b933a320eb5667ee72c35a81aa155c8e20cc51c65fb666de3a43b82")
        .expect("Fail");
    let pubkey_list = [pubkey1, pubkey2, pubkey3];
    let multisig = Script::multisig(2, &pubkey_list).expect("Fail");
    assert_eq!(multisig_script.to_asm(), multisig.to_asm());
  }
}
