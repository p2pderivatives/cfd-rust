extern crate cfd_rust;
extern crate sha2;

#[cfg(test)]
mod tests {
  use cfd_rust::{ByteData, Privkey, Pubkey, SchnorrPubkey, Script, TapBranch};
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

  #[test]
  fn tapscript_tree_test1() {
    let privkey =
      Privkey::from_str("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
        .expect("Fail");
    let (pubkey, _) = SchnorrPubkey::from_privkey(&privkey).expect("Fail");
    assert_eq!(
      "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb",
      pubkey.to_hex()
    );

    let script_checksig =
      Script::from_asm(&format!("{} OP_CHECKSIG", pubkey.to_hex())).expect("Fail");
    let script_op_true = Script::from_asm("OP_TRUE").expect("Fail");
    let script_checksig2 = Script::from_asm(
      "ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440 OP_CHECKSIG",
    )
    .expect("Fail");

    let mut tree1 = TapBranch::from_tapscript(&script_checksig).expect("Fail");
    assert_eq!(
      "tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)",
      tree1.to_str()
    );
    tree1.add_by_tapleaf(&script_op_true).expect("Fail");
    assert_eq!(
      "{tl(51),tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)}",
      tree1.to_str()
    );
    tree1.add_by_tapleaf(&script_checksig2).expect("Fail");
    assert_eq!("{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(51),tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)}}", tree1.to_str());
    let node_list1 = tree1.get_target_nodes();
    assert_eq!(2, node_list1.len());
    let count1 = tree1.get_branch_count().expect("Fail");
    assert_eq!(2, count1);

    // deserialize
    let tree_str = "{{{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}},{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)}},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}},tl(2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac)}";
    let control_nodes: Vec<[u8; 32]> = vec![
      ByteData::from_str("06b46c960d6824f0da5af71d9ecc55714de5b2d2da51be60bd12c77df20a20df")
        .expect("Fail")
        .to_32byte_array(),
      ByteData::from_str("4691fbb1196f4675241c8958a7ab6378a63aa0cc008ed03d216fd038357f52fd")
        .expect("Fail")
        .to_32byte_array(),
      ByteData::from_str("e47f58011f27e9046b8195d0ab6a2acbc68ce281437a8d5132dadf389b2a5ebb")
        .expect("Fail")
        .to_32byte_array(),
      ByteData::from_str("32a0a039ec1412be2803fd7b5f5444c03d498e5e8e107ee431a9597c7b5b3a7c")
        .expect("Fail")
        .to_32byte_array(),
      ByteData::from_str("d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75")
        .expect("Fail")
        .to_32byte_array(),
    ];
    let tree2 = TapBranch::from_string_by_tapscript(&tree_str, &script_op_true, &control_nodes)
      .expect("Fail");
    assert_eq!(5, tree2.get_branch_count().expect("Fail"));
    assert_eq!(tree_str, tree2.to_str());
    let node_list = tree2.get_target_nodes();
    assert_eq!(5, node_list.len());
    if node_list.len() == 5 {
      let mut index = 0;
      while index < node_list.len() {
        assert_eq!(control_nodes[index], node_list[index]);
        index += 1;
      }
    }
    let branch = tree2.get_branch(3).expect("Fail");
    assert_eq!("{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}", branch.to_str());

    let empty_nodes: Vec<[u8; 32]> = vec![];
    let mut tree3 = TapBranch::from_string_by_tapscript(
      "{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)}},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}",
      &&script_op_true,
      &&empty_nodes,
    ).expect("Fail");
    tree3.add_by_tapbranch(&branch).expect("Fail");
    tree3.add_by_tree_string("tl(2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac)").expect("Fail");
    assert_eq!(tree2.to_str(), tree3.to_str());
  }
}
