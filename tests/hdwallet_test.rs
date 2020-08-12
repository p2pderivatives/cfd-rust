extern crate cfd_rust;

#[cfg(test)]
mod tests {
  use cfd_rust::{ExtPrivkey, ExtPubkey};

  #[test]
  fn ext_pubkey() {
    let privkey_str: &str = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
    let pubkey_str: &str = "xpub6DsNDJWpxZBXsbWsCy1VeBY8xf6hZBgznDTXSnp3FregxWoWfGsvtQ9j5wBJNPebZXD5YmhpQBV7nVjhUsUgkG9R7yE31mh6sVh2w854a1o";
    let extkey_obj = ExtPubkey::new(&pubkey_str);
    assert!(extkey_obj.is_ok(), "err: \"{}\"", extkey_obj.unwrap_err());
    let extkey_fail = ExtPubkey::new(&privkey_str);
    assert!(extkey_fail.is_err(), "err: \"{}\"", extkey_fail.unwrap());

    let obj = extkey_obj.unwrap();
    let pubkey = obj.get_pubkey();
    assert_eq!(
      "038746b92b722894e533dbbda3fb7fa673da00f4b309bf98a2cf586c27100004b0",
      pubkey.to_hex()
    );
  }

  #[test]
  fn ext_privkey() {
    let privkey_str: &str = "xprv9zt1onyw8BdEf7SQ6wUVH3bQQdGD9iy9QzXveQQRhX7i5iUN7jZgLbqFEe491LfjozztYa6bJAGZ65GmDCNcbjMdjZcgmdisPJwVjcfcDhV";
    let pubkey_str: &str = "xpub6DsNDJWpxZBXsbWsCy1VeBY8xf6hZBgznDTXSnp3FregxWoWfGsvtQ9j5wBJNPebZXD5YmhpQBV7nVjhUsUgkG9R7yE31mh6sVh2w854a1o";
    let extkey_obj = ExtPrivkey::new(&privkey_str);
    assert!(extkey_obj.is_ok(), "err: \"{}\"", extkey_obj.unwrap_err());
    let extkey_fail = ExtPrivkey::new(&pubkey_str);
    assert!(extkey_fail.is_err(), "err: \"{}\"", extkey_fail.unwrap());

    let obj = extkey_obj.unwrap();
    let privkey = obj.get_privkey();
    assert_eq!(
      "73a2361673d25f998d1e9d94aabdeba8ac1ddd4628bc4f55341397d263bd560c",
      privkey.to_hex()
    );
  }
}
