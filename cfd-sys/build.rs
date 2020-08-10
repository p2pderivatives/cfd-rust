extern crate cmake;
extern crate pkg_config;
use std::env;
use std::path::Path;

fn main() {
  // cargo build -vv
  let _build_type = env::var("PROFILE").unwrap();
  let release_name = "release";

  let release_type = "Release";
  let debug_type = "Debug";
  let cmake_build_type = if _build_type == release_name {
    release_type
  } else {
    debug_type
  };

  let separator_slash = "/";
  let separator_back = "\\";
  let _os_type = env::var("CARGO_CFG_TARGET_OS").unwrap();
  let os_windows = "windows";
  let os_mac = "macos";
  let separator = if _os_type == os_windows {
    separator_back
  } else {
    separator_slash
  };

  let static_pkg_ret = pkg_config::Config::new().statik(true).probe("cfd");
  if let Ok(pkg) = static_pkg_ret {
    // already printed "cargo:rustc-link-lib"
    let r1 = pkg_config::Config::new().statik(true).probe("cfd-core");
    let r2 = pkg_config::Config::new().statik(true).probe("wally");
    let r3 = pkg_config::Config::new().statik(true).probe("univalue");
    if let Err(e) = r1 {
      println!("cargo:warning=pkg-config warn: cfd-core. Err={}", e);
    }
    if let Err(e) = r2 {
      println!("cargo:warning=pkg-config warn: wally. Err={}", e);
    }
    if let Err(e) = r3 {
      println!("cargo:warning=pkg-config error: univalue. Err={}", e);
    }
    let is_static: bool = {
      let lib_name = "libcfd.a";
      let system_roots = if cfg!(target_os = "macos") {
        vec![Path::new("/Library"), Path::new("/System")]
      } else {
        vec![Path::new("/usr")]
      };
      pkg.link_paths.iter().any(|dir| {
        !system_roots.iter().any(|sys| dir.starts_with(sys)) && dir.join(&lib_name).exists()
      })
    };
    if is_static {
      println!("cargo:rustc-link-lib=static=cfd");
      println!("cargo:rustc-link-lib=static=cfdcore");
      println!("cargo:rustc-link-lib=static=wally");
      println!("cargo:rustc-link-lib=static=univalue");
    }
  } else {
    let dst = cmake::Config::new("cfd-cmake")
      .define("ENABLE_TESTS", "off")
      .define("ENABLE_JS_WRAPPER", "off")
      .define("ENABLE_CAPI", "on")
      .define("ENABLE_SHARED", "off")
      .define("CMAKE_BUILD_TYPE", cmake_build_type)
      .build();

    println!(
      "cargo:rustc-link-search=native={}{}build{}{}",
      dst.display(),
      separator,
      separator,
      cmake_build_type
    );
    // println!(
    //   "cargo:rustc-link-search=native={}",
    //   dst.display(),
    // );
    println!("cargo:rustc-link-lib=static=cfd");
    println!("cargo:rustc-link-lib=static=cfdcore");
    println!("cargo:rustc-link-lib=static=wally");
    println!("cargo:rustc-link-lib=static=univalue");
  }

  if _os_type != os_windows {
    println!("cargo:rustc-link-lib=dylib=pthread");
  }
  if _os_type == os_mac {
    println!("cargo:rustc-link-lib=dylib=c++");
  //println!("cargo:rustc-flags=-l dylib=c++");
  } else if _os_type != os_windows {
    println!("cargo:rustc-link-lib=dylib=stdc++");
    //println!("cargo:rustc-flags=-l dylib=stdc++");
  }
}
