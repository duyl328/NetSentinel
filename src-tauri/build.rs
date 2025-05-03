use std::path::PathBuf;
use std::env;
use std::fs;

fn main() {
  // 向 Cargo 构建系统传递编译指令
  println!("cargo:rustc-link-search=native=windivert");
  println!("cargo:rustc-link-lib=dylib=WinDivert");

  println!("cargo:rerun-if-changed=wrapper.h");

  // 生成 bindings.rs
  let bindings = bindgen::Builder::default()
      .header("wrapper.h") // 你写一个包含 WinDivert.h 的 wrapper
      .generate()
      .expect("Unable to generate bindings");

  let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
  bindings
      .write_to_file(out_path.join("bindings.rs"))
      .expect("Couldn't write bindings!");

  // 自动复制 DLL 到 target/debug/
  let profile = env::var("PROFILE").unwrap(); // debug 或 release
  let target_dir = PathBuf::from(env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into()))
      .join(&profile);

  let dll_src = PathBuf::from("windivert").join("WinDivert.dll");
  let dll_dst = target_dir.join("WinDivert.dll");

  if let Err(e) = fs::copy(&dll_src, &dll_dst) {
    eprintln!("❌ Failed to copy WinDivert.dll: {}", e);
  }


  tauri_build::build()
}
