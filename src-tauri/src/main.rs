// 防止 Windows 上发布时出现额外的控制台窗口，请勿删除！！
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// include!("./bindings.rs");
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

fn main() {

  test_windivert_open();

  app_lib::run();
}

#[allow(non_snake_case)]
fn test_windivert_open() {
  use std::ffi::CString;
  use std::ptr;
  use std::os::raw::c_char;

  unsafe {
    let filter = CString::new("true").unwrap();  // 捕获所有包
    let handle = WinDivertOpen(
      filter.as_ptr() as *const c_char,
      0, // Layer
      0, // Priority
      0, // Flags
    );

    if handle.is_null() {
      log::warn!("❌ WinDivertOpen failed.");
      println!("❌ WinDivertOpen failed.");
    } else {
      println!("✅ WinDivertOpen succeeded!");
      log::info!("❌ WinDivertOpen failed.");
    }
  }
}
