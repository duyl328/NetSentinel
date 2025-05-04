// 防止 Windows 上发布时出现额外的控制台窗口，请勿删除！！
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

fn main() {
    app_lib::run();
}
