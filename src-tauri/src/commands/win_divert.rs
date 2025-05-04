use tauri_plugin_dialog::DialogExt;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;
use windows::Win32::Foundation::*;
use crate::core::win_divert;

#[tauri::command]
pub fn win_divert_command(name: &str) -> String {
    log::error!("{:?}", "win_divert_command 获取系统网络连接");

    win_divert::display_all_connections();

    format!("Hello, {}! You've been greeted from Rust!", name)



}
