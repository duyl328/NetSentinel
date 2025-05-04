use crate::core::win_divert;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use tauri_plugin_dialog::DialogExt;
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;

/// 显示所有网络连接信息
#[tauri::command]
pub fn win_divert_command() {
    log::info!("{:?}", "win_divert_command 显示所有网络连接信息");

    win_divert::display_all_connections();
}


/// 使用WinDivert监控网络数据包
#[tauri::command]
pub fn monitor_network_with_windivert_command() {
    log::info!("{:?}", "使用WinDivert监控网络数据包");
    win_divert::monitor_network_with_windivert();
}
