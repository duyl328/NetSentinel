use std::ffi::c_void;
use crate::core::win_divert;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use tauri_plugin_dialog::DialogExt;
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;
use crate::core::win_divert::{open_windivert, recv_packet1, WinDivertLayer};

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
    let x = win_divert::monitor_network_with_windivert();
    match x {
        Ok(_) => println!("Success"),
        Err(e) => println!("出现错误: {}", e),
    }
}

/// 安全接收数据包的辅助函数
#[tauri::command]
pub fn recv_packet_command() {
    log::info!("{:?}", "安全接收数据包的辅助函数");

    let handle = open_windivert(
        "tcp",WinDivertLayer::WinDivertLayerNetwork,0,0
    ).expect("open_windivert failed");
    // 1500 字节是以太网默认的最大传输单元
    // 65535 是 IP 协议允许的最大值
    let mut buf = vec![0u8; 1500];
    log::info!("获取 handle {:?}",handle);
    match recv_packet1(handle, Some(&mut buf), true) {
        Some((len, Some(addr))) => {
            println!("Received {} bytes", len);
            println!("Address info: {:?}", addr);
        }
        Some((len, None)) => {
            println!("Received {} bytes without address info", len);
        }
        None => {
            eprintln!("Receive failed.");
        }
    }
}
