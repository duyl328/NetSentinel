use crate::core::win_divert;
use crate::core::win_divert::{open_windivert, recv_packet1};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use sysinfo::System;
use tauri_plugin_dialog::DialogExt;
use windivert::error::WinDivertError;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;
use windivert::{layer, WinDivert};
use windivert_sys::WinDivertValueError::Layer;
use windivert_sys::{WinDivertFlags, WinDivertLayer};
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::*;
use crate::utils::win_utils::{get_tcp_connections, get_udp_connections};

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
pub fn recv_packet_command1() {
    // 使用 WinDivert 过滤表达式（这里是所有 IPv4 流量）
    let filter = "tcp and inbound"; // 表示不过滤，捕获所有网络包
    let divert_flags = WinDivertFlags::new();
    divert_flags.set_sniff();
    let mut divert = WinDivert::network(filter, 0, divert_flags);
    match divert {
        Ok(val) => {
            println!("Listening for packets...");

            loop {
                let mut buffer = vec![0u8; 1500];
                let slice_opt: Option<&mut [u8]> = Some(&mut buffer[..]);

                let length = val.recv(slice_opt);

                match length {
                    Ok(obj) => {
                        let data = obj.data;
                        if let Some(ipv4_packet) = Ipv4Packet::new(&*data) {
                            println!(
                                "IPv4 Packet: {} -> {}",
                                ipv4_packet.get_source(),
                                ipv4_packet.get_destination()
                            );

                            if ipv4_packet.get_next_level_protocol()
                                == pnet::packet::ip::IpNextHeaderProtocols::Tcp
                            {
                                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                    let x = tcp_packet.payload();
                                    let src = tcp_packet.get_source();
                                    let dst = tcp_packet.get_destination();

                                    // println!(
                                    //     "hex: {:02X?}; | utf8 lossy -> {} | src -> {} | dst -> {}",
                                    //     x,
                                    //     String::from_utf8_lossy(x),
                                    //     src,dst
                                    // );

                                    // 获取TCP标志
                                    let flags = tcp_packet.get_flags();
                                    println!("SYN: {}, ACK: {}, FIN: {}, RST: {}, PSH: {}, TCP Flags: {:#010b}, src: {}, dst: {} ,x: {}",
                                             flags & TcpFlags::SYN != 0,
                                             flags & TcpFlags::ACK != 0,
                                             flags & TcpFlags::FIN != 0,
                                             flags & TcpFlags::RST != 0,
                                             flags & TcpFlags::PSH != 0,flags,
                                    src,dst,x.len());

                                    // 获取序列号和确认号
                                    println!("Sequence Number: {} | Acknowledgment Number->{} \
                                    获取窗口大小和校验和 Window Size=> {} | Checksum: {:#06x} | \
                                    获取数据偏移(头部长度) => {} | 获取IPv4其他信息 TTL=> {} | Total Length: {} bytes",
                                             tcp_packet.get_sequence(),
                                             tcp_packet.get_acknowledgement(),
                                             tcp_packet.get_window(),
                                             tcp_packet.get_checksum(),
                                             tcp_packet.get_data_offset() * 4,
                                             ipv4_packet.get_ttl(),
                                             ipv4_packet.get_total_length());

                                    // println!(
                                    //     "TCP Segment: {} -> {} | payload size: {}",
                                    //     tcp_packet.get_source(),
                                    //     tcp_packet.get_destination(),
                                    //     x.len()
                                    // );
                                    // payload 内容作为应用层数据，如 HTTP、TLS，可进一步解析
                                }
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("recv 失败: {}", err); // 打印日志
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        Err(e) => {
            eprintln!("操作失败: {}", e); // 打印日志
        }
    }
}

/// 显示所有网络连接信息
#[tauri::command]
pub fn get_all_tcp_info() {
    log::info!("正在获取系统网络连接信息...\n");

    // 获取TCP连接
    let tcp_connections = get_tcp_connections();
    log::info!("TCP连接 ({}个):", tcp_connections.len());
    log::info!(
        "{:<5} {:<15} {:<8} {:<15} {:<8} {:<15} {:<20} {:<25}",
        "协议",
        "本地IP",
        "本地端口",
        "远程IP",
        "远程端口",
        "进程ID",
        "进程名",
        "状态",
    );
    log::info!("{:-<90}", "");

    for conn in tcp_connections {
        log::info!(
            "{:<5} {:<15} {:<8} {:<15} {:<8} {:<15} {:<20} {:<25}",
            conn.protocol,
            conn.local_addr,
            conn.local_port,
            conn.remote_addr.unwrap_or_default(),
            conn.remote_port.unwrap_or_default(),
            conn.process_id.unwrap_or_default(),
            conn.process_name.unwrap_or_default(),
            conn.state.unwrap_or_default()
        );
    }

    log::info!("\n");

    // 获取UDP连接
    let udp_connections = get_udp_connections();
    log::info!("UDP连接 ({}个):", udp_connections.len());
    log::info!(
        "{:<5} {:<15} {:<8} {:<15} {:<20}",
        "协议",
        "本地IP",
        "本地端口",
        "进程ID",
        "进程名"
    );
    log::info!("{:-<70}", "");

    for conn in udp_connections {
        log::info!(
            "{:<5} {:<15} {:<8} {:<15} {:<20}",
            conn.protocol,
            conn.local_addr,
            conn.local_port,
            conn.process_id.unwrap_or_default(),
            conn.process_name.unwrap_or_default()
        );
    }
}

/// 安全接收数据包的辅助函数
#[tauri::command]
pub fn recv_packet_command() {
    log::info!("{:?}", "安全接收数据包的辅助函数");

    // let handle = open_windivert(
    //     "tcp",WinDivertLayer::WinDivertLayerNetwork,0,0
    // ).expect("open_windivert failed");
    // // 1500 字节是以太网默认的最大传输单元
    // // 65535 是 IP 协议允许的最大值
    // let mut buf = vec![0u8; 1500];
    // log::info!("获取 handle {:?}",handle);
    // match recv_packet1(handle, Some(&mut buf), true) {
    //     Some((len, Some(addr))) => {
    //         println!("Received {} bytes", len);
    //         println!("Address info: {:?}", addr);
    //     }
    //     Some((len, None)) => {
    //         println!("Received {} bytes without address info", len);
    //     }
    //     None => {
    //         eprintln!("Receive failed.");
    //     }
    // }
}
/// 获取线程 ID 信息
#[tauri::command]
pub fn get_more_info(id:String) {
    log::info!("{:?}", "获取线程 ID 信息");
    // 创建系统信息实例
    let mut system = System::new_all();
    let n: usize = id.parse().unwrap();

    // 刷新所有进程信息
    system.refresh_all();

    // 假设已知的PID
    let pid = sysinfo::Pid::from(n); // 替换为您的实际PID

    // 尝试获取进程信息
    if let Some(process) = system.process(pid) {
        println!("进程名称: {:?}", process.name());
        println!("可执行文件路径: {:?}", process.exe());
        println!("命令行: {:?}", process.cmd());
        println!("内存使用: {} KB", process.memory() / 1024);
        println!("CPU使用率: {}%", process.cpu_usage());
        println!("运行时间: {} 秒", process.run_time());
        println!("父进程ID: {:?}", process.parent());
        println!("状态: {:?}", process.status());
    } else {
        println!("未找到PID为{}的进程", pid);
    }
}
