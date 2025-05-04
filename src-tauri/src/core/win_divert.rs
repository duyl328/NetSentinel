use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::Duration;
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, TCP_TABLE_CLASS, UDP_TABLE_CLASS,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// WinDivert FFI 定义
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertAddress {
    /// 数据包捕获的时间戳
    pub timestamp: i64,
    /// 捕获层级（网络层、应用层等）
    pub layer: u8,
    /// 事件类型（数据包事件）
    pub event: u8,
    /// 是否为嗅探模式捕获的数据包
    pub sniffed: u8,
    /// 指示数据包的方向（出站=1，入站=0）
    pub outbound: u8,
    /// IP校验和状态标志
    pub ip_checksum: u8,
    /// TCP校验和状态标志
    pub tcp_checksum: u8,
    /// UDP校验和状态标志
    pub udp_checksum: u8,
    /// 保留字段1，用于将来扩展
    pub reserved1: u8,
    /// 保留字段2，用于将来扩展
    pub reserved2: u32,
    /// 是否为IPv6数据包（1=IPv6，0=IPv4）
    pub is_ipv6: u32,
    /// 网络接口相关数据（包含接口索引和子接口索引）
    pub network: WinDivertNetworkData,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertNetworkData {
    pub IfIdx: u32,
    pub SubIfIdx: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    GRE = 47,
    ESP = 50,
    AH = 51,
    ICMPv6 = 58,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::ICMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            47 => IpProtocol::GRE,
            50 => IpProtocol::ESP,
            51 => IpProtocol::AH,
            58 => IpProtocol::ICMPv6,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IpProtocol::ICMP => "ICMP",
            IpProtocol::TCP => "TCP",
            IpProtocol::UDP => "UDP",
            IpProtocol::GRE => "GRE",
            IpProtocol::ESP => "ESP",
            IpProtocol::AH => "AH",
            IpProtocol::ICMPv6 => "ICMPv6",
            IpProtocol::Unknown(code) => return write!(f, "Unknown({})", code),
        };
        write!(f, "{}", s)
    }
}


/// 基于 IPv4 协议的标准定义
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct windivert_iphdr {
    /// 高 4 位是 Version（IP版本号，通常为4），低 4 位是 Header Length（头部长度，以4字节为单位）。你需要位运算提取。
    pub HdrLength: u8,
    pub Version: u8,
    /// Type of Service，服务类型，影响包的优先级/QoS（现代用法中也称为 DSCP）。
    pub TOS: u8,
    /// 总长度，整个 IP 包的长度（包括头部和数据），单位是字节。
    pub Length: u16,
    /// 标识符，用于分片（fragmentation）重组。
    pub Id: u16,
    /// 分片偏移和标志位的组合字段（需要位运算提取标志位和偏移量）。
    pub FragOff: u16,
    /// Time To Live，生存时间，防止数据包在网络中无限循环（每跳减1，到0就丢弃）。
    pub TTL: u8,
    /// 表示上层协议，如 6=TCP，17=UDP，1=ICMP 等。
    pub Protocol: u8,
    /// IP 头部校验和（用于确保头部未损坏）。
    pub Checksum: u16,
    /// 源 IP 地址，IPv4 格式（可以转换成人类可读字符串）。
    pub SrcAddr: u32,
    /// 目标 IP 地址
    pub DstAddr: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct windivert_ipv6hdr {
    pub TrafficClass: u8, // 4位版本号，8位流量类
    pub Version: u8,
    pub FlowLabel: u32, // 20位流标签
    pub Length: u16,
    pub NextHdr: u8,
    pub HopLimit: u8,
    pub SrcAddr: [u8; 16],
    pub DstAddr: [u8; 16],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct windivert_tcphdr {
    pub SrcPort: u16,
    pub DstPort: u16,
    pub SeqNum: u32,
    pub AckNum: u32,
    pub Reserved1: u8, // 4位数据偏移，6位保留
    pub Reserved2: u8, // 6位标志位
    pub Window: u16,
    pub Checksum: u16,
    pub UrgPtr: u16,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct windivert_udphdr {
    pub SrcPort: u16,
    pub DstPort: u16,
    pub Length: u16,
    pub Checksum: u16,
}

#[link(name = "WinDivert")]
extern "C" {
    fn WinDivertOpen(filter: *const i8, layer: u8, priority: i16, flags: u64) -> *mut c_void;
    fn WinDivertClose(handle: *mut c_void) -> bool;
    fn WinDivertRecv(
        handle: *mut c_void,
        pPacket: *mut u8,
        packetLen: u32,
        pAddr: *mut WinDivertAddress,
        readLen: *mut u32,
    ) -> bool;
    fn WinDivertHelperParsePacket(
        pPacket: *const u8,
        packetLen: u32,
        ppIpHdr: *mut *mut windivert_iphdr,
        ppIpv6Hdr: *mut *mut windivert_ipv6hdr,
        ppIcmpHdr: *mut *mut c_void,
        ppIcmpv6Hdr: *mut *mut c_void,
        ppTcpHdr: *mut *mut windivert_tcphdr,
        ppUdpHdr: *mut *mut windivert_udphdr,
        ppData: *mut *mut u8,
        pDataLen: *mut u32,
    ) -> bool;
}

// 网络层常量
const WINDIVERT_LAYER_NETWORK: u8 = 0;
const WINDIVERT_FLAG_SNIFF: u64 = 1;
const WINDIVERT_FLAG_DROP: u64 = 2;

// TCP/UDP 表类型常量
const TCP_TABLE_OWNER_PID_ALL: TCP_TABLE_CLASS = TCP_TABLE_CLASS(5);
const UDP_TABLE_OWNER_PID_ALL: UDP_TABLE_CLASS = UDP_TABLE_CLASS(1);

// TCP/UDP端口表结构
#[repr(C)]
struct MIB_TCPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCPROW_OWNER_PID; 1],
}

#[repr(C)]
struct MIB_TCPROW_OWNER_PID {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MIB_UDPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_UDPROW_OWNER_PID; 1],
}

#[repr(C)]
struct MIB_UDPROW_OWNER_PID {
    local_addr: u32,
    local_port: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MIB_TCP6ROW_OWNER_PID {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope_id: u32,
    remote_port: u32,
    state: u32,
    owning_pid: u32,
}

#[repr(C)]
struct MIB_UDP6ROW_OWNER_PID {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    owning_pid: u32,
}

// 连接信息结构
#[derive(Debug)]
struct ConnectionInfo {
    protocol: String,
    local_addr: String,
    local_port: u16,
    remote_addr: Option<String>,
    remote_port: Option<u16>,
    process_id: Option<u32>,
    process_name: Option<String>,
    state: Option<String>,
}

// 将端口从网络字节序转换为主机字节序
fn ntohs(netshort: u16) -> u16 {
    ((netshort & 0xff) << 8) | ((netshort >> 8) & 0xff)
}

// 获取进程名称
fn get_process_name(pid: u32) -> Option<String> {
    unsafe {
        // 打开进程
        let process_handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

        // 获取进程路径
        let mut buffer = [0u8; 260]; // MAX_PATH
        let result = GetModuleFileNameExA(Some(process_handle), None, &mut buffer);

        if result == 0 {
            return None;
        }

        // 转换为Rust字符串
        let path = CStr::from_ptr(buffer.as_ptr() as *const i8)
            .to_string_lossy()
            .into_owned();

        // 提取进程名
        path.split('\\').last().map(|s| s.to_string())
    }
}

// 获取TCP连接表
fn get_tcp_connections() -> Vec<ConnectionInfo> {
    let mut result = Vec::new();
    unsafe {
        let mut table_size: u32 = 0;
        let mut ret = GetExtendedTcpTable(
            Some(ptr::null_mut()),
            &mut table_size,
            true,
            2, // AF_INET (IPv4)
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if table_size == 0 {
            return result;
        }

        let mut buffer = vec![0u8; table_size as usize];
        ret = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut table_size,
            true,
            2, // AF_INET (IPv4)
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != 0 {
            return result;
        }

        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let num_entries = table.dwNumEntries;
        let table_ptr = buffer.as_ptr().add(mem::size_of::<u32>()) as *const MIB_TCPROW_OWNER_PID;

        for i in 0..num_entries {
            let entry = &*table_ptr.add(i as usize);
            let local_ip = Ipv4Addr::from(entry.local_addr.to_be());
            let remote_ip = Ipv4Addr::from(entry.remote_addr.to_be());

            // 端口是以网络字节序存储的，需要转换
            let local_port = ((entry.local_port & 0xFF) << 8) | ((entry.local_port >> 8) & 0xFF);
            let remote_port = ((entry.remote_port & 0xFF) << 8) | ((entry.remote_port >> 8) & 0xFF);

            let state = match entry.state {
                5 => "ESTABLISHED".to_string(),
                1 => "CLOSED".to_string(),
                2 => "LISTENING".to_string(),
                3 => "SYN_SENT".to_string(),
                4 => "SYN_RCVD".to_string(),
                5 => "FIN_WAIT1".to_string(),
                6 => "FIN_WAIT2".to_string(),
                7 => "CLOSE_WAIT".to_string(),
                8 => "CLOSING".to_string(),
                9 => "LAST_ACK".to_string(),
                10 => "TIME_WAIT".to_string(),
                11 => "DELETE_TCB".to_string(),
                _ => format!("UNKNOWN({})", entry.state),
            };

            let process_name = get_process_name(entry.owning_pid);

            result.push(ConnectionInfo {
                protocol: "TCP".to_string(),
                local_addr: local_ip.to_string(),
                local_port: local_port as u16,
                remote_addr: Some(remote_ip.to_string()),
                remote_port: Some(remote_port as u16),
                process_id: Some(entry.owning_pid),
                process_name,
                state: Some(state),
            });
        }
    }
    result
}

// 获取UDP连接表
fn get_udp_connections() -> Vec<ConnectionInfo> {
    let mut result = Vec::new();
    unsafe {
        let mut table_size: u32 = 0;
        let mut ret = GetExtendedUdpTable(
            Some(ptr::null_mut()),
            &mut table_size,
            true,
            2, // AF_INET (IPv4)
            UDP_TABLE_OWNER_PID_ALL,
            0,
        );

        if table_size == 0 {
            return result;
        }

        let mut buffer = vec![0u8; table_size as usize];
        ret = GetExtendedUdpTable(
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut table_size,
            true,
            2, // AF_INET (IPv4)
            UDP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != 0 {
            return result;
        }

        let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let num_entries = table.dwNumEntries;
        let table_ptr = buffer.as_ptr().add(mem::size_of::<u32>()) as *const MIB_UDPROW_OWNER_PID;

        for i in 0..num_entries {
            let entry = &*table_ptr.add(i as usize);
            let local_ip = Ipv4Addr::from(entry.local_addr.to_be());

            // 端口是以网络字节序存储的，需要转换
            let local_port = ((entry.local_port & 0xFF) << 8) | ((entry.local_port >> 8) & 0xFF);

            let process_name = get_process_name(entry.owning_pid);

            result.push(ConnectionInfo {
                protocol: "UDP".to_string(),
                local_addr: local_ip.to_string(),
                local_port: local_port as u16,
                remote_addr: None,
                remote_port: None,
                process_id: Some(entry.owning_pid),
                process_name,
                state: None,
            });
        }
    }
    result
}

// 使用WinDivert捕获和分析网络包
fn monitor_network_with_windivert() {
    println!("开始监控网络连接...");

    // 创建WinDivert过滤器字符串: 捕获所有TCP和UDP流量
    let filter = CString::new("tcp or udp").unwrap();

    unsafe {
        // 打开WinDivert句柄
        let handle = WinDivertOpen(
            filter.as_ptr(),
            WINDIVERT_LAYER_NETWORK,
            0,
            WINDIVERT_FLAG_SNIFF,
        );
        if handle.is_null() {
            eprintln!("无法打开WinDivert句柄，请确保以管理员权限运行且安装了WinDivert库");
            return;
        }

        println!("WinDivert已启动，正在捕获数据包...");

        // 分配数据包缓冲区
        let mut packet_buffer = vec![0u8; 65536];
        let mut addr: WinDivertAddress = mem::zeroed();
        let mut packet_len: u32 = 0;

        // 解析数据包所需的指针
        let mut ip_header: *mut windivert_iphdr = ptr::null_mut();
        let mut ipv6_header: *mut windivert_ipv6hdr = ptr::null_mut();
        let mut icmp_header: *mut c_void = ptr::null_mut();
        let mut icmpv6_header: *mut c_void = ptr::null_mut();
        let mut tcp_header: *mut windivert_tcphdr = ptr::null_mut();
        let mut udp_header: *mut windivert_udphdr = ptr::null_mut();
        let mut data: *mut u8 = ptr::null_mut();
        let mut data_len: u32 = 0;

        // 持续捕获数据包
        while WinDivertRecv(
            handle,
            packet_buffer.as_mut_ptr(),
            packet_buffer.len() as u32,
            &mut addr,
            &mut packet_len,
        ) {
            // 解析数据包
            if !WinDivertHelperParsePacket(
                packet_buffer.as_ptr(),
                packet_len,
                &mut ip_header, // IPv4 头部
                &mut ipv6_header, // IPv6 头部
                &mut icmp_header,
                &mut icmpv6_header,
                &mut tcp_header,
                &mut udp_header,
                &mut data,
                &mut data_len,
            ) {
                continue;
            }

            // 处理IPv4数据包
            if !ip_header.is_null() {
                let ip = &*ip_header;
                let src_ip = Ipv4Addr::from(u32::from_be(ip.SrcAddr));
                let dst_ip = Ipv4Addr::from(u32::from_be(ip.DstAddr));
                println!("ip.Protocol => {}", ip.Protocol);
                // 处理TCP数据包
                if !tcp_header.is_null() {
                    let tcp = &*tcp_header;
                    let src_port = ntohs(tcp.SrcPort);
                    let dst_port = ntohs(tcp.DstPort);

                    println!("TCP: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
                // 处理UDP数据包
                else if !udp_header.is_null() {
                    let udp = &*udp_header;
                    let src_port = ntohs(udp.SrcPort);
                    let dst_port = ntohs(udp.DstPort);

                    println!("UDP: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
            }
            // 处理IPv6数据包
            else if !ipv6_header.is_null() {
                let ip6 = &*ipv6_header;
                let src_ip = Ipv6Addr::from(to_ipv6_addr(&ip6.SrcAddr));
                let dst_ip = Ipv6Addr::from(to_ipv6_addr(&ip6.DstAddr));

                // 处理TCP数据包
                if !tcp_header.is_null() {
                    let tcp = &*tcp_header;
                    let src_port = ntohs(tcp.SrcPort);
                    let dst_port = ntohs(tcp.DstPort);

                    println!("TCP6: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
                // 处理UDP数据包
                else if !udp_header.is_null() {
                    let udp = &*udp_header;
                    let src_port = ntohs(udp.SrcPort);
                    let dst_port = ntohs(udp.DstPort);

                    println!("UDP6: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
            }

            // 休眠一小段时间，避免CPU使用率过高
            std::thread::sleep(Duration::from_millis(10));
        }

        // 关闭WinDivert句柄
        WinDivertClose(handle);
    }
}

// 辅助函数：将IPv6地址字节数组转换为[u16; 8]格式
fn to_ipv6_addr(bytes: &[u8; 16]) -> [u16; 8] {
    let mut addr = [0u16; 8];
    for i in 0..8 {
        addr[i] = ((bytes[i * 2] as u16) << 8) | (bytes[i * 2 + 1] as u16);
    }
    addr
}

// 获取并显示所有网络连接信息
pub fn display_all_connections() {
    println!("正在获取系统网络连接信息...\n");

    // 获取TCP连接
    let tcp_connections = get_tcp_connections();
    println!("TCP连接 ({}个):", tcp_connections.len());
    println!(
        "{:<5} {:<15} {:<8} {:<15} {:<8} {:<15} {:<20}",
        "协议", "本地IP", "本地端口", "远程IP", "远程端口", "进程ID", "进程名"
    );
    println!("{:-<90}", "");

    for conn in tcp_connections {
        println!(
            "{:<5} {:<15} {:<8} {:<15} {:<8} {:<15} {:<20}",
            conn.protocol,
            conn.local_addr,
            conn.local_port,
            conn.remote_addr.unwrap_or_default(),
            conn.remote_port.unwrap_or_default(),
            conn.process_id.unwrap_or_default(),
            conn.process_name.unwrap_or_default()
        );
    }

    println!("\n");

    // 获取UDP连接
    let udp_connections = get_udp_connections();
    println!("UDP连接 ({}个):", udp_connections.len());
    println!(
        "{:<5} {:<15} {:<8} {:<15} {:<20}",
        "协议", "本地IP", "本地端口", "进程ID", "进程名"
    );
    println!("{:-<70}", "");

    for conn in udp_connections {
        println!(
            "{:<5} {:<15} {:<8} {:<15} {:<20}",
            conn.protocol,
            conn.local_addr,
            conn.local_port,
            conn.process_id.unwrap_or_default(),
            conn.process_name.unwrap_or_default()
        );
    }
}

fn main() {
    println!("网络连接监控工具");
    println!("=================");
    println!("1. 显示当前系统所有网络连接");
    println!("2. 使用WinDivert实时监控网络数据包");
    println!("请选择功能 (1-2): ");

    let mut choice = String::new();
    std::io::stdin()
        .read_line(&mut choice)
        .expect("无法读取输入");

    match choice.trim() {
        "1" => display_all_connections(),
        "2" => monitor_network_with_windivert(),
        _ => println!("无效选择"),
    }
}
