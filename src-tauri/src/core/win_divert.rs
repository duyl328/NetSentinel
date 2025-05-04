//! WinDivert 网络监控工具
//! 用于捕获和分析 Windows 系统上的网络流量

use std::ffi::{c_void, CStr, CString};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::Duration;
use windows::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, TCP_TABLE_CLASS, UDP_TABLE_CLASS,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;

/// WinDivert 数据包地址信息
#[derive(Debug)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertAddress {
    /// 数据包捕获的时间戳(微秒)
    pub timestamp: i64,
    /// 捕获层级(0:网络层, 1:网络转发层)
    pub layer: u8,
    /// 事件类型(0:出站, 1:入站)
    pub event: u8,
    /// 是否为嗅探模式(0:否, 1:是)
    pub is_sniffed: u8,
    /// 数据流向(0:入站, 1:出站)
    pub is_outbound: u8,
    /// IP校验和状态(0:无效, 1:有效)
    pub ip_checksum_valid: u8,
    /// TCP校验和状态(0:无效/不适用, 1:有效)
    pub tcp_checksum_valid: u8,
    /// UDP校验和状态(0:无效/不适用, 1:有效)
    pub udp_checksum_valid: u8,
    /// 保留字段1
    pub reserved1: u8,
    /// 保留字段2
    pub reserved2: u32,
    /// IP版本标志(0:IPv4, 1:IPv6)
    pub is_ipv6: u32,
    /// 网络接口信息
    pub network: WinDivertNetworkData,
}

/// 网络接口数据
#[derive(Debug)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertNetworkData {
    /// 网络接口索引
    pub interface_index: u32,
    /// 子接口索引
    pub sub_interface_index: u32,
}

/// IP协议类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpProtocol {
    /// ICMP协议
    Icmp = 1,
    /// TCP协议
    Tcp = 6,
    /// UDP协议
    Udp = 17,
    /// GRE协议
    Gre = 47,
    /// ESP协议
    Esp = 50,
    /// AH协议
    Ah = 51,
    /// ICMPv6协议
    Icmpv6 = 58,
    /// 未知协议
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            47 => IpProtocol::Gre,
            50 => IpProtocol::Esp,
            51 => IpProtocol::Ah,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Unknown(other),
        }
    }
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            IpProtocol::Icmp => "ICMP",
            IpProtocol::Tcp => "TCP",
            IpProtocol::Udp => "UDP",
            IpProtocol::Gre => "GRE",
            IpProtocol::Esp => "ESP",
            IpProtocol::Ah => "AH",
            IpProtocol::Icmpv6 => "ICMPv6",
            IpProtocol::Unknown(code) => return write!(f, "Unknown({})", code),
        };
        write!(f, "{}", s)
    }
}

/// IPv4头部结构
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertIpHdr {
    /// 头部长度(4位)和版本号(4位)
    pub header_length: u8,
    /// IP版本号
    pub version: u8,
    /// 服务类型
    pub tos: u8,
    /// 总长度
    pub length: u16,
    /// 标识符
    pub id: u16,
    /// 分片偏移
    pub frag_off: u16,
    /// 生存时间
    pub ttl: u8,
    /// 上层协议
    pub protocol: u8,
    /// 头部校验和
    pub checksum: u16,
    /// 源IP地址
    pub src_addr: u32,
    /// 目标IP地址
    pub dst_addr: u32,
}

/// IPv6头部结构
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertIpv6Hdr {
    /// 通信类别
    pub traffic_class: u8,
    /// IP版本号
    pub version: u8,
    /// 流标签
    pub flow_label: u32,
    /// 负载长度
    pub length: u16,
    /// 下一个头部
    pub next_header: u8,
    /// 跳数限制
    pub hop_limit: u8,
    /// 源IPv6地址
    pub src_addr: [u8; 16],
    /// 目标IPv6地址
    pub dst_addr: [u8; 16],
}

/// TCP头部结构
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertTcpHdr {
    /// 源端口
    pub src_port: u16,
    /// 目标端口
    pub dst_port: u16,
    /// 序列号
    pub seq_num: u32,
    /// 确认号
    pub ack_num: u32,
    /// 保留字段1
    pub reserved1: u8,
    /// 保留字段2
    pub reserved2: u8,
    /// 窗口大小
    pub window: u16,
    /// 校验和
    pub checksum: u16,
    /// 紧急指针
    pub urg_ptr: u16,
}

/// UDP头部结构
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertUdpHdr {
    /// 源端口
    pub src_port: u16,
    /// 目标端口
    pub dst_port: u16,
    /// 数据长度
    pub length: u16,
    /// 校验和
    pub checksum: u16,
}

#[link(name = "WinDivert")]
extern "C" {
    /// 打开一个WinDivert捕获句柄
    ///
    /// # 参数
    /// * `filter` - 过滤器字符串,用于指定要捕获的数据包类型
    ///   例如:"tcp"只捕获TCP包,"udp"只捕获UDP包,"tcp.DstPort == 80"捕获目标端口为80的TCP包
    /// * `layer` - 捕获层级:
    ///   - 0: WINDIVERT_LAYER_NETWORK (网络层)
    ///   - 1: WINDIVERT_LAYER_FORWARD (转发层)
    /// * `priority` - 过滤器优先级(-30000到30000),数值越大优先级越高
    /// * `flags` - 捕获标志位组合:
    ///   - 0: 默认模式
    ///   - 1: WINDIVERT_FLAG_SNIFF (嗅探模式,只复制数据包不修改)
    ///   - 2: WINDIVERT_FLAG_DROP (丢弃模式,丢弃匹配的数据包)
    ///   - 4: WINDIVERT_FLAG_NO_CHECKSUM (不验证校验和)
    ///
    /// # 返回值
    /// * 成功返回句柄指针
    /// * 失败返回NULL
    fn WinDivertOpen(filter: *const i8, layer: u8, priority: i16, flags: u64) -> *mut c_void;

    /// 关闭WinDivert句柄
    ///
    /// # 参数
    /// * `handle` - 由WinDivertOpen返回的句柄
    ///
    /// # 返回值
    /// * true: 关闭成功
    /// * false: 关闭失败
    fn WinDivertClose(handle: *mut c_void) -> bool;

    /// 接收数据包
    ///
    /// # 参数
    /// * `handle` - WinDivert句柄
    /// * `pPacket` - 接收数据包的缓冲区
    /// * `packetLen` - 缓冲区大小
    /// * `pAddr` - 接收数据包的元信息(时间戳、方向等)
    /// * `readLen` - 实际接收到的数据长度
    ///
    /// # 返回值
    /// * true: 接收成功
    /// * false: 接收失败
    fn WinDivertRecv(
        handle: *mut c_void,
        pPacket: *mut u8,
        packetLen: u32,
        pAddr: *mut WinDivertAddress,
        readLen: *mut u32,
    ) -> bool;

    /// 解析数据包内容,提取各层协议头部信息
    ///
    /// # 参数
    /// * `pPacket` - 要解析的数据包内容
    /// * `packetLen` - 数据包长度
    /// * `ppIpHdr` - 接收IPv4头部信息的指针
    /// * `ppIpv6Hdr` - 接收IPv6头部信息的指针
    /// * `ppIcmpHdr` - 接收ICMP头部信息的指针
    /// * `ppIcmpv6Hdr` - 接收ICMPv6头部信息的指针
    /// * `ppTcpHdr` - 接收TCP头部信息的指针
    /// * `ppUdpHdr` - 接收UDP头部信息的指针
    /// * `ppData` - 接收数据负载的指针
    /// * `pDataLen` - 数据负载长度
    ///
    /// # 返回值
    /// * true: 解析成功
    /// * false: 解析失败
    ///
    /// # 说明
    /// * 如果数据包不包含某层协议,对应的指针会被设置为NULL
    /// * 所有输出参数都是可选的,不需要的可以传NULL
    fn WinDivertHelperParsePacket(
        pPacket: *const u8,
        packetLen: u32,
        ppIpHdr: *mut *mut WinDivertIpHdr,
        ppIpv6Hdr: *mut *mut WinDivertIpv6Hdr,
        ppIcmpHdr: *mut *mut c_void,
        ppIcmpv6Hdr: *mut *mut c_void,
        ppTcpHdr: *mut *mut WinDivertTcpHdr,
        ppUdpHdr: *mut *mut WinDivertUdpHdr,
        ppData: *mut *mut u8,
        pDataLen: *mut u32,
    ) -> bool;
}

// 网络层常量
/// 网络层标识
const WINDIVERT_LAYER_NETWORK: u8 = 0;
/// 嗅探模式标志
const WINDIVERT_FLAG_SNIFF: u64 = 1;
/// 丢弃数据包标志
const WINDIVERT_FLAG_DROP: u64 = 2;

// TCP/UDP表类型常量
/// TCP连接表类型(包含PID)
const TCP_TABLE_OWNER_PID_ALL: TCP_TABLE_CLASS = TCP_TABLE_CLASS(5);
/// UDP连接表类型(包含PID)
const UDP_TABLE_OWNER_PID_ALL: UDP_TABLE_CLASS = UDP_TABLE_CLASS(1);

/// TCP连接表结构
#[repr(C)]
struct TcpTableOwnerPid {
    /// 条目数量
    entry_count: u32,
    /// 连接记录表
    table: [TcpRowOwnerPid; 1],
}

/// TCP连接记录结构
#[repr(C)]
struct TcpRowOwnerPid {
    /// 连接状态
    state: u32,
    /// 本地IP地址
    local_addr: u32,
    /// 本地端口
    local_port: u32,
    /// 远程IP地址
    remote_addr: u32,
    /// 远程端口
    remote_port: u32,
    /// 所属进程ID
    owning_pid: u32,
}

/// UDP连接表结构
#[repr(C)]
struct UdpTableOwnerPid {
    /// 条目数量
    entry_count: u32,
    /// 连接记录表
    table: [UdpRowOwnerPid; 1],
}

/// UDP连接记录结构
#[repr(C)]
struct UdpRowOwnerPid {
    /// 本地IP地址
    local_addr: u32,
    /// 本地端口
    local_port: u32,
    /// 所属进程ID
    owning_pid: u32,
}

/// TCP IPv6连接记录结构
#[repr(C)]
struct Tcp6RowOwnerPid {
    /// 本地IPv6地址
    local_addr: [u8; 16],
    /// 本地作用域ID
    local_scope_id: u32,
    /// 本地端口
    local_port: u32,
    /// 远程IPv6地址
    remote_addr: [u8; 16],
    /// 远程作用域ID
    remote_scope_id: u32,
    /// 远程端口
    remote_port: u32,
    /// 连接状态
    state: u32,
    /// 所属进程ID
    owning_pid: u32,
}

/// UDP IPv6连接记录结构
#[repr(C)]
struct Udp6RowOwnerPid {
    /// 本地IPv6地址
    local_addr: [u8; 16],
    /// 本地作用域ID
    local_scope_id: u32,
    /// 本地端口
    local_port: u32,
    /// 所属进程ID
    owning_pid: u32,
}

/// 网络连接信息结构
#[derive(Debug)]
struct ConnectionInfo {
    /// 协议类型
    protocol: String,
    /// 本地IP地址
    local_addr: String,
    /// 本地端口号
    local_port: u16,
    /// 远程IP地址(可选)
    remote_addr: Option<String>,
    /// 远程端口号(可选)
    remote_port: Option<u16>,
    /// 进程ID(可选)
    process_id: Option<u32>,
    /// 进程名称(可选)
    process_name: Option<String>,
    /// 连接状态(可选)
    state: Option<String>,
}

/// 将网络字节序转换为主机字节序
fn ntohs(netshort: u16) -> u16 {
    ((netshort & 0xff) << 8) | ((netshort >> 8) & 0xff)
}

/// 获取进程名称
fn get_process_name(pid: u32) -> Option<String> {
    unsafe {
        // 打开进程句柄
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

/// 获取TCP连接列表
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

        let table = &*(buffer.as_ptr() as *const TcpTableOwnerPid);
        let num_entries = table.entry_count;
        let table_ptr = buffer.as_ptr().add(mem::size_of::<u32>()) as *const TcpRowOwnerPid;

        for i in 0..num_entries {
            let entry = &*table_ptr.add(i as usize);
            let local_ip = Ipv4Addr::from(entry.local_addr.to_be());
            let remote_ip = Ipv4Addr::from(entry.remote_addr.to_be());

            // 端口转换(网络字节序到主机字节序)
            let local_port = ((entry.local_port & 0xFF) << 8) | ((entry.local_port >> 8) & 0xFF);
            let remote_port = ((entry.remote_port & 0xFF) << 8) | ((entry.remote_port >> 8) & 0xFF);

            let state = match entry.state {
                1 => "CLOSED".to_string(),
                2 => "LISTENING".to_string(),
                3 => "SYN_SENT".to_string(),
                4 => "SYN_RCVD".to_string(),
                5 => "ESTABLISHED".to_string(),
                6 => "FIN_WAIT1".to_string(),
                7 => "FIN_WAIT2".to_string(),
                8 => "CLOSE_WAIT".to_string(),
                9 => "CLOSING".to_string(),
                10 => "LAST_ACK".to_string(),
                11 => "TIME_WAIT".to_string(),
                12 => "DELETE_TCB".to_string(),
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

/// 获取UDP连接列表
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

        let table = &*(buffer.as_ptr() as *const UdpTableOwnerPid);
        let num_entries = table.entry_count;
        let table_ptr = buffer.as_ptr().add(mem::size_of::<u32>()) as *const UdpRowOwnerPid;

        for i in 0..num_entries {
            let entry = &*table_ptr.add(i as usize);
            let local_ip = Ipv4Addr::from(entry.local_addr.to_be());

            // 端口转换(网络字节序到主机字节序)
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

/// 使用WinDivert监控网络数据包
pub(crate) fn monitor_network_with_windivert() {
    println!("开始监控网络连接...");

    // 创建WinDivert过滤器
    // let filter = CString::new("tcp or udp").unwrap();
    let filter = CString::new("true").unwrap();  // 捕获所有数据包用于调试
    let filter_ptr = filter.as_ptr(); // 保存指针

    unsafe {
        // 打开WinDivert句柄
        let handle = WinDivertOpen(
            filter_ptr,
            WINDIVERT_LAYER_NETWORK,
            0,
            WINDIVERT_FLAG_SNIFF,
        );

        // 正确检查句柄是否有效
        // INVALID_HANDLE_VALUE 在Windows上是 -1 (0xffffffffffffffff)
        if handle == -1isize as *mut c_void {
            let error_code = GetLastError();
            println!("无法打开WinDivert句柄，错误码: {}，请确保以管理员权限运行且安装了WinDivert库", error_code.0);
            return;
        }

        println!("WinDivert句柄已成功打开: {:?}", handle);

        println!("WinDivert已启动，正在捕获数据包...");

        // 分配数据包缓冲区
        let mut packet_buffer = vec![0u8; 65536];
        let mut addr: WinDivertAddress = mem::zeroed();
        let mut packet_len: u32 = 0;

        // 解析数据包所需的指针
        let mut ip_header: *mut WinDivertIpHdr = ptr::null_mut();
        let mut ipv6_header: *mut WinDivertIpv6Hdr = ptr::null_mut();
        let mut icmp_header: *mut c_void = ptr::null_mut();
        let mut icmpv6_header: *mut c_void = ptr::null_mut();
        let mut tcp_header: *mut WinDivertTcpHdr = ptr::null_mut();
        let mut udp_header: *mut WinDivertUdpHdr = ptr::null_mut();
        let mut data: *mut u8 = ptr::null_mut();
        let mut data_len: u32 = 0;

        // 持续捕获数据包
        loop {
            // 捕获数据包
            let recv_result = WinDivertRecv(
                handle,
                packet_buffer.as_mut_ptr(),
                packet_buffer.len() as u32,
                &mut addr,
                &mut packet_len,
            );

            // 检查接收结果
            if recv_result {
                let error = GetLastError();
                println!("数据包接收失败，错误码: {}", error.0);
                // 可能需要根据错误码进行特定处理
                if error.0 == 6 { // ERROR_INVALID_HANDLE
                    println!("无效句柄，退出循环");
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            // 解析数据包
            if !WinDivertHelperParsePacket(
                packet_buffer.as_ptr(),
                packet_len,
                &mut ip_header,
                &mut ipv6_header,
                &mut icmp_header,
                &mut icmpv6_header,
                &mut tcp_header,
                &mut udp_header,
                &mut data,
                &mut data_len,
            ) {
                println!("解析数据包失败");
                continue;
            }

            // 处理IPv4数据包
            if !ip_header.is_null() {
                let ip = &*ip_header;
                let src_ip = Ipv4Addr::from(u32::from_be(ip.src_addr));
                let dst_ip = Ipv4Addr::from(u32::from_be(ip.dst_addr));
                println!("IP协议 => : {}", ip.protocol);

                // 处理TCP数据包
                if !tcp_header.is_null() {
                    let tcp = &*tcp_header;
                    let src_port = ntohs(tcp.src_port);
                    let dst_port = ntohs(tcp.dst_port);

                    println!("TCP: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
                // 处理UDP数据包
                else if !udp_header.is_null() {
                    let udp = &*udp_header;
                    let src_port = ntohs(udp.src_port);
                    let dst_port = ntohs(udp.dst_port);

                    println!("UDP: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
            }
            // 处理IPv6数据包
            else if !ipv6_header.is_null() {
                let ip6 = &*ipv6_header;
                let src_ip = Ipv6Addr::from(to_ipv6_addr(&ip6.src_addr));
                let dst_ip = Ipv6Addr::from(to_ipv6_addr(&ip6.dst_addr));

                // 处理TCP数据包
                if !tcp_header.is_null() {
                    let tcp = &*tcp_header;
                    let src_port = ntohs(tcp.src_port);
                    let dst_port = ntohs(tcp.dst_port);

                    println!("TCP6: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
                // 处理UDP数据包
                else if !udp_header.is_null() {
                    let udp = &*udp_header;
                    let src_port = ntohs(udp.src_port);
                    let dst_port = ntohs(udp.dst_port);

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
/// 将IPv6地址字节数组转换为[u16; 8]格式
fn to_ipv6_addr(bytes: &[u8; 16]) -> [u16; 8] {
    let mut addr = [0u16; 8];
    for i in 0..8 {
        addr[i] = ((bytes[i * 2] as u16) << 8) | (bytes[i * 2 + 1] as u16);
    }
    addr
}

/// 显示所有网络连接信息
pub fn display_all_connections() {
    //println!("正在获取系统网络连接信息...\n");

    // 获取TCP连接
    let tcp_connections = get_tcp_connections();
    //println!("TCP连接 ({}个):", tcp_connections.len());
    // println!(
    //     "{:<5} {:<15} {:<8} {:<15} {:<8} {:<15} {:<20}",
    //     "协议", "本地IP", "本地端口", "远程IP", "远程端口", "进程ID", "进程名"
    // );
    //println!("{:-<90}", "");

    for conn in tcp_connections {
        // println!(
        //     "{:<5} {:<15} {:<8} {:<15} {:<8} {:<15} {:<20}",
        //     conn.protocol,
        //     conn.local_addr,
        //     conn.local_port,
        //     conn.remote_addr.unwrap_or_default(),
        //     conn.remote_port.unwrap_or_default(),
        //     conn.process_id.unwrap_or_default(),
        //     conn.process_name.unwrap_or_default()
        // );
    }

    //println!("\n");

    // 获取UDP连接
    let udp_connections = get_udp_connections();
    //println!("UDP连接 ({}个):", udp_connections.len());
    // println!(
    //     "{:<5} {:<15} {:<8} {:<15} {:<20}",
    //     "协议", "本地IP", "本地端口", "进程ID", "进程名"
    // );
    //println!("{:-<70}", "");

    for conn in udp_connections {
        // println!(
        //     "{:<5} {:<15} {:<8} {:<15} {:<20}",
        //     conn.protocol,
        //     conn.local_addr,
        //     conn.local_port,
        //     conn.process_id.unwrap_or_default(),
        //     conn.process_name.unwrap_or_default()
        // );
    }
}

/// 主函数
fn main() {
    //println!("网络连接监控工具");
    //println!("=================");
    //println!("1. 显示当前系统所有网络连接");
    //println!("2. 使用WinDivert实时监控网络数据包");
    //println!("请选择功能 (1-2): ");

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
