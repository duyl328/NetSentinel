//! WinDivert 网络监控工具
//! 用于捕获和分析 Windows 系统上的网络流量

use crate::utils::sys_utils;
use std::ffi::{c_char, c_uint, c_void, CStr, CString};
use std::mem;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::Duration;
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, TCP_TABLE_CLASS, UDP_TABLE_CLASS,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// WinDivert错误码
pub enum WinDivertError {
    Success = 0,              // 操作成功
    AccessDenied = 5,         // 访问被拒绝，需要管理员权限
    InvalidHandle = 6,        // 无效的句柄
    InvalidParameter = 87,    // 参数错误（如过滤器语法错误）
    InsufficientBuffer = 122, // 缓冲区太小
    MoreData = 234,           // 有更多数据可用
    NoData = 232,             // 没有可用数据
    InvalidImage = 577,       // 驱动程序文件无效或未找到
    PrivilegeNotHeld = 1314,  // 权限不足
    DeviceNotFound = 1167,    // 设备未找到
}

// Define the WINDIVERT_LAYER enum
#[repr(C)]
pub enum WinDivertLayer {
    /// 网络层标识
    WinDivertLayerNetwork = 0,
    WinDivertLayerNetworkForward = 1,
    WinDivertLayerFlow = 2,
    WinDivertLayerSocket = 3,
    WinDivertLayerReflect = 4,
}
/// 嗅探模式标志
pub(crate) const WINDIVERT_FLAG_SNIFF: u64 = 1;
/// 丢弃数据包标志
const WINDIVERT_FLAG_DROP: u64 = 2;

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
    pub sniffed: u8,
    /// 数据流向(0:入站, 1:出站)
    pub outbound: u8,

    pub loopback: u8,
    pub impostor: u8,
    pub ipv6: u8,
    pub ip_checksum: u8,
    pub tcp_checksum: u8,
    pub udp_checksum: u8,
    pub _reserved: [u8; 5], // 填充使结构体对齐
    /// 网络接口信息
    pub data: WinDivertNetworkData,
}
impl WinDivertAddress {
    pub fn new() -> Self {
        WinDivertAddress {
            timestamp: 0,
            layer: 0,
            event: 0,
            sniffed: 0,
            outbound: 0,
            loopback: 0,
            impostor: 0,
            ipv6: 0,
            ip_checksum: 0,
            tcp_checksum: 0,
            udp_checksum: 0,
            _reserved: [0; 5],
            data: WinDivertNetworkData::new(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WinDivertDataFlow {
    pub endpoint: u64,
    pub parent_endpoint: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
    // padding to align size to multiple of 8
    pub _padding: [u8; 5],
}
impl WinDivertDataFlow {
    pub fn new() -> Self {
        WinDivertDataFlow {
            endpoint: 0,
            parent_endpoint: 0,
            process_id: 0,
            local_addr: [0, 0, 0, 0],
            remote_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_port: 0,
            protocol: 0,
            _padding: [0, 0, 0, 0, 0],
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WinDivertDataSocket {
    pub endpoint: u64,
    pub parent_endpoint: u64,
    pub process_id: u32,
    pub local_addr: [u32; 4],
    pub remote_addr: [u32; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
    pub _padding: [u8; 5],
}
impl WinDivertDataSocket {
    pub fn new() -> Self {
        WinDivertDataSocket {
            endpoint: 0,
            parent_endpoint: 0,
            process_id: 0,
            local_addr: [0, 0, 0, 0],
            remote_addr: [0, 0, 0, 0],
            local_port: 0,
            remote_port: 0,
            protocol: 0,
            _padding: [0, 0, 0, 0, 0],
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WinDivertDataReflect {
    pub timestamp: i64,
    pub process_id: u32,
    pub layer: u32, // 将 C 的 enum WINDIVERT_LAYER 作为 u32 表示
    pub flags: u64,
    pub priority: i16,
    pub _padding: [u8; 6],
}
impl WinDivertDataReflect {
    pub fn new() -> Self {
        WinDivertDataReflect {
            timestamp: 0,
            process_id: 0,
            layer: 0,
            flags: 0,
            priority: 0,
            _padding: [0, 0, 0, 0, 0, 0],
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WinDivertDataNetwork {
    pub if_idx: u32,
    pub sub_if_idx: u32,
}
impl WinDivertDataNetwork {
    pub fn new() -> Self {
        WinDivertDataNetwork {
            if_idx: 0,
            sub_if_idx: 0,
        }
    }
}
/// 网络接口数据
#[derive(Debug)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct WinDivertNetworkData {
    pub network: WinDivertDataNetwork,
    pub flow: WinDivertDataFlow,
    pub socket: WinDivertDataSocket,
    pub reflect: WinDivertDataReflect,
}
impl WinDivertNetworkData {
    pub fn new() -> Self {
        WinDivertNetworkData {
            network: WinDivertDataNetwork::new(),
            flow: WinDivertDataFlow::new(),
            socket: WinDivertDataSocket::new(),
            reflect: WinDivertDataReflect::new(),
        }
    }
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

// TCP/UDP表类型常量
/// TCP连接表类型(包含PID)
const TCP_TABLE_OWNER_PID_ALL: TCP_TABLE_CLASS = TCP_TABLE_CLASS(5);
/// UDP连接表类型(包含PID)
const UDP_TABLE_OWNER_PID_ALL: UDP_TABLE_CLASS = UDP_TABLE_CLASS(1);

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

/// TCP连接表结构
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
    fn WinDivertOpen(
        filter: *const c_char,
        layer: WinDivertLayer,
        priority: i16,
        flags: u64,
    ) -> *mut c_void;

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
        pPacket: *mut c_void,
        packetLen: c_uint,
        readLen: *mut c_uint,
        pAddr: *mut WinDivertAddress,
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

    /// 设置WinDivert参数
    fn WinDivertSetParam(handle: *mut c_void, param: u32, value: u64) -> bool;

    /// 获取WinDivert参数
    fn WinDivertGetParam(handle: *mut c_void, param: u32, pValue: *mut u64) -> bool;
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

/// WinDivert参数常量
const WINDIVERT_PARAM_QUEUE_LENGTH: u32 = 1; // 队列长度参数
const WINDIVERT_PARAM_QUEUE_TIME: u32 = 2; // 队列时间参数
const WINDIVERT_PARAM_QUEUE_SIZE: u32 = 3; // 队列大小参数

/// 打印数据包信息的辅助函数
fn print_packet_info(packet: &[u8], len: u32, addr: &WinDivertAddress) {
    log::info!("=== 数据包信息 ===");
    log::info!("包长度: {} 字节", len);
    log::info!(
        "方向: {}",
        if addr.outbound == 1 {
            "出站"
        } else {
            "入站"
        }
    );
    log::info!("层级: {}", addr.layer);
    log::info!("事件: {}", addr.event);
    log::info!("时间戳: {}", addr.timestamp);

    // 打印前32字节的十六进制数据
    if len > 0 {
        print!("数据预览: ");
        for i in 0..std::cmp::min(32, len) {
            print!("{:02X} ", packet[i as usize]);
        }
    }
    log::info!("================");
}

/// 检查WinDivert是否正确安装
fn check_windivert_installation() -> Result<(), String> {
    let paths = ["WinDivert.dll", "WinDivert64.sys"];
    let elevated = sys_utils::get_exe_directory();
    if let Some(dir) = elevated {
        for path in paths {
            let mut buf = dir.clone();
            buf.push(path);
            log::info!("检查的路径：{}", buf.display());
            if !buf.exists() {
                return Err(format!("缺少必需文件: {}", path));
            }
        }
    } else {
        return Err("无法获取程序路径！".parse().unwrap());
    }

    Ok(())
}

/// Rust 安全打开 WinDivert 句柄的辅助函数
pub fn open_windivert(
    filter: &str,
    layer: WinDivertLayer,
    priority: i16,
    flags: u64,
) -> Result<*mut c_void, String> {
    use std::ffi::CString;

    let c_filter = CString::new(filter).map_err(|_| "无效的字符串！")?;

    unsafe {
        let handle = WinDivertOpen(c_filter.as_ptr(), layer, priority, flags);
        if handle.is_null() {
            Err("Failed to open WinDivert handle".to_string())
        } else {
            Ok(handle)
        }
    }
}

/// Rust 安全接收数据包的辅助函数
pub fn recv_packet(
    handle: *mut c_void,
    buffer: &mut [u8],
) -> Result<(usize, WinDivertAddress), String> {
    let mut addr = WinDivertAddress::new();
    let mut recv_len: u32 = 0;

    unsafe {
        let result = WinDivertRecv(
            handle,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
            &mut recv_len,
            &mut addr,
        );

        if result {
            Err("无法接收数据包!".to_string())
        } else {
            Ok((recv_len as usize, addr))
        }
    }
}

pub fn recv_packet1(
    handle: *mut c_void,
    mut buffer: Option<&mut [u8]>,
    capture_address: bool,
) -> Option<(usize, Option<WinDivertAddress>)> {
    unsafe {
        let (packet_ptr, packet_len) = match &mut buffer {
            Some(buf) => (buf.as_mut_ptr() as *mut c_void, buf.len() as u32),
            None => (ptr::null_mut(), 0),
        };
        let mut recv_len: u32 = 0;
        let recv_len_ptr = if buffer.is_some() {
            &mut recv_len as *mut u32
        } else {
            ptr::null_mut()
        };

        let mut addr_uninit = MaybeUninit::<WinDivertAddress>::uninit();
        let addr_ptr = if capture_address {
            addr_uninit.as_mut_ptr()
        } else {
            ptr::null_mut()
        };

        let result: bool = WinDivertRecv(handle, packet_ptr, packet_len, recv_len_ptr, addr_ptr);

        if result {
            return None;
        }

        let addr = if capture_address {
            Some(addr_uninit.assume_init())
        } else {
            None
        };

        Some((recv_len as usize, addr))
    }
}


/// 使用WinDivert监控网络数据包
pub fn monitor_network_with_windivert() -> Result<(), String> {
    println!("开始监控网络连接...");

    unsafe {
        let handle = open_windivert(
            "true",
            WinDivertLayer::WinDivertLayerNetwork,
            0,
            WINDIVERT_FLAG_SNIFF,
        )?;

        if handle == -1isize as *mut c_void {
            let error = GetLastError();
            return Err(match error.0 {
                5 => "访问被拒绝 - 请确保以管理员权限运行".to_string(),
                577 => "未找到WinDivert驱动 - 请确保正确安装".to_string(),
                6 => "句柄无效".to_string(),
                _ => format!("未知错误: {}", error.0),
            });
        }

        println!("WinDivert初始化成功，开始捕获数据包...");

        // 分配缓冲区
        let mut packet_buffer = vec![0u8; 65536];
        let mut addr: WinDivertAddress = mem::zeroed();
        let mut packet_len: u32 = 0;

        // 数据包解析指针
        let mut ip_header: *mut WinDivertIpHdr = ptr::null_mut();
        let mut ipv6_header: *mut WinDivertIpv6Hdr = ptr::null_mut();
        let mut icmp_header: *mut c_void = ptr::null_mut();
        let mut icmpv6_header: *mut c_void = ptr::null_mut();
        let mut tcp_header: *mut WinDivertTcpHdr = ptr::null_mut();
        let mut udp_header: *mut WinDivertUdpHdr = ptr::null_mut();
        let mut data: *mut u8 = ptr::null_mut();
        let mut data_len: u32 = 0;

        loop {
            println!("进入 loop ");
            // 接收数据包
            let recv_result = WinDivertRecv(
                handle,
                packet_buffer.as_mut_ptr() as *mut std::ffi::c_void,
                packet_buffer.len() as u32,
                &mut packet_len, // 错误 - 这应该是倒数第二个参数
                &mut addr,       // 错误 - 这应该是最后一个参数
            );
            println!("实际接收数据包长度: {}", packet_len);

            if !recv_result {
                let error = GetLastError();
                println!("接收失败，错误码: {}", error.0);
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }

            // 验证packet_len是否在有效范围内
            if packet_len as usize > packet_buffer.len() {
                println!(
                    "警告：数据包长度超出缓冲区大小: {} > {}",
                    packet_len,
                    packet_buffer.len()
                );
                continue;
            }

            // 确保我们只使用实际接收到的数据
            let actual_packet = &packet_buffer[..packet_len as usize];

            // 解析数据包
            if !WinDivertHelperParsePacket(
                actual_packet.as_ptr(),
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
                log::info!("IPV4");
                let ip = &*ip_header;
                let src_ip = Ipv4Addr::from(u32::from_be(ip.src_addr));
                let dst_ip = Ipv4Addr::from(u32::from_be(ip.dst_addr));

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
                log::info!("IPV6");
                let ip6 = &*ipv6_header;
                let src_ip = Ipv6Addr::from(to_ipv6_addr(&ip6.src_addr));
                let dst_ip = Ipv6Addr::from(to_ipv6_addr(&ip6.dst_addr));

                if !tcp_header.is_null() {
                    let tcp = &*tcp_header;
                    let src_port = ntohs(tcp.src_port);
                    let dst_port = ntohs(tcp.dst_port);
                    println!("TCP6: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                } else if !udp_header.is_null() {
                    let udp = &*udp_header;
                    let src_port = ntohs(udp.src_port);
                    let dst_port = ntohs(udp.dst_port);
                    println!("UDP6: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                }
            }

            // 添加短暂延时避免CPU占用过高
            std::thread::sleep(Duration::from_millis(100));
        }

        // 关闭WinDivert句柄
        WinDivertClose(handle);
    }

    Ok(())
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
    log::info!("正在获取系统网络连接信息...\n");

    // 获取TCP连接
    let tcp_connections = get_tcp_connections();
    log::info!("TCP连接 ({}个):", tcp_connections.len());
    log::info!(
        "{:<5} {:<15} {:<8} {:<15} {:<8} {:<15} {:<20}",
        "协议",
        "本地IP",
        "本地端口",
        "远程IP",
        "远程端口",
        "进程ID",
        "进程名"
    );
    log::info!("{:-<90}", "");

    for conn in tcp_connections {
        log::info!(
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

/// 主函数
fn main() {
    //log::info!("网络连接监控工具");
    //log::info!("=================");
    //log::info!("1. 显示当前系统所有网络连接");
    //log::info!("2. 使用WinDivert实时监控网络数据包");
    //log::info!("请选择功能 (1-2): ");

    let mut choice = String::new();
    std::io::stdin()
        .read_line(&mut choice)
        .expect("无法读取输入");

    match choice.trim() {
        "1" => display_all_connections(),
        // "2" => monitor_network_with_windivert(),
        _ => log::info!("无效选择"),
    }
}
