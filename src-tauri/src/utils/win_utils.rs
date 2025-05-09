use std::ffi::{c_void, CStr};
use std::net::Ipv4Addr;
use std::{mem, ptr};
use windows::core::{PSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_CLASS, UDP_TABLE_CLASS,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;
use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameA, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ};

// TCP/UDP表类型常量
/// TCP连接表类型(包含PID)
const TCP_TABLE_OWNER_PID_ALL: TCP_TABLE_CLASS = TCP_TABLE_CLASS(5);
/// UDP连接表类型(包含PID)
const UDP_TABLE_OWNER_PID_ALL: UDP_TABLE_CLASS = UDP_TABLE_CLASS(1);

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

/// UDP连接表结构
#[repr(C)]
struct UdpTableOwnerPid {
    /// 条目数量
    entry_count: u32,
    /// 连接记录表
    table: [UdpRowOwnerPid; 1],
}

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

/// 网络连接信息结构
#[derive(Debug)]
pub(crate) struct ConnectionInfo {
    /// 协议类型
    pub(crate) protocol: String,
    /// 本地IP地址
    pub(crate) local_addr: String,
    /// 本地端口号
    pub(crate) local_port: u16,
    /// 远程IP地址(可选)
    pub(crate) remote_addr: Option<String>,
    /// 远程端口号(可选)
    pub(crate) remote_port: Option<u16>,
    /// 进程ID(可选)
    pub(crate) process_id: Option<u32>,
    /// 进程名称(可选)
    pub(crate) process_name: Option<String>,
    /// 连接状态(可选)
    pub(crate) state: Option<String>,
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
pub(crate) fn get_tcp_connections() -> Vec<ConnectionInfo> {
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

            let file_path = get_process_path(entry.owning_pid);
            // let company_name = get_company_name(entry.owning_pid);
            let result2 = file_path.unwrap_or("".to_string());

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
/*
为什么 GetExtendedUdpTable 要调用两次？
Windows 的很多 API（包括 GetExtendedUdpTable）要求你传入一个缓冲区，它会将数据写入这个缓冲区中。但问题是：
第一次你不知道缓冲区应该有多大；
所以第一次传一个空指针（null_mut()）和 0 作为大小，它会返回所需的缓冲区大小到 table_size；
然后你用这个大小重新分配缓冲区，再调用一次来真正获取数据。
这是标准的“预检大小 -> 分配 -> 再调一次”的模式。

*/
/// 获取UDP连接列表
pub(crate) fn get_udp_connections() -> Vec<ConnectionInfo> {
    let mut result = Vec::new();
    unsafe {
        let mut table_size: u32 = 0;
        let mut ret = GetExtendedUdpTable(
            None,
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
            // let local_port = ((entry.local_port & 0xFF) << 8) | ((entry.local_port >> 8) & 0xFF);
            let local_port = u16::from_be(entry.local_port as u16);

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



// fn get_process_path(pid: u32) -> Option<String> {
//     unsafe {
//         // 打开进程
//         let process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
//         let mut buffer = [0u8; 260]; // MAX_PATH
//         let result = GetModuleFileNameExA(Some(process_handle), None, &mut buffer);
//         if result == 0 {
//             return None;
//         }
//
//         let mut length: u32 = 0;
//         let format = PROCESS_NAME_FORMAT::default();
//         PSTR::from_raw(buffer);
//         // 获取进程路径
//         let result = QueryFullProcessImageNameA(process, format, &mut buffer, &mut length);
//
//         if result == ERROR_SUCCESS {
//             // 将获取的路径转换为 UTF-8 字符串
//             let path = String::from_utf8_lossy(&buffer[..length as usize]);
//             Some(path.to_string())
//         } else {
//             None
//         }
//     }
// }

/// 获取完整路径
fn get_process_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        if handle.is_invalid() {
            return None;
        }

        let mut buffer = vec![0u16; 260];
        let mut size = buffer.len() as u32;

        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),               // 正确传入 enum 类型
            PWSTR(buffer.as_mut_ptr()),           // 正确传入 UTF-16 指针
            &mut size,
        );

        CloseHandle(handle); // 提前释放句柄

        if result.is_ok() {
            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        } else {
            None
        }
    }
}


// 获取公司名称
// fn get_company_name(file_path: &str) -> Option<String> {
//     let wide_path: Vec<u16> = file_path.encode_utf16().chain(Some(0)).collect();
//     unsafe {
//         let mut handle = 0u32;
//         let size = windows::Win32::Storage::FileSystem::GetFileVersionInfoSizeW(&wide_path, Some(&mut handle));
//         if size == 0 {
//             return None;
//         }
//
//         let mut buffer = vec![0u8; size as usize];
//         let result = windows::Win32::Storage::FileSystem::GetFileVersionInfoW(&wide_path, Some(0), size, buffer.as_mut_ptr() as *mut _);
//
//         let mut lp_buffer: *mut std::ffi::c_void = std::ptr::null_mut();
//         let mut len = 0u32;
//
//         let query = "\\StringFileInfo\\040904b0\\CompanyName";
//         let query: Vec<u16> = query.encode_utf16().chain(Some(0)).collect();
//
//         if windows::Win32::Storage::FileSystem::VerQueryValueW(
//             buffer.as_ptr() as *const _,
//             &query,
//             &mut lp_buffer,
//             &mut len,
//         )
//             .as_bool()
//         {
//             let str_ptr = lp_buffer as *const u16;
//             let slice = std::slice::from_raw_parts(str_ptr, len as usize);
//             return Some(String::from_utf16_lossy(slice));
//         }
//         None
//
//         // if result.is_ok() {
//         //     Some(String::from_utf16_lossy(&buffer[..size as usize]))
//         // } else {
//         //     None
//         // }
//     }
// }
