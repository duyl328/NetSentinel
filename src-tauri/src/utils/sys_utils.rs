use std::env;
use std::path::PathBuf;
fn detect_arch() {
    // unsafe {
    //     let mut info: SYSTEM_INFO = std::mem::zeroed();
    //     GetNativeSystemInfo(&mut info);
    //
    //     match info.wProcessorArchitecture {
    //         9 => println!("x64"),
    //         0 => println!("x86"),
    //         _ => println!("Other arch: {}", info.wProcessorArchitecture),
    //     }
    // }
}
/// 检查是否是管理员权限
#[cfg(target_os = "windows")]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::*;
    use windows::Win32::System::Threading::*;
    use windows::Win32::Security::Authorization::*;
    use windows::Win32::Security::*;
    use core::ffi::c_void;

    unsafe {
        let mut token = HANDLE::default();

        // 使用 is_ok() 检查 Result
        if !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        // 使用 is_ok() 检查 Result
        if !GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            size,
            &mut size,
        ).is_ok()
        {
            CloseHandle(token);
            return false;
        }

        CloseHandle(token);
        elevation.TokenIsElevated != 0
    }
}

/// 获取程序所在目录
pub fn get_exe_directory() -> Option<PathBuf> {
    env::current_exe().ok().and_then(|path| path.parent().map(|p| p.to_path_buf()))
}
