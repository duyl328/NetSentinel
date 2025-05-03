use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};

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
