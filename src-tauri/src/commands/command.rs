use crate::utils::sys_utils;
use tauri_plugin_dialog::DialogExt;

#[tauri::command]
pub fn greet(name: &str) -> String {
    println!("Hello, {}!", name);
    let builder = tauri::Builder::default();
    let _res = builder.setup(|app| {
        println!("执行");
        app.dialog().message("Tauri is Awesome!").show(|_| {
            println!("dialog closed");
        });
        Ok(())
    });
    log::error!("{:?}", "你好！！！！！！！！！！！！！");
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
pub fn is_elevated_command() -> bool {
    let elevated = sys_utils::is_elevated();
    log::info!("管理员权限检查 :{}", elevated);
    elevated
}


#[tauri::command]
pub fn get_exe_directory_command() -> String {
    let elevated = sys_utils::get_exe_directory();
    log::info!("获取程序所在目录 :{:?}", elevated);
    if let Some(path) = elevated {
        let path_str = path.to_string_lossy().to_string();
        path_str
    }else{
        "".to_string()
    }
}
