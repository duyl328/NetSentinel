mod commands;
mod constant;
mod core;
mod utils;

use std::error::Error;
use tauri::{App, Emitter, Listener, Manager, State, WindowEvent};
use tauri_plugin_log::{Target, TargetKind};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default().plugin(tauri_plugin_log::Builder::new().build());
    // 非生产环境，使用外部日志
    let log_plugin = tauri_plugin_log::Builder::new()
        // 设置文件大小
        .max_file_size(50_000)
        .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepAll)
        .level(log::LevelFilter::Trace)
        // 仅对命令模块进行动词日志
        // .level_for("commands::log_command", log::LevelFilter::Info)
        // 日志格式
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {}] - {}",
                record.level(),
                record.target(),
                message
            ))
        })
        // 使用本机时间格式化日期
        .timezone_strategy(tauri_plugin_log::TimezoneStrategy::UseLocal)
        .target(tauri_plugin_log::Target::new(
            // 将日志打印到终端
            // tauri_plugin_log::TargetKind::Stdout,
            // 记录到 webView
            // tauri_plugin_log::TargetKind::Webview,
            // tauri_plugin_log::TargetKind::LogDir {
            //     file_name: Some("logs".to_string()),
            // },
            // 写入自定义位置
            tauri_plugin_log::TargetKind::Folder {
                path: std::path::PathBuf::from(constant::LOG_PATH),
                file_name: None,
            },
        ))
        .build();
    builder = builder.plugin(log_plugin);
    println!("日志路径: {:?}", constant::LOG_PATH);

    builder
        .invoke_handler(tauri::generate_handler![
            commands::command::greet,
            commands::command::is_elevated_command,
            commands::command::get_exe_directory_command,
            commands::win_divert::win_divert_command,
            commands::win_divert::monitor_network_with_windivert_command,
            commands::win_divert::recv_packet_command,
            commands::win_divert::recv_packet_command1,
            commands::win_divert::get_all_tcp_info,
            commands::win_divert::get_more_info,
        ])
        .setup(main_setup())
        .run(tauri::generate_context!())
        .expect("启动失败!");
}

fn main_setup() -> fn(&mut App) -> Result<(), Box<dyn Error>> {
    |app| {
        log::info!(" =================== 启动成功! ===================");
        // 打开控制台
        #[cfg(debug_assertions)] // 仅在调试版本中包含此代码
        {
            let window = app.get_webview_window("main").unwrap();
            window.open_devtools();
            window.close_devtools();
        }

        Ok(())
    }
}
