#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == netdect_lib::probe::PROBE_FLAG {
        std::process::exit(netdect_lib::probe::run_probe_child(&args[2]));
    }
    netdect_lib::run();
}
