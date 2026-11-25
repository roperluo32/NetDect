//! Resolves an exit's public IP: `cargo run --example exit_ip -- host:port:user:pass`
use netdect_lib::{config, exits};

fn main() {
    let raw = std::env::args().nth(1).expect("usage: exit_ip host:port:user:pass");
    let (host, port, user, pass) = config::parse_exit_string(&raw).expect("bad exit string");

    let id = "netdect-example";
    config::set_password(id, &pass).expect("keyring write");
    let stored = config::get_password(id).expect("keyring read");
    assert_eq!(stored, pass);
    config::delete_password(id);
    assert!(config::get_password(id).is_none());
    println!("keyring: ok");

    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(exits::resolve(&host, port, &user, &stored)) {
        Ok(i) => println!("exit ip: {} {:?} {:?}", i.ip, i.country, i.org),
        Err(e) => println!("error: {e}"),
    }
}
