use sha256sum_from_scratch::Config;
use std::env;
use std::process;

fn main() {
    let config = Config::new(env::args()).unwrap_or_else(|err| {
        eprintln!("Invalid argument: {err}");
        process::exit(1);
    });

    if let Err(err) = sha256sum_from_scratch::run(config) {
        eprintln!("error during execution:{err}");
        process::exit(1);
    }
}
