use std::env;
use std::error::Error;
use std::fs;

pub struct Config {
    pub filename: String,
}

impl Config {
    pub fn new(mut args: env::Args) -> Result<Config, &'static str> {
        args.next(); // ignores application name

        let filename = match args.next() {
            Some(filename) => filename,
            None => return Err("No filename has been provided"),
        };

        Ok(Config { filename })
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let content_bytes = fs::read(config.filename)?;

    let hash = sha_256_scratch::sha_256(content_bytes);
    println!("{hash}");

    Ok(())
}
