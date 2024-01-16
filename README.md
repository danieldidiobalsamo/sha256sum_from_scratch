# About

Rust SHA-256 hash function from scratch implementation that can be called from CLI.
Hash implementation and CLI are two separated crates.

# How to launch (recommended)

Install [Rust](https://www.rust-lang.org/tools/install) and launch:
~~~
cargo install sha256sum_from_scratch
sha256sum_from_scratch <FILE_PATH>
~~~

# Build manually

~~~
cargo run --release sha_256_scratch/sample_files_for_testing/sample.pdf
~~~