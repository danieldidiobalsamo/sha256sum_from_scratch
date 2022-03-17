# About

This project consists in a from scratch implementation of sha256sum in Rust.
If you are interested in only the SHA-256 implementation without the CLI command, please check out "sha_256_scratch" crate.

# How to run

~~~
cargo run --release sha_256_scratch/sample_files_for_testing/sample.pdf
~~~

# Install the command

~~~
cargo install sha_256_from_scratch
~~~

Then you can call the command as following :
~~~
sha256sum_from_scratch file_you_want
~~~

