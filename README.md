
A traffic sniffer similar to tcpdump built using the Rust language.

<b>THIS PROJECT IS A WORK IN PROGRESS!</b>

I am working on this project to further my knowledge in the Rust language, so it may contain bugs or inefficiencies.

To compile:


* Download rust-nightly for your operating system from https://www.rust-lang.org/install.html. YOU MUST USE RUST-NIGHTLY.
* Run with

```
cargo run {network interface}
```


You can create a release build with
```
cargo build --release
```

<br>
License notes:<br>
<b>THIS PROJECT IS NOT ENDORSED BY OR AFFILIATED WITH TCPDUMP, LIBPNET, OR RUST.</b>

<br><br>
Technical notes:

This project uses the following crates:

Crate  | Version
------------- | -------------
libpnet  | 0.1.1
rustc-serialize  | 0.3

libpnet provides the capability to sniff packets directly off of the wire. Per libpnet, "libpnet provides a cross-platform API for low level networking using Rust."

Data is read directly off of the wire and then shown with an offset in both hexadecimal and UTF-8 (if it is valid). I plan to add more features that tcpudmp and similar programs have in the near future.
