# sfw

A simple firewall for Windows, based on the WinpkFilter driver and written in Rust. Built for my Fall 2024 Internship Project and the Clemson Cyber Club. This project is designed to be a complete replacement for the Windows Firewall and surrounding APIs, and hence does not rely on anything but the WinpkFilter driver and the NDISAPI library

### Technologies
- Rust
- [windows-rs](https://github.com/microsoft/windows-rs)
- [serde-json](https://github.com/serde-rs/json)
- [smoltcp](https://github.com/smoltcp-rs/smoltcp)
- [ndisapi-rs](https://github.com/wiresock/ndisapi-rs)

### Requirements
- Windows 11 24H2 (May work on earlier versions, have not tested. Driver theoretically works on Windows 95)
- [WinpkFilter driver](https://www.ntkernel.com/windows-packet-filter/)

### How to use
- Don't