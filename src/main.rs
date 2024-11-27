/// This example demonstrates the essential usage of active filtering modes for packet processing. It selects a
/// network interface and sets it into a filtering mode, where both sent and received packets are queued. The example
/// registers a Win32 event using the `Ndisapi::set_packet_event` function, and enters a waiting state for incoming packets.
/// Upon receiving a packet, its content is decoded and displayed on the console screen, providing a real-time view of
/// the network traffic.
use clap::Parser;
use ndisapi::{
    DirectionFlags, EthRequest, EthRequestMut, FilterFlags, IntermediateBuffer, Ndisapi, MacAddress, PacketOidData, RasLinks
};
use smoltcp::wire::{
    ArpPacket, EthernetFrame, EthernetProtocol, Icmpv4Packet, Icmpv6Packet, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, UdpPacket,
};
use windows::{
    core::Result,
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
};
use std::{
    mem::{self, size_of},
    ptr::write_bytes,
};

// #[derive(Parser)]
// struct Cli {
//     /// Network interface index (please use listadapters example to determine the right one)
//     #[clap(short, long)]
//     interface_index: usize,
//     /// Number of packets to read from the specified network interface
//     #[clap(short, long)]
//     packets_number: usize,
// }

fn main() -> Result<()> {
    // Parse command line arguments and extract interface index and number of packets
    // let Cli {
    //     mut interface_index,
    //     mut packets_number,
    // } = Cli::parse();

    // Subtract 1 from interface index to convert from 1-based to 0-based indexing
    let interface_index = 3;

    let driver = Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!");

    // Get information about TCP/IP adapters bound to the driver
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    // If the specified interface index is greater than the number of available interfaces, panic with an error message
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    for (index, adapter) in adapters.iter().enumerate() {
        // Display the information about each network interface provided by the get_tcpip_bound_adapters_info
        let network_interface_name = Ndisapi::get_friendly_adapter_name(adapter.get_name())
            .expect("Unknown network interface");
        println!(
            "{}. {}\n\t{}",
            index + 1,
            network_interface_name,
            adapter.get_name(),
        );
        println!("\t Medium: {}", adapter.get_medium());
        println!(
            "\t MAC: {}",
            MacAddress::from_slice(adapter.get_hw_address()).unwrap_or_default()
        );
        println!("\t MTU: {}", adapter.get_mtu());
        println!(
            "\t FilterFlags: {:?}",
            driver.get_adapter_mode(adapter.get_handle()).unwrap()
        );

        // Query hardware packet filter for the adapter using built wrapper for ndis_get_request
        match driver.get_hw_packet_filter(adapter.get_handle()) {
            Err(err) => println!(
                "Getting OID_GEN_CURRENT_PACKET_FILTER Error: {}",
                err.message()
            ),
            Ok(current_packet_filter) => {
                println!("\t OID_GEN_CURRENT_PACKET_FILTER: 0x{current_packet_filter:08X}")
            }
        }
    }

    // Print a message showing the interface name and the number of packets being used.
    println!(
        "Using interface {}",
        adapters[interface_index].get_name(),
    );

    // Create a Win32 event for packet handling.
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?; // Creating a Win32 event without a name.
    }

    // Set the created event within the driver to signal completion of packet handling.
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put the network interface into tunnel mode by setting it's filter flags.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;

    // Allocate single IntermediateBuffer on the stack
    let mut packet = IntermediateBuffer::default();

    // Loop through all the packets from the network until we are done.
    loop {
        unsafe {
            WaitForSingleObject(event, u32::MAX); // Wait for the event to finish before continuing.
        }

        loop {
            // Initialize EthPacketMut to pass to driver API
            let mut read_request = EthRequestMut::new(adapters[interface_index].get_handle());

            read_request.set_packet(&mut packet);

            if driver.read_packet(&mut read_request).ok().is_none() {
                break;
            }

            // Store the direction flags
            let direction_flags = packet.get_device_flags();

            // Print packet information
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                println!(
                    "\nMSTCP --> Interface ({} bytes)\n",
                    packet.get_length(),
                );
            } else {
                println!(
                    "\nInterface --> MSTCP ({} bytes)\n",
                    packet.get_length(),
                );
            }

            // Decrement the number of packets.

            // Print some information about the sliced packet
            //print_packet_info(&packet);

            let mut write_request = EthRequest::new(adapters[interface_index].get_handle());
            write_request.set_packet(&packet);

            // Re-inject the packet back into the network stack
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                match driver.send_packet_to_adapter(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                };
            } else {
                match driver.send_packet_to_mstcp(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                }
            }
        }

        let _ = unsafe {
            ResetEvent(event) // Reset the event to continue waiting for packets to arrive.
        };
    }

    // Put the network interface into default mode.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::default(),
    )?;

    let _ = unsafe {
        CloseHandle(event) // Close the event handle.
    };

    // Return the result.
    Ok(())
}

/// Print detailed information about a network packet.
///
/// This function takes an `IntermediateBuffer` containing a network packet and prints various
/// details about the packet, such as Ethernet, IPv4, IPv6, ICMPv4, ICMPv6, UDP, and TCP information.
///
/// # Arguments
///
/// * `packet` - A reference to an `IntermediateBuffer` containing the network packet.
///
/// # Examples
///
/// ```no_run
/// let packet: IntermediateBuffer = ...;
/// print_packet_info(&packet);
/// ```
fn print_packet_info(packet: &IntermediateBuffer) {
    let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());
            println!(
                "  Ipv4 {:?} => {:?}",
                ipv4_packet.src_addr(),
                ipv4_packet.dst_addr()
            );
            match ipv4_packet.next_header() {
                IpProtocol::Icmp => {
                    let icmp_packet = Icmpv4Packet::new_unchecked(ipv4_packet.payload());
                    println!(
                        "ICMPv4: Type: {:?} Code: {:?}",
                        icmp_packet.msg_type(),
                        icmp_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                    println!(
                        "   TCP {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                    println!(
                        "   UDP {:?} -> {:?}",
                        udp_packet.src_port(),
                        udp_packet.dst_port()
                    );
                }
                _ => {
                    println!("Unknown IPv4 packet: {:?}", ipv4_packet);
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload());
            println!(
                "  Ipv6 {:?} => {:?}",
                ipv6_packet.src_addr(),
                ipv6_packet.dst_addr()
            );
            match ipv6_packet.next_header() {
                IpProtocol::Icmpv6 => {
                    let icmpv6_packet = Icmpv6Packet::new_unchecked(ipv6_packet.payload());
                    println!(
                        "ICMPv6 packet: Type: {:?} Code: {:?}",
                        icmpv6_packet.msg_type(),
                        icmpv6_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                    println!(
                        "   TCP {:?} -> {:?}",
                        tcp_packet.src_port(),
                        tcp_packet.dst_port()
                    );
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                    println!(
                        "   UDP {:?} -> {:?}",
                        udp_packet.src_port(),
                        udp_packet.dst_port()
                    );
                }
                _ => {
                    println!("Unknown IPv6 packet: {:?}", ipv6_packet);
                }
            }
        }
        EthernetProtocol::Arp => {
            let arp_packet = ArpPacket::new_unchecked(eth_hdr.payload());
            println!("ARP packet: {:?}", arp_packet);
        }
        EthernetProtocol::Unknown(_) => {
            println!("Unknown Ethernet packet: {:?}", eth_hdr);
        }
    }
}
