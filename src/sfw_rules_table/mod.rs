use ndisapi::{DirectionFlags, IntermediateBuffer};
use serde::Deserialize;
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use std::fs;
use crate::sfw_state_table::StateTableKey;

#[derive(Debug, Deserialize)]
pub struct Rule {
    action: String,                // "ALLOW" or "BLOCK"
    protocol: String,              // "TCP" or "UDP"
    source_address: Option<String>, // "192.168.1.100" or "ANY"
    destination_address: Option<String>, // "10.0.0.0" or "ANY"
    source_port: Option<String>,   // Specific port or "ANY"
    destination_port: Option<String>, // Specific port or "ANY"
    direction: String,             // "INBOUND" or "OUTBOUND"
    logging: bool,                 // Whether to log the packet
    enabled: bool,                 // Whether the rule is enabled
}

pub struct RulesTable {
    rules: Vec<Rule>,
}

struct PacketInfo {
    protocol: IpProtocol,
    direction: DirectionFlags,
    source_address: IpAddress,
    destination_address: IpAddress,
    source_port: u16,
    destination_port: u16,
}

impl RulesTable {
    /// Constructor for creating a new RulesTable by loading from a JSON file
    pub fn new(json_path: &str) -> Self {
        let json_data = fs::read_to_string(json_path).expect("Unable to read JSON rules file");
        let rules: Vec<Rule> = serde_json::from_str(&json_data).expect("Unable to parse JSON");
        RulesTable { rules }
    }

    /// Check if a packet matches a rule and should be blocked or allowed
    fn filter_from_rules(
        &self,
        packet_info: &PacketInfo,
    ) -> bool {
        for rule in &self.rules {
            if !rule.enabled {
                continue; // Skip disabled rules
            }

            // Match protocol
            if rule.protocol.to_uppercase() != protocol_to_string(packet_info.protocol) {
                continue;
            }

            // Match direction
            if rule.direction.to_uppercase() != direction_to_string(packet_info.direction) {
                continue;
            }

            // Match source address
            if let Some(ref rule_source_address) = rule.source_address {
                if rule_source_address.to_uppercase() != "ANY"
                    && rule_source_address.parse::<IpAddress>().unwrap() != packet_info.source_address
                {
                    continue;
                }
            }

            // Match destination address
            if let Some(ref rule_destination_address) = rule.destination_address {
                if rule_destination_address.to_uppercase() != "ANY"
                    && rule_destination_address.parse::<IpAddress>().unwrap() != packet_info.destination_address
                {
                    continue;
                }
            }

            // Match source port
            if let Some(ref rule_source_port) = rule.source_port {
                if rule_source_port.to_uppercase() != "ANY"
                    && rule_source_port.parse::<u16>().unwrap() != packet_info.source_port
                {
                    continue;
                }
            }

            // Match destination port
            if let Some(ref rule_destination_port) = rule.destination_port {
                if rule_destination_port.to_uppercase() != "ANY"
                    && rule_destination_port.parse::<u16>().unwrap() != packet_info.destination_port
                {
                    continue;
                }
            }

            // Log if required
            if rule.logging {
                dbg!(&rule);
                dbg!(packet_info.source_address, packet_info.destination_address, packet_info.source_port, packet_info.destination_port);
            }

            println!("Matched rule {:?}", rule);
            // Determine action
            if rule.action.to_uppercase() == "BLOCK" {
                return false; // Block the packet
            }
        }

        true // Allow packet by default
    }

    pub fn filter_packet(
        &mut self,
        packet: &IntermediateBuffer,
        direction_flags: &DirectionFlags,
    ) -> bool {
        let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());

        match eth_hdr.ethertype() {
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());

                match ipv4_packet.next_header() {
                    IpProtocol::Tcp => {
                        let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                        let packet = PacketInfo {
                            protocol: IpProtocol::Tcp,
                            direction: *direction_flags,
                            source_address: IpAddress::Ipv4(ipv4_packet.src_addr()),
                            source_port: tcp_packet.src_port(),
                            destination_address: IpAddress::Ipv4(ipv4_packet.dst_addr()),
                            destination_port: tcp_packet.dst_port(),
                        };

                        self.filter_from_rules(&packet)
                    }
                    IpProtocol::Udp => {
                        let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                        let packet = PacketInfo {
                            protocol: IpProtocol::Udp,
                            direction: *direction_flags,
                            source_address: IpAddress::Ipv4(ipv4_packet.src_addr()),
                            source_port: udp_packet.src_port(),
                            destination_address: IpAddress::Ipv4(ipv4_packet.dst_addr()),
                            destination_port: udp_packet.dst_port(),
                        };

                        self.filter_from_rules(&packet)
                    }
                    _ => {
                        // Unsupported protocol, drop the packet
                        false
                    }
                }
            }
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload());

                match ipv6_packet.next_header() {
                    IpProtocol::Tcp => {
                        let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                        let packet = PacketInfo {
                            protocol: IpProtocol::Tcp,
                            direction: *direction_flags,
                            source_address: IpAddress::Ipv6(ipv6_packet.src_addr()),
                            source_port: tcp_packet.src_port(),
                            destination_address: IpAddress::Ipv6(ipv6_packet.dst_addr()),
                            destination_port: tcp_packet.dst_port(),
                        };

                        self.filter_from_rules(&packet)
                    }
                    IpProtocol::Udp => {
                        let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                        let packet = PacketInfo {
                            protocol: IpProtocol::Udp,
                            direction: *direction_flags,
                            source_address: IpAddress::Ipv6(ipv6_packet.src_addr()),
                            source_port: udp_packet.src_port(),
                            destination_address: IpAddress::Ipv6(ipv6_packet.dst_addr()),
                            destination_port: udp_packet.dst_port(),
                        };

                        self.filter_from_rules(&packet)
                    }
                    _ => {
                        // Unsupported protocol, drop the packet
                        false
                    }
                }
            }
            EthernetProtocol::Arp => {
                true
            }
            _ => {
                // Unsupported Ethernet protocol, drop the packet
                dbg!("Dropped packet with unsupported Ethernet protocol: {:?}", eth_hdr.ethertype());
                false
            }
        }
    }
}

fn protocol_to_string(protocol: IpProtocol) -> String {
    match protocol {
        IpProtocol::Tcp => "TCP".to_string(),
        IpProtocol::Udp => "UDP".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

fn direction_to_string(direction: DirectionFlags) -> String {
    match direction {
        DirectionFlags::PACKET_FLAG_ON_SEND => "OUTBOUND".to_string(),
        DirectionFlags::PACKET_FLAG_ON_RECEIVE => "INBOUND".to_string(),
        DirectionFlags::PACKET_FLAG_ON_SEND_RECEIVE => "ANY".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}
