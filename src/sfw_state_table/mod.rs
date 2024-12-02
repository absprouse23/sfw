use ndisapi::{DirectionFlags, IntermediateBuffer};
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct StateTableKey {
    pub source_ip: IpAddress,
    //pub source_port: u16,
    pub destination_ip: IpAddress,
    //pub destination_port: u16,
}

#[derive(Debug)]
pub struct StateTableEntry {
    pub timeout: SystemTime,        // Expiration time using system clock
}

pub struct ConnectionTable {
    pub table: HashMap<StateTableKey, StateTableEntry>,
}

impl ConnectionTable {
    /// Constructor for creating a new connection table
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    /// Handle outgoing connections - add a new entry to the table
    pub fn handle_outgoing_connection(
        &mut self,
        key: StateTableKey,
    ) {
        let timeout = SystemTime::now() + Duration::from_secs(300); // Set a 5-minute timeout for entries

        let entry = StateTableEntry {
            timeout,
        };

        if !self.table.contains_key(&key) {
            dbg!("Inserting new connection key");
            dbg!(&key, &entry);
        }

        self.table.entry(key).or_insert(entry);
    }

    /// Handle incoming connections - check if an entry exists by flipping the key
    /// If not, drop the packet; otherwise, update the timeout
    pub fn handle_incoming_connection(&mut self, key: &StateTableKey) -> bool {
        // Flip the source and destination fields for incoming packets
        let flipped_key = StateTableKey {
            source_ip: key.destination_ip,
            //source_port: key.destination_port,
            destination_ip: key.source_ip,
            //destination_port: key.source_port,
        };

        // Clean up expired connections before checking for a match
        self.cleanup_expired_connections();

        if let Some(entry) = self.table.get_mut(&flipped_key) {
            // Update the timeout for the active connection
            entry.timeout = SystemTime::now() + Duration::from_secs(300);

            true // Allow packet
        } else {
            false // Drop packet
        }
    }

    /// Clean up expired connections
    fn cleanup_expired_connections(&mut self) {
        let now = SystemTime::now();
        self.table.retain(|_, entry| entry.timeout > now);
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
                        let key = StateTableKey {
                            source_ip: IpAddress::Ipv4(ipv4_packet.src_addr()),
                            //source_port: tcp_packet.src_port(),
                            destination_ip: IpAddress::Ipv4(ipv4_packet.dst_addr()),
                            //destination_port: tcp_packet.dst_port(),
                        };

                        if *direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                            // Outgoing packet: Add the entry to the connection table
                            self.handle_outgoing_connection(key);
                            true
                        } else { self.handle_incoming_connection(&key) }
                    }
                    IpProtocol::Udp => {
                        let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                        let key = StateTableKey {
                            source_ip: IpAddress::Ipv4(ipv4_packet.src_addr()),
                            //source_port: udp_packet.src_port(),
                            destination_ip: IpAddress::Ipv4(ipv4_packet.dst_addr()),
                            //destination_port: udp_packet.dst_port(),
                        };

                        if *direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                            // Outgoing packet: Add the entry to the connection table
                            self.handle_outgoing_connection(key);
                            true
                        } else {
                            self.handle_incoming_connection(&key)
                        }
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
                        let key = StateTableKey {
                            source_ip: IpAddress::Ipv6(ipv6_packet.src_addr()),
                            //source_port: tcp_packet.src_port(),
                            destination_ip: IpAddress::Ipv6(ipv6_packet.dst_addr()),
                            //destination_port: tcp_packet.dst_port(),
                        };

                        if *direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                            // Outgoing packet: Add the entry to the connection table
                            self.handle_outgoing_connection(key);
                            true
                        } else { self.handle_incoming_connection(&key) }
                    }
                    IpProtocol::Udp => {
                        let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                        let key = StateTableKey {
                            source_ip: IpAddress::Ipv6(ipv6_packet.src_addr()),
                            //source_port: udp_packet.src_port(),
                            destination_ip: IpAddress::Ipv6(ipv6_packet.dst_addr()),
                            //destination_port: udp_packet.dst_port(),
                        };

                        if *direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                            // Outgoing packet: Add the entry to the connection table
                            self.handle_outgoing_connection(key);
                            true
                        } else { self.handle_incoming_connection(&key) }
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