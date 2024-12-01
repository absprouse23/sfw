use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv6Address, TcpPacket, UdpPacket, IpAddress};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// #[derive(Hash, Eq, PartialEq, Debug)]
// pub enum IpAddress {
//     Ipv4(Ipv4Address),
//     Ipv6(Ipv6Address),
// }

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct StateTableKey {
    pub source_ip: IpAddress,
    //pub source_port: u16,
    pub destination_ip: IpAddress,
    //pub destination_port: u16,
}

#[derive(Debug)]
pub struct StateTableEntry {
    pub protocol: IpProtocol,       // TCP or UDP
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
        protocol: IpProtocol,
    ) {
        let timeout = SystemTime::now() + Duration::from_secs(300); // Set a 5-minute timeout for entries

        let entry = StateTableEntry {
            protocol,
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
            source_ip: key.destination_ip.clone(),
            //source_port: key.destination_port,
            destination_ip: key.source_ip.clone(),
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
}