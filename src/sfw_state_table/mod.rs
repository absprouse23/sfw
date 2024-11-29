use smoltcp::{
    socket::{tcp::State},
    wire::{IpProtocol, Ipv4Address, Ipv6Address}
};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum IpAddress {
    Ipv4(Ipv4Address),
    Ipv6(Ipv6Address),
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct StateTableKey {
    source_ip: IpAddress,
    source_port: u16,
    destination_ip: IpAddress,
    destination_port: u16,
}

#[derive(Eq, PartialEq, Debug)]
pub struct StateTableEntry {
    protocol: IpProtocol,       // TCP or UDP
    state: Option<State>,  // Only used for TCP
    timeout: SystemTime,      // Expiration time using system clock
}

pub struct ConnectionTable {
    pub table: std::collections::HashMap<StateTableKey, StateTableEntry>,
}

impl ConnectionTable {
    // Constructor for creating a new connection table
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    // Insert a new connection into the table
    pub fn insert(&mut self, key: StateTableKey, entry: StateTableEntry) {
        self.table.insert(key, entry);
    }

    // Remove a connection from the table
    pub fn remove(&mut self, key: &StateTableKey) {
        self.table.remove(key);
    }

    // Get a connection entry by its key
    pub fn get(&self, key: &StateTableKey) -> Option<&StateTableEntry> {
        self.table.get(key)
    }

    // Display all connections in the table
    pub fn display_all(&self) {
        for (key, entry) in &self.table {
            println!("Connection: {:?}", key);
            println!("Protocol: {:?}, Timeout: {:?}, State: {:?}", entry.protocol, entry.timeout, entry.state);
        }
    }

    // Clean up expired connections
    pub fn cleanup_expired_connections(&mut self) {
        let now = SystemTime::now();
        self.table.retain(|_, entry| entry.timeout > now);
    }
}