mod sfw_rules_table;
mod sfw_state_table;

use ndisapi::{
    DirectionFlags, EthRequest, EthRequestMut, FilterFlags, IntermediateBuffer, MacAddress, Ndisapi
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{env, io};
use windows::Win32::System::Threading::SetEvent;
use windows::{
    core::Result,
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
};


use sfw_rules_table::RulesTable;
use sfw_state_table::ConnectionTable;

fn main() -> Result<()> {
    let driver = Ndisapi::new("NDISRD").expect("WinpkFilter driver is not installed or failed to load!");

    let rules_file_path = get_rules_file_path();

    // Load user-defined rules from the rules.json file
    let mut rules_table = RulesTable::new(rules_file_path.to_str().expect("Invalid rules file path"));
    // Get information about TCP/IP adapters bound to the driver
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    for (index, adapter) in adapters.iter().enumerate() {
        // Display the information about each network interface provided by the get_tcpip_bound_adapters_info
        let network_interface_name = Ndisapi::get_friendly_adapter_name(adapter.get_name())
            .expect("Unknown network interface");
        println!(
            "{}: {}\n\t{}",
            index,
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
            driver.get_adapter_mode(adapter.get_handle())?
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

    let interface_index;
    let adapter_count = adapters.len() - 1;
    println!("Select an interface");

    loop {
        println!("Please enter a number between 0 and {}:", adapter_count);

        // Read user input
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");

        // Try parsing the input to a number
        match input.trim().parse::<usize>() {
            Ok(num) if num <= adapter_count => {
                interface_index = num;
                println!("Using interface {}", interface_index);
                break;
            }
            _ => println!("Invalid input. Make sure it is a number between 0 and {}.", adapter_count),
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

    // Set up a Ctrl-C handler to terminate the packet processing loop
    let terminate: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let ctrlc_pressed = terminate.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl-C was pressed. Terminating...");
        // Set the atomic flag to exit the loop
        ctrlc_pressed.store(true, Ordering::SeqCst);
        // Signal the event to release the loop if there are no packets in the queue
        let _ = unsafe { SetEvent(event) };
    })
    .expect("Error setting Ctrl-C handler");

    // Set the created event within the driver to signal completion of packet handling.
    driver.set_packet_event(adapters[interface_index].get_handle(), event)?;

    // Put the network interface into tunnel mode by setting it's filter flags.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
    )?;
    
    // Create our connection state table
    let mut connection_table = ConnectionTable::new();

    // Allocate single IntermediateBuffer on the stack
    let mut packet = IntermediateBuffer::default();

    // Loop until we get a ctrl-c

    while !terminate.load(Ordering::SeqCst) {
        unsafe { WaitForSingleObject(event, u32::MAX) };

        loop {
            let mut read_request = EthRequestMut::new(adapters[interface_index].get_handle());
            read_request.set_packet(&mut packet);

            if driver.read_packet(&mut read_request).is_err() {
                break;
            }

            let direction_flags = packet.get_device_flags();

            if connection_table.filter_packet(&packet, &direction_flags) && rules_table.filter_packet(&packet, &direction_flags) {
                let mut write_request = EthRequest::new(adapters[interface_index].get_handle());
                write_request.set_packet(&packet);
            
                if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                    driver.send_packet_to_adapter(&write_request).ok();
                } else {
                    driver.send_packet_to_mstcp(&write_request).ok();
                }
            }
        }

        unsafe { let _ = ResetEvent(event); };
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
//

fn get_rules_file_path() -> PathBuf {
    let exe_path = env::current_exe().expect("Failed to get current executable path");
    
    let mut rules_path = exe_path.parent().expect("Failed to get executable directory").to_path_buf();
    rules_path.push("rules.json");
    
    if rules_path.exists() {
        return rules_path;
    }
    
    loop {
        println!("Please enter the full path to the rules.json file: ");

        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        let trimmed_input = input.trim();

        let user_provided_path = PathBuf::from(trimmed_input);
        if user_provided_path.exists() {
            return user_provided_path;
        } else {
            println!("The provided file path does not exist. Please try again.");
        }
    }
}