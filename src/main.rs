use ndisapi::{DataLinkLayerFilter, DirectionFlags, FilterLayerFlags, IpAddressV4, IpAddressV4Union, IpRangeV4, IpSubnetV4, IpV4Filter, IpV4FilterFlags, Ndisapi, NetworkLayerFilter, NetworkLayerFilterUnion, StaticFilter, StaticFilterTable, TransportLayerFilter, FILTER_PACKET_DROP, FILTER_PACKET_DROP_RDR, FILTER_PACKET_PASS, FILTER_PACKET_PASS_RDR, IPV4, IP_SUBNET_V4_TYPE};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::vec::*;
use windows::Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, IN_ADDR_0_0};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const FILTER_TABLE_SIZE: usize = 256;
#[derive(Debug, Serialize, Deserialize)]
struct JsonFirewallRule {
    action: String,
    protocol: String,
    source_address: String,
    destination_address: String,
    source_port: String,
    destination_port: String,
    direction: String,
    logging: bool,
    enabled: bool,
}



fn create_filter_rule(rule: &JsonFirewallRule) -> Result<StaticFilter, &'static str> {
    let direction_flags = match rule.direction.as_str() {
        "inbound" => DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        "outbound" => DirectionFlags::PACKET_FLAG_ON_SEND,
        "both" => DirectionFlags::PACKET_FLAG_ON_SEND | DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        _ => return Err(r#"Invalid direction specified"#),
    };

    let action = match rule.action.as_str() {
        "allow" => match rule.logging {
            true => FILTER_PACKET_PASS_RDR, // Send the packet, but make a copy and send it back to us for logging
            false => FILTER_PACKET_PASS
        },
        "deny" => match rule.logging {
            true => FILTER_PACKET_DROP_RDR,
            false => FILTER_PACKET_DROP
        },
        _ => return Err(r#"Invalid action specified"#),
    };
    
    let protocol_flags = match rule.protocol.as_str() {
        "tcp" => IPPROTO_TCP,
        "udp" => IPPROTO_UDP,
        "icmp" => IPPROTO_ICMP,
        "any" => IPPROTO_UDP | IPPROTO_TCP | IPPROTO_ICMP,
        _ => return Err(r#"Invalid protocol specified"#),
    };

    let filter_flags = FilterLayerFlags::NETWORK_LAYER_VALID;

    //TODO: For now we only can block a single host, will add range and subnet in future
    // let ip_filter = IpV4Filter::new(
    //     // Filter all fields, actual filtering should occur based on defined parameters
    //     IpV4FilterFlags::IP_V4_FILTER_PROTOCOL | IpV4FilterFlags::IP_V4_FILTER_DEST_ADDRESS | IpV4FilterFlags::IP_V4_FILTER_SRC_ADDRESS,
    //     IpAddressV4::new( // src addr
    //         IP_SUBNET_V4_TYPE,
    //         IpAddressV4Union {
    //             ip_range: IpRangeV4::new(
    //                 IN_ADDR {
    //                     S_un: IN_ADDR_0 {
    //                         S_addr: u32::from(Ipv4Addr::from_str(rule.source_address.as_str()).unwrap())
    //                     }
    //                 },
    //                 IN_ADDR {
    //                     S_un: IN_ADDR_0 {
    //                         S_addr: u32::from(Ipv4Addr::from_str(rule.source_address.as_str()).unwrap())
    //                     }
    //                 }
    //             )
    //         },
    //     ),
    //     IpAddressV4::new( // src addr
    //                       IP_SUBNET_V4_TYPE,
    //                       IpAddressV4Union {
    //                           ip_range: IpRangeV4::new(
    //                               IN_ADDR {
    //                                   S_un: IN_ADDR_0 {
    //                                       S_addr: u32::from(Ipv4Addr::from_str(rule.source_address.as_str()).unwrap())
    //                                   }
    //                               },
    //                               IN_ADDR {
    //                                   S_un: IN_ADDR_0 {
    //                                       S_addr: u32::from(Ipv4Addr::from_str(rule.source_address.as_str()).unwrap())
    //                                   }
    //                               }
    //                           )
    //                       },
    //     ),
    //     protocol_flags
    // );


    Ok(StaticFilter::new(
        0,
        DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        FILTER_PACKET_DROP, 
        filter_flags, 
        DataLinkLayerFilter::default(), 
        NetworkLayerFilter::new(
            IPV4,
            NetworkLayerFilterUnion {
                ipv4: IpV4Filter::new(
                    IpV4FilterFlags::IP_V4_FILTER_PROTOCOL
                        | IpV4FilterFlags::IP_V4_FILTER_SRC_ADDRESS,
                    IpAddressV4::default(),
                    IpAddressV4::new(
                        IP_SUBNET_V4_TYPE,
                        IpAddressV4Union {
                            ip_subnet: IpSubnetV4::new(
                                IN_ADDR {
                                    S_un: IN_ADDR_0 {
                                        S_un_b: IN_ADDR_0_0 {
                                            s_b1: 192,
                                            s_b2: 168,
                                            s_b3: 133,
                                            s_b4: 1,
                                        },
                                    },
                                },
                                IN_ADDR {
                                    S_un: IN_ADDR_0 {
                                        S_un_b: IN_ADDR_0_0 {
                                            s_b1: 255,
                                            s_b2: 255,
                                            s_b3: 255,
                                            s_b4: 255,
                                        },
                                    },
                                },
                            ),
                        },
                    ),
                    IPPROTO_TCP,
                ),
            }
        ), 
        TransportLayerFilter::default()
        )
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let driver = Ndisapi::new("NDISRD").expect("Failed driver connection");
    // Load JSON file
    let file = File::open("rules.json")?;
    let reader = BufReader::new(file);

    // Deserialize JSON into a Vec of FirewallRule
    let rules: Vec<JsonFirewallRule> = serde_json::from_reader(reader).unwrap();
    
    for rule in &rules {
        println!("{:?}", rule);
    }

    let mut compiled_filters: Vec<StaticFilter> = Vec::new();

    for rule in &rules {
        compiled_filters.push(create_filter_rule(rule)?);
    }

    let mut static_filters_list = [StaticFilter::new(
        0,
        DirectionFlags::PACKET_FLAG_ON_SEND | DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        FILTER_PACKET_PASS,
        FilterLayerFlags::empty(),
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::default(),
        TransportLayerFilter::default()); 256];
    
    static_filters_list.iter_mut().zip(compiled_filters.iter()).for_each(|(arr_item, &vec_item)|
        {
            *arr_item = vec_item;
        }
    );

    let filter_table = StaticFilterTable::<FILTER_TABLE_SIZE>::from_filters(static_filters_list);

    driver.set_packet_filter_table(&filter_table).expect("TODO: panic message");
    println!("{}", driver.get_packet_filter_table_size().unwrap());

    Ok(())
}