// Copyright (c) 2015 Timothy Mullican <cyberboxster@gmail.com>
//     Part of this file contains code from libpnet/libpnet/examples/packetdump.rs
//     Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// FIXME Remove before 1.0
#![feature(ip_addr)]

// for step_by
#![feature(step_by)]

extern crate pnet;

use std::env;
use std::net::{IpAddr};

use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::ipv6::{Ipv6Packet};
use pnet::packet::udp::{UdpPacket};

use pnet::datalink::{datalink_channel};
use pnet::datalink::DataLinkChannelType::{Layer2};

use pnet::util::{NetworkInterface, get_network_interfaces};

// for from_utf8
use std::str;
use rustc_serialize::hex::ToHex;
extern crate rustc_serialize;

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}", interface_name, source,
                        udp.get_source(), destination, udp.get_destination(), udp.get_length());
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

pub fn utf8_to_string(bytes: &[u8]) -> String {
  let vector: Vec<u8> = Vec::from(bytes);
  String::from_utf8(vector).unwrap()
}

/*
fn print_payload(payload: &[u8], len: i16) {
    let mut len_rem = len;
    let line_width = 16;
    let mut line_len = 0;
    let mut offset = 0;
    let mut ch: u8;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
    }

    /* data spans multiple lines */
    loop {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

fn print_hex_ascii_line(payload: u8, len: i16, offset: i16) {
    let mut i = 0;
    let mut gap = 0;
    let ch: u8;

    /* offset */
    print!("{}   ", offset);
    
    /* hex */
    ch = payload;
    for i in (0 .. len) {
        print!("{:04X} ", payload[ch]);
        ch+=1;
        /* print extra space after 8th byte for visual aid */
        if (i == 7) {
            print!(" ");
        }
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8) {
        print!(" ");
    }
    
    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for i in (0 .. gap) {
            print!("   ");
        }
    }
    print!("   ");
    
    /* ascii (if printable) */
    ch = payload;
    for i in (0 .. len) {
        if (isprint(ch)) {
            print!("{}", ch[i]);
        }
        else {
            print!(".");
        }
        ch+=1;
    }

    print!("\n");
}*/

/*
 * print data in rows of 16 bytes: offset   hexadecimalt   ascii
 * 00 00 00 00 00 00 00 00 00 00 00 00 47 45 54 20   ............GET 
 * 2F 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74   /.HTTP/1.1..Host
 * 3A 20 79 61 68 6F 6F 2E 63 6F 6D                  :.yahoo.com
*/
fn hex_and_ascii_print(payload: &[u8]) -> () {
    //let mut count = 0;
    // step value for loops
    let step = 16;
    // offset value
    let mut offset = 0;
    for num_value in (0..payload.len()).step_by(step) {
        // if we want a separator every 16 lines
        /*if (count == 16) {
            tmo = 0;
            println!("");
        }*/
        print!("   0x{:04X}:\t", offset);

        // slice stores the temporary index for payload
        let mut slice = 0;
        for count in 0..step {
            // set slice to byte (increment 16 each time)
            // + count (0 to 16)
            slice = num_value + count;
            // make sure slice is not larger than payload.len()
            if (slice < payload.len()) {
                // print the hexadecimal value
                print!("{:02X}", payload[slice]);
            }
            // add separation
            print!(" ");
        }

        // add separation
        print!("  ");

        // reset slice to 0
        slice = 0;
        // print the next 16 utf-8 characters
        for count in 0..step {
            slice = num_value + count;
            if (slice < payload.len()) {
                // printable utf-8?
                if (isprint(payload[slice])) {
                    // translate payload into a vector since
                    // String::from_utf8 requires it
                    let payload_data = vec![payload[slice]];
                    let utf8_data = String::from_utf8(payload_data).unwrap();
                    // print the payload as a string
                    print!("{}", utf8_data.to_string());
                } else {
                    // non-printable utf-8 character, so
                    // print a "." instead.
                    print!(".");
                }
            }
        }

        // update the offset
        offset += step;
        // print a newline
        println!("");

        //tmo += 1;
    }
}

fn isprint(payload: u8) -> bool {
    // UTF-8 printable characters from 20 (32) to 7E (126).
    // 127 is invalid DELETE (U+007F) character.
    // Chart at
    // http://www.fileformat.info/info/charset/UTF-8/list.htm
    if (payload > 32 && payload < 127) {
        return true;
    }

    return false;
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    // Since we only look at source and destination ports, and these are located in the same
    // place in both TCP and UDP headers, we cheat here
    let udp = UdpPacket::new(packet);
    if let Some(udp) = udp {
        println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}", interface_name, source,
                    udp.get_source(), destination, udp.get_destination(), packet.len());

        //println!("[{}]: Packet Data {:2X}", interface_name, udp.payload().to_hex());
        let mut ascii = String::from_utf8_lossy(udp.payload());
        let mut hex = udp.payload().to_hex().to_string();
        //println!("{}", ascii);
        let mut s = String::new();
        // hex
        let mut count = 0;

        let payload_len = udp.payload().len();
        let text_len = 16;
        //print!("{}", 16 % payload_len);
        let rows = (payload_len / text_len);

        // code
        hex_and_ascii_print(udp.payload());
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(interface_name: &str, source: IpAddr, destination: IpAddr,
                             protocol: IpNextHeaderProtocol, packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Udp  => handle_udp_packet(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Tcp  => handle_tcp_packet(interface_name, source, destination, packet),
        _ => println!("[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                interface_name,
                match source { IpAddr::V4(..) => "IPv4", _ => "IPv6" },
                source,
                destination,
                protocol,
                packet.len())

    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
                                  IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
                                  IpAddr::V6(header.get_source()),
                                  IpAddr::V6(header.get_destination()),
                                  header.get_next_header(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
    println!("[{}]: ARP packet: {} > {}; length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.packet().len())

}

fn handle_packet(interface_name: &str, ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp  => handle_arp_packet(interface_name, ethernet),
        _                => println!("[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                                        interface_name,
                                        ethernet.get_source(),
                                        ethernet.get_destination(),
                                        ethernet.get_ethertype(),
                                        ethernet.packet().len())
    }
}

fn main() {
    let iface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = get_network_interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink_channel(&interface, 0, 4096, Layer2) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("packetdump: unable to create channel: {}", e)
    };

    let mut iter = rx.iter();
    loop {
        match iter.next() {
            Ok(packet) => handle_packet(&interface.name[..], &packet),
            Err(e) => panic!("packetdump: unable to receive packet: {}", e)
        }
    }
}