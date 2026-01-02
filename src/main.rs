use libc::{bind, c_int, c_ushort, sockaddr, sockaddr_ll, socket, socklen_t};
use log::{info, warn};
use std::sync::mpsc::channel;
use std::{mem, thread};

use myrouter::arp::{arp_table_thread, ArpTableRequest};
use myrouter::device::{self, NET_DVICES};
use myrouter::ip::IpDevice;
use myrouter::ip::{fib_thread, FibRequest, IpRouteEntry, IpRouteType};
use myrouter::util::{self, ip_print, mac_print};

const ETH_P_ALL: c_ushort = 0x0003;
const AF_PACKET: c_ushort = 17;
const SOCK_RAW: c_int = 3;

fn main() {
    env_logger::init();

    // FIBを動かすスレッドを作成
    let (fib_request_tx, fib_request_rx) = channel::<FibRequest>();
    let _ = thread::spawn(move || fib_thread(fib_request_rx));

    for ifaddr in nix::ifaddrs::getifaddrs().unwrap() {
        if is_ignore_interface(&ifaddr.interface_name) {
            continue;
        }
        if let Some(linkaddr) = ifaddr.address.unwrap().as_link_addr() {
            let sock: c_int;
            unsafe {
                sock = socket(
                    AF_PACKET as c_int,
                    SOCK_RAW,
                    util::htons(ETH_P_ALL) as c_int,
                );
                if sock == -1 {
                    warn!("faild to socket()");
                    std::process::exit(1);
                }
            }

            let sockaddrll = sockaddr_ll {
                sll_family: AF_PACKET,
                sll_protocol: util::htons(ETH_P_ALL),
                sll_ifindex: linkaddr.ifindex() as c_int,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };

            let saddr_len: socklen_t = mem::size_of_val(&sockaddrll.sll_family) as socklen_t
                + mem::size_of_val(&sockaddrll.sll_protocol) as socklen_t
                + mem::size_of_val(&sockaddrll.sll_ifindex) as socklen_t
                + mem::size_of_val(&sockaddrll.sll_hatype) as socklen_t
                + mem::size_of_val(&sockaddrll.sll_pkttype) as socklen_t
                + mem::size_of_val(&sockaddrll.sll_halen) as socklen_t
                + mem::size_of_val(&sockaddrll.sll_addr) as socklen_t;

            unsafe {
                if bind(sock, &sockaddrll as *const _ as *const sockaddr, saddr_len) == -1 {
                    warn!("faild to bind()");
                    std::process::exit(1);
                }
            }
            let ifname = ifaddr.interface_name.clone();
            let mac_address = linkaddr.addr().unwrap();

            info!(
                "Created device {} socket {} mac_address {}",
                &ifname,
                sock,
                util::mac_print(&mac_address)
            );
            let mut net_devices = NET_DVICES.write().unwrap();
            if ifname == "router1-host1" {
                // interface設定
                let ip_addr = 0xc0a80101; //192.168.1.1
                let netmask = 0xffffff00;
                let dev = device::NetDevice {
                    name: ifname.clone(),
                    mac_address: mac_address,
                    ip_device: IpDevice {
                        address: ip_addr,
                        netmask: netmask,
                        broadcast: ip_addr & netmask | !netmask,
                    },
                    fd: sock,
                };
                info!("set configure interface name:{}, mac_address:{} ip_address:{}, netmask:{}, fd:{}",
                    dev.name,
                    mac_print(&dev.mac_address),
                    ip_print(dev.ip_device.address),
                    ip_print(dev.ip_device.netmask),
                    dev.fd
                );
                net_devices.add(dev.clone());
                // 192.168.1.0/24をConnectedの設定
                let ip_entry = FibRequest::Add {
                    ip_addr: 0xc0a80100,
                    ip_addr_len: 24,
                    entry: IpRouteEntry {
                        _type: IpRouteType::Connected,
                        dev: Some(dev),
                        next_hop: None,
                    },
                };
                let _ = fib_request_tx.send(ip_entry);
            }
            if ifname == "router1-router2" {
                // interface設定
                let ip_addr = 0xc0a80001; //192.168.0.1
                let netmask = 0xffffff00;
                let dev = device::NetDevice {
                    name: ifname.clone(),
                    mac_address: mac_address,
                    ip_device: IpDevice {
                        address: ip_addr,
                        netmask: netmask,
                        broadcast: ip_addr & netmask | !netmask,
                    },
                    fd: sock,
                };
                info!("set configure interface name:{}, mac_address:{} ip_address:{}, netmask:{}, fd:{}",
                    dev.name,
                    mac_print(&dev.mac_address),
                    ip_print(dev.ip_device.address),
                    ip_print(dev.ip_device.netmask),
                    dev.fd
                );
                net_devices.add(dev.clone());
                // 192.168.0.0/24をConnectedの設定
                let ip_entry = FibRequest::Add {
                    ip_addr: 0xc0a80000,
                    ip_addr_len: 24,
                    entry: IpRouteEntry {
                        _type: IpRouteType::Connected,
                        dev: Some(dev.clone()),
                        next_hop: None,
                    },
                };
                let _ = fib_request_tx.send(ip_entry);

                // 192.168.2.0/24をNetworkで設定する
                let ip_entry = FibRequest::Add {
                    ip_addr: 0xc0a80200,
                    ip_addr_len: 24,
                    entry: IpRouteEntry {
                        _type: IpRouteType::Network,
                        dev: None,
                        next_hop: Some(0xc0a80002),
                    },
                };
                let _ = fib_request_tx.send(ip_entry);
            }
            if ifname == "router1-router3" {
                // interface設定
                let ip_addr = 0xc0a80301; //192.168.3.1
                let netmask = 0xffffff00;
                let dev = device::NetDevice {
                    name: ifname.clone(),
                    mac_address: mac_address,
                    ip_device: IpDevice {
                        address: ip_addr,
                        netmask: netmask,
                        broadcast: ip_addr & netmask | !netmask,
                    },
                    fd: sock,
                };
                info!("set configure interface name:{}, mac_address:{} ip_address:{}, netmask:{}, fd:{}",
                    dev.name,
                    mac_print(&dev.mac_address),
                    ip_print(dev.ip_device.address),
                    ip_print(dev.ip_device.netmask),
                    dev.fd
                );
                net_devices.add(dev.clone());
                // 192.168.3.0/24をConnectedの設定
                let ip_entry = FibRequest::Add {
                    ip_addr: 0xc0a80300,
                    ip_addr_len: 24,
                    entry: IpRouteEntry {
                        _type: IpRouteType::Connected,
                        dev: Some(dev.clone()),
                        next_hop: None,
                    },
                };
                let _ = fib_request_tx.send(ip_entry);

                // 192.168.4.0/24をNetworkで設定する
                let ip_entry = FibRequest::Add {
                    ip_addr: 0xc0a80400,
                    ip_addr_len: 24,
                    entry: IpRouteEntry {
                        _type: IpRouteType::Network,
                        dev: None,
                        next_hop: Some(0xc0a80302),
                    },
                };
                let _ = fib_request_tx.send(ip_entry);
            }
        }
    }

    // ARP Tableを動かすスレッドを作成
    let (arp_table_request_tx, arp_table_request_rx) = channel::<ArpTableRequest>();
    let _ = thread::spawn(move || arp_table_thread(arp_table_request_rx));

    let net_devices = NET_DVICES.read().unwrap();
    let mut children = vec![];
    for net_device in net_devices.net_devices.clone().into_iter() {
        children.push(thread::spawn({
            let arp_table_request_tx = arp_table_request_tx.clone();
            let fib_request_tx = fib_request_tx.clone();
            move || {
                //info!("{:?}", net_device);
                net_device.poll(arp_table_request_tx, fib_request_tx);
            }
        }));
    }
    drop(net_devices);

    for child in children {
        let _ = child.join();
    }
}

const IGNORE_INTERFACES: [&'static str; 5] = ["lo", "bound0", "dummy0", "tunl0", "sit0"];

fn is_ignore_interface(ifname: &str) -> bool {
    IGNORE_INTERFACES.iter().any(|&x| x == ifname)
}
