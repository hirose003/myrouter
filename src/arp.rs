use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, RwLock};

use crate::device::NetDevice;
use crate::ethernet::{
    self, ethernet_encapsulate_output, ETHERNET_ADDRESS_LEN, ETHER_TYPE_ARP, ETHER_TYPE_IP,
};
use crate::ip::IP_ADDRESS_LEN;
use crate::util::{self, htnol, ip_print, mac_print, ntohl};

const ARP_MINI_SIZE: usize = 28;
const ARP_OPERATION_CODE_REQUEST: u16 = 0x0001;
const ARP_OPERATION_CODE_REPLY: u16 = 0x0002;
#[allow(dead_code)]
const ARP_ETHERNET_PACKET_LEN: usize = 46;
const ARP_HTYPE_ETHERNET: u16 = 0x0001;
const ARP_TABLE_SIZE: u32 = 1111;
const ETH_P_ARP: u16 = 0x0806;
const ETHERNET_ADDRESS_BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

#[derive(Debug, PartialEq)]
pub struct Arp {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    op: u16,
    sha: [u8; 6],
    spa: u32,
    tha: [u8; 6],
    tpa: u32,
}

#[derive(Debug, Clone)]
pub struct ArpTableEntry {
    pub mac_addr: [u8; 6],
    pub ip_addr: u32,
    pub dev: NetDevice,
}

pub struct ArpTable(HashMap<u32, ArpTableEntryList>);

struct ArpTableEntryList {
    head: Arc<RwLock<Node>>,
}

pub struct Node {
    pub data: ArpTableEntry,
    next: Option<Arc<RwLock<Node>>>,
}

impl Node {
    fn new(entry: ArpTableEntry) -> Arc<RwLock<Node>> {
        Arc::new(RwLock::new(Node {
            data: entry,
            next: None,
        }))
    }
}

pub enum ArpTableRequest {
    Get {
        ip_addr: u32,
        response_tx: Sender<Option<Arc<RwLock<Node>>>>,
    },
    Insert {
        ip_addr: u32,
        entry: ArpTableEntry,
    },
    Dump,
}

impl TryFrom<BytesMut> for Arp {
    type Error = anyhow::Error;

    fn try_from(bytes: BytesMut) -> Result<Self, Self::Error> {
        let htype = u16::from_be_bytes([bytes[0], bytes[1]]);
        let ptype = u16::from_be_bytes([bytes[2], bytes[3]]);
        let hlen = bytes[4];
        let plen = bytes[5];
        let op = u16::from_be_bytes([bytes[6], bytes[7]]);
        let sha = bytes[8..14].try_into()?;
        let spa = u32::from_be_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
        let tha: [u8; 6] = bytes[18..24].try_into()?;
        let tpa = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        Ok(Arp {
            htype,
            ptype,
            hlen,
            plen,
            op,
            sha,
            spa,
            tha,
            tpa,
        })
    }
}

impl From<Arp> for BytesMut {
    fn from(arp: Arp) -> Self {
        let mut buf = BytesMut::new();
        let htype = arp.htype;
        let ptype = arp.ptype;
        let hlen = arp.hlen;
        let plen = arp.plen;
        let op = arp.op;
        let sha: [u8; 6] = arp.sha;
        let spa = arp.spa;
        let tha: [u8; 6] = arp.tha;
        let tpa = arp.tpa;
        buf.put_u16(htype);
        buf.put_u16(ptype);
        buf.put_u8(hlen);
        buf.put_u8(plen);
        buf.put_u16(op);
        buf.put(&sha[..]);
        buf.put_u32(spa);
        buf.put(&tha[..]);
        buf.put_u32(tpa);
        buf
    }
}

impl ArpTable {
    pub fn new() -> ArpTable {
        return ArpTable(HashMap::new());
    }

    pub fn insert(&mut self, ip_addr: u32, new_entry: ArpTableEntry) {
        let index = ip_addr % ARP_TABLE_SIZE;
        match self.0.get_mut(&index) {
            None => {
                info!("add arp tables entry first");
                let new_entry = ArpTableEntryList {
                    head: Node::new(new_entry),
                };
                self.0.insert(index, new_entry);
            }
            Some(list) => {
                let mut current = list.head.clone();
                loop {
                    let node = current.clone();
                    let mut n = node.write().unwrap();
                    if n.data.mac_addr != new_entry.mac_addr {
                        n.next = Some(Node::new(new_entry.clone()))
                    }
                    if n.next.is_none() {
                        break;
                    }
                    current = n.next.clone().unwrap();
                }
            }
        }
    }

    pub fn dump_arp_table_entry(&self) {
        println!("|---IP ADDRESS----|----MAC ADDRESS----|------DEVICE-------|-INDEX-|");
        for list in self.0.values() {
            let mut current = list.head.clone();
            loop {
                let node = current.clone();
                let n = node.read().unwrap();
                print!("{:>18}", ip_print(htnol(n.data.ip_addr)));
                print!("{:>20}", mac_print(&n.data.mac_addr));
                print!("{:>20}", n.data.dev.name);
                println!("");
                if n.next.is_none() {
                    break;
                }
                current = n.next.clone().unwrap();
            }
        }
        println!("|-----------------|-------------------|-------------------|-------|");
    }

    pub fn get(&self, ip_addr: &u32) -> Option<Arc<RwLock<Node>>> {
        let index = ip_addr % ARP_TABLE_SIZE;
        match self.0.get(&index) {
            None => return None,
            Some(arptable_list) => {
                let mut current = arptable_list.head.clone();
                loop {
                    let node = current.clone();
                    let n = node.read().unwrap();
                    if n.data.ip_addr == *ip_addr {
                        return Some(current);
                    }
                    if n.next.is_none() {
                        break;
                    }
                    current = n.next.clone().unwrap();
                }
                None
            }
        }
    }
}

fn add_arp_table_entry(
    dev: NetDevice,
    mac_addr: [u8; 6],
    ip_addr: u32,
    arp_table_request_tx: Sender<ArpTableRequest>,
) {
    let entry = ArpTableEntry {
        mac_addr,
        ip_addr,
        dev,
    };
    let _ = arp_table_request_tx.send(ArpTableRequest::Insert { ip_addr, entry });
    let _ = arp_table_request_tx.send(ArpTableRequest::Dump);
}

pub fn arp_input(
    input_dev: NetDevice,
    buf: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
) -> Result<(), anyhow::Error> {
    if buf.len() < ARP_MINI_SIZE {
        warn!("too short");
        return Ok(());
    }

    let arp = Arp::try_from(buf)?;
    info!("Arp hypte:{}, ptype:{}, hlen:{}, plen:{}, op:{}, src_mac:{}, src_ip:{}, dst_mac:{}, dst_ip:{}", 
        arp.htype,
        arp.ptype,
        arp.hlen,
        arp.plen,
        arp.op,
        mac_print(&arp.sha),
        ip_print(arp.spa),
        mac_print(&arp.tha),
        ip_print(arp.tpa)
    );

    let err_msg = match arp.ptype {
        ETHER_TYPE_IP => {
            if arp.hlen != ETHERNET_ADDRESS_LEN {
                warn!("Illegal hardware address length");
                return Ok(());
            }
            if arp.plen != IP_ADDRESS_LEN {
                warn!("Illegal protocol address length");
                return Ok(());
            }

            match arp.op {
                ARP_OPERATION_CODE_REQUEST => {
                    arp_request_arrives(input_dev, arp, arp_table_request_tx);
                    return Ok(());
                }
                ARP_OPERATION_CODE_REPLY => {
                    arp_reply_arrives(input_dev, arp, arp_table_request_tx);
                    return Ok(());
                }
                _ => format!("unsupported operation {}", arp.op),
            }
        }
        _ => format!("unsupported protocol {}", arp.ptype),
    };
    Err(anyhow!(err_msg))
}

fn arp_request_arrives(
    dev: NetDevice,
    request: Arp,
    arp_table_request_tx: Sender<ArpTableRequest>,
) {
    if dev.ip_device.address == request.tpa {
        info!("Sending arp reply via {}", ip_print(request.tpa));

        let htype = ARP_HTYPE_ETHERNET;
        let ptype = ETHER_TYPE_IP;
        let hlen = ETHERNET_ADDRESS_LEN;
        let plen = IP_ADDRESS_LEN;
        let op = ARP_OPERATION_CODE_REPLY;

        let sha = dev.mac_address;
        let spa = dev.ip_device.address;
        let tha = request.sha;
        let tpa = request.spa;
        let response = Arp {
            htype,
            ptype,
            hlen,
            plen,
            op,
            sha,
            spa,
            tha,
            tpa,
        };

        debug!(
            "Reply htype:{:x} ptype:{:x} hlen:{:x} plen:{:x} op:{:x} \
            sha:{} spa:{} tha:{} tpa{}",
            htype,
            ptype,
            hlen,
            plen,
            op,
            util::mac_print(&sha),
            std::net::Ipv4Addr::from(spa),
            util::mac_print(&tha),
            std::net::Ipv4Addr::from(tpa),
        );

        ethernet::ethernet_encapsulate_output(&dev, request.sha, response.into(), ETH_P_ARP);
        add_arp_table_entry(dev, request.sha, ntohl(request.spa), arp_table_request_tx);
    }
}

fn arp_reply_arrives(dev: NetDevice, reply: Arp, arp_table_request_tx: Sender<ArpTableRequest>) {
    info!(
        "Added arp table entry by arp reply ({} => {})",
        ip_print(reply.spa),
        mac_print(&reply.sha)
    );
    add_arp_table_entry(dev, reply.sha, ntohl(reply.spa), arp_table_request_tx);
}

pub fn arp_table_thread(receiver: Receiver<ArpTableRequest>) {
    let mut arp_table = ArpTable::new();
    loop {
        match receiver.recv() {
            Ok(ArpTableRequest::Get {
                ip_addr,
                response_tx,
            }) => {
                let entry = arp_table.get(&ip_addr);
                let _ = response_tx.send(entry);
            }
            Ok(ArpTableRequest::Insert {
                ip_addr,
                entry: new_entry,
            }) => {
                arp_table.insert(ip_addr, new_entry);
            }
            Ok(ArpTableRequest::Dump) => {
                arp_table.dump_arp_table_entry();
            }
            Err(_) => {
                break;
            }
        }
    }
}

pub fn send_arp_request(dev: &NetDevice, ip_addr: u32) {
    info!(
        "Sending arp request via {} for {}",
        dev.name,
        ip_print(ip_addr)
    );

    let arp_msg = Arp {
        htype: ARP_HTYPE_ETHERNET,
        ptype: ETHER_TYPE_IP,
        hlen: ETHERNET_ADDRESS_LEN,
        plen: IP_ADDRESS_LEN,
        op: ARP_OPERATION_CODE_REQUEST,
        sha: dev.mac_address, //送信者ハードウェアアドレスにデバイスのMACアドレスを設定
        spa: dev.ip_device.address, //送信者プロトコルアドレスにデバイスのIPアドレスを設定
        tha: [0x00; 6],
        tpa: ip_addr, //ターゲットプロトコルアドレスに、探すホストのIPを
    }
    .into();

    ethernet_encapsulate_output(dev, ETHERNET_ADDRESS_BROADCAST, arp_msg, ETHER_TYPE_ARP);
}

#[cfg(test)]
mod tests {

    use bytes::BytesMut;
    use std::sync::mpsc::channel;
    use std::sync::{Arc, RwLock};
    use std::thread;

    use crate::ip;
    use crate::{arp, device::NetDevice};

    use super::{arp_table_thread, ArpTableEntry, ArpTableRequest, Node};
    #[test]
    fn arp_byte_to_struct() {
        let packet: [u8; 44] = [
            0, 1, 8, 0, 6, 4, 0, 1, 198, 56, 252, 1, 60, 195, 192, 168, 1, 2, 0, 0, 0, 0, 0, 0,
            192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let arp = arp::Arp::try_from(BytesMut::from(&packet[..])).unwrap();
        assert_eq!(
            arp,
            arp::Arp {
                htype: 0x0001,
                ptype: 0x0800,
                hlen: 0x06,
                plen: 0x04,
                op: 0x0001,
                sha: [0xc6, 0x38, 0xfc, 0x01, 0x3c, 0xc3],
                spa: 0xc0a80102, //192.168.1.2
                tha: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                tpa: 0xc0a80101, //192.168.1.1
            }
        );
    }

    #[test]
    fn add_arp_table_entry() {
        let mac_addr: [u8; 6] = [0x02, 0x42, 0x35, 0xf3, 0x8a, 0x15];
        let ip_addr = 0xc0a80101;
        let dev = NetDevice {
            name: "eth0".to_string(),
            mac_address: mac_addr,
            ip_device: ip::IpDevice {
                address: 0xc0a80101,
                netmask: 0xffffff00,
                broadcast: 0xc0a801ff,
            },
            fd: 0,
        };
        let (arp_table_request_tx, arp_table_request_rx) = channel::<ArpTableRequest>();
        let _ = thread::spawn(move || arp_table_thread(arp_table_request_rx));

        let handle1 = thread::spawn({
            let arp_table_request_tx = arp_table_request_tx.clone();
            move || {
                let _ = arp_table_request_tx.send(ArpTableRequest::Insert {
                    ip_addr,
                    entry: ArpTableEntry {
                        mac_addr,
                        ip_addr,
                        dev,
                    },
                });
            }
        });
        handle1.join().unwrap();
        let handle2 = thread::spawn({
            let arp_table_request_tx = arp_table_request_tx.clone();
            move || {
                let (arp_table_response_tx, arp_table_response_rx) =
                    channel::<Option<Arc<RwLock<Node>>>>();
                let _ = arp_table_request_tx.send(ArpTableRequest::Get {
                    ip_addr,
                    response_tx: arp_table_response_tx,
                });
                let entry = arp_table_response_rx.recv().unwrap().expect("no entry");
                let rlock = entry.read().unwrap();
                assert_eq!(rlock.data.mac_addr, mac_addr);
            }
        });
        handle2.join().unwrap();
    }
}
