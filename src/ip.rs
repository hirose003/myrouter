use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use log::{info, warn};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, RwLock};

use crate::arp::{send_arp_request, ArpTableRequest, Node};
use crate::binary_trie::IpRouteTable;
use crate::device::{NetDevice, NET_DVICES};
use crate::ethernet::{ethernet_encapsulate_output, ETHER_TYPE_IP};
use crate::icmp::{
    icmp_input, send_icmp_destination_unreachable, send_icmp_time_excedded, IcmpCode,
    IcmpDestinationUnreachableCode,
};
use crate::util::{checksum_16, htnol, htons, ip_print, to_u16_slice};

pub const IP_HEADER_LEN: u8 = 20;
pub const IP_ADDRESS_LEN: u8 = 4;
pub const IP_BROADCST: u32 = 0xffffffff;

#[derive(Debug, Clone, Copy)]
pub struct IpDevice {
    pub address: u32,
    pub netmask: u32,
    pub broadcast: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Device {
    pub address: u128,
    pub prefix_len: u32,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IpProtocol {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
}

impl TryFrom<u8> for IpProtocol {
    type Error = anyhow::Error;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0x01 => Ok(IpProtocol::ICMP),
            0x06 => Ok(IpProtocol::TCP),
            0x11 => Ok(IpProtocol::UDP),
            _ => Err(anyhow!("Unsupported ip protocol {}", num)),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        value as u8
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct IpHeader {
    version: u8,
    header_len: u8,
    tos: u8,
    total_len: u16,
    identify: u16,
    frag_offset: u16,
    ttl: u8,
    protocol: IpProtocol,
    header_checksum: u16,
    src_addr: u32,
    dest_addr: u32,
}

impl TryFrom<BytesMut> for IpHeader {
    type Error = anyhow::Error;

    fn try_from(bytes: BytesMut) -> Result<IpHeader, Self::Error> {
        let version = (bytes[0] & 0xf0) >> 4;
        let header_len = bytes[0] & 0x0f;
        let tos = bytes[1];
        let total_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identify = u16::from_be_bytes([bytes[4], bytes[5]]);
        let frag_offset = u16::from_be_bytes([bytes[6], bytes[7]]);
        let ttl = bytes[8];
        let protocol = IpProtocol::try_from(bytes[9])?;
        let header_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        let src_addr = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let dest_addr = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        Ok(IpHeader {
            header_len,
            version,
            tos,
            total_len,
            identify,
            frag_offset,
            ttl,
            protocol,
            header_checksum,
            src_addr,
            dest_addr,
        })
    }
}

impl From<IpHeader> for BytesMut {
    fn from(ip_header: IpHeader) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u8((ip_header.version << 4) | ip_header.header_len);
        buf.put_u8(ip_header.tos);
        buf.put_u16(ip_header.total_len);
        buf.put_u16(ip_header.identify);
        buf.put_u16(ip_header.frag_offset);
        buf.put_u8(ip_header.ttl);
        buf.put_u8(ip_header.protocol.into());
        buf.put_u16(ip_header.header_checksum);
        buf.put_u32(ip_header.src_addr);
        buf.put_u32(ip_header.dest_addr);
        buf
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum IpRouteType {
    Connected,
    Network,
}

#[derive(Debug, Clone)]
pub struct IpRouteEntry {
    pub _type: IpRouteType,
    pub dev: Option<NetDevice>,
    pub next_hop: Option<u32>,
}

impl PartialEq for IpRouteEntry {
    fn eq(&self, other: &Self) -> bool {
        self._type == other._type && self.dev == other.dev && self.next_hop == other.next_hop
    }
}

pub enum FibRequest {
    Get {
        ip_addr: u32,
        response_tx: Sender<Option<Arc<RwLock<IpRouteEntry>>>>,
    },
    Add {
        ip_addr: u32,
        ip_addr_len: u32,
        entry: IpRouteEntry,
    },
    Dump,
}

// FIBへの問い合わせを待ち受ける
pub fn fib_thread(recevier: Receiver<FibRequest>) {
    let fib = IpRouteTable::new();
    loop {
        match recevier.recv() {
            Ok(FibRequest::Get {
                ip_addr,
                response_tx,
            }) => {
                let entry = fib.search(ip_addr);
                let _ = response_tx.send(entry);
            }
            Ok(FibRequest::Add {
                ip_addr,
                ip_addr_len,
                entry,
            }) => {
                info!(
                    "add fib entry prefix:{}, prefix_len:{}, type:{:?}, dev:{:?}, next_hop:{:?}",
                    ip_print(ip_addr),
                    ip_addr_len,
                    entry._type,
                    entry.dev,
                    entry.next_hop
                );
                fib.add(ip_addr, ip_addr_len, entry);
            }
            Ok(FibRequest::Dump) => {
                todo!();
            }
            Err(_) => break,
        }
    }
}

pub fn ip_input(
    input_dev: NetDevice,
    mut buf: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
    fib_request_tx: Sender<FibRequest>,
) -> Result<(), anyhow::Error> {
    if buf.len() < 20 {
        warn!("Received IP packet too short from {}", input_dev.name);
        return Ok(());
    }

    let mut ip_header_byte = buf.split_to(20);
    let mut ip_header = IpHeader::try_from(ip_header_byte.clone())?;
    info!(
        "Received IP packet type {} from {} to {}",
        ip_header.protocol as u8,
        ip_print(ip_header.src_addr),
        ip_print(ip_header.dest_addr)
    );

    if ip_header.version != 4 {
        warn!("Incorrect IP version");
        return Err(anyhow!("Incorrect IP version"));
    }

    if ip_header.header_len != (20 >> 2) {
        warn!("IP header option is not supported");
        return Err(anyhow!("IP header option is not supported"));
    }

    // 宛先IPアドレスをルータが持ってるか調べる
    if ip_header.dest_addr == IP_BROADCST {
        ip_input_to_ours(&input_dev, ip_header, buf, arp_table_request_tx);
        return Ok(());
    }

    let net_devices = NET_DVICES.read().unwrap();
    for dev in net_devices.net_devices.iter() {
        if dev.ip_device.address == ip_header.dest_addr
            || dev.ip_device.broadcast == ip_header.dest_addr
        {
            ip_input_to_ours(
                &input_dev,
                ip_header,
                buf.clone(),
                arp_table_request_tx.clone(),
            );
            return Ok(());
        }
    }

    let (fib_response_tx, fib_response_rx) = channel::<Option<Arc<RwLock<IpRouteEntry>>>>();
    let _ = fib_request_tx.send(FibRequest::Get {
        ip_addr: ip_header.dest_addr,
        response_tx: fib_response_tx,
    });
    match fib_response_rx.recv().unwrap() {
        None => {
            return Err(anyhow!(
                "no route to host {}",
                ip_print(ip_header.dest_addr)
            ))
        }
        Some(e) => {
            let ip_entry = e.read().unwrap();
            if ip_header.ttl <= 1 {
                send_icmp_time_excedded();
                return Ok(());
            }
            // TTLを1減らす
            ip_header.ttl -= 1;

            // IPヘッダチェックサムの再計算
            ip_header.header_checksum = 0;
            ip_header.header_checksum = htons(checksum_16(to_u16_slice(&mut BytesMut::from(
                ip_header.clone(),
            ))));
            ip_header_byte.unsplit(buf);
            match ip_entry._type {
                //直接接続ネットワークの経路なら
                //hostに直接送信
                IpRouteType::Connected => ip_output_to_host(
                    ip_entry.dev.clone().unwrap(),
                    ip_header.dest_addr,
                    ip_header.src_addr,
                    ip_header_byte,
                    arp_table_request_tx,
                ),
                //直接接続ネットワークの経路ではなかったら
                // next hopに送信
                IpRouteType::Network => ip_output_to_next_hop(
                    ip_entry.next_hop.unwrap(),
                    ip_header_byte,
                    arp_table_request_tx,
                    fib_request_tx,
                ),
            }
            return Ok(());
        }
    }
}

fn ip_input_to_ours(
    input_dev: &NetDevice,
    ip_header: IpHeader,
    payload: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
) {
    match ip_header.protocol {
        IpProtocol::ICMP => {
            let _ = icmp_input(
                ip_header.src_addr,
                ip_header.dest_addr,
                payload,
                arp_table_request_tx,
            );
            return;
        }
        IpProtocol::UDP => {
            send_icmp_destination_unreachable(
                ip_header.src_addr,
                input_dev.ip_device.address,
                IcmpCode::DestinationUnreachable(IcmpDestinationUnreachableCode::PortUnreachable),
                payload,
                arp_table_request_tx,
            );
            return;
        }
        IpProtocol::TCP => {
            return;
        }
    }
}

fn ip_output_to_host(
    dev: NetDevice,
    dest_addr: u32,
    _src_addr: u32,
    mut buffer: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
) {
    // ARP Tableから応答をもらうためのチャンネルを作成
    let (arp_table_response_tx, arp_table_response_rx) = channel::<Option<Arc<RwLock<Node>>>>();
    let _ = arp_table_request_tx.send(ArpTableRequest::Get {
        ip_addr: htnol(dest_addr),
        response_tx: arp_table_response_tx,
    });
    match arp_table_response_rx.recv().unwrap() {
        None => {
            //ARPエントリが無かったら
            info!(
                "Trying ip output, but no arp record to {}",
                ip_print(dest_addr)
            );
            send_arp_request(&dev, dest_addr);
            buffer.clear(); //drop packet
            return;
        }
        Some(entry) => {
            let rlock = entry.read().unwrap();
            //イーサネットでカプセル化して送信
            ethernet_encapsulate_output(&dev, rlock.data.mac_addr, buffer, ETHER_TYPE_IP);
            return;
        }
    }
}

fn ip_output_to_next_hop(
    next_hop: u32,
    mut buffer: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
    fib_request_tx: Sender<FibRequest>,
) {
    // ARPテーブルの検索
    let (arp_table_response_tx, arp_table_response_rx) = channel::<Option<Arc<RwLock<Node>>>>();
    let _ = arp_table_request_tx.send(ArpTableRequest::Get {
        ip_addr: htnol(next_hop),
        response_tx: arp_table_response_tx,
    });
    match arp_table_response_rx.recv().unwrap() {
        None => {
            //ARPエントリが無かったら
            info!(
                "Trying ip output to next hop, but no arp record to {}",
                ip_print(next_hop)
            );
            // ルーティングテーブルのルックアップ
            let (fib_response_tx, fib_response_rx) = channel::<Option<Arc<RwLock<IpRouteEntry>>>>();
            let _ = fib_request_tx.send(FibRequest::Get {
                ip_addr: next_hop,
                response_tx: fib_response_tx,
            });
            match fib_response_rx.recv().unwrap() {
                None => info!(
                    //ARPエントリがなかったら
                    "Trying ip output to next hop, but no arp record to {}",
                    ip_print(next_hop)
                ),
                Some(ip_entry) => {
                    let ip_entry_ro = ip_entry.read().unwrap();
                    if ip_entry_ro._type != IpRouteType::Connected {
                        // next hopへの到達性が無かったら
                        info!("Next hop {} is not reachable", ip_print(next_hop));
                    } else {
                        send_arp_request(&ip_entry_ro.dev.clone().unwrap(), next_hop);
                    }
                }
            }
            buffer.clear(); //drop packet
            return;
        }
        Some(entry) => {
            // ARPエントリがあり、MACアドレスが得られた
            let rlock = entry.read().unwrap();
            ethernet_encapsulate_output(
                //イーサネットでカプセル化して送信
                &rlock.data.dev,
                rlock.data.mac_addr,
                buffer,
                ETHER_TYPE_IP,
            );
            return;
        }
    }
}

pub fn ip_encapsulate_output(
    dest_addr: u32,
    src_addr: u32,
    payload_buf: BytesMut,
    protocol_num: IpProtocol,
    arp_table_request_tx: Sender<ArpTableRequest>,
) {
    let mut ip_header = IpHeader {
        version: 4,
        header_len: IP_HEADER_LEN >> 2,
        tos: 0,
        total_len: IP_HEADER_LEN as u16 + payload_buf.len() as u16,
        identify: 1,
        frag_offset: 0,
        ttl: 0xff,
        protocol: protocol_num,
        header_checksum: 0,
        dest_addr: dest_addr,
        src_addr: src_addr,
    };
    let mut reply_buf = BytesMut::from(ip_header.clone());
    reply_buf.put(payload_buf.clone());

    ip_header.header_checksum = htons(checksum_16(to_u16_slice(&mut reply_buf[..])));
    let mut reply_buf = BytesMut::from(ip_header);
    reply_buf.put(payload_buf);

    let net_devices = NET_DVICES.read().unwrap();
    for dev in net_devices.net_devices.iter() {
        if in_subnet(dev.ip_device.address, dev.ip_device.netmask, dest_addr) {
            let (arp_table_response_tx, arp_table_response_rx) =
                channel::<Option<Arc<RwLock<Node>>>>();
            let _ = arp_table_request_tx.send(ArpTableRequest::Get {
                ip_addr: htnol(dest_addr),
                response_tx: arp_table_response_tx,
            });
            match arp_table_response_rx.recv().unwrap() {
                None => {
                    info!(
                        "Trying ip output, but no arp record to {}",
                        ip_print(dest_addr)
                    );
                    send_arp_request(dev, dest_addr);
                    return;
                }
                Some(entry) => {
                    let rlock = entry.read().unwrap();
                    ethernet_encapsulate_output(
                        dev,
                        rlock.data.mac_addr,
                        reply_buf.clone(),
                        ETHER_TYPE_IP,
                    );
                    return;
                }
            }
        }
    }
}

fn in_subnet(dev_ip_address: u32, netmask: u32, address: u32) -> bool {
    let network1 = dev_ip_address & netmask;
    let network2 = address & netmask;
    network1 == network2
}

#[cfg(test)]
mod test {
    use bytes::BytesMut;

    use super::IpHeader;
    use super::IpProtocol;
    use crate::ip::in_subnet;
    use crate::ip::IP_HEADER_LEN;

    #[test]
    fn convert() {
        let bytes: [u8; 20] = [
            0x45, 0x00, 0x00, 0x54, 0x23, 0x70, 0x40, 0x00, 0x40, 0x01, 0x93, 0xe5, 0xc0, 0xa8,
            0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01,
        ];
        let ip_header1 = IpHeader::try_from(BytesMut::from(&bytes[..])).unwrap();
        let ip_header = IpHeader {
            version: 0x04,
            header_len: 0x05,
            tos: 0,
            total_len: 0x0054,
            identify: 0x2370,
            frag_offset: 0x4000,
            ttl: 64,
            protocol: IpProtocol::ICMP,
            header_checksum: 0x93e5,
            src_addr: 0xc0a80102,
            dest_addr: 0xc0a80101,
        };
        assert_eq!(ip_header1, ip_header);

        let ip_header1_bytes = BytesMut::from(ip_header1);
        assert_eq!(ip_header1_bytes[..], bytes);
    }

    #[test]
    fn test_in_subnet() {
        let address1: u32 = 0xc0a80001;
        let address2: u32 = 0xc0a80002;
        let address3: u32 = 0xc0a80101;
        let netmask: u32 = 0xffffff00;

        assert!(in_subnet(address1, netmask, address2));
        assert!(!in_subnet(address3, netmask, address2));
    }

    #[test]
    fn test_total_length() {
        let payload_buf: [u8; 64] = [
            0x08, 0x00, 0xff, 0x59, 0x7f, 0xf4, 0x00, 0x02, 0x73, 0x68, 0x95, 0x68, 0x00, 0x00,
            0x00, 0x00, 0xa7, 0x0b, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];
        let ip_header = IpHeader {
            version: 4,
            header_len: IP_HEADER_LEN >> 2,
            tos: 0,
            total_len: IP_HEADER_LEN as u16 + payload_buf.len() as u16,
            identify: 1,
            frag_offset: 0,
            ttl: 0xff,
            protocol: IpProtocol::ICMP,
            header_checksum: 0,
            src_addr: 0xc0a80102,
            dest_addr: 0xc0a80101,
        };
        assert_eq!(ip_header.total_len, 0x0054)
    }
}
