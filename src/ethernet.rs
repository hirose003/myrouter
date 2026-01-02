use anyhow::{anyhow, Ok};
use bytes::{BufMut, BytesMut};
use log::info;
use std::sync::mpsc::Sender;

use crate::arp::{arp_input, ArpTableRequest};
use crate::device::NetDevice;
use crate::ip::{ip_input, FibRequest};
use crate::util;

pub const ETHER_TYPE_IP: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
const EHTERNET_ADDRESS_BROADCAST: [u8; 6] = [0xff; 6];

pub const ETHERNET_HEADER_SIZE: usize = 14;
pub const ETHERNET_ADDRESS_LEN: u8 = 6;

#[derive(Debug)]
pub struct EtherHeader {
    dest_addr: [u8; 6],
    src_addr: [u8; 6],
    type_: u16,
}

impl EtherHeader {
    pub fn new(dest_addr: [u8; 6], src_addr: [u8; 6], type_: u16) -> Self {
        Self {
            dest_addr,
            src_addr,
            type_,
        }
    }
}

impl TryFrom<BytesMut> for EtherHeader {
    type Error = anyhow::Error;

    fn try_from(bytes: BytesMut) -> Result<EtherHeader, Self::Error> {
        let dest_addr = bytes[0..6].try_into()?;
        let src_addr = bytes[6..12].try_into()?;
        let type_ = u16::from_be_bytes([bytes[12], bytes[13]]);
        Ok(EtherHeader {
            dest_addr,
            src_addr,
            type_,
        })
    }
}

impl From<EtherHeader> for BytesMut {
    fn from(etherheader: EtherHeader) -> Self {
        let mut buf = BytesMut::new();
        let dest_addr = etherheader.dest_addr;
        let src_addr = etherheader.src_addr;
        let type_ = etherheader.type_;
        buf.put(&dest_addr[..]);
        buf.put(&src_addr[..]);
        buf.put_u16(type_);
        buf
    }
}

pub fn ethernet_input(
    dev: NetDevice,
    mut buf: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
    fib_request_tx: Sender<FibRequest>,
) -> Result<(), anyhow::Error> {
    let eth_header = EtherHeader::try_from(buf.split_to(14))?;
    if eth_header.dest_addr != dev.mac_address && eth_header.dest_addr != EHTERNET_ADDRESS_BROADCAST
    {
        return Ok(());
    }

    info!(
        "Received ethernet frame type {:04x} from {} to {}",
        eth_header.type_,
        util::mac_print(&eth_header.src_addr),
        util::mac_print(&eth_header.dest_addr)
    );

    let err_msg = match eth_header.type_ {
        ETHER_TYPE_ARP => {
            arp_input(dev, buf, arp_table_request_tx)?;
            return Ok(());
        }
        ETHER_TYPE_IP => {
            ip_input(dev, buf, arp_table_request_tx, fib_request_tx)?;
            return Ok(());
        }
        _ => format!("unsupported protocol: {}", eth_header.type_),
    };
    Err(anyhow!(err_msg))
}

pub fn ethernet_encapsulate_output(
    dev: &NetDevice,
    dest_addr: [u8; 6],
    payload: BytesMut,
    ether_type: u16,
) {
    info!(
        "Sending ethernet frame type {} from {} to {}",
        ether_type,
        util::mac_print(&dev.mac_address),
        util::mac_print(&dest_addr)
    );
    let header: BytesMut = EtherHeader {
        src_addr: dev.mac_address,
        dest_addr,
        type_: ether_type,
    }
    .into();

    let mut buf = BytesMut::with_capacity(1550);
    buf.put(&header[..]);
    buf.put(&payload[..]);
    let len = buf.len();

    dev.clone().transmit(&mut buf[..], len);
}
