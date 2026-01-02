use bytes::BytesMut;
use libc::{c_void, recv, send, ssize_t};
use log::{debug, warn};
use std::sync::mpsc::Sender;
use std::sync::{LazyLock, RwLock};

use crate::arp::ArpTableRequest;
use crate::ethernet;
use crate::ip::{FibRequest, IpDevice};

pub static NET_DVICES: LazyLock<RwLock<NetDevices>> =
    LazyLock::new(|| RwLock::new(NetDevices::new()));

#[derive(Debug)]
pub struct NetDevices {
    pub net_devices: Vec<NetDevice>,
}

#[derive(Debug, Clone)]
pub struct NetDevice {
    pub name: String,
    pub mac_address: [u8; 6],
    pub ip_device: IpDevice,
    pub fd: i32,
}

impl PartialEq for NetDevice {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl NetDevices {
    pub fn new() -> Self {
        Self {
            net_devices: Vec::new(),
        }
    }

    pub fn add(&mut self, device: NetDevice) {
        self.net_devices.push(device)
    }
}

impl NetDevice {
    pub fn transmit(self, buf: &mut [u8], len: usize) -> ssize_t {
        debug!("Send interface: {} packet: {:02x?}", self.name, &buf[..len]);
        unsafe { send(self.fd, (&mut buf[..]).as_mut_ptr() as *mut c_void, len, 0) }
    }

    pub fn poll(
        self,
        arp_table_request_tx: Sender<ArpTableRequest>,
        fib_request_tx: Sender<FibRequest>,
    ) {
        loop {
            let mut buf = [0u8; 1550];
            let n: isize;
            unsafe {
                n = recv(self.fd, (&mut buf[..]).as_mut_ptr() as *mut c_void, 2048, 0);
                if n == -1 {
                    panic!("recv panic");
                }
            }
            debug!(
                "Recive interface:{} packet: {:02x?}",
                self.name,
                &buf[0..(n as usize)]
            );
            match ethernet::ethernet_input(
                self.clone(),
                BytesMut::from(&buf[0..n as usize]),
                arp_table_request_tx.clone(),
                fib_request_tx.clone(),
            ) {
                Err(e) => warn!("{}", e),
                Ok(_) => {}
            }
        }
    }

    pub fn configure_ip_address(mut self, address: u32, netmask: u32) {
        self.ip_device.address = address;
        self.ip_device.netmask = netmask;
        self.ip_device.broadcast = (address & netmask) | (!netmask);
    }
}
