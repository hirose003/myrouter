use std::cell::RefCell;
use std::rc::{Rc, Weak};
use std::sync::{Arc, RwLock};

use crate::ip::IpRouteEntry;
const IP_BIT_LEN: u32 = 32;

#[allow(dead_code)]
#[derive(Debug)]
pub struct BinaryTrieNode {
    data: Option<Arc<RwLock<IpRouteEntry>>>,
    depth: u32,
    parent: Option<Weak<RefCell<BinaryTrieNode>>>,
    node_0: Option<Rc<RefCell<BinaryTrieNode>>>,
    node_1: Option<Rc<RefCell<BinaryTrieNode>>>,
}

#[derive(Debug)]
pub struct IpRouteTable {
    root: Rc<RefCell<BinaryTrieNode>>,
}

impl IpRouteTable {
    pub fn new() -> Self {
        IpRouteTable {
            root: Rc::new(RefCell::new(BinaryTrieNode {
                data: None,
                depth: 1,
                parent: None,
                node_0: None,
                node_1: None,
            })),
        }
    }

    pub fn add(&self, prefix: u32, prefix_len: u32, ip_route_entry: IpRouteEntry) {

        let mut current = Some(self.root.clone());

        for i in 1..=prefix_len {
            if let Some(n) = current {
                let mut node = n.borrow_mut();
                if (prefix >> (IP_BIT_LEN - i)) & 0x01 == 1 {
                    if node.node_1.is_none() {
                        node.node_1 = Some(Rc::new(RefCell::new(BinaryTrieNode {
                            data: None,
                            depth: i,
                            parent: Some(Rc::downgrade(&n)),
                            node_0: None,
                            node_1: None,
                        })));
                    }
                    current = node.node_1.clone();
                } else {
                    if node.node_0.is_none() {
                        node.node_0 = Some(Rc::new(RefCell::new(BinaryTrieNode {
                            data: None,
                            depth: i,
                            parent: Some(Rc::downgrade(&n)),
                            node_0: None,
                            node_1: None,
                        })));
                    }
                    current = node.node_0.clone();
                }
            }
        }
        if let Some(n) = current {
            let mut node = n.borrow_mut();
            node.data = Some(Arc::new(RwLock::new(ip_route_entry)));
        }
    }

    pub fn search(&self, prefix: u32) -> Option<Arc<RwLock<IpRouteEntry>>> {
        let mut current = Some(self.root.clone());
        let mut result: Option<Arc<RwLock<IpRouteEntry>>> = None;

        for i in 1..=IP_BIT_LEN {
            if let Some(n) = current.clone() {
                let node = n.borrow();
                if node.data.is_some() {
                    result = node.data.clone()
                }
                if (prefix >> (IP_BIT_LEN - i)) & 0x01 == 1 {
                    if node.node_1.is_none() {
                        break;
                    }
                    current = node.node_1.clone();
                } else {
                    if node.node_0.is_none() {
                        break;
                    }
                    current = node.node_0.clone();
                }
            }
        }
        return result;
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        device::NetDevice,
        ip::{IpDevice, IpRouteEntry, IpRouteType},
    };

    use super::IpRouteTable;

    #[test]
    fn add_ip_routing_tabble() {
        let fib = IpRouteTable::new();
        let prefix = 0xc0a80000; //192.168.0.0
        let prefix_len: u32 = 24;
        let ip_addr = 0xc0a80002; //192.168.0.2
        let netmask = 0xffffffff;
        let device = IpRouteEntry {
            _type: IpRouteType::Connected,
            dev: Some(NetDevice {
                name: "eth0".to_string(),
                mac_address: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],
                ip_device: IpDevice {
                    address: ip_addr,
                    netmask: netmask,
                    broadcast: ip_addr & netmask | !netmask,
                },
                fd: 0,
            }),
            next_hop: None,
        };
        let prefix2 = 0xc0a80100; //192.168.1.0
        let prefix_len2: u32 = 24;
        let device2 = IpRouteEntry {
            _type: IpRouteType::Network,
            dev: None,
            next_hop: Some(0xc0a80001),
        };
        fib.add(prefix, prefix_len, device.clone());
        fib.add(prefix2, prefix_len2, device2.clone());
        let entry = fib.search(ip_addr).unwrap();
        let entry_ro = entry.read().unwrap();
        assert_eq!(entry_ro._type, IpRouteType::Connected);
        assert_eq!(entry_ro.dev, device.dev);
        let entry2 = fib.search(0xc0a80101).unwrap();
        let entry2_ro = entry2.read().unwrap();
        assert_eq!(entry2_ro._type, IpRouteType::Network);
        assert_eq!(entry2_ro.next_hop, Some(0xc0a80001));
    }
}
