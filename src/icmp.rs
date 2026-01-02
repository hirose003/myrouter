use bytes::{BufMut, BytesMut};
use log::{debug, info};
use std::sync::mpsc::Sender;

use crate::arp::ArpTableRequest;
use crate::ip::{ip_encapsulate_output, IpProtocol, IP_HEADER_LEN};
use crate::util::{checksum_16, htons, ip_print, ntohs, to_u16_slice};

const ICMP_HEADER: usize = 4;
const ICMP_ECHO_MINI_SIZE: usize = 5;

#[derive(Debug, Clone)]
struct IcmpHeader {
    _type: IcmpType,
    code: IcmpCode,
    checksum: u16,
}

impl TryFrom<BytesMut> for IcmpHeader {
    type Error = String;

    fn try_from(buf: BytesMut) -> Result<Self, Self::Error> {
        let _type = IcmpType::try_from(buf[0])?;
        let _type_code: [u8; 2] = buf[0..=1].try_into().unwrap();
        let code = IcmpCode::try_from(_type_code)?;
        let checksum = u16::from_be_bytes([buf[2], buf[3]]);
        Ok(IcmpHeader {
            _type,
            code,
            checksum,
        })
    }
}

impl From<IcmpHeader> for BytesMut {
    fn from(header: IcmpHeader) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u8(header._type.into());
        buf.put_u8(header.code.into());
        buf.put_u16(header.checksum);
        buf
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
enum IcmpType {
    EchoReply = 0,
    DestinationUnreachable = 1,
    EchoRequest = 8,
    TimeExceeded = 11,
}

impl TryFrom<u8> for IcmpType {
    type Error = String;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(IcmpType::EchoReply),
            1 => Ok(IcmpType::DestinationUnreachable),
            8 => Ok(IcmpType::EchoRequest),
            11 => Ok(IcmpType::TimeExceeded),
            _ => Err(format!("unsupported icmp type {}", num)),
        }
    }
}

impl From<IcmpType> for u8 {
    fn from(value: IcmpType) -> Self {
        value as u8
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IcmpCode {
    EchoReply = 0,
    DestinationUnreachable(IcmpDestinationUnreachableCode),
    TimeExceeded(IcmpTimeExceededCode),
}

impl TryFrom<[u8; 2]> for IcmpCode {
    type Error = String;

    fn try_from(num: [u8; 2]) -> Result<Self, Self::Error> {
        match num[0] {
            0 => Ok(IcmpCode::EchoReply),
            3 => match num[1] {
                _ => Ok(IcmpCode::DestinationUnreachable(
                    IcmpDestinationUnreachableCode::try_from(num[1])?,
                )),
            },
            8 => Ok(IcmpCode::EchoReply),
            11 => match num[1] {
                _ => Ok(IcmpCode::TimeExceeded(IcmpTimeExceededCode::try_from(
                    num[1],
                )?)),
            },
            _ => Err(format!("unsupported icmp code {}", num[1])),
        }
    }
}

impl From<IcmpCode> for u8 {
    fn from(value: IcmpCode) -> Self {
        match value {
            IcmpCode::EchoReply => 0,
            IcmpCode::DestinationUnreachable(num) => num.into(),
            IcmpCode::TimeExceeded(num) => num.into(),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IcmpDestinationUnreachableCode {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentNeededAndDfSet = 4,
    SourceRouteFailed = 5,
}

impl TryFrom<u8> for IcmpDestinationUnreachableCode {
    type Error = String;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(IcmpDestinationUnreachableCode::NetUnreachable),
            1 => Ok(IcmpDestinationUnreachableCode::HostUnreachable),
            2 => Ok(IcmpDestinationUnreachableCode::ProtocolUnreachable),
            3 => Ok(IcmpDestinationUnreachableCode::PortUnreachable),
            4 => Ok(IcmpDestinationUnreachableCode::FragmentNeededAndDfSet),
            5 => Ok(IcmpDestinationUnreachableCode::SourceRouteFailed),
            _ => Err(format!("Unsupported ip protocol {}", num)),
        }
    }
}

impl From<IcmpDestinationUnreachableCode> for u8 {
    fn from(value: IcmpDestinationUnreachableCode) -> Self {
        value as u8
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IcmpTimeExceededCode {
    TimeToLiveExceeded = 0,
    FragmentReassemblyTimeExceeded = 1,
}

impl TryFrom<u8> for IcmpTimeExceededCode {
    type Error = String;

    fn try_from(num: u8) -> Result<Self, Self::Error> {
        match num {
            0 => Ok(IcmpTimeExceededCode::TimeToLiveExceeded),
            1 => Ok(IcmpTimeExceededCode::FragmentReassemblyTimeExceeded),
            _ => Err(format!("Unsupported icmp tome exceedec code {}", num)),
        }
    }
}

impl From<IcmpTimeExceededCode> for u8 {
    fn from(value: IcmpTimeExceededCode) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone)]
struct IcmpEcho {
    identify: u16,
    sequence: u16,
    data: BytesMut,
}

impl TryFrom<BytesMut> for IcmpEcho {
    type Error = String;

    fn try_from(mut buf: BytesMut) -> Result<Self, Self::Error> {
        let identify = u16::from_be_bytes([buf[0], buf[1]]);
        let sequence = u16::from_be_bytes([buf[2], buf[3]]);
        let data = buf.split_off(4);
        Ok(IcmpEcho {
            identify,
            sequence,
            data,
        })
    }
}

impl From<IcmpEcho> for BytesMut {
    fn from(echo: IcmpEcho) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u16(echo.identify);
        buf.put_u16(echo.sequence);
        buf.put(echo.data);
        buf
    }
}

#[derive(Debug, Clone)]
struct IcmpDestinationUnreachable {
    unused: u32,
    data: BytesMut,
}

impl TryFrom<BytesMut> for IcmpDestinationUnreachable {
    type Error = String;

    fn try_from(_value: BytesMut) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<IcmpDestinationUnreachable> for BytesMut {
    fn from(dest_unreach: IcmpDestinationUnreachable) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u32(dest_unreach.unused);
        buf.put(dest_unreach.data);
        buf
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct IcmpTimeExceeded {
    unused: u32,
    data: BytesMut,
}

pub fn icmp_input(
    dest_addr: u32,
    src_addr: u32,
    mut buf: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
) -> Result<(), String> {
    debug!("Received: {:02x?}", &buf[..]);
    //ICMPメッセージ長より短かったら
    if buf.len() < ICMP_HEADER {
        info!("Received ICMP packet too short");
        return Ok(());
    }

    let icmp_header = IcmpHeader::try_from(buf.split_to(4))?;
    debug!("ICMP Header: {:?}", icmp_header);
    match icmp_header._type {
        IcmpType::EchoReply => {
            //ICMO Echoより短かったら
            if buf.len() < ICMP_HEADER + ICMP_ECHO_MINI_SIZE {
                info!("Received ICMP echo packet too short");
                return Ok(());
            }
            let echo = IcmpEcho::try_from(buf)?;
            info!(
                "Received icmp echo reply id {:x} seq {:x}",
                ntohs(echo.identify),
                ntohs(echo.sequence)
            );
        }
        IcmpType::DestinationUnreachable => {
            todo!()
        }
        IcmpType::EchoRequest => {
            //ICMO Echoより短かったら
            if buf.len() < ICMP_HEADER + ICMP_ECHO_MINI_SIZE {
                info!("Received ICMP echo packet too short");
                return Ok(());
            }
            let echo = IcmpEcho::try_from(buf)?;
            info!(
                "Received icmp echo request id {:x} seq {:x} data {:x}",
                ntohs(echo.identify),
                ntohs(echo.sequence),
                echo.data
            );

            let mut reply_header = IcmpHeader {
                _type: IcmpType::EchoReply,
                code: IcmpCode::EchoReply,
                checksum: 0,
            };
            let reply_body = IcmpEcho {
                identify: echo.identify, //識別番号をコピー
                sequence: echo.sequence, //シーケンス番号をコピー
                data: echo.data,
            };
            // echo replyのパケット作成
            let mut reply_buf = BytesMut::from(reply_header.clone());
            reply_buf.put(BytesMut::from(reply_body.clone()));
            reply_header.checksum = htons(checksum_16(to_u16_slice(&mut reply_buf[..])));

            let mut reply_buf = BytesMut::from(reply_header);
            reply_buf.put(BytesMut::from(reply_body));

            ip_encapsulate_output(
                dest_addr,
                src_addr,
                reply_buf,
                IpProtocol::ICMP,
                arp_table_request_tx,
            );
        }
        IcmpType::TimeExceeded => {
            todo!()
        }
    }

    return Ok(());
}

pub fn send_icmp_destination_unreachable(
    dest_addr: u32,
    src_addr: u32,
    code: IcmpCode,
    buf: BytesMut,
    arp_table_request_tx: Sender<ArpTableRequest>,
) {
    if buf.len() < (IP_HEADER_LEN + 8 as u8) as usize {
        info!("Received UDP packet too short");
        return;
    }

    let mut reply_header = IcmpHeader {
        _type: IcmpType::DestinationUnreachable,
        code: code,
        checksum: 0,
    };
    let icmp_destination_unreachable = IcmpDestinationUnreachable {
        unused: 0,
        data: buf,
    };
    info!(
        "Send Icmp Destination Unreachable from {} to {}",
        ip_print(src_addr),
        ip_print(dest_addr)
    );
    let mut reply_buf = BytesMut::from(reply_header.clone());
    reply_buf.put(BytesMut::from(icmp_destination_unreachable.clone()));
    reply_header.checksum = htons(checksum_16(to_u16_slice(&mut reply_buf[..])));

    let mut reply_buf = BytesMut::from(reply_header);
    reply_buf.put(BytesMut::from(icmp_destination_unreachable));

    ip_encapsulate_output(
        dest_addr,
        src_addr,
        reply_buf,
        IpProtocol::ICMP,
        arp_table_request_tx,
    );
}

pub fn send_icmp_time_excedded() {
    unimplemented!()
}

#[cfg(test)]
mod test {
    use crate::icmp::IcmpHeader;
    use bytes::BytesMut;

    use super::IcmpCode;
    use super::IcmpType;

    #[test]
    fn test_icmp_byte_to_struct() {
        let buf: [u8; 64] = [
            0x08, 0x00, 0x83, 0x03, 0x4d, 0x7f, 0x00, 0x01, 0x30, 0x76, 0x99, 0x68, 0x00, 0x00,
            0x00, 0x00, 0x98, 0xca, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];
        let mut buf = BytesMut::from(&buf[..]);
        let icmp_header = IcmpHeader::try_from(buf.split_to(4)).unwrap();
        assert_eq!(icmp_header._type, IcmpType::EchoRequest);
        assert_eq!(icmp_header.code, IcmpCode::EchoReply);
    }
}
