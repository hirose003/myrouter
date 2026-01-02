pub fn mac_print(n: &[u8]) -> String {
    let mut r = String::new();
    r.push_str(&format!("{:02x}:", n[0]));
    r.push_str(&format!("{:02x}:", n[1]));
    r.push_str(&format!("{:02x}:", n[2]));
    r.push_str(&format!("{:02x}:", n[3]));
    r.push_str(&format!("{:02x}:", n[4]));
    r.push_str(&format!("{:02x}", n[5]));
    return r;
}

pub fn ip_print(ip: u32) -> String {
    return ip_ntoa(htnol(ip));
}

pub fn ip_ntoa(ip: u32) -> String {
    let mut r = String::new();
    let a: u8 = (ip & 0x000000ff) as u8;
    let b: u8 = (ip >> 8 & 0x000000ff) as u8;
    let c: u8 = (ip >> 16 & 0x000000ff) as u8;
    let d: u8 = (ip >> 24 & 0x000000ff) as u8;
    r.push_str(&format!("{}.", a));
    r.push_str(&format!("{}.", b));
    r.push_str(&format!("{}.", c));
    r.push_str(&format!("{}", d));
    return r;
}

pub fn htons(u: u16) -> u16 {
    u.to_be()
}

pub fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

pub fn htnol(u: u32) -> u32 {
    u.to_be()
}

pub fn ntohl(u: u32) -> u32 {
    u32::from_be(u)
}

pub fn to_u16_slice(slice: &mut [u8]) -> &mut [u16] {
    let byte_len = slice.len() / 2 + slice.len() % 2;
    unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr().cast::<u16>(), byte_len) }
}

pub fn checksum_16(buffer: &[u16]) -> u16 {
    let mut sum: u32 = 0;
    let mut count = buffer.len();

    while count > 0 {
        sum += buffer[count - 1] as u32;
        count -= 1;
    }

    if count > 0 {
        sum += buffer[count - 1] as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16)
    }

    !sum as u16
}

#[cfg(test)]
mod test {
    use super::checksum_16;
    use crate::util::{htons, to_u16_slice};

    #[test]
    fn test_htons() {
        let test_u16: u16 = 0x0001;
        let result = htons(test_u16);
        assert_eq!(result, 0x0100);
    }

    #[test]
    fn test_checksum() {
        let mut buf: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x34, 0x51, 0x25, 0x40, 0x00, 0xff, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x0a, 0xbb, 0x0a, 0x00, 0x03, 0xc3,
        ];
        let mut buf2: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0xd7, 0xe1, 0x00, 0x01, 0x88, 0xcc, 0x67, 0x67, 0x00, 0x00,
            0x00, 0x00, 0x75, 0xc9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];

        let checksum = checksum_16(to_u16_slice(&mut buf[..]));
        let checksum2 = checksum_16(to_u16_slice(&mut buf2[..]));
        assert_eq!(checksum, 0x2108);
        assert_eq!(checksum2, 0x4cff);
    }
}
