use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::Utf8Error;
use std::string::FromUtf8Error;

use crate::dns::{DnsAnswer, DnsResponse, MaybeValidString};
use crate::dns::packet::primitives::{
    AnyDnsClass, AnyDnsType, AnyQueryKind, AnyResponseCode,
    DnsClass, DnsRecord, DnsType,
    SoaData, SrvData,
};

#[derive(Debug, From)]
pub enum ResponseParseError {
    OutOfBoundsIndex,

    InvalidSize,

    InvalidStructure,

    Utf8Error(Utf8Error),
    FromUtf8Error(FromUtf8Error)
}

#[derive(Clone, PartialEq)]
struct PacketParser<'a> {
    /// Because RFC1035 mentions something called message compression
    /// which in general works like:
    ///     Here is pointer to data. Read it form this place.
    buf: &'a [u8]
}

impl<'a> PacketParser<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
        }
    }
}

impl<'a> PacketParser<'a> {
    // TODO(teawithsand): Beautify this function
    /// parse_packet takes some basic information about DNS packet and parses it.
    fn parse_packet(&self, ty: AnyDnsType, cl: AnyDnsClass, buf: &'a [u8]) -> Result<Option<DnsRecord<'a>>, ResponseParseError> {
        Ok(Some(match ty.into_canonical() {
            AnyDnsType::Known(ty) => match ty {
                DnsType::NS => DnsRecord::NS(self.parse_ns(buf)?),
                DnsType::CNAME => DnsRecord::CNAME(self.parse_cname(buf)?),
                DnsType::SOA => DnsRecord::SOA(self.parse_soa(buf)?),
                DnsType::PTR => DnsRecord::PTR(self.parse_ptr(buf)?),
                DnsType::TXT => DnsRecord::TXT(self.parse_txt(buf)?),
                DnsType::SRV => DnsRecord::SRV(self.parse_srv(buf)?),
                DnsType::HINFO => {
                    let (a, b) = self.parse_hinfo(buf)?;
                    DnsRecord::HINFO(a, b)
                }
                DnsType::MINFO => {
                    let (a, b) = self.parse_minfo(buf)?;
                    DnsRecord::MINFO(a, b)
                }
                DnsType::MX => {
                    let (addr, priority) = self.parse_mx(buf)?;
                    DnsRecord::MX(addr, priority)
                }
                ty => {
                    let interpret_ips = match cl.into_canonical() {
                        AnyDnsClass::Known(cl) => match cl {
                            DnsClass::IN => true,
                            _ => false,
                        }
                        AnyDnsClass::Unknown(_) => true,
                    };
                    if interpret_ips {
                        match ty {
                            DnsType::A => DnsRecord::A(self.parse_a(buf)?),
                            DnsType::AAAA => DnsRecord::AAAA(self.parse_aaaa(buf)?),
                            _ => {
                                return Ok(None);
                            }
                        }
                    } else {
                        return Ok(None);
                    }
                }
            }
            AnyDnsType::Unknown(_) => {
                return Ok(None);
            }
        }))
    }

    fn parse_a(&self, buf: &'a [u8]) -> Result<Ipv4Addr, ResponseParseError> {
        if buf.len() != 4 {
            return Err(ResponseParseError::InvalidSize);
        }
        Ok(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]))
    }

    fn parse_aaaa(&self, buf: &'a [u8]) -> Result<Ipv6Addr, ResponseParseError> {
        // u16 * ipv6 number count
        if buf.len() != 2 * 8 {
            return Err(ResponseParseError::InvalidSize);
        }
        // numbers are encoded as big endian
        Ok(Ipv6Addr::new(
            u16::from_be_bytes([buf[0], buf[1]]),
            u16::from_be_bytes([buf[2], buf[3]]),
            u16::from_be_bytes([buf[4], buf[5]]),
            u16::from_be_bytes([buf[6], buf[7]]),
            u16::from_be_bytes([buf[8], buf[9]]),
            u16::from_be_bytes([buf[10], buf[11]]),
            u16::from_be_bytes([buf[12], buf[13]]),
            u16::from_be_bytes([buf[14], buf[15]]),
        ))
    }

    fn parse_mx(&self, buf: &'a [u8]) -> Result<(MaybeValidString<'a>, u16), ResponseParseError> {
        if buf.len() < 2 {
            return Err(ResponseParseError::InvalidSize);
        }
        let priority = u16::from_be_bytes([buf[0], buf[1]]);
        let (_, _, data) = self.read_names(&buf[2..])?;
        Ok((data, priority))
    }

    fn parse_cname(&self, buf: &'a [u8]) -> Result<MaybeValidString<'a>, ResponseParseError> {
        let (_, _, data) = self.read_names(buf)?;
        Ok(data)
    }

    fn parse_srv(&self, buf: &'a [u8]) -> Result<SrvData<'a>, ResponseParseError> {
        if buf.len() < 6 {
            return Err(ResponseParseError::InvalidSize);
        }
        Ok(SrvData {
            port: u16::from_be_bytes([buf[0], buf[1]]),
            priority: u16::from_be_bytes([buf[2], buf[3]]),
            weight: u16::from_be_bytes([buf[4], buf[5]]),
            target: {
                let (_, _, res) = self.read_names(&buf[6..])?;
                res
            },
        })
    }

    fn parse_ns(&self, buf: &'a [u8]) -> Result<MaybeValidString<'a>, ResponseParseError> {
        let (_, _, res) = self.read_names(buf)?;
        Ok(res)
    }

    fn parse_ptr(&self, buf: &'a [u8]) -> Result<MaybeValidString<'a>, ResponseParseError> {
        let (_, _, res) = self.read_names(buf)?;
        Ok(res)
    }

    fn parse_hinfo(&self, buf: &'a [u8]) -> Result<(MaybeValidString<'a>, MaybeValidString<'a>), ResponseParseError> {
        if buf.len() < 1 {
            return Err(ResponseParseError::InvalidSize);
        }
        let sz = buf[0] as usize;
        if sz + 1 > buf.len() {
            return Err(ResponseParseError::OutOfBoundsIndex);
        }
        let cpu = &buf[1..(sz + 1)];
        let buf = &buf[sz + 1..];
        if buf.len() < 1 {
            return Err(ResponseParseError::InvalidSize);
        }
        let sz = buf[0] as usize;
        if sz + 1 > buf.len() {
            return Err(ResponseParseError::OutOfBoundsIndex);
        }
        let os = &buf[1..(sz + 1)];
        Ok((
            MaybeValidString::Raw(Cow::Borrowed(cpu)).into_canonical(),
            MaybeValidString::Raw(Cow::Borrowed(os)).into_canonical()
        ))
    }

    fn parse_minfo(&self, buf: &'a [u8]) -> Result<(MaybeValidString<'a>, MaybeValidString<'a>), ResponseParseError> {
        let (offset, _, rmailbx) = self.read_names(buf)?;
        if offset > buf.len() {
            return Err(ResponseParseError::OutOfBoundsIndex);
        }
        let (_, _, emailbx) = self.read_names(buf)?;
        Ok((rmailbx, emailbx))
    }

    // note: TXT may include multiple strings.
    // for spf purposes it does not make any difference anyway...
    fn parse_txt(&self, buf: &'a [u8]) -> Result<MaybeValidString<'a>, ResponseParseError> {
        if buf.len() < 1 {
            return Err(ResponseParseError::InvalidSize);
        }
        let sz = buf[0] as usize;
        if buf.len() < sz + 1 {
            return Err(ResponseParseError::InvalidSize);
        }
        // here: investigate: RFC says that there may be many character string but...
        // how many?

        // TODO(teawithsand): Implement parsing of text of dns.packet
        // <character-string> is expressed in one or two ways: as a contiguous set
        // of characters without interior spaces,
        // /THIS IS IMPLEMENTED FURTHER PART IS NOT/
        // or as a string beginning with a "
        // and ending with a ".  Inside a " delimited string any character can
        // occur, except for a " itself, which must be quoted using \ (back slash).
        Ok(MaybeValidString::Raw(Cow::Borrowed(&buf[1..(sz + 1)])).into_canonical())
    }

    fn parse_soa(&self, buf: &'a [u8]) -> Result<SoaData<'a>, ResponseParseError> {
        let (offset, _, primary_ns) = self.read_names(buf)?;
        debug_assert!(offset <= buf.len(), "Invalid offset produced by read_names");
        let buf = &buf[offset..];

        let (offset, _, resp_mailbox) = self.read_names(buf)?;
        debug_assert!(offset <= buf.len(), "Invalid offset produced by read_names");
        let buf = &buf[offset..];
        if buf.len() < 20 {
            return Err(ResponseParseError::InvalidSize);
        }
        // TODO(teawithsand): if rfc does not state that integer is unsigned then it's signed
        //  right?
        Ok(SoaData {
            mname: primary_ns,
            rname: resp_mailbox,
            serial: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            refresh: i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            retry: i32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            expire: i32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            minimum: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
        })
    }

    fn internal_read_names(
        &self,
        buf: &'a [u8],
        labels: &mut Vec<&'a [u8]>,
        used_pointer_count: u32,
    ) -> Result<(usize, usize), ResponseParseError> {
        // how many pointers may be there...
        // we have to prevent infinite recursion stack
        if used_pointer_count > 25 {
            return Err(ResponseParseError::InvalidStructure);
        }
        let mut offset = 0;
        loop {
            if offset >= buf.len() {
                return Err(ResponseParseError::OutOfBoundsIndex);
            }
            let len = buf[offset] as usize;
            // ...The domain name terminates with the zero length octet
            if len == 0 {
                offset += 1;
                break;
            }
            if len & 0xc0 == 0xc0 {
                if offset >= buf.len() || offset + 1 >= buf.len() {
                    return Err(ResponseParseError::OutOfBoundsIndex);
                }
                let new_offset = (u16::from_be_bytes([buf[offset], buf[offset + 1]]) & 0x3fff) as usize;
                if new_offset > self.buf.len() {
                    return Err(ResponseParseError::OutOfBoundsIndex);
                }
                // NOTE: calling self.internal_read_names with may_be_compressed=false
                // Is not 100% RFC compatible BUT prevents us from being stuck in infinite recursion loop when
                // pointer one points to pointer two and vice versa
                self.internal_read_names(&self.buf[new_offset..], labels, used_pointer_count + 1)?;
                offset += 2;
                break;
            } else {
                if offset + 1 > buf.len() || offset + len + 1 > buf.len() {
                    return Err(ResponseParseError::OutOfBoundsIndex);
                }
                labels.push(&buf[offset + 1..offset + len + 1]);
                offset += len + 1;
            }
        }
        Ok((offset, labels.len()))
    }

    /// read_names reads names form given DNS dns.packet to returning offset, amount of labels found
    /// and result after concatenation
    ///
    /// # Note
    /// Please note that this function DOES NOT CHECK if result is valid utf8 neither ascii(rust `&str`).
    fn read_names(&self, buf: &'a [u8]) -> Result<(usize, usize, MaybeValidString<'a>), ResponseParseError> {
        // TODO(teawithsand): knowing that there is upper bound of labels that may be provided
        //  use some stack allocated vector for this(with known start capacity)
        //  so our parser may be even more easily migrated to
        //  (NOTE: it could be stack allocated up to N entries and then normal heap vector)
        let mut labels = Vec::new();

        let (offset, count) = self.internal_read_names(buf, &mut labels, 0)?;

        debug_assert_eq!(count, labels.len());

        if labels.len() == 0 {
            Ok((offset, count, MaybeValidString::Parsed(Cow::Owned(String::new()))))
        } else if labels.len() == 1 {
            Ok((offset, count, MaybeValidString::Raw(Cow::Borrowed(labels[0])).into_canonical()))
        } else {
            Ok((offset, count,
                /*
                // labels have to be joined with dot...
                labels
                    .into_iter()
                    .map(|v| Vec::from(v))
                    .flatten()
                    .collect()
                    */
                {
                    let mut res = Vec::new();
                    let dot_switch = labels.len() - 1; // in order to find out last iteration index
                    for (i, l) in labels.into_iter().enumerate() {
                        res.extend_from_slice(l);
                        if i != dot_switch {
                            res.push(b'.');
                        }
                    }
                    MaybeValidString::Raw(Cow::Owned(res)).into_canonical()
                }
            ))
        }
    }
}

// TODO(teawithsand): move this function to DnsResponse level
/// parse_response parses raw DNS response received from DNS server
///
/// # Result order
/// Result order is preserved. It's same just like in original data.
pub fn parse_response(data: &[u8]) -> Result<DnsResponse, ResponseParseError> {
    // let orig_data = data;
    if data.len() < 12 {
        return Err(ResponseParseError::InvalidSize);
    }
    let id = &data[..2];
    let pp = PacketParser::new(data);

    /*
    // here stuff like is this response may be checked but whatever.

    // these checks are not really relevant for fuzzer
    // and only slow it down
    #[cfg(not(fuzzer))]
    {
    if data[3] & 1 == 0 {}
    }
    */

    let query_kind = {
        let opcode = (data[3] << 1) & 0b11110000;
        let opcode = opcode >> 4;
        debug_assert!(opcode <= 16);
        AnyQueryKind::from(opcode)
    };

    let response_code = {
        let rcode = (data[4]) & 0b00001111;
        debug_assert!(rcode <= 16);
        AnyResponseCode::from(rcode)
    };
    let qd_count = u16::from_be_bytes([data[4], data[5]]);
    let res_count = u16::from_be_bytes([data[6], data[7]]);
    let mut data = &data[12..];

    // TODO(teawithsand): parse(and return) queries here, right now they are ignored
    for _ in 0..qd_count {
        let (o, _, _) = pp.read_names(data)?;
        let o = o + 4;
        if o > data.len() {
            return Err(ResponseParseError::OutOfBoundsIndex);
        }
        data = &data[o..];
    }

    let mut answers = Vec::new();
    for _ in 0..res_count {
        let (o, _, name) = pp.read_names(data)?;

        let buf = &data[o..];
        if buf.len() < 10 {
            return Err(ResponseParseError::OutOfBoundsIndex);
        }

        let ty = AnyDnsType::from(u16::from_be_bytes([buf[0], buf[1]]));
        let cls = AnyDnsClass::from(u16::from_be_bytes([buf[2], buf[3]]));
        let ttl = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let rdata_len = u16::from_be_bytes([buf[8], buf[9]]) as usize;

        if rdata_len > buf.len() - 10 {
            return Err(ResponseParseError::OutOfBoundsIndex);
        }
        let rdata = &buf[10..rdata_len + 10];
        data = &buf[rdata_len + 10..];

        let parsed = pp.parse_packet(ty, cls, rdata)?;

        answers.push(DnsAnswer {
            record: parsed,
            ty,
            cls,
            ttl,
            name,
        })
    }
    Ok(DnsResponse {
        id: u16::from_be_bytes([id[0], id[1]]),
        query_kind,
        answers,
        response_code,
    })
}

#[cfg(test)]
mod test {
    // Tests taken from:
    // https://github.com/aol/moloch
    // Files from tests/pcap/dns-*.pcap
    // interpreted as hexstream with wireshark and then simply cut off non-dns part

    use std::borrow::Cow;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use super::*;

    const GITHUB_RESPONSE: &str = "9663818000010002000000000667697468756203636f6d0000010001c00c00010001000000050004c01efd70c00c00010001000000050004c01efd71";
    const CNAME_AAAA_RESPONSE: &str = "01d181800001000400000000017007747970656b6974036e657400001c0001c00c000500010000005f001b017007747970656b6974066e65742d763207656467656b6579c016c02b0005000100000180001805653833383504647363670a616b616d616965646765c016c052001c000100000014001026001404002702a200000000000020c1c052001c0001000000140010260014040027029900000000000020c1";
    const MX_RESPONSE: &str = "4c1781800001000200020002026d7803636f6d00000f0001c00c000f000100000e10001c000a08636c7573746572350275730b6d6573736167656c616273c00fc00c000f000100000e10000e001409636c75737465723561c02fc00c0002000100000e10001504646e73320d737461626c657472616e736974c00fc00c0002000100000e10000704646e7331c06bc06600010001000005160004413dbc04c0870001000100000de7000445145f04";

    fn run_test(data: &str, cb: impl FnOnce(&[u8])) {
        let data = hex::decode(data).unwrap();
        (cb)(&data[..])
    }

    #[test]
    fn test_can_parse_github_response() {
        run_test(GITHUB_RESPONSE, |data| {
            let res = parse_response(data).unwrap();
            assert_eq!(res.answers.len(), 2);
            assert_eq!(res.answers[0].record.as_ref().unwrap(), &DnsRecord::A(Ipv4Addr::new(192, 30, 253, 112)));
            assert_eq!(res.answers[1].record.as_ref().unwrap(), &DnsRecord::A(Ipv4Addr::new(192, 30, 253, 113)));
        });
    }

    #[test]
    fn test_can_parse_mx_response() {
        run_test(MX_RESPONSE, |data| {
            let res = parse_response(data).unwrap();
            assert_eq!(res.answers.len(), 2);
            assert_eq!(res.answers[0].record.as_ref().unwrap(), &DnsRecord::MX(
                MaybeValidString::Parsed(Cow::Owned(
                    String::from("cluster5.us.messagelabs.com")
                )),
                10,
            ));
            assert_eq!(res.answers[1].record.as_ref().unwrap(), &DnsRecord::MX(
                MaybeValidString::Parsed(Cow::Owned(
                    String::from("cluster5a.us.messagelabs.com")
                )),
                20,
            ));
        });
    }

    #[test]
    fn test_can_parse_cname_aaaa_response() {
        run_test(CNAME_AAAA_RESPONSE, |data| {
            let res = parse_response(data).unwrap();
            assert_eq!(res.answers.len(), 4);
            assert_eq!(res.answers[0].record.as_ref().unwrap(), &DnsRecord::CNAME(
                MaybeValidString::Parsed(Cow::Owned(
                    String::from("p.typekit.net-v2.edgekey.net")
                ))
            ));
            assert_eq!(res.answers[1].record.as_ref().unwrap(), &DnsRecord::CNAME(
                MaybeValidString::Parsed(Cow::Owned(
                    String::from("e8385.dscg.akamaiedge.net")
                ))
            ));
            assert_eq!(res.answers[2].record.as_ref().unwrap(), &DnsRecord::AAAA(
                Ipv6Addr::from_str("2600:1404:27:2a2::20c1").unwrap()
            ));
            assert_eq!(res.answers[3].record.as_ref().unwrap(), &DnsRecord::AAAA(
                Ipv6Addr::from_str("2600:1404:27:299::20c1").unwrap()
            ));
        });
    }
}