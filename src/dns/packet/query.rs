use std::io;

use crate::dns::DnsRequest;

impl<'a> DnsRequest<'a> {
    /// to_dns_binary serializes given request into DNS binary format.
    ///
    /// # Error
    /// It returns error if writer fails.
    /// If some label can't be encoded for some reason appropriate `std::io::Error` is returned.
    /// Otherwise it always succeeds and returns `Ok(())`.
    ///
    /// # Note
    /// Checks for name correctness aren't necessarily strict and thus this function may create
    /// invalid(according to RFC) dns request.
    /// This may happen for instance when there are too many labels.
    pub fn to_dns_binary(&self, w: &mut impl io::Write) -> Result<(), io::Error> {
        /*
        Format described in RFC:

        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        */

        let query_kind_num: u8 = self.query_kind.into();
        debug_assert!(query_kind_num <= 0b00001111); // ensure only four bits are allowed for this opcode
        let query_kind_num = query_kind_num & 0b00001111;

        // id row
        w.write_all(&self.id.to_be_bytes()[..])?;
        // second row
        w.write_all(&[
            0b00000000 | (query_kind_num << 3), 0b00000000
        ])?;
        // QDCOUNT row
        // there is one query
        w.write_all(&1u16.to_be_bytes()[..])?;
        // ANCOUNT row
        w.write_all(&0u16.to_be_bytes()[..])?;
        // NSCOUNT row
        w.write_all(&0u16.to_be_bytes()[..])?;
        // ARCOUNT row
        w.write_all(&0u16.to_be_bytes()[..])?;

        for l in self.query_name.split(".") {
            if l.len() > 63 {
                return Err(io::Error::new(io::ErrorKind::Other, "Some label in name is too long"));
            }
            if l.len() == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "Some label in name is zero sized"));
            }
            w.write_all(&[(l.len() as u8)])?;
            w.write_all(l.as_bytes())?;
        }
        // last label with zero length
        w.write_all(&[0u8])?;

        let ty: u16 = self.ty.into();
        let cls: u16 = self.cls.into();
        w.write_all(&ty.to_be_bytes()[..])?;
        w.write_all(&cls.to_be_bytes()[..])?;

        Ok(())
    }
}