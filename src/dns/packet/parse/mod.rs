pub use parser_utils::ResponseParseError;

use crate::dns::DnsResponse;

mod parser_utils;

impl<'a> DnsResponse<'a> {
    // TODO(teawithsand): implement parse function here rather than calling it from parser utils
    #[inline]
    pub fn parse_dns_binary(data: &'a [u8]) -> Result<Self, ResponseParseError> {
        parser_utils::parse_response(data)
    }
}