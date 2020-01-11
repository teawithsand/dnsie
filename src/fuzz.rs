/*
pub fn fuzz_parse_names<'a>(data: &'a [u8]) {
    let mut labels: [&'a [u8]; 100] = unsafe { std::mem::uninitialized() };
    let _ = crate::dns.packet::parser::read_names(data, &mut labels);
}
*/

use crate::suffix::PublicSuffixListRule;
use crate::dns::packet::parser_utils::parse_response;

pub fn fuzz_parse_public_suffix_list_rule(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = PublicSuffixListRule::from_line(text);
    }
}

pub fn fuzz_parse_dns_response_packet(data: &[u8]) {
    let _ = parse_response(data);
}