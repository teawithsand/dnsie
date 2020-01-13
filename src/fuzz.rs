pub fn fuzz_parse_dns_response_packet(data: &[u8]) {
    let _ = crate::DnsResponse::parse_dns_binary(data);
}