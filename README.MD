# dnsie

[documentation](https://docs.rs/dnsie)

DNSie is rust dns client library. 
It's goal is to be small, simple, cross platform DNS client library with many implementations
of resolvers and transports for DNS packets.
 
It implements following DNS types:
 - A
 - AAAA
 - MX
 - CNAME
 - HINFO
 - MINFO
 - SOA 
 - PTR 
 - SRV 
 - TXT 
 - NS

# Serialization
Records may be serialized with `serde` if `serialize` feature is enabled

# Testing
Some tests require network in order to work properly.
Run `cargo test` with `RUSTFLAGS="--cfg nettest"` in order to run tests which require network.