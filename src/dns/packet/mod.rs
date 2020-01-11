//! Record module implements DNS parsing which is required in order to make this crate work with either DNS over UDP, DNS over TCP,
//! DNS over TLS or DNS over HTTPS
//!
//! For implementation details take look at https://tools.ietf.org/html/rfc1035
pub mod primitives;
pub mod query;
pub mod parse;
// pub mod check;