use std::ffi::NulError;
use std::io;
use std::net::AddrParseError;

use crate::dns::{DnsRequest, DnsResponse};
use crate::dns::packet::parse::ResponseParseError;

// TODO(teawithsand): TCP resolver
// TODO(teawithsand): UDP resolver
// TODO(teawithsand): Libc(aka OS) resolver

#[derive(Debug, From)]
pub enum DnsResolverError {
    IOError(io::Error),
    ParseError(ResponseParseError),

    /// domain string which contains null byte(`0x00`) may cause problems with some resolvers
    NulError(NulError),
    AddrParseError(AddrParseError),
    UnknownError,

    /// Given resolver does not support any type of query required to satisfy requirements of given function
    NotSupported,

    #[cfg(feature = "doh")]
    HyperHttpError(hyper::http::Error),

    #[cfg(feature = "doh")]
    HyperError(hyper::Error),
}

/// DnsResolver is trait which represents asynchronous DNS resolver - thing able to process dns requests and
/// return responses.
///
///
#[async_trait]
pub trait DnsResolver {
    /// send_request performs single DNS request using given resolver and parses response.
    ///
    /// # Notes
    /// If request for given query kind is not supported `DnsResolverError::NotSupported` is returned.
    /// For instance given resolver uses libc and can resolve only Ipv4 addresses.
    async fn send_request(&self, req: &DnsRequest<'_>) -> Result<DnsResponse<'static>, DnsResolverError>;
}