//! DoH module implements DNS over HTTP(S) resolver with `hyper` as HTTP client
//! It does not open stream

use std::borrow::Cow;
use std::io::Cursor;

use hyper::body::HttpBody;
use hyper::client::connect::Connect;

use crate::dns::{DnsRequest, DnsResolver, DnsResolverError, DnsResponse};

/*
use crate::dns::{
    AnyDnsClass, AnyDnsType,
    AnyQueryKind, DnsClass,
    DnsRecord, DnsType,
    QueryKind,
};
*/

/// DnsOverHttpsResolver is simple resolver which is able to resolve DNS queries with `hyper` as http client
/// and `RFC8484` capable http(s) server.
pub struct DnsOverHttpsResolver<'a, C> {
    request_url: Cow<'a, str>,
    client: hyper::Client<C>,
}

impl<'a, C> DnsOverHttpsResolver<'a, C> {
    /// new crates new resolver using url to request and hyper client.
    ///
    /// # URL
    /// For instance in order to use google's resolver use URL like `Cow::Borrowed("https://dns.google/dns-query")`
    pub fn new(request_url: Cow<'a, str>, client: hyper::Client<C>) -> Self {
        Self {
            request_url,
            client,
        }
    }

    pub fn into_inner(self) -> (Cow<'a, str>, hyper::Client<C>) {
        (self.request_url, self.client)
    }
}

#[async_trait]
impl<'a, C> DnsResolver for DnsOverHttpsResolver<'a, C>
    where C: Connect + Clone + Send + Sync + 'static {
    async fn send_request(&self, request: &DnsRequest<'_>) -> Result<DnsResponse<'static>, DnsResolverError> {
        let serialized_request = {
            let mut buf = Vec::new();
            let mut c = Cursor::new(&mut buf);
            request.to_dns_binary(&mut c).map_err(|_| DnsResolverError::UnknownError)?;
            let pos = c.position();
            buf.drain(pos as usize..);
            buf
        };

        // panic!("{:X?}", serialized_request);

        let req = hyper::Request::builder()
            .uri(self.request_url.as_ref())
            .method("POST")
            .header("Accept", "application/dns-message")
            .header("Content-Type", "application/dns-message")
            .body(hyper::body::Body::from(serialized_request))?;

        let mut res = self.client.request(req).await?;
        let data = res.body_mut().data().await;
        let data = if let Some(data) = data {
            data?
        } else {
            // TODO(teawithsand): move this to hyper error
            return Err(DnsResolverError::UnknownError);
        };
        Ok(DnsResponse::parse_dns_binary(data.as_ref())?
            .into_owned())
    }
}

// TODO(teawithsand): test it only with appropriate cfg enabled
#[cfg(all(test, nettest))]
mod test {
    use openssl::ssl::SslVerifyMode;

    use crate::dns::{AnyDnsType, DnsType};

    use super::*;

    #[test]
    fn test_can_resolve_google_different_kind_of_records() {
        // TODO(teawithsand): more robust testing in future. Google may not respond with any record sometimes for some types.

        for k in [
            DnsType::A,
            DnsType::AAAA,
            DnsType::SOA,
            DnsType::MX,
            DnsType::TXT,
            DnsType::PTR,
        ].iter().cloned() {
            let mut conn = hyper_openssl::HttpsConnector::new().unwrap();
            conn.set_callback(|cc, _url| {
                cc.set_verify(SslVerifyMode::NONE);
                Ok(())
            });
            let mut cl = hyper::Client::builder()
                .build(conn);
            let mut resolver =
                DnsOverHttpsResolver::new(Cow::Borrowed("https://dns.google/dns-query"), cl);

            let mut rt = tokio::runtime::Builder::new()
                .enable_all()
                .basic_scheduler()
                .build()
                .unwrap();
            rt.block_on(async move {
                let res =
                    resolver.send_request(
                        &DnsRequest::make_simple(AnyDnsType::Known(k), "google.com")
                    ).await.unwrap();
                if res.answers.len() > 0 {
                    assert!(res.answers.iter().all(|a| a.ty == AnyDnsType::from(k)));
                }
            });
        }
    }
}