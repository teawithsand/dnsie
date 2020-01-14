use std::borrow::Cow;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

/// flag_enum creates enum which may be either known or unknown(yet) flag.
macro_rules! flag_enum {
    (
        $name:ident, $any_name:ident: $val_ty:ty {
             $(
                $variant_name:ident = $variant_val:tt
             ),*
        }

    ) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
        pub enum $name {
            $(
                $variant_name = ($variant_val) as isize
            ),*
        }

        impl $name {
            // deprecate this fn?
            #[inline]
            pub fn try_from_num(n: $val_ty) -> Result<Self, ()> {
                Self::try_from(n)
            }

            #[inline]
            pub fn into_num(self) -> $val_ty {
                self.into()
            }
        }

        impl Into<$val_ty> for $name {
            #[inline]
            fn into(self) -> $val_ty {
                match self {
                    $(
                        Self::$variant_name => $variant_val
                    ),*
                }
            }
        }

        impl TryFrom<$val_ty> for $name {
            type Error = ();

            #[inline]
            fn try_from(val: $val_ty) -> Result<Self, Self::Error> {
                match val {
                    $(
                        $variant_val => Ok(Self::$variant_name),
                    )*
                    _ => Err(()),
                }
            }
        }

        /*
        impl Into<$any_name> for $name {
            fn into(self) -> $any_name {
                $any_name::Known(self)
            }
        }
        */

        impl From<$name> for $any_name {
            fn from(data: $name) -> $any_name {
                $any_name::Known(data)
            }
        }

        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
        pub enum $any_name {
            Known($name),
            Unknown($val_ty)
        }

        impl $any_name {
            pub fn into_canonical(self) -> Self {
                match self {
                    Self::Known(v) => Self::Known(v),
                    Self::Unknown(v) => match $name::try_from(v) {
                        Ok(new_v) => Self::Known(new_v),
                        Err(_) => Self::Unknown(v),
                    }
                }
            }
        }

        impl Into<$val_ty> for $any_name {
            #[inline]
            fn into(self) -> $val_ty {
                match self {
                    Self::Known(v) => v.into(),
                    Self::Unknown(v) => v,
                }
            }
        }

        impl From<$val_ty> for $any_name {
            #[inline]
            fn from(val: $val_ty) -> Self {
                Self::Unknown(val).into_canonical()
            }
        }
    }
}

/// MaybeValidString contains either `&str` or `&[u8]` in case parser was not able to parse it.
/// Both types are wrapped in cows
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[derive(From, TryInto)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum MaybeValidString<'a> {
    Parsed(Cow<'a, str>),
    Raw(Cow<'a, [u8]>),
}

impl<'a> From<&'a str> for MaybeValidString<'a> {
    fn from(text: &'a str) -> Self {
        MaybeValidString::Parsed(Cow::Borrowed(text))
    }
}

impl<'a> From<&'a [u8]> for MaybeValidString<'a> {
    fn from(data: &'a [u8]) -> Self {
        MaybeValidString::Raw(Cow::Borrowed(data))
    }
}

impl<'a> MaybeValidString<'a> {
    pub fn into_canonical(self) -> Self {
        match self {
            MaybeValidString::Parsed(text) => Self::Parsed(text),
            MaybeValidString::Raw(data) => {
                match data {
                    Cow::Borrowed(v) => match std::str::from_utf8(v) {
                        Ok(v) => Self::Parsed(Cow::Borrowed(v)),
                        Err(_) => Self::Raw(data),
                    }
                    Cow::Owned(v) => {
                        // for performance reason we are going to use some unsafe glue here

                        // Note: in fact what is done here is done already in STD lib:
                        //      1. run check
                        //      2. If it passes return Ok from unsafe function result else return Err

                        // 0. if v is not valid str return self as-is without changes
                        if let Ok(text) = std::str::from_utf8(&v) {
                            Self::Parsed(Cow::Owned(text.to_string()))
                        } else {
                            Self::Raw(Cow::Owned(v))
                        }
                    }
                }
            }
        }
    }

    pub fn into_owned(self) -> MaybeValidString<'static> {
        match self {
            MaybeValidString::Parsed(a) => MaybeValidString::Parsed(Cow::Owned(a.into_owned())),
            MaybeValidString::Raw(a) => MaybeValidString::Raw(Cow::Owned(a.into_owned())),
        }
    }
}

flag_enum!(
    DnsType, AnyDnsType: u16 {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        SRV = 33
    }
);

flag_enum!(
    DnsClass, AnyDnsClass: u16 {
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4
    }
);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct SrvData<'a> {
    pub target: MaybeValidString<'a>,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

impl<'a> SrvData<'a> {
    pub fn into_owned(self) -> SrvData<'static> {
        SrvData {
            target: self.target.into_owned(),
            port: self.port,
            priority: self.priority,
            weight: self.weight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct SoaData<'a> {
    pub mname: MaybeValidString<'a>,
    pub rname: MaybeValidString<'a>,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

impl<'a> SoaData<'a> {
    pub fn into_owned(self) -> SoaData<'static> {
        SoaData {
            mname: self.mname.into_owned(),
            rname: self.rname.into_owned(),
            serial: self.serial,
            refresh: self.refresh,
            retry: self.retry,
            expire: self.expire,
            minimum: self.minimum,
        }
    }
}

/// DNSRecord represents single DNS dns.packet that this library is able to parse
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum DnsRecord<'a> {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),

    // CPU, OS fields
    HINFO(MaybeValidString<'a>, MaybeValidString<'a>),
    // RMAILBX, EMAILBX fields
    MINFO(MaybeValidString<'a>, MaybeValidString<'a>),

    CNAME(MaybeValidString<'a>),
    TXT(MaybeValidString<'a>),
    PTR(MaybeValidString<'a>),
    MX(MaybeValidString<'a>, u16),
    NS(MaybeValidString<'a>),
    SRV(SrvData<'a>),
    SOA(SoaData<'a>),
}

impl<'a> DnsRecord<'a> {
    pub fn into_owned(self) -> DnsRecord<'static> {
        match self {
            DnsRecord::A(a) => DnsRecord::A(a),
            DnsRecord::AAAA(a) => DnsRecord::AAAA(a),
            DnsRecord::HINFO(cpu, os) =>
                DnsRecord::HINFO(cpu.into_owned(), os.into_owned()),
            DnsRecord::MINFO(rmailbx, emailbx) =>
                DnsRecord::MINFO(rmailbx.into_owned(), emailbx.into_owned()),
            DnsRecord::CNAME(name) => DnsRecord::CNAME(name.into_owned()),
            DnsRecord::TXT(txt) => DnsRecord::TXT(txt.into_owned()),
            DnsRecord::PTR(ptr) => DnsRecord::PTR(ptr.into_owned()),
            DnsRecord::MX(name, priority) => DnsRecord::MX(name.into_owned(), priority),
            DnsRecord::NS(ns) => DnsRecord::NS(ns.into_owned()),
            DnsRecord::SRV(data) => DnsRecord::SRV(data.into_owned()),
            DnsRecord::SOA(data) => DnsRecord::SOA(data.into_owned())
        }
    }
}

flag_enum!(
    QueryKind, AnyQueryKind: u8 {
        StandardQuery = 0,
        InverseQuery = 1,
        ServerStatusRequest = 2
    }
);

flag_enum!(
    ResponseCode, AnyResponseCode: u8 {
        NoErrorCondition = 0,
        FormatError = 1,
        ServerFailure = 2,
        NameError = 3,
        NotImplemented = 4,
        Refused = 5
    }
);

/// DNSResponse is parsed response of DNS server.
/// It contains multiple `DnsAnswer`s
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct DnsResponse<'a> {
    pub id: u16,
    pub answers: Vec<DnsAnswer<'a>>,

    /// query_kind is set dependent on opcode in query and it specifies kind of requested data
    pub query_kind: AnyQueryKind,

    /// response indicates if response was success or error
    pub response_code: AnyResponseCode,
}

impl<'a> DnsResponse<'a> {
    /// into_owned copies data if required in order to make struct lifetime `'static`
    pub fn into_owned(self) -> DnsResponse<'static> {
        DnsResponse {
            id: self.id,
            answers: self.answers.into_iter().map(|a| a.into_owned()).collect(),
            query_kind: self.query_kind,
            response_code: self.response_code,
        }
    }
}

/// DnsRequest is parsed(or manually constructed) dns request
/// which may be serialized and sent to DNS server.
///
/// Right now the only serialization destination format is DNS binary but it may be serialized
/// to some JSON specific for DNS resolver platform.
///
/// # Note
/// It does not contain fields which are.
pub struct DnsRequest<'a> {
    pub id: u16,

    /// query_name is domain name represented as string
    pub query_name: Cow<'a, str>,
    pub query_kind: AnyQueryKind,

    pub ty: AnyDnsType,
    pub cls: AnyDnsClass,
}

impl<'a> DnsRequest<'a> {
    /// make_simple constructs request with reasonable defaults to resolve given record type for given domain
    pub fn make_simple(ty: AnyDnsType, domain: &'a str) -> Self {
        DnsRequest {
            id: 0,
            query_name: Cow::Borrowed(domain),
            query_kind: AnyQueryKind::Known(QueryKind::StandardQuery),
            ty,
            cls: AnyDnsClass::Known(DnsClass::IN),
        }
    }
}

/// DNSResponse contains single response for given dns packet
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct DnsAnswer<'a> {
    pub record: Option<DnsRecord<'a>>,
    pub ty: AnyDnsType,
    pub cls: AnyDnsClass,
    pub ttl: u32,
    pub name: MaybeValidString<'a>,
}

impl<'a> DnsAnswer<'a> {
    pub fn into_owned(self) -> DnsAnswer<'static> {
        DnsAnswer {
            record: self.record.map(|r| r.into_owned()),
            ty: self.ty,
            cls: self.cls,
            ttl: self.ttl,
            name: self.name.into_owned(),
        }
    }
}