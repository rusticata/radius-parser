use nom::{IResult,be_u8,be_u32,Needed};
use std::net::Ipv4Addr;
use enum_primitive::FromPrimitive;

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum RadiusAttributeType {
    UserName = 1,
    UserPassword = 2,
    ChapPassword = 3,
    NasIPAddress = 4,
    NasPort = 5,
    ServiceType = 6,
    FramedProtocol = 7,
    FramedIPAddress = 8,
    FramedIPNetmask = 9,
    FramedRouting = 10,
    FilterId = 11,
    FramedMTU = 12,
    FramedCompression = 13,
    VendorSpecific = 26,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum ServiceType {
    Login = 1,
    Framed = 2,
    CallbackLogin = 3,
    CallbackFramed = 4,
    Outbound = 5,
    Administrative = 6,
    NasPrompt = 7,
    AuthenticateOnly = 8,
    CallbackNasPrompt = 9,
    CallCheck = 10,
    CallbackAdministrative = 11,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum FramedRouting {
    None = 0,
    Send = 1,
    Receive = 2,
    SendReceive = 3,
}
}

enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum FramedProtocol {
    Ppp = 1,
    Slip = 2,
    /// AppleTalk Remote Access Protocol
    Arap = 3,
    /// Gandalf proprietary SingleLink/MultiLink protocol
    Gandalf = 4,
    /// Xylogics proprietary IPX/SLIP
    Xylogics = 5,
    /// X.75 Synchronous
    X75 = 6,
}
}


/// This Attribute indicates a compression protocol to be used for the
/// link.  It MAY be used in Access-Accept packets.  It MAY be used in
/// an Access-Request packet as a hint to the server that the NAS
/// would prefer to use that compression, but the server is not
/// required to honor the hint.
///
/// More than one compression protocol Attribute MAY be sent.  It is
/// the responsibility of the NAS to apply the proper compression
/// protocol to appropriate link traffic.
enum_from_primitive! {
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum FramedCompression {
    /// No compression
    None = 0,
    /// VJ TCP/IP header compression (See RFC1144)
    TcpIp = 1,
    /// IPX header compression
    Ipx = 2,
    /// Stac-LZS compression
    StaticLzs = 3,
}
}

#[derive(Debug,PartialEq)]
pub enum RadiusAttribute<'a> {
    UserName(&'a[u8]),
    UserPassword(&'a[u8]),
    ChapPassword(u8,&'a[u8]),
    NasIPAddress(Ipv4Addr),
    NasPort(u32),
    ServiceType(ServiceType),
    FramedProtocol(FramedProtocol),
    FramedIPAddress(Ipv4Addr),
    FramedIPNetmask(Ipv4Addr),
    FramedRouting(FramedRouting),
    FilterId(&'a[u8]),
    FramedMTU(u32),
    FramedCompression(FramedCompression),
    VendorSpecific(u32, &'a [u8]),

    Unknown(u8,&'a[u8]),
}


fn parse_attribute_content(i:&[u8], t:u8) -> IResult<&[u8],RadiusAttribute> {
    match t {
        1 => value!(i, RadiusAttribute::UserName(i)),
        2 => value!(i, RadiusAttribute::UserPassword(i)),
        3 => {
            if i.len() < 2 { return IResult::Incomplete(Needed::Size(2)); }
            value!(i, RadiusAttribute::ChapPassword(i[0],&i[1..]))
        },
        4 => map!(i, take!(4), |v:&[u8]| RadiusAttribute::NasIPAddress(Ipv4Addr::new(v[0],v[1],v[2],v[3]))),
        5 => map!(i, be_u32, |v| RadiusAttribute::NasPort(v)),
        6 => map_opt!(i, be_u32, |v| ServiceType::from_u32(v).map(|v| RadiusAttribute::ServiceType(v))),
        7 => map_opt!(i, be_u32, |v| FramedProtocol::from_u32(v).map(|v| RadiusAttribute::FramedProtocol(v))),
        8 => map!(i, take!(4), |v:&[u8]| RadiusAttribute::FramedIPAddress(Ipv4Addr::new(v[0],v[1],v[2],v[3]))),
        9 => map!(i, take!(4), |v:&[u8]| RadiusAttribute::FramedIPNetmask(Ipv4Addr::new(v[0],v[1],v[2],v[3]))),
        10 => map_opt!(i, be_u32, |v| FramedRouting::from_u32(v).map(|v| RadiusAttribute::FramedRouting(v))),
        11 => value!(i, RadiusAttribute::FilterId(i)),
        12 => map!(i, be_u32, |v| RadiusAttribute::FramedMTU(v)),
        13 => map_opt!(i, be_u32, |v| FramedCompression::from_u32(v).map(|v| RadiusAttribute::FramedCompression(v))),
        26 => {
            if i.len() < 5 {
                return IResult::Incomplete(Needed::Size(5));
            }
            value!(
                i,
                RadiusAttribute::VendorSpecific(
                    ((i[0] as u32) << 24) + ((i[1] as u32) << 16) + ((i[2] as u32) << 8) + (i[3] as u32),
                    &i[4..]
                )
            )
        }
        _ => value!(i, RadiusAttribute::Unknown(t,i)),
    }
}

pub fn parse_radius_attribute(i:&[u8]) -> IResult<&[u8],RadiusAttribute> {
    do_parse!(i,
        t: be_u8 >>
        l: verify!(be_u8, |val:u8| val >= 2) >>
        v: flat_map!(take!(l-2),call!(parse_attribute_content,t)) >>
        ( v )
    )
}

#[cfg(test)]
mod tests {
    use radius_attr::*;
    use nom::{IResult,ErrorKind};

#[test]
fn test_attribute_invalid() {
    let data = &[255, 0, 2, 2];
    assert_eq!(
        parse_radius_attribute(data),
        IResult::Error(error_position!(ErrorKind::Verify,&data[1..]))
    );
}

#[test]
fn test_attribute_empty() {
    let data = &[255, 2, 2, 2];
    assert_eq!(
        parse_radius_attribute(data),
        IResult::Done(&data[2..], RadiusAttribute::Unknown(255,&[]))
    );
}

#[test]
fn test_attribute() {
    let data = &[255, 4, 2, 2];
    assert_eq!(
        parse_radius_attribute(data),
        IResult::Done(&b""[..], RadiusAttribute::Unknown(255,&[2,2]))
    );
}

#[test]
fn test_parse_vendor_specific() {
    {
        let data = &[26, 7, 0, 1, 2, 3, 120];
        assert_eq!(
            parse_radius_attribute(data),
            IResult::Done(
                &b""[..],
                RadiusAttribute::VendorSpecific(66051, "x".as_bytes())
            )
        )
    }
    {
        let data = &[26, 6, 0, 1, 2, 3];
        assert_eq!(
            parse_radius_attribute(data),
            IResult::Incomplete(Needed::Size(7))
        )
    }
}
}
