use nom::bytes::streaming::take;
use nom::combinator::{map, map_parser, verify};
use nom::number::streaming::{be_u32, be_u8};
use nom::{Err, IResult, Needed};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadiusAttributeType(pub u8);

#[allow(non_upper_case_globals)]
impl RadiusAttributeType {
    pub const UserName: RadiusAttributeType = RadiusAttributeType(1);
    pub const UserPassword: RadiusAttributeType = RadiusAttributeType(2);
    pub const ChapPassword: RadiusAttributeType = RadiusAttributeType(3);
    pub const NasIPAddress: RadiusAttributeType = RadiusAttributeType(4);
    pub const NasPort: RadiusAttributeType = RadiusAttributeType(5);
    pub const ServiceType: RadiusAttributeType = RadiusAttributeType(6);
    pub const FramedProtocol: RadiusAttributeType = RadiusAttributeType(7);
    pub const FramedIPAddress: RadiusAttributeType = RadiusAttributeType(8);
    pub const FramedIPNetmask: RadiusAttributeType = RadiusAttributeType(9);
    pub const FramedRouting: RadiusAttributeType = RadiusAttributeType(10);
    pub const FilterId: RadiusAttributeType = RadiusAttributeType(11);
    pub const FramedMTU: RadiusAttributeType = RadiusAttributeType(12);
    pub const FramedCompression: RadiusAttributeType = RadiusAttributeType(13);
    pub const VendorSpecific: RadiusAttributeType = RadiusAttributeType(26);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceType(pub u32);

#[allow(non_upper_case_globals)]
impl ServiceType {
    pub const Login: ServiceType = ServiceType(1);
    pub const Framed: ServiceType = ServiceType(2);
    pub const CallbackLogin: ServiceType = ServiceType(3);
    pub const CallbackFramed: ServiceType = ServiceType(4);
    pub const Outbound: ServiceType = ServiceType(5);
    pub const Administrative: ServiceType = ServiceType(6);
    pub const NasPrompt: ServiceType = ServiceType(7);
    pub const AuthenticateOnly: ServiceType = ServiceType(8);
    pub const CallbackNasPrompt: ServiceType = ServiceType(9);
    pub const CallCheck: ServiceType = ServiceType(10);
    pub const CallbackAdministrative: ServiceType = ServiceType(11);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramedRouting(pub u32);

#[allow(non_upper_case_globals)]
impl FramedRouting {
    pub const None: FramedRouting = FramedRouting(0);
    pub const Send: FramedRouting = FramedRouting(1);
    pub const Receive: FramedRouting = FramedRouting(2);
    pub const SendReceive: FramedRouting = FramedRouting(3);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramedProtocol(pub u32);

#[allow(non_upper_case_globals)]
impl FramedProtocol {
    pub const Ppp: FramedProtocol = FramedProtocol(1);
    pub const Slip: FramedProtocol = FramedProtocol(2);
    /// AppleTalk Remote Access Protocol
    pub const Arap: FramedProtocol = FramedProtocol(3);
    /// Gandalf proprietary SingleLink/MultiLink protocol
    pub const Gandalf: FramedProtocol = FramedProtocol(4);
    /// Xylogics proprietary IPX/SLIP
    pub const Xylogics: FramedProtocol = FramedProtocol(5);
    /// X.75 Synchronous
    pub const X75: FramedProtocol = FramedProtocol(6);
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramedCompression(pub u32);

#[allow(non_upper_case_globals)]
impl FramedCompression {
    /// No compression
    pub const None: FramedCompression = FramedCompression(0);
    /// VJ TCP/IP header compression (See RFC1144)
    pub const TcpIp: FramedCompression = FramedCompression(1);
    /// IPX header compression
    pub const Ipx: FramedCompression = FramedCompression(2);
    /// Stac-LZS compression
    pub const StaticLzs: FramedCompression = FramedCompression(3);
}

#[derive(Clone, Debug, PartialEq)]
pub enum RadiusAttribute<'a> {
    UserName(&'a [u8]),
    UserPassword(&'a [u8]),
    ChapPassword(u8, &'a [u8]),
    NasIPAddress(Ipv4Addr),
    NasPort(u32),
    ServiceType(ServiceType),
    FramedProtocol(FramedProtocol),
    FramedIPAddress(Ipv4Addr),
    FramedIPNetmask(Ipv4Addr),
    FramedRouting(FramedRouting),
    FilterId(&'a [u8]),
    FramedMTU(u32),
    FramedCompression(FramedCompression),
    VendorSpecific(u32, &'a [u8]),
    CalledStationId(&'a [u8]),
    CallingStationId(&'a [u8]),

    Unknown(u8, &'a [u8]),
}

fn parse_attribute_content(i: &[u8], t: u8) -> IResult<&[u8], RadiusAttribute> {
    const EMPTY: &[u8] = &[];
    match t {
        1 => Ok((EMPTY, RadiusAttribute::UserName(i))),
        2 => Ok((EMPTY, RadiusAttribute::UserPassword(i))),
        3 => {
            if i.len() < 2 {
                return Err(Err::Incomplete(Needed::new(2)));
            }
            Ok((EMPTY, RadiusAttribute::ChapPassword(i[0], &i[1..])))
        }
        4 => map(take(4usize), |v: &[u8]| {
            RadiusAttribute::NasIPAddress(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
        })(i),
        5 => map(be_u32, RadiusAttribute::NasPort)(i),
        6 => map(be_u32, |v| RadiusAttribute::ServiceType(ServiceType(v)))(i),
        7 => map(be_u32, |v| RadiusAttribute::FramedProtocol(FramedProtocol(v)))(i),
        8 => map(take(4usize), |v: &[u8]| {
            RadiusAttribute::FramedIPAddress(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
        })(i),
        9 => map(take(4usize), |v: &[u8]| {
            RadiusAttribute::FramedIPNetmask(Ipv4Addr::new(v[0], v[1], v[2], v[3]))
        })(i),
        10 => map(be_u32, |v| RadiusAttribute::FramedRouting(FramedRouting(v)))(i),
        11 => Ok((EMPTY, RadiusAttribute::FilterId(i))),
        12 => map(be_u32, RadiusAttribute::FramedMTU)(i),
        13 => map(be_u32, |v| RadiusAttribute::FramedCompression(FramedCompression(v)))(i),
        26 => {
            if i.len() < 5 {
                return Err(Err::Incomplete(Needed::new(5)));
            }
            let (i, vendorid) = be_u32(i)?;
            let vendordata = i;
            Ok((EMPTY, RadiusAttribute::VendorSpecific(vendorid, vendordata)))
        }
        30 => Ok((EMPTY, RadiusAttribute::CalledStationId(i))),
        31 => Ok((EMPTY, RadiusAttribute::CallingStationId(i))),
        _ => Ok((EMPTY, RadiusAttribute::Unknown(t, i))),
    }
}

pub fn parse_radius_attribute(i: &[u8]) -> IResult<&[u8], RadiusAttribute> {
    let (i, t) = be_u8(i)?;
    let (i, l) = verify(be_u8, |&n| n >= 2)(i)?;
    let (i, v) = map_parser(take(l - 2), |d| parse_attribute_content(d, t))(i)?;
    Ok((i, v))
}

#[cfg(test)]
mod tests {
    use crate::radius_attr::*;
    use nom::error::{make_error, ErrorKind};
    use nom::Err;

    #[test]
    fn test_attribute_invalid() {
        let data = &[255, 0, 2, 2];
        assert_eq!(
            parse_radius_attribute(data),
            Err(Err::Error(make_error(&data[1..], ErrorKind::Verify)))
        );
    }

    #[test]
    fn test_attribute_empty() {
        let data = &[255, 2, 2, 2];
        assert_eq!(parse_radius_attribute(data), Ok((&data[2..], RadiusAttribute::Unknown(255, &[]))));
    }

    #[test]
    fn test_attribute() {
        let data = &[255, 4, 2, 2];
        assert_eq!(parse_radius_attribute(data), Ok((&b""[..], RadiusAttribute::Unknown(255, &[2, 2]))));
    }

    #[test]
    fn test_parse_vendor_specific() {
        {
            let data = &[26, 7, 0, 1, 2, 3, 120];
            assert_eq!(
                parse_radius_attribute(data),
                Ok((&b""[..], RadiusAttribute::VendorSpecific(66051, "x".as_bytes())))
            )
        }
        {
            let data = &[26, 6, 0, 1, 2, 3];
            assert_eq!(parse_radius_attribute(data), Err(Err::Incomplete(Needed::new(5))))
        }
    }

    #[test]
    fn test_parse_called_station_id() {
        {
            let data = &[30, 19, 97, 97, 45, 98, 98, 45, 99, 99, 45, 100, 100, 45, 101, 101, 45, 102, 102];
            assert_eq!(
                parse_radius_attribute(data),
                Ok((&b""[..], RadiusAttribute::CalledStationId("aa-bb-cc-dd-ee-ff".as_bytes())))
            )
        }
    }

    #[test]
    fn test_parse_calling_station_id() {
        {
            let data = &[31, 19, 97, 97, 45, 98, 98, 45, 99, 99, 45, 100, 100, 45, 101, 101, 45, 102, 102];
            assert_eq!(
                parse_radius_attribute(data),
                Ok((&b""[..], RadiusAttribute::CallingStationId("aa-bb-cc-dd-ee-ff".as_bytes())))
            )
        }
    }
}
