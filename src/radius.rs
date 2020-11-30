//! Radius accounting
//!
//! RFC 2865: Remote Authentication Dial In User Service (RADIUS)
//! RFC 2866: RADIUS Accounting

use crate::radius_attr::*;
use nom::bytes::streaming::take;
use nom::combinator::{complete, cond, map, map_parser};
use nom::multi::many1;
use nom::number::streaming::{be_u16, be_u8};
use nom::IResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadiusCode(pub u8);

#[allow(non_upper_case_globals)]
impl RadiusCode {
    pub const AccessRequest: RadiusCode = RadiusCode(1);
    pub const AccessAccept: RadiusCode = RadiusCode(2);
    pub const AccessReject: RadiusCode = RadiusCode(3);
    pub const AccountingRequest: RadiusCode = RadiusCode(4);
    pub const AccountingResponse: RadiusCode = RadiusCode(5);
    pub const AccessChallenge: RadiusCode = RadiusCode(11);
    pub const StatusServer: RadiusCode = RadiusCode(12);
    pub const StatusClient: RadiusCode = RadiusCode(13);
    pub const Reserved: RadiusCode = RadiusCode(255);
}

#[derive(Clone, Debug, PartialEq)]
pub struct RadiusData<'a> {
    pub code: RadiusCode,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: &'a [u8], // 16 bytes
    pub attributes: Option<Vec<RadiusAttribute<'a>>>,
}

pub fn parse_radius_data(i: &[u8]) -> IResult<&[u8], RadiusData> {
    let (i, code) = map(be_u8, RadiusCode)(i)?;
    let (i, identifier) = be_u8(i)?;
    let (i, length) = be_u16(i)?;
    let (i, authenticator) = take(16usize)(i)?;
    // We cannot use cond(length > 20, ... take(length-20) ... here
    // because `length-20` will be evaluated before cond, resulting in a potential
    // (though harmless, since not used) integer underflow
    // So, force lazy evaluation in `take`
    let (i, attributes) = cond(
        length > 20,
        map_parser(
            |d| take(length - 20)(d),
            many1(complete(parse_radius_attribute)),
        ),
    )(i)?;
    let data = RadiusData {
        code,
        identifier,
        length,
        authenticator,
        attributes,
    };
    Ok((i, data))
}
