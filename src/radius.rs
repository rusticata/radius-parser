//! Radius accounting
//!
//! RFC 2865: Remote Authentication Dial In User Service (RADIUS)
//! RFC 2866: RADIUS Accounting

use nom::{IResult, be_u16, be_u8};

use radius_attr::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadiusCode(pub u8);

#[allow(non_upper_case_globals)]
impl RadiusCode {
    pub const AccessRequest      : RadiusCode = RadiusCode(1);
    pub const AccessAccept       : RadiusCode = RadiusCode(2);
    pub const AccessReject       : RadiusCode = RadiusCode(3);
    pub const AccountingRequest  : RadiusCode = RadiusCode(4);
    pub const AccountingResponse : RadiusCode = RadiusCode(5);
    pub const AccessChallenge    : RadiusCode = RadiusCode(11);
    pub const StatusServer       : RadiusCode = RadiusCode(12);
    pub const StatusClient       : RadiusCode = RadiusCode(13);
    pub const Reserved           : RadiusCode = RadiusCode(255);
}

#[derive(Clone, Debug, PartialEq)]
pub struct RadiusData<'a> {
    pub code:          RadiusCode,
    pub identifier:    u8,
    pub length:        u16,
    pub authenticator: &'a [u8], // 16 bytes
    pub attributes:    Option<Vec<RadiusAttribute<'a>>>,
}

pub fn parse_radius_data(i: &[u8]) -> IResult<&[u8], RadiusData> {
    do_parse!{i,
        c:    be_u8 >>
        id:   be_u8 >>
        len:  be_u16 >>
        auth: take!(16) >>
        attr: cond!(len > 20,
                    flat_map!(take!(len - 20),complete!(many1!(parse_radius_attribute)))
        ) >>
        (
            RadiusData {
                code: RadiusCode(c),
                identifier: id,
                length: len,
                authenticator: auth,
                attributes: attr,
            }
        )
    }
}
