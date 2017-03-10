use nom::{IResult,be_u8,be_u16};

#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum RadiusCode {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    StatusServer = 12,
    StatusClient = 13,
    Reserved = 255,
}

#[derive(Debug,PartialEq)]
pub struct RadiusData<'a> {
    pub code: u8,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: &'a [u8], // 16 bytes
    pub attributes: Option<Vec<RadiusAttribute<'a>>>,
}

#[derive(Debug,PartialEq)]
pub struct RadiusAttribute<'a> {
    pub typ: u8,
    pub len: u8,
    pub val: &'a [u8],
}


pub fn parse_radius_attribute(i:&[u8]) -> IResult<&[u8],RadiusAttribute> {
    do_parse!(i,
        t: be_u8 >>
        l: be_u8 >>
        v: take!(l-2) >>
        (
            RadiusAttribute {
                typ: t,
                len: l,
                val: v,
            }
        )
    )
}

pub fn parse_radius_data(i:&[u8]) -> IResult<&[u8],RadiusData> {
    do_parse!(i,
        c:    be_u8 >>
        id:   be_u8 >>
        len:  be_u16 >>
        auth: take!(16) >>
        attr: cond!(len > 20,
                    flat_map!(take!(len - 20),complete!(many1!(parse_radius_attribute)))
        ) >>
        (
            RadiusData {
                code: c,
                identifier: id,
                length: len,
                authenticator: auth,
                attributes: attr,
            }
        )
    )
}
