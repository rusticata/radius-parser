extern crate radius_parser;
use radius_parser::*;

static RADIUS_ACCESS_REQ: &'static [u8] = include_bytes!("../assets/radius_access-request.bin");

#[test]
fn test_access_request() {
    let res = parse_radius_data(RADIUS_ACCESS_REQ);

    println!("{:?}", res);
}
