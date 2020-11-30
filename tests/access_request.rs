use radius_parser::*;

static RADIUS_ACCESS_REQ: &'static [u8] = include_bytes!("../assets/radius_access-request.bin");

#[test]
fn test_access_request() {
    let (rem, acces_req) = parse_radius_data(RADIUS_ACCESS_REQ).expect("could not parse data");

    assert!(rem.is_empty());
    println!("{:?}", acces_req);
    assert_eq!(acces_req.code, RadiusCode(1));
}
