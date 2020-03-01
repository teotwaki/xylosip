use crate::method::Method;
use crate::header::{ Header, Version, };

#[derive(PartialEq, Debug, Clone)]
pub struct RequestLine<'a> {
    pub method: Method<'a>,
    pub uri: &'a str,
    pub version: Version,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Request<'a> {
    pub request_line: RequestLine<'a>,
    pub headers: Vec<Header<'a>>,
    pub body: Option<&'a [u8]>,
}
