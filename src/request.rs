use crate::method::Method;
use crate::header::{ Header, Version, };
use crate::parser::rfc3261;
use crate::parser::{ Error, ErrorKind, };

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

impl<'a> Request<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, Error<'a, &[u8]>> {
        match rfc3261::request(input) {
            Ok((_, req)) => Ok(req),
            Err(nom::Err::Failure(err)) => Err(err),
            Err(_) => Err(Error::new(ErrorKind::UnknownError)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parse_can_read_whole_message() {
        let bytes = include_bytes!("../assets/invite.sip");
        assert_eq!(Request::parse(bytes).is_err(), false);
    }
}
