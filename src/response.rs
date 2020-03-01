use crate::parser::rfc3261;
use crate::parser::{ Error, ErrorKind, };

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Response<'a> {
    pub content: &'a str,
}

impl<'a> Response<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, Error<'a, &[u8]>> {
        match rfc3261::response(input) {
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
    fn response_parse_can_read_whole_message() {
        let bytes = include_bytes!("../assets/200ok.sip");
        assert_eq!(Response::parse(bytes).is_err(), false);
    }
}
