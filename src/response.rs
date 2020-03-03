use crate::parser::rfc3261;
use crate::parser::{ Error, ErrorKind, };

/// Representation of a SIP Response
///
/// **Note**: Responses are currently not well-supported. Patches welcome!
#[derive(PartialEq, Debug, Clone)]
pub struct Response {
    /// unparsed content of the Response
    pub content: Vec<u8>,
}

impl<'a> Response {
    /// Attempts to parse a byte-slice representation of a SIP response
    ///
    /// **Note**: Responses are currently not parsed in detail.
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
