use crate::request::Request;
use crate::response::Response;
use crate::parser::rfc3261;
use crate::parser::{ Error, ErrorKind, };

#[derive(PartialEq, Debug, Clone)]
pub enum Message<'a> {
    Request(Request<'a>),
    Response(Response<'a>),
}

impl<'a> Message<'a> {
    pub fn parse(input: &'a [u8]) -> Result<Self, Error<'a, &[u8]>> {
        match rfc3261::message(input) {
            Ok((_, msg)) => Ok(msg),
            Err(nom::Err::Failure(err)) => Err(err),
            Err(_) => Err(Error::new(ErrorKind::UnknownError)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_parse_can_read_whole_message() {
        let bytes = include_bytes!("../assets/invite.sip");
        assert_eq!(Message::parse(bytes).is_err(), false);
    }
}
