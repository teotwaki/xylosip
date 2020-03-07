use crate::request::Request;
use crate::response::Response;
use crate::parser::rfc3261;
use crate::parser::{ Error, ErrorKind, };

/// Representation of a SIP message (either a Request or a Response)
///
#[derive(PartialEq, Debug, Clone)]
pub enum Message {
    /// variant when a SIP request is parsed
    Request(Request),
    /// variant when a SIP response is parsed
    Response(Response),
}

impl<'a> Message {
    /// Attempts to parse a byte-slice representation of a SIP message
    ///
    /// This method should be the primary way to parse data coming from the network, as it is
    /// rarely known whether the next message that will arrive on the wire will be a request or a
    /// response (unless a connected protocol is used).
    pub fn parse(input: &'a [u8]) -> Result<Self, Error<'a, &[u8]>> {
        match rfc3261::message(input) {
            Ok((_, msg)) => Ok(msg),
            Err(nom::Err::Failure(err)) => Err(err),
            Err(nom::Err::Error(err)) => Err(err),
            Err(_err) => Err(Error::new(ErrorKind::UnknownError)),
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
