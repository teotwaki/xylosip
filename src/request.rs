use crate::method::Method;
use crate::header::{ Header, Version, };
use crate::parser::rfc3261;
use crate::parser::{ Error, ErrorKind, };

/// Representation of a SIP Request-Line
///
/// A SIP Request-Line is composed of a Method, a Request-URI and a protocol version descriptor.
/// The Request-Line is always terminated by CRLF (`\r\n`), and is followed by one or more headers.
/// The headers are available in the Request object.
///
/// ## Sample Request-Line
///
/// ```ignore
///                     |- URI
///        --------------------------
/// INVITE sip:bob@biloxi.example.com SIP/2.0
/// ------                            -------
///    |- method                         |- Protocol version
/// ```
#[derive(PartialEq, Debug, Clone)]
pub struct RequestLine<'a> {
    /// the parsed Method
    pub method: Method<'a>,

    /// the URI describing the user or service being addressed
    pub uri: &'a str,

    /// the version of the SIP protocol this request adheres to. There is virtually only one version
    /// in use: 2.0.
    pub version: Version,
}

/// Representation of a SIP Request
///
/// A SIP request is composed of its Request-Line, a number of mandatory and optional headers, and
/// an optional body. Considering that the request's body is not strictly relevant to the parsing
/// of SIP messages, it is provided in an unparsed and unvalidated form (`&[u8]`). The body
/// typically contains an SDP description of where the media streams should connect.
///
/// **Note**: Future implementations might list mandatory headers separately from the current
/// `headers` field.
///
/// ## Sample request
///
/// ```ignore
/// INVITE sip:bob@biloxi.example.com SIP/2.0                            <-- the Request-Line
/// Via: SIP/2.0/TCP client.atlanta.example.com:5060;branch=z9hG4bK74b43 |
/// Max-Forwards: 70                                                     |
/// Route: <sip:ss1.atlanta.example.com;lr>                              |
/// From: Alice <sip:alice@atlanta.example.com>;tag=9fxced76sl           |
/// To: Bob <sip:bob@biloxi.example.com>                                 | - mandatory and
/// Call-ID: 3848276298220188511@atlanta.example.com                     |  optional headers
/// CSeq: 1 INVITE                                                       |
/// Contact: <sip:alice@client.atlanta.example.com;transport=tcp>        |
/// Content-Type: application/sdp                                        |
/// Content-Length: 151                                                  |
///
/// v=0                                                                  |
/// o=alice 2890844526 2890844526 IN IP4 client.atlanta.example.com      |
/// s=-                                                                  |
/// c=IN IP4 192.0.2.101                                                 | - optional body
/// t=0 0                                                                |
/// m=audio 49172 RTP/AVP 0                                              |
/// a=rtpmap:0 PCMU/8000                                                 |
/// ```
#[derive(PartialEq, Debug, Clone)]
pub struct Request<'a> {
    /// the parsed Request-Line
    pub request_line: RequestLine<'a>,

    /// mandatory and optional headers extracted from the request
    pub headers: Vec<Header<'a>>,

    /// the optional body of the request. This is completely unparsed and unvalidated.
    pub body: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    /// Attempts to parse a byte-slice representation of a SIP request
    ///
    /// **Note**: The error type of this method will probably change in the future.
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
