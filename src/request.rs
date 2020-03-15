use crate::{
    sip::{ Method, Version, },
    header::{ self, Header, },
    parser::{ rfc3261, Error, ErrorKind },
};

#[derive(PartialEq, Debug, Clone)]
pub struct Invite {
    /// the parsed Request-Line
    pub request_line: RequestLine,

    /// the call ID of the INVITE
    pub call_id: String,

    /// the command sequence of the INVITE
    pub cseq: (i32, Method),

    /// the remote user sending the INVITE
    pub from: header::From,

    /// the max forwards (ttl) of the INVITE
    pub max_forwards: i32,

    /// local user the INVITE is for
    pub to: header::To,

    /// the upstream UAs this request has passed through
    pub via: Vec<header::Via>,

    /// mandatory and optional headers extracted from the INVITE
    pub headers: Vec<Header>,

    /// the optional body of the INVITE. This is completely unparsed and unvalidated.
    pub body: Option<Vec<u8>>,
}

#[derive(PartialEq, Debug, Copy, Clone, thiserror::Error)]
pub enum InvalidInviteError {
    #[error("mandatory header missing: Contact")]
    MissingContactHeader,
}

impl Invite {
    pub fn method(&self) -> &Method {
        &self.request_line.method
    }

    pub fn from_request(r: Request) -> Result<Self, InvalidInviteError> {
        let mut contact = None;

        for header in r.headers.iter() {
            match header {
                Header::Contact(c) => contact = Some(c),
                _ => {},
            };
        }

        if contact.is_none() {
            Err(InvalidInviteError::MissingContactHeader)
        } else {
            Ok(Self {
                request_line: r.request_line,
                call_id: r.call_id,
                cseq: r.cseq,
                from: r.from,
                max_forwards: r.max_forwards,
                to: r.to,
                via: r.via,
                headers: r.headers,
                body: r.body,
            })
        }
    }
}

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
pub struct RequestLine {
    /// the parsed Method
    pub method: Method,

    /// the URI describing the user or service being addressed
    pub uri: String,

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
pub struct Request {
    /// the parsed Request-Line
    pub request_line: RequestLine,

    /// the call ID of the request
    pub call_id: String,

    /// the command sequence of the request
    pub cseq: (i32, Method),

    /// the remote user making the request
    pub from: header::From,

    /// the max forwards (ttl) of the request
    pub max_forwards: i32,

    /// local user the request is for
    pub to: header::To,

    /// the upstream UAs this request has passed through
    pub via: Vec<header::Via>,

    /// mandatory and optional headers extracted from the request
    pub headers: Vec<Header>,

    /// the optional body of the request. This is completely unparsed and unvalidated.
    pub body: Option<Vec<u8>>,
}

#[derive(PartialEq, Debug, Copy, Clone, thiserror::Error)]
pub enum InvalidRequestError {
    #[error("mandatory header missing: Call-ID")]
    MissingCallIDHeader,
    #[error("mandatory header missing: CSeq")]
    MissingCSeqHeader,
    #[error("mandatory header missing: From")]
    MissingFromHeader,
    #[error("mandatory header missing: Max-Forwards")]
    MissingMaxForwardsHeader,
    #[error("mandatory header missing: To")]
    MissingToHeader,
    #[error("mandatory header missing: Via")]
    MissingViaHeader,
}

impl Request {
    pub fn new(request_line: RequestLine, headers: Vec<Header>, body: Option<Vec<u8>>) -> Result<Self, InvalidRequestError> {
        let mut call_id = None;
        let mut cseq = None;
        let mut from = None;
        let mut max_forwards = None;
        let mut to = None;
        let mut via = None;

        for header in headers.iter() {
            match header {
                Header::CallID(id) => call_id = Some(id.clone()),
                Header::CSeq(c, m) => cseq = Some((*c, m.clone())),
                Header::From(f) => from = Some(f.clone()),
                Header::MaxForwards(mf) => max_forwards = Some(*mf),
                Header::To(t) => to = Some(t.clone()),
                Header::Via(v) => via = Some(v.clone()),
                _ => {},
            };
        }

        if call_id.is_none() {
            Err(InvalidRequestError::MissingCallIDHeader)
        } else if cseq.is_none() {
            Err(InvalidRequestError::MissingCSeqHeader)
        } else if from.is_none() {
            Err(InvalidRequestError::MissingFromHeader)
        } else if max_forwards.is_none() {
            Err(InvalidRequestError::MissingMaxForwardsHeader)
        } else if to.is_none() {
            Err(InvalidRequestError::MissingToHeader)
        } else if via.is_none() {
            Err(InvalidRequestError::MissingViaHeader)
        } else {
            Ok(Self {
                request_line,
                call_id: call_id.unwrap(),
                cseq: cseq.unwrap(),
                from: from.unwrap(),
                max_forwards: max_forwards.unwrap(),
                to: to.unwrap(),
                via: via.unwrap(),
                headers: headers,
                body,
            })
        }
    }

    pub fn method(&self) -> &Method {
        &self.request_line.method
    }
}

impl<'a> Request {
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
        let req = Request::parse(bytes);
        assert_eq!(req.is_err(), false);
    }
}
