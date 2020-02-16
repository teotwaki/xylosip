use crate::{
    message::{ Message, Request, RequestLine },
    parser::{
        Result,
        rfc3261::{
            common,
            tokens,
            headers,
        },
    },
};

use nom::{
    combinator::opt,
    sequence::tuple,
    branch::alt,
    multi::many0,
    bytes::complete::tag,
};

fn request_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        common::sip_uri,
        common::sips_uri,
        common::absolute_uri,
    ))(input)
}

fn request_line(input: &[u8]) -> Result<&[u8], RequestLine> {
    let (input, (method, _, uri, _, version, _)) = tuple((
        common::method,
        tag(" "),
        request_uri,
        tag(" "),
        common::sip_version,
        tokens::newline,
    ))(input)?;

    Ok((input, RequestLine {
        method,
        uri,
        version,
    }))
}

pub fn request(input: &[u8]) -> Result<&[u8], Message> {
    let (input, (request_line, headers, _, body)) = tuple((
            request_line,
            many0(headers::message_header),
            tokens::newline,
            opt(common::message_body),
        ))(input)?;

    Ok((input, Message::Request(Request {
        request_line,
        body,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::*;

    #[test]
    fn request_line_can_parse_full_request_line() {
        let rl = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n";
        let parsed = request_line(rl).unwrap().1;
        assert_eq!(parsed.method, Method::Invite);
        assert!(parsed.uri == b"sip:bob@biloxi.example.com");
        assert_eq!(parsed.version, Version::Two);
    }
}
