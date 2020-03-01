use crate::{
    request::{ Request, RequestLine, },
    parser::{
        Error,
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
    sequence::{ tuple, preceded, terminated },
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
    let (input, (method, uri, version)) = terminated(
        tuple((
            common::method,
            preceded(tag(" "), request_uri),
            preceded(tag(" "), common::sip_version),
        )),
        tokens::newline,
    )(input)?;

    let uri = std::str::from_utf8(uri)
        .map_err(|err| nom::Err::Failure(Error::from(err)))?;

    Ok((input, RequestLine {
        method,
        uri,
        version,
    }))
}

pub fn request(input: &[u8]) -> Result<&[u8], Request> {
    let (input, (request_line, headers, body)) = tuple((
            request_line,
            many0(headers::message_header),
            preceded(tokens::newline, opt(common::message_body)),
        ))(input)?;

    Ok((input, Request {
        request_line,
        headers,
        body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method::Method;
    use crate::header::Version;

    #[test]
    fn request_line_can_parse_full_request_line() {
        let rl = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n";
        let parsed = request_line(rl).unwrap().1;
        assert_eq!(parsed.method, Method::Invite);
        assert_eq!(parsed.uri, "sip:bob@biloxi.example.com");
        assert_eq!(parsed.version, Version::Two);
    }
}
