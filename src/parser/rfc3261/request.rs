use crate::parser::{
    Result,
    rfc3261::{
        common,
        tokens,
        headers,
    },
};

use nom::{
    combinator::{ opt, recognize },
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

fn request_line(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            common::method,
            tag(" "),
            request_uri,
            tag(" "),
            common::sip_version,
            tokens::newline,
        ))
    )(input)
}

pub fn request(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            request_line,
            many0(headers::message_header),
            tokens::newline,
            opt(common::message_body),
        ))
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_can_parse_full_request_line() {
        let line = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n";
        assert!(request_line(line) == Ok((b"", line)));
    }
}
