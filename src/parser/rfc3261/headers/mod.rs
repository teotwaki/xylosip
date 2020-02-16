mod priority;
mod error;
mod content;
mod date;
mod alert;
mod auth;
mod call;
mod contact;
mod via;
mod warning;

use crate::parser::rfc3261::{
    tokens::{
        header_colon,
        token,
        utf8_char1,
        is_utf8_cont,
        linear_whitespace,
        newline,
        comma,
        utf8_trim,
        equal,
        slash,
        semicolon,
        comment,
    },
    common::{
        method,
        generic_param,
    },
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    branch::alt,
    multi:: many0,
    character::complete::{ digit0, digit1 },
    bytes::complete::{ tag, tag_no_case, take_while, },
};

use crate::parser::Result;

fn allow(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Allow"),
            header_colon,
            opt(pair(method, many0(pair(comma, method))))
        ))
    )(input)
}

fn cseq(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("CSeq"),
            header_colon,
            digit1,
            linear_whitespace,
            method,
        ))
    )(input)
}

fn expires(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Expires"),
            header_colon,
            digit1
        ))
    )(input)
}

fn max_forwards(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Max-Forwards"),
            header_colon,
            digit1
        ))
    )(input)
}

fn mime_version(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("MIME-Version"),
            header_colon,
            digit1,
            tag("."),
            digit1,
        ))
    )(input)
}

fn min_expires(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Min-Expires"),
            header_colon,
            digit1
        ))
    )(input)
}

fn organization(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Organization"),
            header_colon,
            opt(utf8_trim),
        ))
    )(input)
}

fn require(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Require"),
            header_colon,
            token,
            many0(pair(comma, token))
        ))
    )(input)
}

fn retry_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(tuple((
            tag_no_case("duration"),
            equal,
            digit1,
        ))),
        generic_param,
    ))(input)
}

fn retry_after(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Retry-After"),
            header_colon,
            digit1,
            opt(comment),
            many0(pair(semicolon, retry_param))
        ))
    )(input)
}

fn server_val(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(pair(
            token,
            opt(pair(slash, token))
        )),
        comment
    ))(input)
}

fn server(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Server"),
            header_colon,
            server_val,
            many0(pair(comma, server_val))
        ))
    )(input)
}

fn user_agent(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("User-Agent"),
            header_colon,
            server_val,
            many0(pair(linear_whitespace, server_val))
        ))
    )(input)
}

fn subject(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((tag_no_case("Subject"), tag_no_case("s"))),
            header_colon,
            opt(utf8_trim),
        ))
    )(input)
}

fn supported(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((tag_no_case("Supported"), tag_no_case("k"))),
            header_colon,
            token,
            many0(pair(comma, token))
        ))
    )(input)
}

fn delay(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            digit0,
            opt(pair(tag("."), digit0))
        )
    )(input)
}

fn timestamp(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Supported"),
            header_colon,
            digit1,
            opt(pair(tag("."), digit0)),
            opt(pair(linear_whitespace, delay))
        ))
    )(input)
}

fn unsupported(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Unsupported"),
            header_colon,
            token,
            many0(pair(comma, token))
        ))
    )(input)
}
fn header_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        many0(alt((
            utf8_char1,
            take_while(is_utf8_cont),
            linear_whitespace,
        )))
    )(input)
}

fn extension_header(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            token,
            header_colon,
            header_value,
        ))
    )(input)
}

pub fn message_header(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alt((
                alt((
                    content::accept,
                    content::accept_encoding,
                    content::accept_language,
                    alert::alert_info,
                    allow,
                    auth::authentication_info,
                    auth::authorization,
                    call::call_id,
                    call::call_info,
                    contact::contact,
                    content::content_disposition,
                    content::content_encoding,
                    content::content_language,
                    content::content_length,
                    content::content_type,
                    cseq,
                    date::date,
                    error::error_info,
                    expires,
                    contact::from,
                    via::via,
                )),
                alt((
                    call::in_reply_to,
                    max_forwards,
                    mime_version,
                    min_expires,
                    organization,
                    priority::priority,
                    auth::proxy_authenticate,
                    auth::proxy_authorization,
                    auth::proxy_require,
                    contact::record_route,
                    contact::reply_to,
                    require,
                    retry_after,
                    contact::route,
                    server,
                    subject,
                    supported,
                    timestamp,
                    contact::to,
                    unsupported,
                    user_agent,
                )),
                alt((
                    warning::warning,
                    auth::www_authenticate,
                    extension_header,
                ))
            )),
            newline,
        )
    )(input)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_header_can_parse_via() {
        let h = b"Via: SIP/2.0/TCP client.atlanta.example.com:5060;branch=z9hG4bK74b43\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_max_forwards() {
        let h = b"Max-Forwards: 70\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_route() {
        let h = b"Route: <sip:ss1.atlanta.example.com;lr>\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_from() {
        let h = b"From: Alice <sip:alice@atlanta.example.com>;tag=9fxced76sl\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_to() {
        let h = b"To: Bob <sip:bob@biloxi.example.com>\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_call_id() {
        let h = b"Call-ID: 3848276298220188511@atlanta.example.com\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_cseq() {
        let h = b"CSeq: 1 INVITE\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_contact() {
        let h = b"Contact: <sip:alice@client.atlanta.example.com;transport=tcp>\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_content_type() {
        let h = b"Content-Type: application/sdp\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }

    #[test]
    fn message_header_can_parse_content_length() {
        let h = b"Content-Length: 151\r\n";
        assert!(message_header(h) == Ok((b"", h)));
    }
}
