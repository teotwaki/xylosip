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

use crate::{
    message::{ Header, RetryParam, Method },
    parser::rfc3261::{
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
            option_tag,
        },
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

fn allowed_methods(input: &[u8]) -> Result<&[u8], Vec<Method>> {
    let (input, value) = opt(pair(
        method,
        many0(pair(comma, method))
    ))(input)?;

    let methods = match value {
        Some((method, methods)) => {
            let mut methods: Vec<Method> = methods.into_iter().map(|(_, m)| m).collect();
            methods.insert(0, method);
            methods
        },
        None => vec![],
    };

    Ok((input, methods))
}

fn allow(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, methods)) = tuple((
        tag_no_case("Allow"),
        header_colon,
        allowed_methods,
    ))(input)?;

    Ok((input, Header::Allow(methods)))
}

fn cseq(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, cseq, _, method)) = tuple((
        tag_no_case("CSeq"),
        header_colon,
        digit1,
        linear_whitespace,
        method,
    ))(input)?;

    Ok((input, Header::CSeq(cseq, method)))
}

fn expires(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, e)) = tuple((
        tag_no_case("Expires"),
        header_colon,
        digit1
    ))(input)?;

    Ok((input, Header::Expires(e)))
}

fn max_forwards(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, mf)) = tuple((
        tag_no_case("Max-Forwards"),
        header_colon,
        digit1
    ))(input)?;

    Ok((input, Header::MaxForwards(mf)))
}

fn mime_version(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, version)) = tuple((
        tag_no_case("MIME-Version"),
        header_colon,
        recognize(tuple((
            digit1,
            tag("."),
            digit1,
        )))
    ))(input)?;

    Ok((input, Header::MIMEVersion(version)))
}

fn min_expires(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, me)) = tuple((
        tag_no_case("Min-Expires"),
        header_colon,
        digit1
    ))(input)?;

    Ok((input, Header::MinExpires(me)))
}

fn organization(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, org)) = tuple((
        tag_no_case("Organization"),
        header_colon,
        opt(utf8_trim),
    ))(input)?;

    Ok((input, Header::Organization(org)))
}

fn require(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, mut others)) = tuple((
        tag_no_case("Require"),
        header_colon,
        token,
        option_tag,
    ))(input)?;

    others.insert(0, first);
    Ok((input, Header::Require(others)))
}

fn duration_retry_param(input: &[u8]) -> Result<&[u8], RetryParam> {
    let (input, (_, _, duration)) = tuple((
        tag_no_case("duration"),
        equal,
        digit1,
    ))(input)?;

    Ok((input, RetryParam::Duration(duration)))
}

fn generic_retry_param(input: &[u8]) -> Result<&[u8], RetryParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, RetryParam::Extension(param)))
}

fn retry_param(input: &[u8]) -> Result<&[u8], RetryParam> {
    alt((
        duration_retry_param,
        generic_retry_param,
    ))(input)
}

fn retry_params(input: &[u8]) -> Result<&[u8], Vec<RetryParam>> {
    let (input, params) = many0(pair(semicolon, retry_param))(input)?;
    let params = params.into_iter().map(|(_, param)| param).collect();

    Ok((input, params))
}

fn retry_after(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, ra, comment, params)) = tuple((
        tag_no_case("Retry-After"),
        header_colon,
        digit1,
        opt(comment),
        retry_params
    ))(input)?;

    Ok((input, Header::RetryAfter(ra, comment, params)))
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

fn server(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, s)) = tuple((
        tag_no_case("Server"),
        header_colon,
        recognize(pair(
            server_val,
            many0(pair(linear_whitespace, server_val)),
        )),
    ))(input)?;

    Ok((input, Header::Server(s)))
}

fn user_agent(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, ua)) = tuple((
        tag_no_case("User-Agent"),
        header_colon,
        recognize(pair(
            server_val,
            many0(pair(linear_whitespace, server_val)),
        )),
    ))(input)?;

    Ok((input, Header::UserAgent(ua)))
}

fn subject(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, subject)) = tuple((
        alt((tag_no_case("Subject"), tag_no_case("s"))),
        header_colon,
        opt(utf8_trim),
    ))(input)?;

    Ok((input, Header::Subject(subject)))
}

fn supported(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, mut others)) = tuple((
        alt((tag_no_case("Supported"), tag_no_case("k"))),
        header_colon,
        token,
        option_tag,
    ))(input)?;

    others.insert(0, first);
    Ok((input, Header::Supported(others)))
}

fn delay(input: &[u8]) -> Result<&[u8], Option<&[u8]>> {
    let (input, delay) = opt(pair(
        linear_whitespace,
        recognize(
            pair(
                digit0,
                opt(pair(tag("."), digit0))
            )
        ),
    ))(input)?;

    Ok((input, match delay {
        Some((_, delay)) => Some(delay),
        _ => None,
    }))
}

fn timestamp(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, ts, delay)) = tuple((
        tag_no_case("Timestamp"),
        header_colon,
        recognize(
            pair(
                digit1,
                opt(pair(tag("."), digit0)
            )
        )),
        delay
    ))(input)?;

    Ok((input, Header::Timestamp(ts, delay)))
}

fn unsupported(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, mut others)) = tuple((
        tag_no_case("Unsupported"),
        header_colon,
        token,
        option_tag,
    ))(input)?;

    others.insert(0, first);
    Ok((input, Header::Unsupported(others)))
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

fn extension_header(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (name, _, value)) = tuple((
        token,
        header_colon,
        header_value,
    ))(input)?;

    Ok((input, Header::Extension(name, value)))
}

pub fn message_header(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (header, _)) = pair(
        // alt() only supports 21 entries
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
    )(input)?;

    Ok((input, header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::*;

    #[test]
    fn message_header_can_parse_via() {
        let h = b"Via: SIP/2.0/TCP client.atlanta.example.com:5060;branch=z9hG4bK74b43\r\n";
        let header = message_header(h).unwrap().1;
        match header {
            Header::Via(vias) => {
                let via = &vias[0];
                assert_eq!(via.protocol, b"SIP/2.0/TCP");
                assert_eq!(via.sent_by, b"client.atlanta.example.com:5060");

                match &via.params[0] {
                    ViaParam::Branch(v) => assert_eq!(v, b"z9hG4bK74b43"),
                    _ => panic!(),
                }
            },
            _ => panic!()

        }
    }

    #[test]
    fn message_header_can_parse_max_forwards() {
        let h = b"Max-Forwards: 70\r\n";
        let header = message_header(h).unwrap().1;
        match header {
            Header::MaxForwards(v) => {
                assert_eq!(v, b"70");
            },
            _ => panic!()

        }
    }
/*
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
*/
}
