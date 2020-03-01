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
    header::{ Header, RetryParam, RetryAfter, },
    parser::{
        integer,
        rfc3261::{
            tokens::{
                header_colon,
                token,
                token_str,
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
    },
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple, preceded, terminated, },
    branch::alt,
    multi::{ many0, separated_list, },
    character::complete::{ digit0, digit1 },
    bytes::complete::{ tag, tag_no_case, take_while, },
};

use crate::parser::Result;

fn allow(input: &[u8]) -> Result<&[u8], Header> {
    let (input, methods) = preceded(
        pair(
            tag_no_case("Allow"),
            header_colon,
        ),
        separated_list(comma, method)
    )(input)?;

    Ok((input, Header::Allow(methods)))
}

fn cseq(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (cseq, method)) = preceded(
        pair(
            tag_no_case("CSeq"),
            header_colon,
        ),
        pair(
            integer,
            preceded(linear_whitespace, method)
        )
    )(input)?;

    Ok((input, Header::CSeq(cseq, method)))
}

fn expires(input: &[u8]) -> Result<&[u8], Header> {
    let (input, e) = preceded(
        pair(
            tag_no_case("Expires"),
            header_colon,
        ),
        integer,
    )(input)?;

    Ok((input, Header::Expires(e)))
}

fn max_forwards(input: &[u8]) -> Result<&[u8], Header> {
    let (input, mf) = preceded(
        pair(
            tag_no_case("Max-Forwards"),
            header_colon,
        ),
        integer
    )(input)?;

    Ok((input, Header::MaxForwards(mf)))
}

fn mime_version(input: &[u8]) -> Result<&[u8], Header> {
    let (input, version) = preceded(
        pair(
            tag_no_case("MIME-Version"),
            header_colon,
        ),
        recognize(tuple((
            digit1,
            tag("."),
            digit1,
        )))
    )(input)?;

    let version = std::str::from_utf8(version)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, Header::MIMEVersion(version)))
}

fn min_expires(input: &[u8]) -> Result<&[u8], Header> {
    let (input, me) = preceded(
        pair(
            tag_no_case("Min-Expires"),
            header_colon,
        ),
        integer,
    )(input)?;

    Ok((input, Header::MinExpires(me)))
}

fn organization(input: &[u8]) -> Result<&[u8], Header> {
    let (input, org) = preceded(
        pair(
            tag_no_case("Organization"),
            header_colon,
        ),
        opt(utf8_trim),
    )(input)?;

    let org = match org {
        Some(org) => Some(std::str::from_utf8(org)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, Header::Organization(org)))
}

fn require(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (first, mut others)) = preceded(
        pair(
            tag_no_case("Require"),
            header_colon,
        ),
        pair(
            token_str,
            option_tag,
        )
    )(input)?;
    others.insert(0, first);

    Ok((input, Header::Require(others)))
}

fn duration_retry_param(input: &[u8]) -> Result<&[u8], RetryParam> {
    let (input, duration) = preceded(
        pair(
            tag_no_case("duration"),
            equal,
        ),
        integer
    )(input)?;

    Ok((input, RetryParam::AvailabilityDuration(duration)))
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
    let (input, params) = many0(preceded(semicolon, retry_param))(input)?;

    Ok((input, params))
}

fn retry_after(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (duration, comment, params)) = preceded(
        pair(
            tag_no_case("Retry-After"),
            header_colon,
        ),
        tuple((
            integer,
            opt(comment),
            retry_params
        ))
    )(input)?;

    let comment = match comment {
        Some(comment) => Some(std::str::from_utf8(comment)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, Header::RetryAfter(RetryAfter {
        duration,
        comment,
        params
    })))
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
    let (input, s) = preceded(
        pair(
            tag_no_case("Server"),
            header_colon,
        ),
        recognize(pair(
            server_val,
            many0(pair(linear_whitespace, server_val)),
        )),
    )(input)?;

    let s = std::str::from_utf8(s)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, Header::Server(s)))
}

fn user_agent(input: &[u8]) -> Result<&[u8], Header> {
    let (input, ua) = preceded(
        pair(
            tag_no_case("User-Agent"),
            header_colon,
        ),
        recognize(pair(
            server_val,
            many0(pair(linear_whitespace, server_val)),
        )),
    )(input)?;

    let ua = std::str::from_utf8(ua)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, Header::UserAgent(ua)))
}

fn subject(input: &[u8]) -> Result<&[u8], Header> {
    let (input, subject) = preceded(
        pair(
            alt((tag_no_case("Subject"), tag_no_case("s"))),
            header_colon,
        ),
        opt(utf8_trim),
    )(input)?;

    let subject = match subject {
        Some(subject) => Some(std::str::from_utf8(subject)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, Header::Subject(subject)))
}

fn supported(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (first, mut others)) = preceded(
        pair(
            alt((tag_no_case("Supported"), tag_no_case("k"))),
            header_colon,
        ),
        pair(
            token_str,
            option_tag,
        )
    )(input)?;
    others.insert(0, first);

    Ok((input, Header::Supported(others)))
}

fn delay(input: &[u8]) -> Result<&[u8], Option<&str>> {
    let (input, delay) = opt(preceded(
        linear_whitespace,
        recognize(
            pair(
                digit0,
                opt(pair(tag("."), digit0))
            )
        ),
    ))(input)?;

    let delay = match delay {
        Some(delay) => Some(std::str::from_utf8(delay)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, delay))
}

fn timestamp(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (ts, delay)) = preceded(
        pair(
            tag_no_case("Timestamp"),
            header_colon,
        ),
        pair(
            recognize(
                pair(
                    digit1,
                    opt(pair(tag("."), digit0))
                )
            ),
            delay
        )
    )(input)?;

    let ts = std::str::from_utf8(ts)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, Header::Timestamp(ts, delay)))
}

fn unsupported(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (first, mut others)) = preceded(
        pair(
            tag_no_case("Unsupported"),
            header_colon,
        ),
        pair(
            token_str,
            option_tag,
        )
    )(input)?;
    others.insert(0, first);

    Ok((input, Header::Unsupported(others)))
}

fn header_value(input: &[u8]) -> Result<&[u8], &str> {
    let (input, value) = recognize(
        many0(alt((
            utf8_char1,
            take_while(is_utf8_cont),
            linear_whitespace,
        )))
    )(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, value))
}

fn extension_header(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (name, value)) = pair(
        token_str,
        preceded(header_colon, header_value)
    )(input)?;

    Ok((input, Header::Extension(name, value)))
}

pub fn message_header(input: &[u8]) -> Result<&[u8], Header> {
    let (input, header) = terminated(
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
    use crate::header::*;

    #[test]
    fn message_header_can_parse_via() {
        let h = b"Via: SIP/2.0/TCP client.atlanta.example.com:5060;branch=z9hG4bK74b43\r\n";
        let header = message_header(h).unwrap().1;
        match header {
            Header::Via(vias) => {
                let via = &vias[0];
                assert_eq!(via.protocol, "SIP/2.0/TCP");
                assert_eq!(via.sent_by, "client.atlanta.example.com:5060");

                match &via.params[0] {
                    ViaParam::Branch(v) => assert_eq!(v, &"z9hG4bK74b43"),
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
            Header::MaxForwards(mf) => {
                assert_eq!(mf, 70);
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
