use crate::{
    message::{
        Header,
        To,
        ToParam,
        Route,
        ReplyTo,
        RecordRoute,
        From,
        FromParam,
        Contact,
        ContactValue,
        ContactParam,
    },
    parser::{
        integer,
        Result,
        rfc3261::{
            tokens::{
                token,
                token_str,
                linear_whitespace,
                header_colon,
                comma,
                quoted_string,
                equal,
                left_angle_quote,
                right_angle_quote,
                semicolon,
                star,
            },
            common::{
                absolute_uri,
                generic_param,
                generic_params,
                sip_uri,
                qvalue,
            },
        },
    },
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, preceded, terminated },
    multi::{ many0, many1, separated_nonempty_list, },
    branch::alt,
    bytes::complete::tag_no_case,
};

fn contact_params_expires(input: &[u8]) -> Result<&[u8], ContactParam> {
    let (input, expires) = preceded(
        pair(
            tag_no_case("expires"),
            equal
        ),
        integer,
    )(input)?;

    Ok((input, ContactParam::Expires(expires)))
}

fn contact_params_q(input: &[u8]) -> Result<&[u8], ContactParam> {
    let (input, q) = preceded(
        pair(
            tag_no_case("q"),
            equal,
        ),
        qvalue,
    )(input)?;

    let q = std::str::from_utf8(q)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, ContactParam::Q(q)))
}

fn contact_params_extension(input: &[u8]) -> Result<&[u8], ContactParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, ContactParam::Extension(param)))
}

fn contact_params(input: &[u8]) -> Result<&[u8], ContactParam> {
    alt((
        contact_params_q,
        contact_params_expires,
        contact_params_extension,
    ))(input)
}

fn display_name(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(many1(pair(token, linear_whitespace))),
        quoted_string
    ))(input)
}

fn addr_spec(input: &[u8]) -> Result<&[u8], (Option<&[u8]>, &[u8])> {
    let (input, addr) = alt((
        sip_uri,
        absolute_uri,
    ))(input)?;

    Ok((input, (None, addr)))
}

fn name_addr(input: &[u8]) -> Result<&[u8], (Option<&[u8]>, &[u8])> {
    let (input, (dn, (_, addr))) = pair(
        opt(display_name),
        preceded(left_angle_quote, terminated(addr_spec, right_angle_quote))
    )(input)?;

    Ok((input, (dn, addr)))
}

fn contact_param(input: &[u8]) -> Result<&[u8], Contact> {
    let (input, ((name, addr), params)) = pair(
        alt((name_addr, addr_spec)),
        many0(preceded(semicolon, contact_params))
    )(input)?;

    let addr = std::str::from_utf8(addr)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    let name = match name {
        Some(n) => Some(std::str::from_utf8(n)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, Contact {
        name,
        addr,
        params,
    }))
}

fn contact_star(input: &[u8]) -> Result<&[u8], ContactValue> {
    let (input, _) = star(input)?;

    Ok((input, ContactValue::Any))
}

fn contact_specific(input: &[u8]) -> Result<&[u8], ContactValue> {
    let (input, params) = separated_nonempty_list(comma, contact_param)(input)?;

    Ok((input, ContactValue::Specific(params)))
}

pub fn contact(input: &[u8]) -> Result<&[u8], Header> {
    let (input, value) = preceded(
        pair(
            alt((
                tag_no_case("Contact"),
                tag_no_case("m"),
            )),
            header_colon,
        ),
        alt((
            contact_star,
            contact_specific,
        ))
    )(input)?;

    Ok((input, Header::Contact(value)))
}

fn tag_param(input: &[u8]) -> Result<&[u8], &str> {
    let (input, tag) = preceded(
        pair(
            tag_no_case("tag"),
            equal,
        ),
        token_str,
    )(input)?;

    Ok((input, tag))
}

fn from_param_tag(input: &[u8]) -> Result<&[u8], FromParam> {
    let (input, tag) = tag_param(input)?;

    Ok((input, FromParam::Tag(tag)))
}

fn from_param_extension(input: &[u8]) -> Result<&[u8], FromParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, FromParam::Extension(param)))
}

fn from_spec(input: &[u8]) -> Result<&[u8], From> {
    let (input, ((name, addr), params)) = pair(
        alt((name_addr, addr_spec)),
        many0(preceded(semicolon, alt((from_param_tag, from_param_extension))))
    )(input)?;

    let addr = std::str::from_utf8(addr)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    let name = match name {
        Some(n) => Some(std::str::from_utf8(n)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, From {
        name,
        addr,
        params,
    }))
}

pub fn from(input: &[u8]) -> Result<&[u8], Header> {
    let (input, from) = preceded(
        pair(
            alt((tag_no_case("From"), tag_no_case("f"))),
            header_colon,
        ),
        from_spec
    )(input)?;

    Ok((input, Header::From(from)))
}

fn rec_route(input: &[u8]) -> Result<&[u8], RecordRoute> {
    let (input, ((name, addr), params)) = pair(
        name_addr,
        generic_params,
    )(input)?;

    let addr = std::str::from_utf8(addr)
        .map_err(|err| nom::Err::Failure(err.into()))?;
    let name = match name {
        Some(n) => Some(std::str::from_utf8(n)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, RecordRoute {
        addr,
        name,
        params,
    }))
}

pub fn record_route(input: &[u8]) -> Result<&[u8], Header> {
    let (input, routes) = preceded(
        pair(
            tag_no_case("Record-Route"),
            header_colon,
        ),
        separated_nonempty_list(comma, rec_route)
    )(input)?;

    Ok((input, Header::RecordRoute(routes)))
}

fn rplyto_spec(input: &[u8]) -> Result<&[u8], ReplyTo> {
    let (input, ((name, addr), params)) = pair(
        alt((name_addr, addr_spec)),
        generic_params,
    )(input)?;

    let addr = std::str::from_utf8(addr)
        .map_err(|err| nom::Err::Failure(err.into()))?;
    let name = match name {
        Some(n) => Some(std::str::from_utf8(n)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, ReplyTo {
        addr,
        name,
        params,
    }))
}

pub fn reply_to(input: &[u8]) -> Result<&[u8], Header> {
    let (input, reply_to) = preceded(
        pair(
            tag_no_case("Reply-To"),
            header_colon,
        ),
        rplyto_spec
    )(input)?;

    Ok((input, Header::ReplyTo(reply_to)))
}

fn route_param(input: &[u8]) -> Result<&[u8], Route> {
    let (input, ((name, addr), params)) = pair(
        name_addr,
        generic_params,
    )(input)?;

    let addr = std::str::from_utf8(addr)
        .map_err(|err| nom::Err::Failure(err.into()))?;
    let name = match name {
        Some(n) => Some(std::str::from_utf8(n)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, Route {
        addr,
        name,
        params,
    }))
}

pub fn route(input: &[u8]) -> Result<&[u8], Header> {
    let (input, params) = preceded(
        pair(
            tag_no_case("Route"),
            header_colon,
        ),
        separated_nonempty_list(comma, route_param)
    )(input)?;

    Ok((input, Header::Route(params)))
}

fn to_param_tag(input: &[u8]) -> Result<&[u8], ToParam> {
    let (input, tag) = tag_param(input)?;

    Ok((input, ToParam::Tag(tag)))
}

fn to_param_extension(input: &[u8]) -> Result<&[u8], ToParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, ToParam::Extension(param)))
}

fn to_param(input: &[u8]) -> Result<&[u8], ToParam> {
    alt((
        to_param_tag,
        to_param_extension,
    ))(input)
}

pub fn to(input: &[u8]) -> Result<&[u8], Header> {
    let (input, ((name, addr), params)) = preceded(
        pair(
            alt((tag_no_case("To"), tag_no_case("t"))),
            header_colon,
        ),
        pair(
            alt((name_addr, addr_spec)),
            many0(preceded(semicolon, to_param))
        )
    )(input)?;

    let addr = std::str::from_utf8(addr)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    let name = match name {
        Some(n) => Some(std::str::from_utf8(n)
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, Header::To(To {
        addr,
        name,
        params,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::*;

    #[test]
    fn contact_params_expires_extracts_value() {
        assert_eq!(contact_params_expires(b"expires=18").unwrap().1, ContactParam::Expires(18));
    }

    #[test]
    fn contact_params_q_extracts_value() {
        assert_eq!(contact_params_q(b"q=1.0").unwrap().1, ContactParam::Q("1.0"));
    }

    #[test]
    fn contact_params_extension_extracts_value() {
        assert_eq!(contact_params_extension(b"other").unwrap().1, ContactParam::Extension(GenericParam {
            name: "other",
            value: None,
        }));

        assert_eq!(contact_params_extension(b"other=").unwrap().1, ContactParam::Extension(GenericParam {
            name: "other",
            value: None,
        }));

        assert_eq!(contact_params_extension(b"other=value").unwrap().1, ContactParam::Extension(GenericParam {
            name: "other",
            value: Some("value"),
        }));
    }

    #[test]
    fn name_addr_extracts_addr() {
        assert!(name_addr(b"<sip:example.com>").unwrap().1 == (None, b"sip:example.com"));
        assert!(name_addr(b"<sip:example.com:5060>").unwrap().1 == (None, b"sip:example.com:5060"));
        assert!(name_addr(b"<sips:john@example.com>").unwrap().1 == (None, b"sips:john@example.com"));
    }

    #[test]
    fn display_name_can_handle_quoted_and_unquoted_strings() {
        assert!(display_name(b"John ").unwrap().1 == b"John ");
        assert!(display_name(b"\"John\"").unwrap().1 == b"John");
    }

    #[test]
    fn name_addr_extracts_addr_and_name() {
        assert!(name_addr(b"John <sip:example.com>").unwrap().1 == (Some(b"John "), b"sip:example.com"));
        assert!(name_addr(b"\"John Doe\" <sip:example.com>").unwrap().1 == (Some(b"John Doe"), b"sip:example.com"));
    }

    #[test]
    fn contact_param_can_parse_full_contact() {
        assert!(contact_param(b"\"John\" <sip:j@example.com>;expires=8;q=1.0").unwrap().1 == Contact {
            addr: "sip:j@example.com",
            name: Some("John"),
            params: vec![
                ContactParam::Expires(8),
                ContactParam::Q("1.0")
            ]
        })
    }

    #[test]
    fn to_can_parse_whole_to_line() {
        assert!(to(b"To: Bob <sip:bob@biloxi.example.com>").is_ok());
    }
}
