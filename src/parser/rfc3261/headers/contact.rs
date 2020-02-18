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
    sequence::{ pair, tuple },
    multi::many0,
    branch::alt,
    bytes::complete::tag_no_case,
};

fn contact_params_expires(input: &[u8]) -> Result<&[u8], ContactParam> {
    let (input, (_, _, expires)) = tuple((
        tag_no_case("expires"),
        equal,
        integer,
    ))(input)?;

    Ok((input, ContactParam::Expires(expires)))
}

fn contact_params_q(input: &[u8]) -> Result<&[u8], ContactParam> {
    let (input, (_, _, q)) = tuple((
        tag_no_case("q"),
        equal,
        qvalue,
    ))(input)?;

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
        recognize(many0(pair(token, linear_whitespace))),
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
    let (input, (dn, _, (_, addr), _)) = tuple((
        opt(display_name),
        left_angle_quote,
        addr_spec,
        right_angle_quote,
    ))(input)?;

    Ok((input, (dn, addr)))
}

fn contact_param(input: &[u8]) -> Result<&[u8], Contact> {
    let (input, ((name, addr), params)) = pair(
        alt((name_addr, addr_spec)),
        many0(pair(semicolon, contact_params))
    )(input)?;
    let params = params.into_iter().map(|(_, param)| param).collect();

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
    let (input, (first, others)) = pair(
        contact_param,
        many0(pair(comma, contact_param)),
    )(input)?;
    let mut others: Vec<Contact> = others.into_iter().map(|(_, param)| param).collect();
    others.insert(0, first);

    Ok((input, ContactValue::Specific(others)))
}

pub fn contact(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, value)) = tuple((
        alt((
            tag_no_case("Contact"),
            tag_no_case("m"),
        )),
        header_colon,
        alt((
            contact_star,
            contact_specific,
        ))
    ))(input)?;

    Ok((input, Header::Contact(value)))
}

fn tag_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    let (input, (_, _, tag)) = tuple((
        tag_no_case("tag"),
        equal,
        token,
    ))(input)?;

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
        many0(pair(semicolon, alt((from_param_tag, from_param_extension))))
    )(input)?;
    let params = params.into_iter().map(|(_, param)| param).collect();

    Ok((input, From {
        name,
        addr,
        params,
    }))
}

pub fn from(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, from)) = tuple((
        alt((tag_no_case("From"), tag_no_case("f"))),
        header_colon,
        from_spec
    ))(input)?;

    Ok((input, Header::From(from)))
}

fn rec_route(input: &[u8]) -> Result<&[u8], RecordRoute> {
    let (input, ((name, addr), params)) = pair(
        name_addr,
        generic_params,
    )(input)?;

    Ok((input, RecordRoute {
        addr,
        name,
        params,
    }))
}

pub fn record_route(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, others)) = tuple((
        tag_no_case("Record-Route"),
        header_colon,
        rec_route,
        many0(pair(comma, rec_route))
    ))(input)?;
    let mut others: Vec<RecordRoute> = others.into_iter().map(|(_, route)| route).collect();
    others.insert(0, first);

    Ok((input, Header::RecordRoute(others)))
}

fn rplyto_spec(input: &[u8]) -> Result<&[u8], ReplyTo> {
    let (input, ((name, addr), params)) = pair(
        alt((name_addr, addr_spec)),
        generic_params,
    )(input)?;

    Ok((input, ReplyTo {
        addr,
        name,
        params,
    }))
}

pub fn reply_to(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, reply_to)) = tuple((
        tag_no_case("Reply-To"),
        header_colon,
        rplyto_spec
    ))(input)?;

    Ok((input, Header::ReplyTo(reply_to)))
}

fn route_param(input: &[u8]) -> Result<&[u8], Route> {
    let (input, ((name, addr), params)) = pair(
        name_addr,
        generic_params,
    )(input)?;

    Ok((input, Route {
        addr,
        name,
        params,
    }))
}

pub fn route(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, others)) = tuple((
        tag_no_case("Route"),
        header_colon,
        route_param,
        many0(pair(comma, route_param))
    ))(input)?;
    let mut others: Vec<Route> = others.into_iter().map(|(_, route)| route).collect();
    others.insert(0, first);

    Ok((input, Header::Route(others)))
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
    let (input, (_, _, (name, addr), params)) = tuple((
        alt((tag_no_case("To"), tag_no_case("t"))),
        header_colon,
        alt((name_addr, addr_spec)),
        many0(pair(semicolon, to_param)),
    ))(input)?;
    let params = params.into_iter().map(|(_, param)| param).collect();

    Ok((input, Header::To(To {
        addr,
        name,
        params,
    })))
}
