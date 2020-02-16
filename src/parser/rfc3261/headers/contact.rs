use crate::parser::{
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
            sip_uri,
            sips_uri,
            qvalue,
        },
    },
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    multi::many0,
    branch::alt,
    character::complete::digit1,
    bytes::complete::tag,
};

fn c_p_expires(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("expires"),
            equal,
            digit1,
        ))
    )(input)
}

fn c_p_q(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("q"),
            equal,
            qvalue,
        ))
    )(input)
}

fn contact_params(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        c_p_q,
        c_p_expires,
        generic_param,
    ))(input)
}

fn display_name(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(many0(pair(token, linear_whitespace))),
        quoted_string
    ))(input)
}

fn addr_spec(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        sip_uri,
        sips_uri,
        absolute_uri,
    ))(input)
}

fn name_addr(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            opt(display_name),
            left_angle_quote,
            addr_spec,
            right_angle_quote,
        ))
    )(input)
}

fn contact_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alt((name_addr, addr_spec)),
            many0(pair(semicolon, contact_params))
        )
    )(input)
}

pub fn contact(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                tag("Contact"),
                tag("m"),
            )),
            header_colon,
            alt((
                star,
                recognize(pair(contact_param, many0(pair(comma, contact_param))))
            ))
        ))
    )(input)
}

fn tag_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("tag"),
            equal,
            token,
        ))
    )(input)
}

fn from_spec(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alt((name_addr, addr_spec)),
            many0(pair(semicolon, alt((tag_param, generic_param))))
        )
    )(input)
}

pub fn from(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((tag("From"), tag("f"))),
            header_colon,
            from_spec
        ))
    )(input)
}

fn rec_route(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            name_addr,
            many0(pair(semicolon, generic_param))
        )
    )(input)
}

pub fn record_route(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("Record-Route"),
            header_colon,
            rec_route,
            many0(pair(comma, rec_route))
        ))
    )(input)
}

fn rplyto_spec(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alt((name_addr, addr_spec)),
            many0(pair(semicolon, generic_param))
        )
    )(input)
}

pub fn reply_to(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("Reply-To"),
            header_colon,
            rplyto_spec
        ))
    )(input)
}

fn route_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            name_addr,
            many0(pair(semicolon, generic_param))
        )
    )(input)
}

pub fn route(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("Route"),
            header_colon,
            route_param,
            many0(pair(comma, route_param))
        ))
    )(input)
}

pub fn to(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((tag("To"), tag("t"))),
            header_colon,
            alt((name_addr, addr_spec)),
            many0(pair(semicolon, alt((tag_param, generic_param))))
        ))
    )(input)
}
