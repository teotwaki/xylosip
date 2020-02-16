use crate::parser::{
    Result,
    rfc3261::{
        tokens::{
            token,
            linear_whitespace,
            header_colon,
            comma,
            equal,
            semicolon,
            colon,
            slash,
        },
        common::{
            generic_param,
            host,
            port,
            transport,
            ipv4_address,
            ipv6_address,
            ttl,
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

fn sent_by(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            host,
            opt(pair(colon, port))
        )
    )(input)
}

fn protocol_name(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("SIP"),
        token,
    ))(input)
}

fn sent_protocol(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            protocol_name,
            slash,
            token,
            slash,
            transport,
        ))
    )(input)
}

fn via_branch(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("branch"),
            equal,
            token,
        ))
    )(input)
}

fn via_received(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("received"),
            equal,
            alt((ipv4_address, ipv6_address)),
        ))
    )(input)
}

fn via_maddr(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("maddr"),
            equal,
            host,
        ))
    )(input)
}

fn via_ttl(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("ttl"),
            equal,
            ttl,
        ))
    )(input)
}

fn via_params(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        via_ttl,
        via_maddr,
        via_received,
        via_branch,
        generic_param,
    ))(input)
}

fn via_parm(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            sent_protocol,
            linear_whitespace,
            sent_by,
            many0(pair(semicolon, via_params))
        ))
    )(input)
}

pub fn via(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((tag_no_case("Via"), tag_no_case("v"))),
            header_colon,
            via_parm,
            many0(pair(comma, via_parm))
        ))
    )(input)
}
