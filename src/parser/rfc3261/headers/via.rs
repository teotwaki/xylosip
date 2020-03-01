use crate::{
    header::{ Header, ViaParam, Via },
    parser::{
        Error,
        integer,
        Result,
        rfc3261::{
            tokens::{
                token,
                token_str,
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
            },
        },
    },
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple, preceded },
    multi::{ many0, separated_nonempty_list, },
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

fn protocol_name(input: &[u8]) -> Result<&[u8], &str> {
    let (input, value) = alt((
        tag_no_case("SIP"),
        token,
    ))(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(Error::from(err)))?;

    Ok((input, value))
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

fn via_extension(input: &[u8]) -> Result<&[u8], ViaParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, ViaParam::Extension(param)))
}

fn via_branch(input: &[u8]) -> Result<&[u8], ViaParam> {
    let (input, branch) = preceded(
        pair(
            tag_no_case("branch"),
            equal,
        ),
        token_str,
    )(input)?;

    Ok((input, ViaParam::Branch(branch)))
}

fn via_received(input: &[u8]) -> Result<&[u8], ViaParam> {
    let (input, addr) = preceded(
        pair(
            tag_no_case("received"),
            equal,
        ),
        alt((ipv4_address, ipv6_address)),
    )(input)?;

    let addr = std::str::from_utf8(addr)
        .map_err(|err| nom::Err::Failure(Error::from(err)))?;

    Ok((input, ViaParam::Received(addr)))
}

fn via_maddr(input: &[u8]) -> Result<&[u8], ViaParam> {
    let (input, maddr) = preceded(
        pair(
            tag_no_case("maddr"),
            equal,
        ),
        host,
    )(input)?;

    let maddr = std::str::from_utf8(maddr)
        .map_err(|err| nom::Err::Failure(Error::from(err)))?;

    Ok((input, ViaParam::MAddr(maddr)))
}

fn via_ttl(input: &[u8]) -> Result<&[u8], ViaParam> {
    let (input, ttl) = preceded(
        pair(
            tag_no_case("ttl"),
            equal,
        ),
        integer,
    )(input)?;

    Ok((input, ViaParam::Ttl(ttl)))
}

fn via_params(input: &[u8]) -> Result<&[u8], ViaParam> {
    alt((
        via_ttl,
        via_maddr,
        via_received,
        via_branch,
        via_extension,
    ))(input)
}

fn via_parm(input: &[u8]) -> Result<&[u8], Via> {
    let (input, (protocol, sent_by, params)) = tuple((
        sent_protocol,
        preceded(linear_whitespace, sent_by),
        many0(preceded(semicolon, via_params))
    ))(input)?;

    let protocol = std::str::from_utf8(protocol)
        .map_err(|err| nom::Err::Failure(Error::from(err)))?;

    let sent_by = std::str::from_utf8(sent_by)
        .map_err(|err| nom::Err::Failure(Error::from(err)))?;

    Ok((input, Via {
        protocol,
        sent_by,
        params,
    }))
}

pub fn via(input: &[u8]) -> Result<&[u8], Header> {
    let (input, vias) = preceded(
        pair(
            alt((tag_no_case("Via"), tag_no_case("v"))),
            header_colon,
        ),
        separated_nonempty_list(comma, via_parm)
    )(input)?;

    Ok((input, Header::Via(vias)))
}
