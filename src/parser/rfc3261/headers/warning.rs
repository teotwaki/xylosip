use crate::{
    message::{ Header, Warning, WarningAgent, },
    parser::{
        Result,
        rfc3261::{
            tokens::{
                token_str,
                header_colon,
                comma,
                quoted_string,
            },
            common::{
                host_port,
            },
        },
    },
};

use nom::{
    sequence::{ pair, tuple, preceded },
    multi::many0,
    branch::alt,
    character::is_digit,
    bytes::complete::{
        tag,
        tag_no_case,
        take_while_m_n,
    },
};

fn warning_agent_host_port(input: &[u8]) -> Result<&[u8], WarningAgent> {
    let (input, (host, port)) = host_port(input)?;

    let host = std::str::from_utf8(host)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, WarningAgent::HostPort(host, port)))
}

fn warning_agent_pseudonym(input: &[u8]) -> Result<&[u8], WarningAgent> {
    let (input, pseudonym) = token_str(input)?;

    Ok((input, WarningAgent::Pseudonym(pseudonym)))
}

fn warning_agent(input: &[u8]) -> Result<&[u8], WarningAgent> {
    alt((
        warning_agent_host_port,
        warning_agent_pseudonym,
    ))(input)
}

fn warning_value(input: &[u8]) -> Result<&[u8], Warning> {
    // TODO: Parse code into an enum
    let (input, (code, agent, text)) = tuple((
        take_while_m_n(3, 3, is_digit),
        preceded(tag(" "), warning_agent),
        preceded(tag(" "), quoted_string)
    ))(input)?;

    let code = std::str::from_utf8(code)
        .map_err(|err| nom::Err::Failure(err.into()))?;
    let text = std::str::from_utf8(text)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, Warning {
        code,
        agent,
        text
    }))
}

pub fn warning(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, others)) = tuple((
        tag_no_case("Warning"),
        header_colon,
        warning_value,
        many0(pair(comma, warning_value))
    ))(input)?;
    let mut others: Vec<Warning> = others.into_iter().map(|(_, warning)| warning).collect();
    others.insert(0, first);

    Ok((input, Header::Warning(others)))
}
