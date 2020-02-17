use crate::{
    message::{ Header, Warning, },
    parser::{
        Result,
        rfc3261::{
            tokens::{
                token,
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
    sequence::{ pair, tuple },
    multi::many0,
    branch::alt,
    character::is_digit,
    bytes::complete::{
        tag,
        tag_no_case,
        take_while_m_n,
    },
};

fn warning_value(input: &[u8]) -> Result<&[u8], Warning> {
    // TODO: Parse code into an enum
    let (input, (code, _, agent, _, text)) = tuple((
        take_while_m_n(3, 3, is_digit),
        tag(" "),
        alt((host_port, token)),
        tag(" "),
        quoted_string,
    ))(input)?;

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
