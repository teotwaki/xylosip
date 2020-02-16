use crate::parser::rfc3261::{
    Result,
    token,
    header_colon,
    comma,
    host_port,
    quoted_string,
};

use nom::{
    combinator::recognize,
    sequence::{ pair, tuple },
    multi::many0,
    branch::alt,
    character::is_digit,
    bytes::complete::{
        tag,
        take_while_m_n,
    },
};

fn warning_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            take_while_m_n(3, 3, is_digit),
            tag(" "),
            alt((host_port, token)),
            tag(" "),
            quoted_string,
        ))
    )(input)
}

pub fn warning(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("Warning"),
            header_colon,
            warning_value,
            many0(pair(comma, warning_value))
        ))
    )(input)
}
