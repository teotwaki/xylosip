use crate::parser::rfc3261::{
    Result,
    semicolon,
    header_colon,
    comma,
    left_angle_quote,
    right_angle_quote,
    generic_param,
    absolute_uri,
};

use nom::{
    combinator::recognize,
    sequence::{ pair, tuple },
    multi::many0,
    bytes::complete::tag,
};

fn error_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            left_angle_quote,
            absolute_uri,
            right_angle_quote,
            many0(pair(semicolon, generic_param))
        ))
    )(input)
}

pub fn error_info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("Error-Info"),
            header_colon,
            error_uri,
            many0(pair(comma, error_uri))
        ))
    )(input)
}
