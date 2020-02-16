use crate::parser::{
    Result,
    rfc3261::{
        tokens::{
            semicolon,
            header_colon,
            comma,
            left_angle_quote,
            right_angle_quote,
        },
        common::{
            absolute_uri,
            generic_param,
        },
    },
};

use nom::{
    combinator::recognize,
    sequence::{ pair, tuple },
    multi::many0,
    bytes::complete::tag_no_case,
};

fn alert_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            left_angle_quote,
            absolute_uri,
            right_angle_quote,
            many0(pair(semicolon, generic_param))
        ))
    )(input)
}

pub fn alert_info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Alert-Info"),
            header_colon,
            alert_param,
            many0(pair(comma, alert_param))
        ))
    )(input)
}
