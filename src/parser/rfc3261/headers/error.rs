use crate::{
    message::{ Header, ErrorInfo, },
    parser::{
        Result,
        rfc3261::{
            tokens::{
                header_colon,
                comma,
                left_angle_quote,
                right_angle_quote,
            },
            common::{
                generic_params,
                absolute_uri,
            },
        },
    },
};

use nom::{
    sequence::{ pair, tuple },
    multi::many0,
    bytes::complete::tag_no_case,
};

fn error_uri(input: &[u8]) -> Result<&[u8], ErrorInfo> {
    let (input, (_, uri, _, params)) = tuple((
        left_angle_quote,
        absolute_uri,
        right_angle_quote,
        generic_params
    ))(input)?;

    let uri = std::str::from_utf8(uri)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, ErrorInfo {
        uri,
        params,
    }))
}

pub fn error_info(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, others)) = tuple((
        tag_no_case("Error-Info"),
        header_colon,
        error_uri,
        many0(pair(comma, error_uri))
    ))(input)?;
    let mut others: Vec<ErrorInfo> = others.into_iter().map(|(_, info)| info).collect();
    others.insert(0, first);

    Ok((input, Header::ErrorInfo(others)))
}
