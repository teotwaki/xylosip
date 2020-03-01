use crate::{
    header::{ Header, ErrorInfo, },
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
    sequence::{ pair, tuple, preceded, },
    multi::separated_nonempty_list,
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
    let (input, errors) = preceded(
        pair(
            tag_no_case("Error-Info"),
            header_colon,
        ),
        separated_nonempty_list(comma, error_uri)
    )(input)?;

    Ok((input, Header::ErrorInfo(errors)))
}
