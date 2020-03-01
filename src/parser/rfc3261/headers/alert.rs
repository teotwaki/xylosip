use crate::{
    header::{ Header, AlertInfo, },
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
                absolute_uri,
                generic_params,
            },
        },
    },
};

use nom::{
    sequence::{ pair, preceded, terminated },
    multi::separated_nonempty_list,
    bytes::complete::tag_no_case,
};

fn alert_param(input: &[u8]) -> Result<&[u8], AlertInfo> {
    let (input, (uri, params)) = pair(
        preceded(left_angle_quote, terminated(absolute_uri, right_angle_quote)),
        generic_params,
    )(input)?;

    let uri = std::str::from_utf8(uri)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, AlertInfo {
        uri,
        params,
    }))
}

pub fn alert_info(input: &[u8]) -> Result<&[u8], Header> {
    let (input, params) = preceded(
        pair(
            tag_no_case("Alert-Info"),
            header_colon
        ),
        separated_nonempty_list(comma, alert_param)
    )(input)?;

    Ok((input, Header::AlertInfo(params)))
}
