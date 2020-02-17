use crate::{
    message::{ Header, AlertInfo, },
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
    sequence::{ pair, tuple },
    multi::many0,
    bytes::complete::tag_no_case,
};

fn alert_param(input: &[u8]) -> Result<&[u8], AlertInfo> {
    let (input, (_, uri, _, params)) = tuple((
        left_angle_quote,
        absolute_uri,
        right_angle_quote,
        generic_params,
    ))(input)?;

    Ok((input, AlertInfo {
        uri,
        params,
    }))
}

pub fn alert_info(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, others)) = tuple((
        tag_no_case("Alert-Info"),
        header_colon,
        alert_param,
        many0(pair(comma, alert_param))
    ))(input)?;
    let mut others: Vec<AlertInfo> = others.into_iter().map(|(_, info)| info).collect();
    others.insert(0, first);

    Ok((input, Header::AlertInfo(others)))
}
