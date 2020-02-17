use crate::{
    message::{ Header, InfoParamPurpose, InfoParam, Info, },
    parser::{
        Result,
        rfc3261::{
            tokens::{
                header_colon,
                comma,
                equal,
                word,
                left_angle_quote,
                right_angle_quote,
                semicolon,
                token,
            },
            common::{
                absolute_uri,
                generic_param,
            },
        },
    },
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    multi::many0,
    branch::alt,
    bytes::complete::{ tag, tag_no_case },
};

fn callid(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            word,
            opt(pair(tag("@"), word))
        )
    )(input)
}

pub fn call_id(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, id)) = tuple((
        alt((
            tag_no_case("Call-ID"),
            tag_no_case("i"),
        )),
        header_colon,
        callid
    ))(input)?;

    Ok((input, Header::CallID(id)))
}

fn info_param_purpose_icon(input: &[u8]) -> Result<&[u8], InfoParamPurpose> {
    let (input, _) = tag_no_case("icon")(input)?;

    Ok((input, InfoParamPurpose::Icon))
}

fn info_param_purpose_info(input: &[u8]) -> Result<&[u8], InfoParamPurpose> {
    let (input, _) = tag_no_case("info")(input)?;

    Ok((input, InfoParamPurpose::Info))
}

fn info_param_purpose_card(input: &[u8]) -> Result<&[u8], InfoParamPurpose> {
    let (input, _) = tag_no_case("card")(input)?;

    Ok((input, InfoParamPurpose::Card))
}

fn info_param_purpose_other(input: &[u8]) -> Result<&[u8], InfoParamPurpose> {
    let (input, value) = token(input)?;

    Ok((input, InfoParamPurpose::Other(value)))
}

fn info_param_purpose(input: &[u8]) -> Result<&[u8], InfoParam> {
    let (input, (_, _, purpose)) = tuple((
        tag_no_case("purpose"),
        equal,
        alt((
            info_param_purpose_icon,
            info_param_purpose_info,
            info_param_purpose_card,
            info_param_purpose_other,
        ))
    ))(input)?;

    Ok((input, InfoParam::Purpose(purpose)))
}

fn info_param_extension(input: &[u8]) -> Result<&[u8], InfoParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, InfoParam::Extension(param)))
}

fn info_param(input: &[u8]) -> Result<&[u8], InfoParam> {
    alt((
        info_param_purpose,
        info_param_extension,
    ))(input)
}

fn info(input: &[u8]) -> Result<&[u8], Info> {
    let (input, (_, uri, _, params)) = tuple((
        left_angle_quote,
        absolute_uri,
        right_angle_quote,
        many0(pair(semicolon, info_param))
    ))(input)?;
    let params = params.into_iter().map(|(_, param)| param).collect();

    Ok((input, Info {
        uri,
        params,
    }))
}

pub fn call_info(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, others)) = tuple((
        tag_no_case("Call-Info"),
        header_colon,
        info,
        many0(pair(comma, info))
    ))(input)?;

    let mut others: Vec<Info> = others.into_iter().map(|(_, info)| info).collect();
    others.insert(0, first);

    Ok((input, Header::CallInfo(others)))
}

pub fn in_reply_to(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, first, others)) = tuple((
        tag_no_case("In-Reply-To"),
        header_colon,
        callid,
        many0(pair(comma, callid))
    ))(input)?;

    let mut others: Vec<&[u8]> = others.into_iter().map(|(_, callid)| callid).collect();
    others.insert(0, first);

    Ok((input, Header::InReplyTo(others)))
}
