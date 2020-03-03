use crate::{
    header::{
        Header,
        InfoParamPurpose,
        InfoParam,
        Info,
    },
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
                token_str,
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
    sequence::{ pair, preceded, terminated, },
    multi::{ separated_list, separated_nonempty_list, },
    branch::alt,
    bytes::complete::{ tag, tag_no_case },
};

fn callid(input: &[u8]) -> Result<&[u8], String> {
    let (input, callid) = recognize(
        pair(
            word,
            opt(pair(tag("@"), word))
        )
    )(input)?;

    let callid = std::str::from_utf8(callid)
        .map(|s| s.to_string())
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, callid))
}

pub fn call_id(input: &[u8]) -> Result<&[u8], Header> {
    let (input, id) = preceded(
        pair(
            alt((
                tag_no_case("Call-ID"),
                tag_no_case("i"),
            )),
            header_colon,
        ),
        callid
    )(input)?;

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
    let (input, value) = token_str(input)?;

    Ok((input, InfoParamPurpose::Other(value.to_string())))
}

fn info_param_purpose(input: &[u8]) -> Result<&[u8], InfoParam> {
    let (input, purpose) = preceded(
        pair(
            tag_no_case("purpose"),
            equal
        ),
        alt((
            info_param_purpose_icon,
            info_param_purpose_info,
            info_param_purpose_card,
            info_param_purpose_other,
        ))
    )(input)?;

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
    let (input, (uri, params)) = pair(
        preceded(left_angle_quote, terminated(absolute_uri, right_angle_quote)),
        separated_list(semicolon, info_param)
    )(input)?;

    let uri = std::str::from_utf8(uri)
        .map(|s| s.to_string())
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, Info {
        uri,
        params,
    }))
}

pub fn call_info(input: &[u8]) -> Result<&[u8], Header> {
    let (input, infos) = preceded(
        pair(
            tag_no_case("Call-Info"),
            header_colon
        ),
        separated_nonempty_list(comma, info),
    )(input)?;

    Ok((input, Header::CallInfo(infos)))
}

pub fn in_reply_to(input: &[u8]) -> Result<&[u8], Header> {
    let (input, callids) = preceded(
        pair(
            tag_no_case("In-Reply-To"),
            header_colon,
        ),
        separated_nonempty_list(comma, callid)
    )(input)?;

    Ok((input, Header::InReplyTo(callids)))
}
