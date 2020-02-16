use crate::parser::{
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
        },
        common::{
            absolute_uri,
            generic_param,
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

pub fn call_id(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                tag_no_case("Call-ID"),
                tag_no_case("i"),
            )),
            header_colon,
            callid
        ))
    )(input)
}

fn info_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(tuple((
            tag_no_case("purpose"),
            equal,
            alt((
                tag_no_case("icon"),
                tag_no_case("info"),
                tag_no_case("card"),
                tag_no_case("token")
            ))
        ))),
        generic_param,
    ))(input)
}

fn info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            left_angle_quote,
            absolute_uri,
            right_angle_quote,
            many0(pair(semicolon, info_param))
        ))
    )(input)
}

pub fn call_info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Call-Info"),
            header_colon,
            info,
            many0(pair(comma, info))
        ))
    )(input)
}

pub fn in_reply_to(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("In-Reply-To"),
            header_colon,
            callid,
            many0(pair(comma, callid))
        ))
    )(input)
}
