use crate::parser::rfc3261::{
    Result,
    header_colon,
    comma,
    absolute_uri,
    equal,
    word,
    generic_param,
    left_angle_quote,
    right_angle_quote,
    semicolon,
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    multi::many0,
    branch::alt,
    bytes::complete::tag,
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
                tag("Call-ID"),
                tag("i"),
            )),
            header_colon,
            callid
        ))
    )(input)
}

fn info_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(tuple((
            tag("purpose"),
            equal,
            alt((
                tag("icon"),
                tag("info"),
                tag("card"),
                tag("token")
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
            tag("Call-Info"),
            header_colon,
            info,
            many0(pair(comma, info))
        ))
    )(input)
}

pub fn in_reply_to(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("In-Reply-To"),
            header_colon,
            callid,
            many0(pair(comma, callid))
        ))
    )(input)
}
