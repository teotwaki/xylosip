use crate::parser::{
    Result,
    rfc3261::{
        tokens::{
            token,
            quoted_string,
            equal,
            slash,
            semicolon,
            header_colon,
            comma,
        },
        common::{
            accept_param,
            generic_param,
        },
    },
};

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    branch::alt,
    multi::many0,
    character::is_alphabetic,
    character::complete::digit1,
    bytes::complete::{ tag, tag_no_case, take_while_m_n, },
};

fn m_type(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("text"),
        tag_no_case("image"),
        tag_no_case("audio"),
        tag_no_case("video"),
        tag_no_case("application"),
        tag_no_case("message"),
        tag_no_case("multipart"),
        extension_token,
    ))(input)
}

fn m_subtype(input: &[u8]) -> Result<&[u8], &[u8]> {
    extension_token(input)
}

fn m_parameter(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            token,
            equal,
            alt((token, quoted_string))
        ))
    )(input)
}

fn media_range(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alt((
                tag("*/*"),
                recognize(tuple((m_type, slash, alt((tag("*"), m_subtype))))),

            )),
            many0(pair(semicolon, m_parameter))
        )
    )(input)
}

fn accept_range(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            media_range,
            many0(pair(semicolon, accept_param))
        )
    )(input)
}

pub fn accept(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Accept"),
            header_colon,
            opt(pair(accept_range, many0(pair(comma, accept_range))))
        ))
    )(input)
}

fn codings(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        token,
        tag("*")
    ))(input)
}

fn encoding(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            codings,
            many0(pair(semicolon, accept_param))
        )
    )(input)
}

pub fn accept_encoding(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Accept-Encoding"),
            header_colon,
            opt(pair(encoding, many0(pair(comma, encoding))))
        ))
    )(input)
}

fn language_range(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag("*"),
        recognize(pair(
            take_while_m_n(1, 8, is_alphabetic),
            many0(pair(tag("-"), take_while_m_n(1, 8, is_alphabetic)))
        ))
    ))(input)
}

fn language(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            language_range,
            many0(pair(semicolon, accept_param))
        )
    )(input)
}

pub fn accept_language(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Accept-Language"),
            header_colon,
            opt(pair(language, many0(pair(comma, language))))
        ))
    )(input)
}

fn extension_token(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        token,
        recognize(pair(tag_no_case("x-"), token)),
    ))(input)
}

fn media_type(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            m_type,
            slash,
            m_subtype,
            many0(pair(semicolon, m_parameter))
        ))
    )(input)
}

pub fn content_type(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                tag_no_case("Content-Type"),
                tag_no_case("c"),
            )),
            header_colon,
            media_type,
        ))
    )(input)
}

pub fn content_length(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                tag_no_case("Content-Length"),
                tag_no_case("l"),
            )),
            header_colon,
            digit1,
        ))
    )(input)
}

pub fn content_encoding(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                tag_no_case("Content-Encoding"),
                tag_no_case("e"),
            )),
            header_colon,
            token,
            many0(pair(comma, token))
        ))
    )(input)
}

fn handling_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("handling"),
            equal,
            alt((
                tag_no_case("optional"),
                tag_no_case("required"),
                token,
            )),
        ))
    )(input)
}

fn disp_type(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("render"),
        tag_no_case("session"),
        tag_no_case("icon"),
        tag_no_case("alert"),
        token,
    ))(input)
}


pub fn content_disposition(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Content-Disposition"),
            header_colon,
            disp_type,
            many0(pair(semicolon, alt((handling_param, generic_param))))
        ))
    )(input)
}

fn language_tag(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 8, is_alphabetic),
            many0(pair(tag("-"), take_while_m_n(1, 8, is_alphabetic)))
        )
    )(input)
}

pub fn content_language(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Content-Language"),
            header_colon,
            language_tag,
            many0(pair(comma, language_tag))
        ))
    )(input)
}
