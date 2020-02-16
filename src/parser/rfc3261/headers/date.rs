use crate::parser::{
    Result,
    rfc3261::tokens::header_colon,
};

use nom::{
    combinator::recognize,
    branch::alt,
    sequence::tuple,
    character::is_digit,
    bytes::complete::{
        tag,
        tag_no_case,
        take_while_m_n,
    },
};

fn month(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("Jan"),
        tag_no_case("Feb"),
        tag_no_case("Mar"),
        tag_no_case("Apr"),
        tag_no_case("May"),
        tag_no_case("Jun"),
        tag_no_case("Jul"),
        tag_no_case("Aug"),
        tag_no_case("Sep"),
        tag_no_case("Oct"),
        tag_no_case("Nov"),
        tag_no_case("Dec"),
    ))(input)
}

fn wkday(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("Mon"),
        tag_no_case("Tue"),
        tag_no_case("Wed"),
        tag_no_case("Thu"),
        tag_no_case("Fri"),
        tag_no_case("Sat"),
        tag_no_case("Sun"),
    ))(input)
}

fn time(input: &[u8]) -> Result<&[u8], &[u8]> {
    // TODO: Limit from 00:00:00 to 23:59:59
    recognize(
        tuple((
            take_while_m_n(2, 2, is_digit),
            tag(":"),
            take_while_m_n(2, 2, is_digit),
            tag(":"),
            take_while_m_n(2, 2, is_digit),
        ))
    )(input)
}

fn date1(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            take_while_m_n(2, 2, is_digit),
            tag(" "),
            month,
            tag(" "),
            take_while_m_n(4, 4, is_digit),
        ))
    )(input)
}

fn rfc1123_date(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            wkday,
            tag(", "),
            date1,
            tag(" "),
            time,
            tag_no_case(" GMT"),
        ))
    )(input)
}

pub fn date(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Date"),
            header_colon,
            rfc1123_date,
        ))
    )(input)
}
