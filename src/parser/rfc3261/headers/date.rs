use crate::parser::rfc3261::{
    Result,
    header_colon,
};

use nom::{
    combinator::recognize,
    branch::alt,
    sequence::tuple,
    character::is_digit,
    bytes::complete::{
        tag,
        take_while_m_n,
    },
};

fn month(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag("Jan"),
        tag("Feb"),
        tag("Mar"),
        tag("Apr"),
        tag("May"),
        tag("Jun"),
        tag("Jul"),
        tag("Aug"),
        tag("Sep"),
        tag("Oct"),
        tag("Nov"),
        tag("Dec"),
    ))(input)
}

fn wkday(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag("Mon"),
        tag("Tue"),
        tag("Wed"),
        tag("Thu"),
        tag("Fri"),
        tag("Sat"),
        tag("Sun"),
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
            tag(" GMT"),
        ))
    )(input)
}

pub fn date(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("Date"),
            header_colon,
            rfc1123_date,
        ))
    )(input)
}
