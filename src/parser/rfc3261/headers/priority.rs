use crate::{
    message::{ Header, Priority, },
    parser::{
        Result,
        rfc3261::tokens::{
            header_colon,
            token_str,
        },
    },
};

use nom::{
    sequence:: tuple ,
    branch::alt,
    bytes::complete::tag_no_case,
};

fn priority_value_emergency(input: &[u8]) -> Result<&[u8], Priority> {
    let (input, _) = tag_no_case("emergency")(input)?;

    Ok((input, Priority::Emergency))
}

fn priority_value_urgent(input: &[u8]) -> Result<&[u8], Priority> {
    let (input, _) = tag_no_case("urgent")(input)?;

    Ok((input, Priority::Urgent))
}

fn priority_value_normal(input: &[u8]) -> Result<&[u8], Priority> {
    let (input, _) = tag_no_case("normal")(input)?;

    Ok((input, Priority::Normal))
}

fn priority_value_non_urgent(input: &[u8]) -> Result<&[u8], Priority> {
    let (input, _) = tag_no_case("non-urgent")(input)?;

    Ok((input, Priority::NonUrgent))
}

fn priority_value_extension(input: &[u8]) -> Result<&[u8], Priority> {
    let (input, value) = token_str(input)?;

    Ok((input, Priority::Extension(value)))
}

fn priority_value(input: &[u8]) -> Result<&[u8], Priority> {
    alt((
        priority_value_emergency,
        priority_value_urgent,
        priority_value_normal,
        priority_value_non_urgent,
        priority_value_extension,
    ))(input)
}

pub fn priority(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, priority)) = tuple((
        tag_no_case("Priority"),
        header_colon,
        priority_value,
    ))(input)?;

    Ok((input, Header::Priority(priority)))
}
