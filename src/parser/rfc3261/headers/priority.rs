use crate::parser::{
    Result,
    rfc3261::tokens::{
        header_colon,
        token,
    },
};

use nom::{
    combinator::recognize,
    sequence:: tuple ,
    branch::alt,
    bytes::complete::tag,
};

fn priority_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag("emergency"),
        tag("urgent"),
        tag("normal"),
        tag("non-urgent"),
        token,
    ))(input)
}

pub fn priority(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("Priority"),
            header_colon,
            priority_value,
        ))
    )(input)
}
