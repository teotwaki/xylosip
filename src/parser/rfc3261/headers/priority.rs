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
    bytes::complete::tag_no_case,
};

fn priority_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("emergency"),
        tag_no_case("urgent"),
        tag_no_case("normal"),
        tag_no_case("non-urgent"),
        token,
    ))(input)
}

pub fn priority(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Priority"),
            header_colon,
            priority_value,
        ))
    )(input)
}
