use crate::{
    response::Response,
    parser::{
        Result,
        rfc3261::{
            headers,
            tokens::newline,
            common::message_body,
        },
    },
};

use nom::{
    multi::many0,
    sequence::{ tuple, preceded, },
    combinator::{ opt, recognize },
};

pub fn response(input: &[u8]) -> Result<&[u8], Response> {
    let (input, response) = recognize(
        tuple((
            status::status_line,
            many0(headers::message_header),
            preceded(newline, opt(message_body)),
        ))
    )(input)?;

    Ok((input, Response {
        content: response.to_vec(),
    }))
}

mod status {
    use crate::parser::{
        Result,
        rfc3261::{
            tokens::{
        is_reserved,
        is_unreserved,
        is_utf8_nonascii,
        is_utf8_cont,
        newline,
            },
            common::{
        sip_version,
            },
        },
    };

    use nom::{
        combinator::recognize,
        sequence::{ tuple, terminated, preceded, },
        branch::alt,
        character::{ is_space, is_digit },
        bytes::complete::{
            tag,
            take_while,
            take_while_m_n,
        },
    };

    fn status_code(input: &[u8]) -> Result<&[u8], &[u8]> {
        // TODO: Rewrite into binary comparison
        alt((
            alt((
                tag("100"),
                tag("180"),
                tag("181"),
                tag("182"),
                tag("183"),
            )),
            tag("200"),
            alt((
                tag("300"),
                tag("301"),
                tag("302"),
                tag("305"),
                tag("380"),
            )),
            alt((
                tag("400"),
                tag("401"),
                tag("402"),
                tag("403"),
                tag("404"),
                tag("405"),
                tag("406"),
                tag("407"),
                tag("408"),
                tag("410"),
                tag("413"),
                tag("414"),
                tag("415"),
                tag("416"),
                tag("420"),
                tag("421"),
                tag("423"),
                tag("480"),
                tag("481"),
                tag("482"),
                tag("483"),
            )),
            alt((
                tag("483"),
                tag("485"),
                tag("486"),
                tag("487"),
                tag("488"),
                tag("491"),
                tag("493"),
            )),
            alt((
                tag("500"),
                tag("501"),
                tag("502"),
                tag("503"),
                tag("504"),
                tag("505"),
                tag("513"),
            )),
            alt((
                tag("600"),
                tag("603"),
                tag("604"),
                tag("606"),
            )),
            take_while_m_n(3, 3, is_digit),
        ))(input)
    }

    fn is_reason_phrase(i: u8) -> bool {
        // TODO: Handle escaped
        is_reserved(i) || is_unreserved(i) || is_utf8_nonascii(i) || is_utf8_cont(i) || is_space(i)
    }

    pub fn status_line(input: &[u8]) -> Result<&[u8], &[u8]> {
        recognize(
            terminated(
                tuple((
                    sip_version,
                    preceded(tag(" "), status_code),
                    preceded(tag(" "), take_while(is_reason_phrase)),
                )),
                newline,
            )
        )(input)
    }
}
