mod common;
mod headers;
mod request;
mod response;
mod tokens;

use nom::branch::alt;

use crate::{
    message::Message,
    parser::Result,
};

pub use common::hostname;

pub use request::request;
pub use response::response;

pub fn message_request(input: &[u8]) -> Result<&[u8], Message> {
    let (input, req) = request(input)?;

    Ok((input, Message::Request(req)))
}

pub fn message_response(input: &[u8]) -> Result<&[u8], Message> {
    let (input, resp) = response(input)?;

    Ok((input, Message::Response(resp)))
}

pub fn message(input: &[u8]) -> Result<&[u8], Message> {
    alt((
        message_request,
        message_response,
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_message_can_read_a_whole_message() {
        let bytes = include_bytes!("../../../assets/invite.sip");
        assert_eq!(message(bytes).is_err(), false);
    }
}
