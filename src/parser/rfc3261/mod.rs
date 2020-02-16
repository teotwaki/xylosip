mod common;
mod headers;
mod request;
mod response;
mod tokens;

use nom::branch::alt;

use super::Result;

pub use common::hostname;

pub fn sip_message(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        request::request,
        response::response,
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_message_can_read_a_whole_message() {
        let message = include_bytes!("../../../assets/invite.sip");
        assert_eq!(sip_message(message).is_err(), false);
    }
}
