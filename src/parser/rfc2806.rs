use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    branch::alt,
    multi::{ many0, many1 },
    character::{ is_digit, is_alphanumeric },
    bytes::complete::{
        tag,
        take_while,
        take_while_m_n,
    },
};

use super::{
    Result,
    rfc3261::hostname,
};

const VISUAL_SEPARATOR: &'static [u8] = b"-.()";

fn numeric(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_digit)(input)
}

fn is_visual_separator(i: u8) -> bool {
    VISUAL_SEPARATOR.contains(&i)
}

fn visual_separator(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_visual_separator)(input)
}

fn phone_digit(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((numeric, visual_separator))(input)
}

fn base_phone_number(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(many1(phone_digit))(input)
}

const DTMF_DIGITS: &'static [u8] = b"*#ABCD";

fn is_dtmf_digit(i: u8) -> bool {
    DTMF_DIGITS.contains(&i)
}

fn dtmf_digit(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_dtmf_digit)(input)
}

fn is_pause_character(i: u8) -> bool {
    i == b'p' || i == b'w'
}

fn pause_character(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_pause_character)(input)
}

fn local_phone_number(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        many1(
            tuple((
                alt((phone_digit, dtmf_digit, pause_character)),
                opt(isdn_subaddress),
                opt(post_dial),
                area_specifier,
                many0(alt((area_specifier, service_provider, future_extension)))
            ))
        )
    )(input)
}

fn global_phone_number(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("+"),
            base_phone_number,
            opt(isdn_subaddress),
            opt(post_dial),
            many0(alt((area_specifier, service_provider, future_extension)))
        ))
    )(input)
}

pub fn telephone_subscriber(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        global_phone_number,
        local_phone_number,
    ))(input)
}

fn service_provider(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(pair(tag(";tsp="), hostname))(input)
}

const FUTURE_EXTENSION_TOKEN_CHARS: &'static [u8] = b"!#$%&'*+-.^_`|~";

fn is_future_extension_token(i: u8) -> bool {
    is_alphanumeric(i) || FUTURE_EXTENSION_TOKEN_CHARS.contains(&i)
}

fn future_extension_token(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_future_extension_token)(input)
}

fn is_rfc2806_quoted_string_char(i: u8) -> bool {
    i >= 0x01 && i <= 0x7f
}

fn rfc2806_quoted_string_char(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_rfc2806_quoted_string_char)(input)
}

fn is_rfc2806_quoted_string_extra_char(i: u8) -> bool {
    i == 0x20 || i == 0x21 || i >= 0x80 ||
        (i >= 0x23 && i <= 0x7e)
}

fn rfc2806_quoted_string_extra_char(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_rfc2806_quoted_string_extra_char)(input)
}

fn rfc2806_quoted_string(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(tuple((
        tag("\""),
        many0(pair(
            pair(
                tag("\\"),
                rfc2806_quoted_string_char,
            ),
            rfc2806_quoted_string_extra_char,
        )),
        tag("\""),
    )))(input)
}

fn future_extension(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag(";"),
            many1(future_extension_token),
            opt(pair(
                tag("="),
                alt((
                    recognize(pair(
                        many1(future_extension_token),
                        opt(pair(
                            tag("?"),
                            many1(future_extension_token)
                        ))
                    )),
                    rfc2806_quoted_string,
                ))
            ))
        ))
    )(input)
}

fn isdn_subaddress(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(tag(";isub="), many1(phone_digit))
    )(input)
}

fn post_dial(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag(";postd="),
            many1(alt((phone_digit, dtmf_digit, pause_character)))
        )
    )(input)
}

fn is_private_prefix_first_char(i: u8) -> bool {
    i == 0x21 || i == 0x22 || i == 0x2c || i == 0x2f || i == 0x3a ||
        (i >= 0x24 && i <= 0x27) ||
        (i >= 0x3c && i <= 0x40) ||
        (i >= 0x45 && i <= 0x4f) ||
        (i >= 0x51 && i <= 0x56) ||
        (i >= 0x58 && i <= 0x60) ||
        (i >= 0x65 && i <= 0x6f) ||
        (i >= 0x71 && i <= 0x76) ||
        (i >= 0x78 && i <= 0x7e)
}

fn is_private_prefix_other_chars(i: u8) -> bool {
    (i >= 0x21 && i <= 0x3a) || (i >= 0x3c && i <= 0x7e)
}

fn private_prefix(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(pair(
        take_while_m_n(1, 1, is_private_prefix_first_char),
        take_while(is_private_prefix_other_chars)
    ))(input)
}

fn local_network_prefix(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(many1(alt((phone_digit, dtmf_digit, pause_character))))(input)
}

fn global_network_prefix(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(pair(tag("+"), many1(phone_digit)))(input)
}

fn network_prefix(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((global_network_prefix, local_network_prefix))(input)
}

fn phone_context_ident(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((network_prefix, private_prefix))(input)
}

fn area_specifier(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(pair(tag(";phone-context="), phone_context_ident))(input)
}
