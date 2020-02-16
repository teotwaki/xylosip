use crate::parser::Result;

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    branch::alt,
    multi::{ many0, many1 },
    character::{ is_alphanumeric, is_hex_digit },
    character::complete::{ space0, space1, },
    bytes::complete::{
        is_a,
        tag,
        take_while,
        take_while1,
        take_while_m_n,
    },
};

fn is_alphanumeric_hyphen(i: u8) -> bool {
    is_alphanumeric(i) || i == b'-'
}

pub fn alphanumeric_hyphen(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_alphanumeric_hyphen)(input)
}

const RESERVED_CHARS: &'static [u8] = b";/?:@&=+$,";

pub fn is_reserved(i: u8) -> bool {
    RESERVED_CHARS.contains(&i)
}

const MARK_CHARS: &'static [u8] = b"-_.!~*'()";

fn is_mark(i: u8) -> bool {
    MARK_CHARS.contains(&i)
}

const LOWERCASE_HEXADECIMAL_CHARS: &'static [u8] = b"0123456789abcdef";

pub fn is_lowercase_hexadecimal(i: u8) -> bool {
    LOWERCASE_HEXADECIMAL_CHARS.contains(&i)
}

pub fn is_unreserved(i: u8) -> bool {
    is_mark(i) || is_alphanumeric(i)
}

fn unreserved(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_unreserved)(input)
}

fn escaped(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('%'),
            take_while_m_n(2, 2, is_hex_digit)
        )
    )(input)
}

pub fn is_space(i: u8) -> bool {
    i == b' '
}

pub fn newline(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag(b"\r\n")(input)
}

pub fn linear_whitespace(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            opt(pair(space0, newline)),
            space1,
        )
    )(input)
}

fn separator_whitespace(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(opt(linear_whitespace))(input)
}

pub fn header_colon(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
                space0,
                nom::character::complete::char(':'),
                separator_whitespace
        ))
    )(input)
}

const TOKEN_CHARS: &'static [u8] = b"-.!%*_+`'~`";

fn is_token(i: u8) -> bool {
    is_alphanumeric(i) || TOKEN_CHARS.contains(&i)
}

pub fn token(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while1(is_token)(input)
}

const WORD_CHARS: &'static [u8] = b"-.!%*_+`'~()<>:\\\"/[]?{}";

fn is_word(i: u8) -> bool {
    is_alphanumeric(i) || WORD_CHARS.contains(&i)
}

pub fn word(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(is_word)(input)
}

pub fn star(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('*'),
            separator_whitespace,
        ))
    )(input)
}

pub fn slash(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('/'),
            separator_whitespace,
        ))
    )(input)
}

pub fn equal(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('='),
            separator_whitespace,
        ))
    )(input)
}

fn left_parenthesis(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('('),
            separator_whitespace,
        ))
    )(input)
}

fn right_parenthesis(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(')'),
            separator_whitespace,
        ))
    )(input)
}

pub fn right_angle_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('>'),
            separator_whitespace,
        )
    )(input)
}

pub fn left_angle_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('<'),
            separator_whitespace,
        )
    )(input)
}

pub fn comma(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(','),
            separator_whitespace,
        ))
    )(input)
}

pub fn semicolon(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(';'),
            separator_whitespace,
        ))
    )(input)
}

pub fn colon(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(':'),
            separator_whitespace,
        ))
    )(input)
}

pub fn left_double_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            separator_whitespace,
            tag("\""),
        )
    )(input)
}

pub fn right_double_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("\""),
            separator_whitespace,
        )
    )(input)
}

pub fn is_utf8_cont(i: u8) -> bool {
    i >= 0x80 && i <= 0xbf
}

fn is_utf8_nonascii_c0_df(i: u8) -> bool {
    i >= 0xc0 && i <= 0xdf
}

fn utf8_nonascii_c0_df(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf8_nonascii_c0_df),
            take_while_m_n(1, 1, is_utf8_cont)
        )
    )(input)
}

fn is_utf8_nonascii_e0_ef(i: u8) -> bool {
    i >= 0xe0 && i <= 0xef
}

fn utf8_nonascii_e0_ef(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf8_nonascii_e0_ef),
            take_while_m_n(2, 2, is_utf8_cont)
        )
    )(input)
}

fn is_utf8_nonascii_f0_f7(i: u8) -> bool {
    i >= 0xf0 && i <= 0xf7
}

fn utf8_nonascii_f0_f7(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf8_nonascii_f0_f7),
            take_while_m_n(3, 3, is_utf8_cont)
        )
    )(input)
}

fn is_utf8_nonascii_f8_fb(i: u8) -> bool {
    i >= 0xf8 && i <= 0xfb
}

fn utf8_nonascii_f8_fb(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf8_nonascii_f8_fb),
            take_while_m_n(4, 4, is_utf8_cont)
        )
    )(input)
}

fn is_utf8_nonascii_fc_fd(i: u8) -> bool {
    i == 0xfc || i == 0xfd
}

fn utf8_nonascii_fc_fd(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf8_nonascii_fc_fd),
            take_while_m_n(5, 5, is_utf8_cont)
        )
    )(input)
}

fn is_utf8_ascii(i: u8) -> bool {
    i >= 0x21 && i <= 0x7e
}

fn utf8_ascii1(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_utf8_ascii)(input)
}

pub fn is_utf8_nonascii(i: u8) -> bool {
    is_utf8_nonascii_c0_df(i) || is_utf8_nonascii_e0_ef(i) ||
        is_utf8_nonascii_f0_f7(i) || is_utf8_nonascii_f8_fb(i) ||
        is_utf8_nonascii_fc_fd(i)
}

fn utf8_nonascii1(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt(
        (
            utf8_nonascii_c0_df,
            utf8_nonascii_e0_ef,
            utf8_nonascii_f0_f7,
            utf8_nonascii_f8_fb,
            utf8_nonascii_fc_fd
        )
    )(input)
}

pub fn utf8_char1(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt(
        (
            utf8_ascii1,
            utf8_nonascii1,
        )
    )(input)
}

pub fn utf8_trim(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            utf8_char1,
            many0(pair(many0(linear_whitespace), utf8_char1))
        )
    )(input)
}

fn is_comment_char(i: u8) -> bool {
    (i >= 0x21 && i <= 0x27) ||
        (i >= 0x2a && i <= 0x5b) ||
        (i >= 0x5d && i <= 0x7e)
}

fn comment_char(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_comment_char)(input)
}

fn comment_text(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((comment_char, utf8_nonascii1, linear_whitespace))(input)
}

pub fn comment(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
                left_parenthesis,
                many0(alt((comment_text, comment, quoted_pair))),
                right_parenthesis,
        ))
    )(input)
}

fn is_quotable_character(i: u8) -> bool {
    i <= 0x09 || i == 0x0b || i == 0x0c ||
        (i >= 0x0e && i <= 0x7f)
}

fn quotable_character(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_quotable_character)(input)
}

fn quoted_pair(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('\\'),
            quotable_character,
        )
    )(input)
}

fn is_quoted_text_char(i: u8) -> bool {
    i == 0x21
        || (i >= 0x23 && i <= 0x5b)
        || (i >= 0x5d && i <= 0x7e)
}

fn quoted_text_char(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_quoted_text_char)(input)
}

fn quoted_text(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        linear_whitespace,
        quoted_text_char,
        utf8_nonascii1,
    ))(input)
}

pub fn quoted_string(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            tag("\""),
            many0(alt((quoted_text, quoted_pair))),
            tag("\""),
        ))
    )(input)
}

const PASSWORD_CHARS: &'static [u8] = b"&=+$,";

pub fn password(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        many0(alt((
            unreserved,
            escaped,
            is_a(PASSWORD_CHARS),
        )))
    )(input)
}

const USER_RESERVED_CHARS: &'static [u8] = b"&=+$,;?/";

pub fn user(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        many1(alt((
            unreserved,
            escaped,
            is_a(USER_RESERVED_CHARS),
        )))
    )(input)
}

const UNRESERVED_PARAM_CHARS: &'static [u8] = b"[]/:&+$";

pub fn is_param_char(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || UNRESERVED_PARAM_CHARS.contains(&i)
}

const UNRESERVED_HEADER_CHARS: &'static [u8] = b"[]/?:+$";

pub fn is_header_char(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || UNRESERVED_HEADER_CHARS.contains(&i)
}

pub fn is_uric(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_reserved(i) || is_unreserved(i)
}

pub fn is_uric_no_slash(i: u8) -> bool {
    i != b'/' && is_uric(i)
}

const REG_NAME_CHARS: &'static [u8] = b"$,;:@&=+";

fn is_reg_name(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || REG_NAME_CHARS.contains(&i)
}

pub fn reg_name(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while1(is_reg_name)(input)
}

const PCHAR_CHARS: &'static [u8] = b":@&=+$,";

fn is_pchar(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || PCHAR_CHARS.contains(&i)
}

pub fn param(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(is_pchar)(input)
}

const SCHEME_CHARS: &'static [u8] = b"+-.";

pub fn is_scheme_char(i: u8) -> bool {
    is_alphanumeric(i) || SCHEME_CHARS.contains(&i)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_consumes_an_escaped_number() {
        assert!(escaped(b"%fFx") == Ok((b"x", b"%fF")));
        assert!(escaped(b"%00x") == Ok((b"x", b"%00")));
        assert_eq!(escaped(b"%0x").is_err(), true);
        assert_eq!(escaped(b"fFx").is_err(), true);
    }

    #[test]
    fn newline_consumes_a_single_newline() {
        assert!(newline(b"\r\na") == Ok((b"a", b"\r\n")));
        assert!(newline(b"\r\n\r\n") == Ok((b"\r\n", b"\r\n")));
    }

    #[test]
    fn linear_whitespace_requires_at_least_whitespace() {
        assert!(linear_whitespace(b"  f") == Ok((b"f", b"  ")));
        assert_eq!(linear_whitespace(b"x").is_err(), true);
    }

    #[test]
    fn linear_whitespace_eats_preceding_crlf() {
        assert!(linear_whitespace(b"\r\n f") == Ok((b"f", b"\r\n ")));
    }

    #[test]
    fn linear_whitespace_eats_preceding_ws_and_crlf() {
        assert!(linear_whitespace(b"\t\t  \t \t \t\r\n\tf") == Ok((b"f", b"\t\t  \t \t \t\r\n\t")));
    }

    #[test]
    fn header_colon_expects_a_colon() {
        assert!(header_colon(b":a") == Ok((b"a", b":")));
    }

    #[test]
    fn header_colon_allows_preceding_ws() {
        assert!(header_colon(b"  \t\t  :a") == Ok((b"a", b"  \t\t  :")));
    }

    #[test]
    fn header_colon_allows_ws_after() {
        assert!(header_colon(b": a") == Ok((b"a", b": ")));
        assert!(header_colon(b":\t\t \r\n a") == Ok((b"a", b":\t\t \r\n ")))
    }

    #[test]
    fn password_allows_empty() {
        assert!(password(b"") == Ok((b"", b"")));
        assert!(password(b"@") == Ok((b"@", b"")));
    }

    #[test]
    fn password_allows_pw_chars() {
        assert!(password(b"&=+$,-_.!~*'()0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
            == Ok((b"", b"&=+$,-_.!~*'()0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")));
    }

    #[test]
    fn password_doesnt_match_special_chars() {
        assert!(password(b";@") == Ok((b";@", b"")));
    }
}
