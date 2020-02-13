#![allow(dead_code)]

use nom::{
    IResult,
    combinator::{ map_res, opt, recognize },
    sequence::{ pair, tuple },
    branch::alt,
    multi::many0,
    bytes::complete::{
        tag,
        is_a,
        take_while,
        take_while1,
        take_while_m_n,
    },
};

const RESERVED_CHARS: &'static [u8] = b";/?:@&=+$,";

pub fn is_reserved(i: u8) -> bool {
    RESERVED_CHARS.contains(&i)
}

pub fn reserved(input: &[u8]) -> IResult<&[u8], &[u8]> {
    is_a(RESERVED_CHARS)(input)
}

const MARK_CHARS: &'static [u8] = b"-_.!~*'()";

pub fn is_mark(i: u8) -> bool {
    MARK_CHARS.contains(&i)
}

pub fn mark(input: &[u8]) -> IResult<&[u8], &[u8]> {
    is_a(MARK_CHARS)(input)
}

pub fn is_unreserved(i: u8) -> bool {
    is_mark(i) || i.is_ascii_alphanumeric()
}

pub fn unreserved(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(is_unreserved)(input)
}

pub fn is_hex_digit(i: u8) -> bool {
    i.is_ascii_hexdigit()
}

pub fn is_lowercase_hex_digit(i: u8) -> bool {
    i.is_ascii_digit() ||
        (i.is_ascii_hexdigit() && i.is_ascii_lowercase())
}

#[derive(PartialEq, Debug)]
pub enum HexConversionError {
    ParseIntError(std::num::ParseIntError),
    Utf8Error(std::str::Utf8Error),
}

impl From<std::num::ParseIntError> for HexConversionError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::ParseIntError(error)
    }
}

impl From<std::str::Utf8Error> for HexConversionError {
    fn from(error: std::str::Utf8Error) -> Self {
        Self::Utf8Error(error)
    }
}

pub fn from_hex(input: &[u8]) -> Result<u8, HexConversionError> {
    let input = std::str::from_utf8(input)?;
    Ok(u8::from_str_radix(input, 16)?)
}

pub fn hex_number(input: &[u8]) -> IResult<&[u8], u8> {
    map_res(
        take_while_m_n(2, 2, is_hex_digit),
        from_hex
    )(input)
}

pub fn escaped(input: &[u8]) -> IResult<&[u8], u8> {
    let (s, _) = tag("%")(input)?;
    hex_number(s)
}

pub fn is_horizontal_tab(i: u8) -> bool {
    i == 0x09
}

pub fn is_space(i: u8) -> bool {
    i == 0x20
}

pub fn is_whitespace(i: u8) -> bool {
    is_space(i) || is_horizontal_tab(i)
}

pub fn whitespace(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(is_whitespace)(input)
}

pub fn whitespace1(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_whitespace)(input)
}

pub fn newline(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(b"\r\n")(input)
}

pub fn linear_whitespace(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            opt(pair(whitespace, newline)),
            whitespace1
        )
    )(input)
}

pub fn separator_whitespace(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(opt(linear_whitespace))(input)
}

pub fn header_colon(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
                whitespace,
                nom::character::complete::char(':'),
                separator_whitespace
        ))
    )(input)
}

const TOKEN_CHARS: &'static [u8] = b"-.!%*_+`'~`";

pub fn is_token(i: u8) -> bool {
    i.is_ascii_alphanumeric() || TOKEN_CHARS.contains(&i)
}

pub fn token(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_token)(input)
}

const SEPARATOR_CHARS: &'static [u8] = b"()<>@,;:\\\"/[]?={} \t";

pub fn is_separator(i: u8) -> bool {
    SEPARATOR_CHARS.contains(&i)
}

pub fn separator(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(is_separator)(input)
}

const WORD_CHARS: &'static [u8] = b"-.!%*_+`'~()<>:\\\"/[]?{}";

pub fn is_word(i: u8) -> bool {
    i.is_ascii_alphanumeric() || WORD_CHARS.contains(&i)
}

pub fn word(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_word)(input)
}

pub fn asterisk(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('*'),
            separator_whitespace,
        ))
    )(input)
}

pub fn star(input: &[u8]) -> IResult<&[u8], &[u8]> {
    asterisk(input)
}

pub fn slash(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('/'),
            separator_whitespace,
        ))
    )(input)
}

pub fn equal(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('='),
            separator_whitespace,
        ))
    )(input)
}

pub fn left_parenthesis(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('('),
            separator_whitespace,
        ))
    )(input)
}

pub fn right_parenthesis(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(')'),
            separator_whitespace,
        ))
    )(input)
}

pub fn right_angle_quote(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('>'),
            separator_whitespace,
        )
    )(input)
}

pub fn left_angle_quote(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('<'),
            separator_whitespace,
        )
    )(input)
}

pub fn comma(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(','),
            separator_whitespace,
        ))
    )(input)
}

pub fn semicolon(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(';'),
            separator_whitespace,
        ))
    )(input)
}

pub fn colon(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(':'),
            separator_whitespace,
        ))
    )(input)
}

pub fn double_quote(input: &[u8]) -> IResult<&[u8], char> {
    nom::character::complete::char('"')(input)
}

pub fn left_double_quote(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            separator_whitespace,
            double_quote,
        )
    )(input)
}

pub fn right_double_quote(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            double_quote,
            separator_whitespace,
        )
    )(input)
}

pub fn is_utf_cont(i: u8) -> bool {
    i >= 0x80 && i <= 0xbf
}

pub fn is_utf_c0_df(i: u8) -> bool {
    i >= 0xc0 && i <= 0xdf
}

pub fn utf8_nonascii_c0_df(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf_c0_df),
            take_while_m_n(1, 1, is_utf_cont)
        )
    )(input)
}

pub fn is_utf_e0_ef(i: u8) -> bool {
    i >= 0xe0 && i <= 0xef
}

pub fn utf8_nonascii_e0_ef(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf_e0_ef),
            take_while_m_n(2, 2, is_utf_cont)
        )
    )(input)
}

pub fn is_utf_f0_f7(i: u8) -> bool {
    i >= 0xf0 && i <= 0xf7
}

pub fn utf8_nonascii_f0_f7(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf_f0_f7),
            take_while_m_n(3, 3, is_utf_cont)
        )
    )(input)
}

pub fn is_utf_f8_fb(i: u8) -> bool {
    i >= 0xf8 && i <= 0xfb
}

pub fn utf8_nonascii_f8_fb(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf_f8_fb),
            take_while_m_n(4, 4, is_utf_cont)
        )
    )(input)
}

pub fn is_utf_fc_fd(i: u8) -> bool {
    i == 0xfc || i == 0xfd
}

pub fn utf8_nonascii_fc_fd(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_utf_fc_fd),
            take_while_m_n(5, 5, is_utf_cont)
        )
    )(input)
}

pub fn is_utf_ascii(i: u8) -> bool {
    i >= 0x21 && i <= 0x7e
}

pub fn utf8_ascii1(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_utf_ascii)(input)
}

pub fn utf8_nonascii1(input: &[u8]) -> IResult<&[u8], &[u8]> {
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

pub fn utf8_char1(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt(
        (
            utf8_ascii1,
            utf8_nonascii1,
        )
    )(input)
}

pub fn utf8_trim(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            utf8_char1,
            many0(pair(opt(linear_whitespace), utf8_char1))
        )
    )(input)
}

pub fn is_comment_char(i: u8) -> bool {
    (i >= 0x21 && i <= 0x27) ||
        (i >= 0x2a && i <= 0x5b) ||
        (i >= 0x5d && i <= 0x7e)
}

pub fn comment_char1(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(is_comment_char)(input)
}

pub fn comment_text(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((comment_char1, utf8_nonascii1))(input)
}

pub fn comment(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
                left_parenthesis,
                many0(alt((comment_text, comment, quoted_pair))),
        ))
    )(input)
}

pub fn is_quotable_character(i: u8) -> bool {
    i <= 0x09 ||
        (i >= 0x0b && i <= 0x0c) ||
        (i >= 0x0e && i <= 0x7f)
}

pub fn quotable_character(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_quotable_character)(input)
}

pub fn quoted_pair(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('\\'),
            quotable_character,
        )
    )(input)
}

pub fn is_quoted_text_char(i: u8) -> bool {
    i == 0x21
        || (i >= 0x23 && i <= 0x5b)
        || (i >= 0x5d && i <= 0x7e)
}

pub fn quoted_text_char(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_quoted_text_char)(input)
}

pub fn quoted_text(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((
        linear_whitespace,
        quoted_text_char,
        utf8_nonascii1,
    ))(input)
}

pub fn quoted_string(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            double_quote,
            many0(alt((quoted_text, quoted_pair))),
            double_quote
        ))
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_reserved_identifies_reserved_chars() {
        b";/?:@&=+$,".iter().for_each(|i| assert_eq!(is_reserved(*i), true));
        assert_eq!(is_reserved(b'z'), false);
    }

    #[test]
    fn reserved_consumes_reserved_chars() {
        assert!(reserved(b";/?:@&=+$,") == Ok((b"", b";/?:@&=+$,")));
        assert!(reserved(b";/?:xx@&=+$,") == Ok((b"xx@&=+$,", b";/?:")));
        assert!(reserved(b";;;;;;foo") == Ok((b"foo", b";;;;;;")))
    }

    #[test]
    fn is_mark_identifies_mark_chars() {
        b"-_.!~*'()".iter().for_each(|i| assert_eq!(is_mark(*i), true));
        assert_eq!(is_mark(b'z'), false);
    }

    #[test]
    fn mark_consumes_mark_chars() {
        assert!(mark(b"-_.!~*'()") == Ok((b"", b"-_.!~*'()")));
        assert!(mark(b"-_.!xx~*'()") == Ok((b"xx~*'()", b"-_.!")));
        assert!(mark(b"______foo") == Ok((b"foo", b"______")));
    }

    #[test]
    fn is_unreserved_identifies_unreserved_chars() {
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_.!~*'()"
            .iter().for_each(|i| assert_eq!(is_unreserved(*i), true));
        assert_eq!(is_unreserved(b';'), false);
    }

    #[test]
    fn unreserved_consumes_unreserved_chars() {
        let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_.!~*'()";
        assert!(unreserved(chars) == Ok((b"", chars)));
        assert!(unreserved(b"aaaaa$") == Ok((b"$", b"aaaaa")));
    }

    #[test]
    fn is_hex_digit_identifies_hex_digits() {
        b"1234567890abcdefABCDEF"
            .iter()
            .for_each(|i| assert_eq!(is_hex_digit(*i), true));

        assert_eq!(is_hex_digit(b';'), false);
    }

    #[test]
    fn is_lowercase_hex_digit_identifies_only_lower() {
        b"1234567890abcdef"
            .iter()
            .for_each(|i| assert_eq!(is_lowercase_hex_digit(*i), true));

        assert_eq!(is_lowercase_hex_digit(b','), false);
        assert_eq!(is_lowercase_hex_digit(b'F'), false);
    }

    #[test]
    fn from_hex_parses_hex_digits() {
        assert_eq!(from_hex(b"0"), Ok(0));
        assert_eq!(from_hex(b"10"), Ok(16));
        assert_eq!(from_hex(b"fF"), Ok(255));
        assert_eq!(from_hex(b";").is_err(), true);
    }

    #[test]
    fn hex_number_consumes_two_hex_digits() {
        assert!(hex_number(b"123") == Ok((b"3", 18)));
        assert!(hex_number(b"Ffz") == Ok((b"z", 255)));
        assert_eq!(hex_number(b"z123").is_err(), true);
    }

    #[test]
    fn escaped_consumes_an_escaped_number() {
        assert!(escaped(b"%fFx") == Ok((b"x", 255)));
        assert!(escaped(b"%00x") == Ok((b"x", 0)));
        assert_eq!(escaped(b"%0x").is_err(), true);
        assert_eq!(escaped(b"fFx").is_err(), true);
    }

    #[test]
    fn is_space_validates_spaces() {
        assert_eq!(is_space(b' '), true);
        assert_eq!(is_space(b'0'), false);
    }

    #[test]
    fn is_whitespace_validates_whitespaces() {
        assert_eq!(is_whitespace(b' '), true);
        assert_eq!(is_whitespace(b'\t'), true);
        assert_eq!(is_whitespace(b'0'), false);
    }

    #[test]
    fn whitespace_consumes_0_or_more_whitespaces() {
        assert!(whitespace(b"  \t  foo") == Ok((b"foo", b"  \t  ")));
        assert!(whitespace(b"foo") == Ok((b"foo", b"")));
    }

    #[test]
    fn whitespace1_consumes_1_or_more_whitespaces() {
        assert!(whitespace1(b"  \t  foo") == Ok((b"foo", b"  \t  ")));
        assert_eq!(whitespace1(b"foo").is_err(), true);
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
        assert!(linear_whitespace(b"\r\n  f") == Ok((b"f", b"\r\n  ")));
    }

    #[test]
    fn linear_whitespace_eats_preceding_ws_and_crlf() {
        assert!(linear_whitespace(b"\t\t  \t \t \t\r\n  \tf") == Ok((b"f", b"\t\t  \t \t \t\r\n  \t")));
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
}
