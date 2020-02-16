mod headers;
mod request;
mod response;

use nom::{
    combinator::{ opt, recognize },
    sequence::{ pair, tuple },
    branch::alt,
    multi::{ many0, many1, many_m_n },
    character::{ is_alphanumeric, is_digit, is_hex_digit },
    character::complete::{ space0, space1, digit1, alpha1 },
    bytes::complete::{
        is_a,
        tag,
        take_while,
        take_while1,
        take_while_m_n,
    },
};

use super::{ Error, ErrorKind, };
use super::Result;

use super::rfc2806::telephone_subscriber;

fn is_alphanumeric_hyphen(i: u8) -> bool {
    is_alphanumeric(i) || i == b'-'
}

fn alphanumeric_hyphen(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 1, is_alphanumeric_hyphen)(input)
}

const RESERVED_CHARS: &'static [u8] = b";/?:@&=+$,";

fn is_reserved(i: u8) -> bool {
    RESERVED_CHARS.contains(&i)
}

const MARK_CHARS: &'static [u8] = b"-_.!~*'()";

fn is_mark(i: u8) -> bool {
    MARK_CHARS.contains(&i)
}

const LOWERCASE_HEXADECIMAL_CHARS: &'static [u8] = b"0123456789abcdef";

fn is_lowercase_hexadecimal(i: u8) -> bool {
    LOWERCASE_HEXADECIMAL_CHARS.contains(&i)
}

fn is_unreserved(i: u8) -> bool {
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

fn is_space(i: u8) -> bool {
    i == b' '
}

fn newline(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag(b"\r\n")(input)
}

fn linear_whitespace(input: &[u8]) -> Result<&[u8], &[u8]> {
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

fn header_colon(input: &[u8]) -> Result<&[u8], &[u8]> {
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

fn token(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while1(is_token)(input)
}

const WORD_CHARS: &'static [u8] = b"-.!%*_+`'~()<>:\\\"/[]?{}";

fn is_word(i: u8) -> bool {
    is_alphanumeric(i) || WORD_CHARS.contains(&i)
}

fn word(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(is_word)(input)
}

fn star(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('*'),
            separator_whitespace,
        ))
    )(input)
}

fn slash(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char('/'),
            separator_whitespace,
        ))
    )(input)
}

fn equal(input: &[u8]) -> Result<&[u8], &[u8]> {
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

fn right_angle_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('>'),
            separator_whitespace,
        )
    )(input)
}

fn left_angle_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            nom::character::complete::char('<'),
            separator_whitespace,
        )
    )(input)
}

fn comma(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(','),
            separator_whitespace,
        ))
    )(input)
}

fn semicolon(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(';'),
            separator_whitespace,
        ))
    )(input)
}

fn colon(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            separator_whitespace,
            nom::character::complete::char(':'),
            separator_whitespace,
        ))
    )(input)
}

fn left_double_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            separator_whitespace,
            tag("\""),
        )
    )(input)
}

fn right_double_quote(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("\""),
            separator_whitespace,
        )
    )(input)
}

fn is_utf8_cont(i: u8) -> bool {
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

fn is_utf8_nonascii(i: u8) -> bool {
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

fn utf8_char1(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt(
        (
            utf8_ascii1,
            utf8_nonascii1,
        )
    )(input)
}

fn utf8_trim(input: &[u8]) -> Result<&[u8], &[u8]> {
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

fn comment(input: &[u8]) -> Result<&[u8], &[u8]> {
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

fn quoted_string(input: &[u8]) -> Result<&[u8], &[u8]> {
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

fn password(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        many0(alt((
            unreserved,
            escaped,
            is_a(PASSWORD_CHARS),
        )))
    )(input)
}

const USER_RESERVED_CHARS: &'static [u8] = b"&=+$,;?/";

fn user(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        many1(alt((
            unreserved,
            escaped,
            is_a(USER_RESERVED_CHARS),
        )))
    )(input)
}

fn user_info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                user,
                telephone_subscriber,
            )),
            opt(pair(tag(":"), password)),
            tag("@"),
        ))
    )(input)
}

fn sip_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("sip:"),
            opt(user_info),
            host_port,
            uri_parameters,
            opt(headers)
        ))
    )(input)
}

fn sips_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("sips:"),
            opt(user_info),
            host_port,
            uri_parameters,
            opt(headers)
        ))
    )(input)
}

fn top_label(input: &[u8]) -> Result<&[u8], &[u8]> {
    let (input, label) = recognize(many1(alphanumeric_hyphen))(input)?;

    if label.iter().last().unwrap().to_owned() == b'-'
        || !label.iter().nth(0).unwrap().is_ascii_alphabetic()
    {
        Err(nom::Err::Error(Error {
            kind: ErrorKind::InvalidDomainPart(label),
            backtrace: Vec::new()
        }))
    } else {
        Ok((input, label))
    }
}

fn domain_label(input: &[u8]) -> Result<&[u8], &[u8]> {
    let (input, label) = recognize(many1(alphanumeric_hyphen))(input)?;

    if label.iter().nth(0).unwrap().to_owned() == b'-'
        || label.iter().last().unwrap().to_owned() == b'-' {
        Err(nom::Err::Error(Error {
            kind: ErrorKind::InvalidDomainPart(label),
            backtrace: Vec::new()
        }))
    } else {
        Ok((input, label))
    }
}

pub fn hostname(input: &[u8]) -> Result<&[u8], &[u8]> {
    let (input, hostname) = alt((
        recognize(pair(many0(pair(domain_label, tag("."))), top_label)),
        recognize(many1(pair(domain_label, tag(".")))),
    ))(input)?;

    if hostname.iter().last().unwrap().to_owned() == b'.' {
        let parts: Vec<&[u8]> = hostname.split(|i| *i == b'.').collect();
        let top = *parts.iter().nth(parts.len() - 2).unwrap();
        if top_label(top).is_ok() {
            Ok((input, hostname))
        } else {
            Err(nom::Err::Error(Error {
                kind: ErrorKind::InvalidHostname(hostname),
                backtrace: Vec::new(),
            }))
        }
    } else {
        Ok((input, hostname))
    }
}

fn ipv4_address(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(tuple((
        take_while_m_n(1, 3, is_digit),
        tag("."),
        take_while_m_n(1, 3, is_digit),
        tag("."),
        take_while_m_n(1, 3, is_digit),
        tag("."),
        take_while_m_n(1, 3, is_digit),
    )))(input)
}

fn port(input: &[u8]) -> Result<&[u8], &[u8]> {
    digit1(input)
}

fn hex4(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(1, 4, is_hex_digit)(input)
}

fn hexseq(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(pair(hex4, many0(pair(tag(":"), hex4))))(input)
}

fn hexpart(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(tuple((
            hexseq,
            tag("::"),
            opt(hexseq),
        ))),
        recognize(pair(
            tag("::"),
            opt(hexseq),
        )),
        hexseq,
    ))(input)
}

fn ipv6_address(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            hexpart,
            opt(pair(tag(":"), ipv4_address))
        )
    )(input)
}

fn ipv6_reference(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("["),
            ipv6_address,
            tag("]"),
        ))
    )(input)
}

fn host(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        hostname,
        ipv4_address,
        ipv6_reference,
    ))(input)
}

fn host_port(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            host,
            opt(pair(tag(":"), port)),
        )
    )(input)
}

fn transport(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag("udp"),
        tag("tcp"),
        tag("sctp"),
        tag("tls"),
        token,
    ))(input)
}

fn transport_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("transport="),
            transport,
        )
    )(input)
}

fn user_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("user="),
            alt((
                tag("phone"),
                tag("ip"),
                token,
            ))
        )
    )(input)
}

fn method_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("method="),
            method,
        )
    )(input)
}

fn ttl_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("ttl="),
            ttl,
        )
    )(input)
}

fn ttl(input: &[u8]) -> Result<&[u8], &[u8]> {
    // TODO: Ensure TTL is between 0 and 255.
    take_while_m_n(1, 3, is_digit)(input)
}

fn maddr_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("maddr="),
            host,
        )
    )(input)
}

fn lr_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag("lr")(input)
}

const UNRESERVED_PARAM_CHARS: &'static [u8] = b"[]/:&+$";

fn is_param_char(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || UNRESERVED_PARAM_CHARS.contains(&i)
}

fn other_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while1(is_param_char),
            opt(
                pair(
                    tag("="),
                    take_while1(is_param_char),
                )
            )
        )
    )(input)
}

fn uri_parameters(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        many0(
            pair(
                tag(";"),
                alt((
                    transport_param,
                    user_param,
                    method_param,
                    ttl_param,
                    maddr_param,
                    lr_param,
                    other_param,
                ))
            )
        )
    )(input)
}

const UNRESERVED_HEADER_CHARS: &'static [u8] = b"[]/?:+$";

fn is_header_char(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || UNRESERVED_HEADER_CHARS.contains(&i)
}

fn header(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            take_while1(is_header_char),
            tag("="),
            take_while(is_header_char),
        ))
    )(input)
}

fn headers(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("?"),
            header,
            many0(pair(tag("&"), header))
        ))
    )(input)
}

fn invite(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag("INVITE")(input)
}

fn ack(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag("ACK")(input)
}

fn options(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag("OPTIONS")(input)
}

fn bye(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag("BYE")(input)
}

fn cancel(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag("CANCEL")(input)
}

fn register(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag("REGISTER")(input)
}

fn method(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        invite,
        ack,
        options,
        bye,
        cancel,
        register,
        token,
    ))(input)
}

fn sip_version(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("SIP/"),
            digit1,
            tag("."),
            digit1,
        ))
    )(input)
}

fn is_uric(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_reserved(i) || is_unreserved(i)
}

fn is_uric_no_slash(i: u8) -> bool {
    i != b'/' && is_uric(i)
}

fn query(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(is_uric)(input)
}

const REG_NAME_CHARS: &'static [u8] = b"$,;:@&=+";

fn is_reg_name(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || REG_NAME_CHARS.contains(&i)
}

fn reg_name(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while1(is_reg_name)(input)
}

fn srvr(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        opt(
            pair(
                opt(pair(user_info, tag("@"))),
                host_port
            )
        )
    )(input)
}

fn authority(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        srvr,
        reg_name,
    ))(input)
}

const SCHEME_CHARS: &'static [u8] = b"+-.";

fn is_scheme_char(i: u8) -> bool {
    is_alphanumeric(i) || SCHEME_CHARS.contains(&i)
}

fn scheme(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alpha1,
            take_while(is_scheme_char)
        )
    )(input)
}

const PCHAR_CHARS: &'static [u8] = b":@&=+$,";

fn is_pchar(i: u8) -> bool {
    // TODO: Handle escaped characters
    is_unreserved(i) || PCHAR_CHARS.contains(&i)
}

fn param(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(is_pchar)(input)
}

fn segment(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            param,
            many0(pair(tag(";"), param))
        )
    )(input)
}

fn path_segments(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            segment,
            many0(pair(tag("/"), segment))
        )
    )(input)
}

fn opaque_part(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while_m_n(1, 1, is_uric_no_slash),
            take_while(is_uric),
        )
    )(input)
}

fn abs_path(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag("/"),
            path_segments,
        )
    )(input)
}

fn net_path(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag("//"),
            authority,
            opt(abs_path),
        ))
    )(input)
}

fn hier_part(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alt((net_path, abs_path)),
            opt(pair(tag("?"), query))
        )
    )(input)
}

fn absolute_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            scheme,
            tag(":"),
            alt((hier_part, opaque_part))
        ))
    )(input)
}

fn request_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        sip_uri,
        sips_uri,
        absolute_uri,
    ))(input)
}

fn request_line(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            method,
            tag(" "),
            request_uri,
            tag(" "),
            sip_version,
            newline,
        ))
    )(input)
}

fn gen_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        token,
        host,
        quoted_string,
    ))(input)
}

fn generic_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            token,
            opt(pair(equal, gen_value))
        )
    )(input)
}

fn qvalue(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(pair(tag("0"), opt(pair(tag("."), take_while_m_n(0, 3, is_digit))))),
        recognize(pair(tag("1"), opt(pair(tag("."), many_m_n(0, 3, tag("0")))))),
    ))(input)
}

fn accept_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(tuple((
            tag("q"),
            equal,
            qvalue
        ))),
        generic_param
    ))(input)
}

fn message_body(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(|_| true)(input)
}

fn request(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            request_line,
            many0(headers::message_header),
            newline,
            opt(message_body),
        ))
    )(input)
}


pub fn sip_message(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        request,
        response::response,
    ))(input)
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

    #[test]
    fn top_label_needs_to_start_with_alphabetic_char() {
        assert!(top_label(b"abc") == Ok((b"", b"abc")));
        assert_eq!(top_label(b"-foo").is_err(), true);
        assert_eq!(top_label(b"$foo").is_err(), true);
    }

    #[test]
    fn top_label_cant_end_in_hyphen() {
        assert_eq!(top_label(b"foo-").is_err(), true);
    }

    #[test]
    fn top_labels_great_and_small() {
        assert!(top_label(b"a") == Ok((b"", b"a")));
        assert!(top_label(b"aa") == Ok((b"", b"aa")));
    }

    #[test]
    fn domain_label_needs_to_start_alphanumeric_char() {
        assert!(domain_label(b"abc") == Ok((b"", b"abc")));
        assert!(domain_label(b"123") == Ok((b"", b"123")));
    }

    #[test]
    fn domain_label_cannot_end_in_hyphen() {
        assert_eq!(domain_label(b"foo-").is_err(), true);
    }

    #[test]
    fn domain_label_allows_hyphen() {
        assert!(domain_label(b"f-o") == Ok((b"", b"f-o")));
    }

    #[test]
    fn domain_label_length() {
        assert!(domain_label(b"a") == Ok((b"", b"a")));
        assert!(domain_label(b"aa") == Ok((b"", b"aa")));
    }

    #[test]
    fn hostname_multiple_subdomains() {
        assert!(hostname(b"test.example.com") == Ok((b"", b"test.example.com")));
        assert!(hostname(b"a.b.c.d.e.test.example.com") == Ok((b"", b"a.b.c.d.e.test.example.com")));
    }

    #[test]
    fn hostname_domain_only() {
        assert!(hostname(b"example.com") == Ok((b"", b"example.com")));
        assert!(hostname(b"example.com.") == Ok((b"", b"example.com.")));
    }

    #[test]
    fn hostname_top_only() {
        assert!(hostname(b"john") == Ok((b"", b"john")));
        assert!(hostname(b"john.") == Ok((b"", b"john.")));
    }

    #[test]
    fn ipv4_address_parses_addresses_of_all_sizes() {
        assert!(ipv4_address(b"1.1.1.1") == Ok((b"", b"1.1.1.1")));
        assert!(ipv4_address(b"255.255.255.255") == Ok((b"", b"255.255.255.255")));
        assert_eq!(ipv4_address(b"1111.1.1.1").is_err(), true);
        assert_eq!(ipv4_address(b"").is_err(), true);
    }

    #[test]
    fn ipv4_address_doesnt_care_about_validity() {
        assert!(ipv4_address(b"999.999.999.999") == Ok((b"", b"999.999.999.999")));
    }

    #[test]
    fn port_needs_one_digit() {
        assert!(port(b"1") == Ok((b"", b"1")));
        assert_eq!(port(b"").is_err(), true);
    }

    #[test]
    fn port_wants_all_the_digits() {
        assert!(port(b"1111111111111111111111111111111111") == Ok((b"", b"1111111111111111111111111111111111")));
    }

    #[test]
    fn ipv6_address_wants_all_the_bits() {
        assert!(ipv6_address(b"fe80:ffff:ffff:ffff:ffff:ffff:ca63:47bf:d5e5:b04c") == Ok((b"", b"fe80:ffff:ffff:ffff:ffff:ffff:ca63:47bf:d5e5:b04c")));
        assert!(ipv6_address(b"fe80") == Ok((b"", b"fe80")));
    }

    #[test]
    fn ipv6_address_accepts_real_addresses() {
        assert!(ipv6_address(b"fe80::ca63:47bf:d5e5:b04c") == Ok((b"", b"fe80::ca63:47bf:d5e5:b04c")));
        assert!(ipv6_address(b"::1") == Ok((b"", b"::1")));
        assert!(ipv6_address(b"2600::") == Ok((b"", b"2600::")));
    }

    #[test]
    fn ipv6_reference_needs_brackets() {
        assert!(ipv6_reference(b"[fe80::ca63:47bf:d5e5:b04c]") == Ok((b"", b"[fe80::ca63:47bf:d5e5:b04c]")));
        assert!(ipv6_reference(b"[::1]") == Ok((b"", b"[::1]")));
        assert!(ipv6_reference(b"[2600::]") == Ok((b"", b"[2600::]")));
    }

    #[test]
    fn host_handles_any_kind_of_name_or_address() {
        assert!(host(b"sip.test.example.com") == Ok((b"", b"sip.test.example.com")));
        assert!(host(b"127.0.0.1") == Ok((b"", b"127.0.0.1")));
        assert!(host(b"[::1]") == Ok((b"", b"[::1]")));
    }

    #[test]
    fn host_port_takes_a_host_and_an_optional_port() {
        assert!(host_port(b"[::1]") == Ok((b"", b"[::1]")));
        assert!(host_port(b"[::1]:12345") == Ok((b"", b"[::1]:12345")));
    }

    #[test]
    fn request_line_can_parse_full_request_line() {
        let line = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n";
        assert!(request_line(line) == Ok((b"", line)));
    }

    #[test]
    fn sip_message_can_read_a_whole_message() {
        let message = include_bytes!("../../../assets/invite.sip");
        assert_eq!(sip_message(message).is_err(), false);
    }
}
