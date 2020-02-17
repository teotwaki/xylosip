use crate::{
    message::{ Method, Version, GenericParam, },
    parser::{
        integer,
        Error,
        ErrorKind,
        Result,
        rfc2806::telephone_subscriber,
        rfc3261::tokens,
    },
};

use nom::{
    combinator::{ opt, recognize, },
    sequence::{ pair, tuple },
    branch::alt,
    multi::{ many0, many1, many_m_n, },
    character::{ is_digit, is_hex_digit },
    character::complete::{ digit1, alpha1 },
    bytes::complete::{
        tag,
        tag_no_case,
        take_while,
        take_while1,
        take_while_m_n,
    },
};

pub fn message_body(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(|_| true)(input)
}

fn user_info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                tokens::user,
                telephone_subscriber,
            )),
            opt(pair(tag(":"), tokens::password)),
            tag("@"),
        ))
    )(input)
}

pub fn sip_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("sip:"),
            opt(user_info),
            host_port,
            uri_parameters,
            opt(headers)
        ))
    )(input)
}

pub fn sips_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("sips:"),
            opt(user_info),
            host_port,
            uri_parameters,
            opt(headers)
        ))
    )(input)
}

fn top_label(input: &[u8]) -> Result<&[u8], &[u8]> {
    let (input, label) = recognize(many1(tokens::alphanumeric_hyphen))(input)?;

    if label.iter().last().unwrap().to_owned() == b'-'
        || !label.iter().nth(0).unwrap().is_ascii_alphabetic()
    {
        Err(nom::Err::Error(
            Error::new(ErrorKind::InvalidDomainPart(label))
        ))
    } else {
        Ok((input, label))
    }
}

fn domain_label(input: &[u8]) -> Result<&[u8], &[u8]> {
    let (input, label) = recognize(many1(tokens::alphanumeric_hyphen))(input)?;

    if label.iter().nth(0).unwrap().to_owned() == b'-'
        || label.iter().last().unwrap().to_owned() == b'-' {
        Err(nom::Err::Error(
            Error::new(ErrorKind::InvalidDomainPart(label))
        ))
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
            Err(nom::Err::Error(
                Error::new(ErrorKind::InvalidHostname(hostname))
            ))
        }
    } else {
        Ok((input, hostname))
    }
}

pub fn ipv4_address(input: &[u8]) -> Result<&[u8], &[u8]> {
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

pub fn port(input: &[u8]) -> Result<&[u8], &[u8]> {
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

pub fn ipv6_address(input: &[u8]) -> Result<&[u8], &[u8]> {
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

pub fn host(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        hostname,
        ipv4_address,
        ipv6_reference,
    ))(input)
}

pub fn host_port(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            host,
            opt(pair(tag(":"), port)),
        )
    )(input)
}

pub fn transport(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("udp"),
        tag_no_case("tcp"),
        tag_no_case("sctp"),
        tag_no_case("tls"),
        tokens::token,
    ))(input)
}

fn transport_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag_no_case("transport="),
            transport,
        )
    )(input)
}

fn user_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag_no_case("user="),
            alt((
                tag_no_case("phone"),
                tag_no_case("ip"),
                tokens::token,
            ))
        )
    )(input)
}

fn method_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag_no_case("method="),
            method,
        )
    )(input)
}

fn ttl_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag_no_case("ttl="),
            ttl,
        )
    )(input)
}

pub fn ttl(input: &[u8]) -> Result<&[u8], i32> {
    let (input, ttl) = take_while_m_n(1, 3, is_digit)(input)?;
    let (_, ttl) = integer(ttl)?;

    if ttl < 0 || ttl > 255 {
        Err(nom::Err::Failure(
            Error::new(ErrorKind::InvalidTTLValue)
        ))
    } else {
        Ok((input, ttl))
    }
}

fn maddr_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tag_no_case("maddr="),
            host,
        )
    )(input)
}

fn lr_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    tag_no_case("lr")(input)
}

fn other_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            take_while1(tokens::is_param_char),
            opt(
                pair(
                    tag("="),
                    take_while1(tokens::is_param_char),
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

fn header(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            take_while1(tokens::is_header_char),
            tag("="),
            take_while(tokens::is_header_char),
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

fn invite(input: &[u8]) -> Result<&[u8], Method> {
    let (input, _) = tag("INVITE")(input)?;

    Ok((input, Method::Invite))
}

fn ack(input: &[u8]) -> Result<&[u8], Method> {
    let (input, _) = tag("ACK")(input)?;

    Ok((input, Method::Ack))
}

fn options(input: &[u8]) -> Result<&[u8], Method> {
    let (input, _) = tag("OPTIONS")(input)?;

    Ok((input, Method::Options))
}

fn bye(input: &[u8]) -> Result<&[u8], Method> {
    let (input, _) = tag("BYE")(input)?;

    Ok((input, Method::Bye))
}

fn cancel(input: &[u8]) -> Result<&[u8], Method> {
    let (input, _) = tag("CANCEL")(input)?;

    Ok((input, Method::Cancel))
}

fn register(input: &[u8]) -> Result<&[u8], Method> {
    let (input, _) = tag("REGISTER")(input)?;

    Ok((input, Method::Register))
}

fn extension_method(input: &[u8]) -> Result<&[u8], Method> {
    let (input, method) = tokens::token(input)?;

    Ok((input, Method::Extension(method)))
}

pub fn method(input: &[u8]) -> Result<&[u8], Method> {
    alt((
        invite,
        ack,
        options,
        bye,
        cancel,
        register,
        extension_method,
    ))(input)
}

pub fn sip_version(input: &[u8]) -> Result<&[u8], Version> {
    let (input, (_, major, _, minor)) = tuple((
        tag_no_case("SIP/"),
        digit1,
        tag("."),
        digit1,
    ))(input)?;

    let version = match (major, minor) {
        (b"2", b"0") => Version::Two,
        (major, minor) => Version::Other(major, minor)
    };

    Ok((input, version))
}

fn query(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while(tokens::is_uric)(input)
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

pub fn authority(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        srvr,
        tokens::reg_name,
    ))(input)
}

fn scheme(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            alpha1,
            take_while(tokens::is_scheme_char)
        )
    )(input)
}

fn segment(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            tokens::param,
            many0(pair(tag(";"), tokens::param))
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
            take_while_m_n(1, 1, tokens::is_uric_no_slash),
            take_while(tokens::is_uric),
        )
    )(input)
}

pub fn abs_path(input: &[u8]) -> Result<&[u8], &[u8]> {
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

pub fn absolute_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            scheme,
            tag(":"),
            alt((hier_part, opaque_part))
        ))
    )(input)
}

fn gen_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        host,
        tokens::token,
        tokens::quoted_string,
    ))(input)
}

pub fn generic_param(input: &[u8]) -> Result<&[u8], GenericParam> {
    let (input, (name, value)) = pair(
        tokens::token,
        opt(pair(tokens::equal, gen_value))
    )(input)?;

    let param = match value {
        Some((_, value)) => GenericParam {
            name,
            value: Some(value),
        },
        _ => GenericParam {
            name,
            value: None,
        }
    };

    Ok((input, param))
}

pub fn generic_params(input: &[u8]) -> Result<&[u8], Vec<GenericParam>> {
    let (input, params) = many0(pair(tokens::semicolon, generic_param))(input)?;
    let params = params.into_iter().map(|(_, param)| param).collect();

    Ok((input, params))
}

pub fn option_tag(input: &[u8]) -> Result<&[u8], Vec<&[u8]>> {
    let (input, options) = many0(pair(tokens::comma, tokens::token))(input)?;
    let options = options.into_iter().map(|(_, option)| option).collect();

    Ok((input, options))
}

pub fn qvalue(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(pair(tag("0"), opt(pair(tag("."), take_while_m_n(0, 3, is_digit))))),
        recognize(pair(tag("1"), opt(pair(tag("."), many_m_n(0, 3, tag("0")))))),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
