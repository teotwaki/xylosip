use crate::{
    sip::{
        Method,
        Transport,
        User,
        Version,
    },
    header::{
        GenericParam,
        URIParam,
        URIHeader,
    },
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
    combinator::{ opt, recognize, rest },
    sequence::{ pair, tuple, preceded, separated_pair, },
    branch::alt,
    multi::{ many0, many1, many_m_n, separated_list, separated_nonempty_list, },
    character::{ is_digit, is_hex_digit },
    character::complete::alpha1,
    bytes::complete::{
        tag,
        tag_no_case,
        take_while,
        take_while1,
        take_while_m_n,
    },
};

pub fn message_body(input: &[u8]) -> Result<&[u8], Vec<u8>> {
    let (input, body) = rest(input)?;

    Ok((input, body.to_vec()))
}

fn user_info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            alt((
                tokens::user,
                telephone_subscriber,
            )),
            opt(preceded(tag(":"), tokens::password)),
            tag("@"),
        ))
    )(input)
}

pub fn sip_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(preceded(
        tag_no_case("sip:"),
        tuple((
            opt(user_info),
            host_port,
            uri_parameters,
            headers,
        ))
    ))(input)
}

pub fn sips_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(preceded(
        tag_no_case("sips:"),
        tuple((
            opt(user_info),
            host_port,
            uri_parameters,
            headers,
        ))
    ))(input)
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

pub fn port(input: &[u8]) -> Result<&[u8], i32> {
    integer(input)
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

pub fn host_port(input: &[u8]) -> Result<&[u8], (&[u8], Option<i32>)> {
    pair(
        host,
        opt(preceded(tag(":"), port)),
    )(input)
}

pub fn transport_udp(input: &[u8]) -> Result<&[u8], Transport> {
    let (input, _) = tag_no_case("udp")(input)?;

    Ok((input, Transport::UDP))
}

pub fn transport_tcp(input: &[u8]) -> Result<&[u8], Transport> {
    let (input, _) = tag_no_case("tcp")(input)?;

    Ok((input, Transport::TCP))
}

pub fn transport_sctp(input: &[u8]) -> Result<&[u8], Transport> {
    let (input, _) = tag_no_case("sctp")(input)?;

    Ok((input, Transport::SCTP))
}

pub fn transport_tls(input: &[u8]) -> Result<&[u8], Transport> {
    let (input, _) = tag_no_case("TLS")(input)?;

    Ok((input, Transport::TLS))
}

pub fn transport_extension(input: &[u8]) -> Result<&[u8], Transport> {
    let (input, value) = tokens::token_str(input)?;

    Ok((input, Transport::Extension(value.to_string())))
}

pub fn transport(input: &[u8]) -> Result<&[u8], Transport> {
    alt((
        transport_udp,
        transport_tcp,
        transport_sctp,
        transport_tls,
        transport_extension,
    ))(input)
}

fn uri_parameter_transport(input: &[u8]) -> Result<&[u8], URIParam> {
    let (input, transport) = preceded(
        tag_no_case("transport="),
        transport
    )(input)?;

    Ok((input, URIParam::Transport(transport)))
}

fn user_phone(input: &[u8]) -> Result<&[u8], User> {
    let (input, _) = tag_no_case("phone")(input)?;

    Ok((input, User::Phone))
}

fn user_ip(input: &[u8]) -> Result<&[u8], User> {
    let (input, _) = tag_no_case("ip")(input)?;

    Ok((input, User::IP))
}

fn user_extension(input: &[u8]) -> Result<&[u8], User> {
    let (input, value) = tokens::token_str(input)?;

    Ok((input, User::Other(value.to_string())))
}

fn user(input: &[u8]) -> Result<&[u8], User> {
    alt((
        user_phone,
        user_ip,
        user_extension,
    ))(input)
}

fn uri_parameter_user(input: &[u8]) -> Result<&[u8], URIParam> {
    let (input, user) = preceded(
        tag_no_case("user="),
        user
    )(input)?;

    Ok((input, URIParam::User(user)))
}

fn uri_parameter_method(input: &[u8]) -> Result<&[u8], URIParam> {
    let (input, method) = preceded(tag_no_case("method="), method)(input)?;

    Ok((input, URIParam::Method(method)))
}

fn uri_parameter_ttl(input: &[u8]) -> Result<&[u8], URIParam> {
    let (input, ttl) = preceded(tag_no_case("ttl="), ttl)(input)?;

    Ok((input, URIParam::TTL(ttl)))
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

fn uri_parameter_maddr(input: &[u8]) -> Result<&[u8], URIParam> {
    let (input, maddr) = preceded(tag_no_case("maddr="), host)(input)?;

    let maddr = std::str::from_utf8(maddr)
        .map(|s| s.to_string())
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, URIParam::MAddr(maddr)))
}

fn uri_parameter_lr(input: &[u8]) -> Result<&[u8], URIParam> {
    let (input, _) = tag_no_case("lr")(input)?;

    Ok((input, URIParam::LR))
}

fn uri_parameter_other(input: &[u8]) -> Result<&[u8], URIParam> {
    let (input, (name, value)) = pair(
        take_while1(tokens::is_param_char),
        opt(
            preceded(
                tag("="),
                take_while1(tokens::is_param_char),
            )
        )
    )(input)?;

    let name = std::str::from_utf8(name)
        .map(|s| s.to_string())
        .map_err(|err| nom::Err::Failure(err.into()))?;
    let value = match value {
        Some(v) => Some(std::str::from_utf8(v)
            .map(|s| s.to_string())
            .map_err(|err| nom::Err::Failure(err.into()))?),
        None => None,
    };

    Ok((input, URIParam::Other(name, value)))
}

fn uri_parameter(input: &[u8]) -> Result<&[u8], URIParam> {
    alt((
        uri_parameter_transport,
        uri_parameter_user,
        uri_parameter_method,
        uri_parameter_ttl,
        uri_parameter_maddr,
        uri_parameter_lr,
        uri_parameter_other,
    ))(input)
}

fn uri_parameters(input: &[u8]) -> Result<&[u8], Vec<URIParam>> {
    many0(
        preceded(
            tag(";"),
            uri_parameter
        )
    )(input)
}

fn header(input: &[u8]) -> Result<&[u8], URIHeader> {
    let (input, (name, value)) = separated_pair(
        take_while1(tokens::is_header_char),
        tag("="),
        take_while(tokens::is_header_char)
    )(input)?;

    let name = std::str::from_utf8(name)
        .map(|s| s.to_string())
        .map_err(|err| nom::Err::Failure(err.into()))?;
    let value = std::str::from_utf8(value)
        .map(|s| s.to_string())
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, URIHeader {
        name,
        value,
    }))
}

fn headers(input: &[u8]) -> Result<&[u8], Vec<URIHeader>> {
    preceded(
        tag("?"),
        separated_list(tag("&"), header)
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
    let (input, method) = tokens::token_str(input)?;

    Ok((input, Method::Extension(method.to_string())))
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
    let (input, (major, minor)) = pair(
        preceded(tag_no_case("SIP/"), integer),
        preceded(tag("."), integer),
    )(input)?;

    let version = match (major, minor) {
        (2, 0) => Version::Two,
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

fn segment(input: &[u8]) -> Result<&[u8], Vec<&[u8]>> {
    separated_nonempty_list(
        tag(";"),
        tokens::param
    )(input)
}

fn path_segments(input: &[u8]) -> Result<&[u8], Vec<Vec<&[u8]>>> {
    separated_nonempty_list(
        tag("/"),
        segment
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
    recognize(separated_pair(
        scheme,
        tag(":"),
        alt((hier_part, opaque_part))
    ))(input)
}

fn gen_value(input: &[u8]) -> Result<&[u8], &str> {
    let (input, value) = alt((
        host,
        tokens::token,
        tokens::quoted_string,
    ))(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, value))
}

pub fn generic_param(input: &[u8]) -> Result<&[u8], GenericParam> {
    let (input, (name, value)) = pair(
        tokens::token_str,
        opt(preceded(tokens::equal, gen_value))
    )(input)?;

    Ok((input, GenericParam {
        name: name.to_string(),
        value: value.and_then(|s| Some(s.to_string())),
    }))
}

pub fn generic_params(input: &[u8]) -> Result<&[u8], Vec<GenericParam>> {
    let (input, params) = many0(preceded(tokens::semicolon, generic_param))(input)?;

    Ok((input, params))
}

pub fn option_tag(input: &[u8]) -> Result<&[u8], Vec<String>> {
    let (input, options) = many0(preceded(tokens::comma, tokens::token_str))(input)?;

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
        assert!(port(b"1") == Ok((b"", 1)));
        assert_eq!(port(b"").is_err(), true);
    }

    #[test]
    fn port_only_handles_reasonable_values() {
        assert!(port(b"2147483647") == Ok((b"", 2_147_483_647)));
        assert!(port(b"2147483648").is_err());
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
        assert!(host_port(b"[::1]") == Ok((b"", (b"[::1]", None))));
        assert!(host_port(b"[::1]:12345") == Ok((b"", (b"[::1]", Some(12345)))));
    }

    #[test]
    fn uri_parameters_should_parse_no_params() {
        assert!(uri_parameters(b"") == Ok((b"", vec![])));
        assert!(uri_parameters(b"transport=udp") == Ok((b"transport=udp", vec![])));
    }

    #[test]
    fn uri_parameters_should_parse_one_param() {
        let (_, params) = uri_parameters(b";transport=udp").unwrap();
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn uri_parameters_should_parse_leading_semi() {
        let (_, params) = uri_parameters(b";transport=udp").unwrap();
        assert_eq!(params.len(), 1);
    }
}
