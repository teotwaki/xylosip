use crate::parser::{
    Result,
    rfc3261::{
        tokens::{
            token,
            linear_whitespace,
            header_colon,
            comma,
            equal,
            left_double_quote,
            right_double_quote,
            is_lowercase_hexadecimal,
            is_space,
            quoted_string,
        },
        common::{
            absolute_uri,
            abs_path,
            authority,
        },
    },

};

use nom::{
    combinator::recognize,
    sequence::{ pair, tuple },
    multi::many0,
    branch::alt,
    bytes::complete::{
        tag,
        tag_no_case,
        take_while,
        take_while1,
        take_while_m_n,
    },
};

fn auth_param(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            token,
            equal,
            alt((token, quoted_string))
        ))
    )(input)
}

fn other_response(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            token,
            linear_whitespace,
            auth_param,
            many0(pair(comma, auth_param))
        ))
    )(input)
}

fn request_digest(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            left_double_quote,
            take_while_m_n(32, 32, is_lowercase_hexadecimal),
            right_double_quote,
        ))
    )(input)
}

fn dresponse(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("response"),
            equal,
            request_digest,
        ))
    )(input)
}

fn nc_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    take_while_m_n(8, 8, is_lowercase_hexadecimal)(input)
}

fn nonce_count(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("nc"),
            equal,
            nc_value
        ))
    )(input)
}

fn cnonce(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("cnonce"),
            equal,
            quoted_string,
        ))
    )(input)
}

fn qop_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag_no_case("auth"),
        tag_no_case("auth-int"),
        token,
    ))(input)
}

fn message_qop(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("qop"),
            equal,
            qop_value,
        ))
    )(input)
}

fn digest_uri_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag("*"),
        absolute_uri,
        abs_path,
        authority,
    ))(input)
}

fn digest_uri(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("uri"),
            equal,
            left_double_quote,
            digest_uri_value,
            right_double_quote,
        ))
    )(input)
}

fn username(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("username"),
            equal,
            quoted_string
        ))
    )(input)
}

fn dig_resp(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        username,
        realm,
        nonce,
        digest_uri,
        dresponse,
        algorithm,
        cnonce,
        opaque,
        message_qop,
        nonce_count,
        auth_param,
    ))(input)
}

fn realm(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("realm"),
            equal,
            quoted_string
        ))
    )(input)
}

fn nonce(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("nonce"),
            equal,
            quoted_string
        ))
    )(input)
}

fn opaque(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("opaque"),
            equal,
            quoted_string
        ))
    )(input)
}

fn algorithm(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("algorithm"),
            equal,
            alt((tag_no_case("MD5"), tag_no_case("MD5-sess"), token))
        ))
    )(input)
}

fn digest_response(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        pair(
            dig_resp,
            many0(pair(comma, dig_resp))
        )
    )(input)
}

fn credentials(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(tuple((
            tag_no_case("Digest"),
            linear_whitespace,
            digest_response,
        ))),
        other_response,
    ))(input)
}

pub fn authorization(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Authorization"),
            header_colon,
            credentials,
        ))
    )(input)
}

fn response_digest(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            left_double_quote,
            take_while(is_lowercase_hexadecimal),
            right_double_quote,
        ))
    )(input)
}

fn response_auth(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("rspauth"),
            equal,
            response_digest,
        ))
    )(input)
}

fn nextnonce(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("nextnonce"),
            equal,
            quoted_string,
        ))
    )(input)
}

fn ainfo(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        nextnonce,
        message_qop,
        response_auth,
        cnonce,
        nonce_count,
    ))(input)
}

pub fn authentication_info(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Authentication-Info"),
            header_colon,
            ainfo,
            many0(pair(comma, ainfo)),
        ))
    )(input)
}

fn qop_options(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("qop"),
            equal,
            left_double_quote,
            qop_value,
            many0(pair(tag(","), qop_value)),
            right_double_quote,
        ))
    )(input)
}

fn stale(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("stale"),
            equal,
            alt((tag_no_case("true"), tag_no_case("false")))
        ))
    )(input)
}

fn domain(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("domain"),
            equal,
            left_double_quote,
            alt((absolute_uri, abs_path)),
            many0(pair(take_while1(is_space), alt((absolute_uri, abs_path)))),
            right_double_quote,
        ))
    )(input)
}

fn digest_cln(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        realm,
        domain,
        nonce,
        opaque,
        stale,
        algorithm,
        qop_options,
        auth_param,
    ))(input)
}

fn other_challenge(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            token,
            linear_whitespace,
            auth_param,
            many0(pair(comma, auth_param))
        ))
    )(input)
}

fn challenge(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        recognize(tuple((
            tag_no_case("Digest"),
            linear_whitespace,
            digest_cln,
            many0(pair(comma, digest_cln))
        ))),
        other_challenge
    ))(input)
}

pub fn proxy_authenticate(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Proxy-Authenticate"),
            header_colon,
            challenge,
        ))
    )(input)
}

pub fn proxy_authorization(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Proxy-Authorization"),
            header_colon,
            credentials,
        ))
    )(input)
}

pub fn proxy_require(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("Proxy-Authorization"),
            header_colon,
            token,
            many0(pair(comma, token))
        ))
    )(input)
}

pub fn www_authenticate(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        tuple((
            tag_no_case("WWW-Authenticate"),
            header_colon,
            challenge,
        ))
    )(input)
}
