use crate::{
    header::{
        Header,
        Challenge,
        DigestParam,
        QOPValue,
        AlgorithmKind,
        DigestResponseParam,
        Credentials,
        AuthenticationInfo,
    },
    parser::{
        Result,
        rfc3261::{
            tokens::{
                token,
                token_str,
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
    },
};

use nom::{
    combinator::recognize,
    sequence::{ pair, tuple, preceded, terminated },
    multi::separated_nonempty_list,
    branch::alt,
    bytes::complete::{
        tag,
        tag_no_case,
        take_while,
        take_while1,
        take_while_m_n,
    },
};

fn auth_param(input: &[u8]) -> Result<&[u8], (&str, &str)> {
    let (input, (name, value)) = pair(
        token_str,
        preceded(equal, alt((token, quoted_string)))
    )(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, (name, value)))
}

fn request_digest(input: &[u8]) -> Result<&[u8], &[u8]> {
    let (input, (_, digest, _)) = tuple((
        left_double_quote,
        take_while_m_n(32, 32, is_lowercase_hexadecimal),
        right_double_quote,
    ))(input)?;

    Ok((input, digest))
}

fn dig_resp_response(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, (_, _, digest)) = tuple((
        tag_no_case("response"),
        equal,
        request_digest,
    ))(input)?;

    let digest = std::str::from_utf8(digest)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, DigestResponseParam::Response(digest)))
}

fn nonce_count(input: &[u8]) -> Result<&[u8], &str> {
    let (input, (_, _, value)) = tuple((
        tag_no_case("nc"),
        equal,
        take_while_m_n(8, 8, is_lowercase_hexadecimal)
    ))(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, value))
}

fn cnonce(input: &[u8]) -> Result<&[u8], &str> {
    let (input, (_, _, cnonce)) = tuple((
        tag_no_case("cnonce"),
        equal,
        quoted_string,
    ))(input)?;

    let cnonce = std::str::from_utf8(cnonce)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, cnonce))
}

fn qop_value_auth(input: &[u8]) -> Result<&[u8], QOPValue> {
    let (input, _) = tag_no_case("auth")(input)?;

    Ok((input, QOPValue::Auth))
}

fn qop_value_auth_int(input: &[u8]) -> Result<&[u8], QOPValue> {
    let (input, _) = tag_no_case("auth-int")(input)?;

    Ok((input, QOPValue::AuthInt))
}

fn qop_value_extension(input: &[u8]) -> Result<&[u8], QOPValue> {
    let (input, value) = token_str(input)?;

    Ok((input, QOPValue::Extension(value)))
}

fn qop_value(input: &[u8]) -> Result<&[u8], QOPValue> {
    alt((
        qop_value_auth,
        qop_value_auth_int,
        qop_value_extension,
    ))(input)
}

fn message_qop(input: &[u8]) -> Result<&[u8], QOPValue> {
    let (input, (_, _, value)) = tuple((
        tag_no_case("qop"),
        equal,
        qop_value,
    ))(input)?;

    Ok((input, value))
}

fn digest_uri_value(input: &[u8]) -> Result<&[u8], &[u8]> {
    alt((
        tag("*"),
        absolute_uri,
        abs_path,
        authority,
    ))(input)
}

fn dig_resp_uri(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, (_, _, _, uri, _)) = tuple((
        tag_no_case("uri"),
        equal,
        left_double_quote,
        digest_uri_value,
        right_double_quote,
    ))(input)?;

    let uri = std::str::from_utf8(uri)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, DigestResponseParam::URI(uri)))
}

fn dig_resp_username(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, (_, _, username)) = tuple((
        tag_no_case("username"),
        equal,
        quoted_string
    ))(input)?;

    let username = std::str::from_utf8(username)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, DigestResponseParam::Username(username)))
}

fn dig_resp_realm(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, realm) = realm(input)?;

    Ok((input, DigestResponseParam::Realm(realm)))
}

fn dig_resp_nonce(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, nonce) = nonce(input)?;

    Ok((input, DigestResponseParam::Nonce(nonce)))
}

fn dig_resp_algorithm(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, kind) = algorithm(input)?;

    Ok((input, DigestResponseParam::Algorithm(kind)))
}

fn dig_resp_cnonce(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, cnonce) = cnonce(input)?;

    Ok((input, DigestResponseParam::CNonce(cnonce)))
}

fn dig_resp_opaque(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, value) = opaque(input)?;

    Ok((input, DigestResponseParam::Opaque(value)))
}

fn dig_resp_qop(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, value) = message_qop(input)?;

    Ok((input, DigestResponseParam::QOP(value)))
}

fn dig_resp_nonce_count(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, value) = nonce_count(input)?;

    Ok((input, DigestResponseParam::NonceCount(value)))
}

fn dig_resp_extension(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    let (input, (name, value)) = auth_param(input)?;

    Ok((input, DigestResponseParam::Extension(name, value)))
}

fn dig_resp(input: &[u8]) -> Result<&[u8], DigestResponseParam> {
    alt((
        dig_resp_username,
        dig_resp_realm,
        dig_resp_nonce,
        dig_resp_uri,
        dig_resp_response,
        dig_resp_algorithm,
        dig_resp_cnonce,
        dig_resp_opaque,
        dig_resp_qop,
        dig_resp_nonce_count,
        dig_resp_extension,
    ))(input)
}

fn realm(input: &[u8]) -> Result<&[u8], &str> {
    let (input, (_, _, realm)) = tuple((
        tag_no_case("realm"),
        equal,
        quoted_string
    ))(input)?;

    let realm = std::str::from_utf8(realm)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, realm))
}

fn nonce(input: &[u8]) -> Result<&[u8], &str> {
    let (input, (_, _, nonce)) = tuple((
        tag_no_case("nonce"),
        equal,
        quoted_string
    ))(input)?;

    let nonce = std::str::from_utf8(nonce)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, nonce))
}

fn opaque(input: &[u8]) -> Result<&[u8], &str> {
    let (input, (_, _, value)) = tuple((
        tag_no_case("opaque"),
        equal,
        quoted_string
    ))(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, value))
}

fn algorithm_md5(input: &[u8]) -> Result<&[u8], AlgorithmKind> {
    let (input, _) = tag_no_case("MD5")(input)?;

    Ok((input, AlgorithmKind::MD5))
}

fn algorithm_md5_sess(input: &[u8]) -> Result<&[u8], AlgorithmKind> {
    let (input, _) = tag_no_case("MD5-sess")(input)?;

    Ok((input, AlgorithmKind::MD5Sess))
}

fn algorithm_extension(input: &[u8]) -> Result<&[u8], AlgorithmKind> {
    let (input, value) = token_str(input)?;

    Ok((input, AlgorithmKind::Extension(value)))
}

fn algorithm(input: &[u8]) -> Result<&[u8], AlgorithmKind> {
    let (input, (_, _, kind)) = tuple((
        tag_no_case("algorithm"),
        equal,
        alt((
            algorithm_md5_sess,
            algorithm_md5,
            algorithm_extension,
        )),
    ))(input)?;

    Ok((input, kind))
}

fn credentials_digest_response(input: &[u8]) -> Result<&[u8], Credentials> {
    let (input, params) = preceded(
        pair(
            tag_no_case("Digest"),
            linear_whitespace,
        ),
        separated_nonempty_list(comma, dig_resp)
    )(input)?;

    Ok((input, Credentials::DigestResponse(params)))
}

fn credentials_other_response(input: &[u8]) -> Result<&[u8], Credentials> {
    let (input, (name, params)) = pair(
        terminated(token_str, linear_whitespace),
        separated_nonempty_list(comma, auth_param)
    )(input)?;

    Ok((input, Credentials::OtherResponse(name, params)))
}

fn credentials(input: &[u8]) -> Result<&[u8], Credentials> {
    alt((
        credentials_digest_response,
        credentials_other_response,
    ))(input)
}

pub fn authorization(input: &[u8]) -> Result<&[u8], Header> {
    let (input, credentials) = preceded(
        pair(
            tag_no_case("Authorization"),
            header_colon
        ),
        credentials,
    )(input)?;

    Ok((input, Header::Authorization(credentials)))
}

fn response_digest(input: &[u8]) -> Result<&[u8], &[u8]> {
    recognize(
        preceded(left_double_quote, terminated(take_while(is_lowercase_hexadecimal), right_double_quote))
    )(input)
}

fn ainfo_response_auth(input: &[u8]) -> Result<&[u8], AuthenticationInfo> {
    let (input, auth) = preceded(
        pair(
            tag_no_case("rspauth"),
            equal
        ),
        response_digest,
    )(input)?;

    let auth = std::str::from_utf8(auth)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, AuthenticationInfo::ResponseAuth(auth)))
}

fn ainfo_nextnonce(input: &[u8]) -> Result<&[u8], AuthenticationInfo> {
    let (input, nextnonce) = preceded(
        pair(
            tag_no_case("nextnonce"),
            equal
        ),
        quoted_string,
    )(input)?;

    let nextnonce = std::str::from_utf8(nextnonce)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, AuthenticationInfo::NextNonce(nextnonce)))
}

fn ainfo_qop(input: &[u8]) -> Result<&[u8], AuthenticationInfo> {
    let (input, value) = message_qop(input)?;

    Ok((input, AuthenticationInfo::QOP(value)))
}

fn ainfo_cnonce(input: &[u8]) -> Result<&[u8], AuthenticationInfo> {
    let (input, cnonce) = cnonce(input)?;

    Ok((input, AuthenticationInfo::CNonce(cnonce)))
}

fn ainfo_nonce_count(input: &[u8]) -> Result<&[u8], AuthenticationInfo> {
    let (input, nc) = nonce_count(input)?;

    Ok((input, AuthenticationInfo::NonceCount(nc)))
}

fn ainfo(input: &[u8]) -> Result<&[u8], AuthenticationInfo> {
    alt((
        ainfo_nextnonce,
        ainfo_qop,
        ainfo_response_auth,
        ainfo_cnonce,
        ainfo_nonce_count,
    ))(input)
}

pub fn authentication_info(input: &[u8]) -> Result<&[u8], Header> {
    let (input, infos) = preceded(
        pair(
            tag_no_case("Authentication-Info"),
            header_colon
        ),
        separated_nonempty_list(comma, ainfo)
    )(input)?;

    Ok((input, Header::AuthenticationInfo(infos)))
}

fn qop_options(input: &[u8]) -> Result<&[u8], Vec<QOPValue>> {
    let (input, values) = preceded(
        pair(
            tag_no_case("qop"),
            equal
        ),
        preceded(
            left_double_quote,
            terminated(
                separated_nonempty_list(tag(","), qop_value),
                right_double_quote
            )
        )
    )(input)?;

    Ok((input, values))
}

fn boolean_true(input: &[u8]) -> Result<&[u8], bool> {
    let (input, _) = tag_no_case("true")(input)?;

    Ok((input, true))
}

fn boolean_false(input: &[u8]) -> Result<&[u8], bool> {
    let (input, _) = tag_no_case("false")(input)?;

    Ok((input, false))
}

fn boolean(input: &[u8]) -> Result<&[u8], bool> {
    alt((
        boolean_true,
        boolean_false,
    ))(input)
}

fn stale(input: &[u8]) -> Result<&[u8], bool> {
    let (input, value) = preceded(
        pair(
            tag_no_case("stale"),
            equal
        ),
        boolean
    )(input)?;

    Ok((input, value))
}

fn domain(input: &[u8]) -> Result<&[u8], Vec<&str>> {
    let (input, domains) = preceded(
        tuple((
            tag_no_case("domain"),
            equal,
            left_double_quote,
        )),
        terminated(
            separated_nonempty_list(
                take_while1(is_space), alt((absolute_uri, abs_path))
            ),
            right_double_quote
        ),
    )(input)?;

    let domains = domains.iter().map(|d|
        std::str::from_utf8(d)
            .map_err(|err| nom::Err::Failure(err.into()))
    ).collect::<std::result::Result<Vec<&str>, _>>()?;

    Ok((input, domains))
}

fn digest_cln_realm(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, realm) = realm(input)?;

    Ok((input, DigestParam::Realm(realm)))
}

fn digest_cln_domain(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, uris) = domain(input)?;

    Ok((input, DigestParam::Domain(uris)))
}

fn digest_cln_nonce(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, nonce) = nonce(input)?;

    Ok((input, DigestParam::Nonce(nonce)))
}

fn digest_cln_opaque(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, value) = opaque(input)?;

    Ok((input, DigestParam::Opaque(value)))
}

fn digest_cln_stale(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, value) = stale(input)?;

    Ok((input, DigestParam::Stale(value)))
}

fn digest_cln_algorithm(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, algo) = algorithm(input)?;

    Ok((input, DigestParam::Algorithm(algo)))
}

fn digest_cln_qop_options(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, options) = qop_options(input)?;

    Ok((input, DigestParam::QOPOptions(options)))
}

fn digest_cln_extension(input: &[u8]) -> Result<&[u8], DigestParam> {
    let (input, (name, value)) = auth_param(input)?;

    Ok((input, DigestParam::Extension(name, value)))
}


fn digest_cln(input: &[u8]) -> Result<&[u8], DigestParam> {
    alt((
        digest_cln_realm,
        digest_cln_domain,
        digest_cln_nonce,
        digest_cln_opaque,
        digest_cln_stale,
        digest_cln_algorithm,
        digest_cln_qop_options,
        digest_cln_extension,
    ))(input)
}

fn challenge_other(input: &[u8]) -> Result<&[u8], Challenge> {
    let (input, (name, params)) = pair(
        terminated(token_str, linear_whitespace),
        separated_nonempty_list(comma, auth_param)
    )(input)?;

    Ok((input, Challenge::Other(name, params)))
}

fn challenge_digest(input: &[u8]) -> Result<&[u8], Challenge> {
    let (input, digest_clns) = preceded(
        pair(
            tag_no_case("Digest"),
            linear_whitespace
        ),
        separated_nonempty_list(comma, digest_cln)
    )(input)?;

    Ok((input, Challenge::Digest(digest_clns)))
}

fn challenge(input: &[u8]) -> Result<&[u8], Challenge> {
    alt((
        challenge_digest,
        challenge_other,
    ))(input)
}

pub fn proxy_authenticate(input: &[u8]) -> Result<&[u8], Header> {
    let (input, challenge) = preceded(
        pair(
            tag_no_case("Proxy-Authenticate"),
            header_colon
        ),
        challenge,
    )(input)?;

    Ok((input, Header::ProxyAuthenticate(challenge)))
}

pub fn proxy_authorization(input: &[u8]) -> Result<&[u8], Header> {
    let (input, credentials) = preceded(
        pair(
            tag_no_case("Proxy-Authorization"),
            header_colon
        ),
        credentials,
    )(input)?;

    Ok((input, Header::ProxyAuthorization(credentials)))
}

pub fn proxy_require(input: &[u8]) -> Result<&[u8], Header> {
    let (input, requires) = preceded(
        pair(
            tag_no_case("Proxy-Require"),
            header_colon
        ),
        separated_nonempty_list(comma, token_str)
    )(input)?;

    Ok((input, Header::ProxyRequire(requires)))
}

pub fn www_authenticate(input: &[u8]) -> Result<&[u8], Header> {
    let (input, challenge) = preceded(
        pair(
            tag_no_case("WWW-Authenticate"),
            header_colon
        ),
        challenge,
    )(input)?;

    Ok((input, Header::WWWAuthenticate(challenge)))
}
