use crate::{
    header::{
        Header,
        Media,
        MediaType,
        MediaSubType,
        MediaParam,
        Accept,
        AcceptParam,
        ContentCoding,
        Encoding,
        Language,
        LanguageRange,
        DispositionType,
        DispositionParam,
        ContentDisposition,
    },
    parser::{
        integer,
        Result,
        rfc3261::{
            tokens::{
                token,
                token_str,
                quoted_string,
                equal,
                slash,
                semicolon,
                header_colon,
                comma,
            },
            common::{
                generic_param,
                qvalue,
            },
        },
    },
};

use nom::{
    combinator::recognize,
    sequence::{ pair, tuple, preceded, },
    branch::alt,
    multi::{ many0, separated_nonempty_list, separated_list },
    character::is_alphabetic,
    bytes::complete::{ tag, tag_no_case, take_while_m_n, },
};

fn m_type_any(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("*")(input)?;

    Ok((input, MediaType::Any))
}

fn m_type_text(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("text")(input)?;

    Ok((input, MediaType::Text))
}

fn m_type_image(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("image")(input)?;

    Ok((input, MediaType::Image))
}

fn m_type_audio(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("audio")(input)?;

    Ok((input, MediaType::Audio))
}

fn m_type_video(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("video")(input)?;

    Ok((input, MediaType::Video))
}

fn m_type_application(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("application")(input)?;

    Ok((input, MediaType::Application))
}

fn m_type_multipart(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("multipart")(input)?;

    Ok((input, MediaType::Multipart))
}

fn m_type_message(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, _) = tag_no_case("message")(input)?;

    Ok((input, MediaType::Message))
}

fn m_type_ietf_extension(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, value) = token_str(input)?;

    Ok((input, MediaType::IETFExtension(value)))
}

fn m_type_x_extension(input: &[u8]) -> Result<&[u8], MediaType> {
    let (input, value) = recognize(
        pair(
            tag_no_case("x-"),
            token,
        )
    )(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, MediaType::XExtension(value)))
}

fn m_type(input: &[u8]) -> Result<&[u8], MediaType> {
    alt((
        m_type_any,
        m_type_text,
        m_type_audio,
        m_type_image,
        m_type_video,
        m_type_multipart,
        m_type_application,
        m_type_message,
        m_type_x_extension,
        m_type_ietf_extension,
    ))(input)
}

fn m_subtype_any(input: &[u8]) -> Result<&[u8], MediaSubType> {
    let (input, _) = tag_no_case("*")(input)?;

    Ok((input, MediaSubType::Any))
}

fn m_subtype_ietf_extension(input: &[u8]) -> Result<&[u8], MediaSubType> {
    let (input, value) = token_str(input)?;

    Ok((input, MediaSubType::IETFExtension(value)))
}

fn m_subtype_iana_extension(input: &[u8]) -> Result<&[u8], MediaSubType> {
    // TODO: This is unreachable?
    let (input, value) = token_str(input)?;

    Ok((input, MediaSubType::IANAExtension(value)))
}

fn m_subtype_x_extension(input: &[u8]) -> Result<&[u8], MediaSubType> {
    let (input, value) = recognize(
        pair(
            tag_no_case("x-"),
            token,
        )
    )(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, MediaSubType::XExtension(value)))
}

fn m_subtype(input: &[u8]) -> Result<&[u8], MediaSubType> {
    alt((
        m_subtype_any,
        m_subtype_x_extension,
        m_subtype_ietf_extension,
        m_subtype_iana_extension,
    ))(input)
}

fn m_parameter(input: &[u8]) -> Result<&[u8], MediaParam> {
    let (input, (name, value)) = pair(
        token_str,
        preceded(equal, alt((token, quoted_string)))
    )(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, MediaParam {
        name,
        value,
    }))
}

fn media_range(input: &[u8]) -> Result<&[u8], Media> {
    let (input, ((r#type, subtype), params)) = pair(
        pair(
            m_type,
            preceded(slash, m_subtype)
        ),
        many0(preceded(semicolon, m_parameter))
    )(input)?;

    Ok((input, Media {
        r#type,
        subtype,
        params,
    }))
}

fn accept_param_q(input: &[u8]) -> Result<&[u8], AcceptParam> {
    let (input, (_, _, q)) = tuple((
        tag_no_case("q"),
        equal,
        qvalue
    ))(input)?;

    let q = std::str::from_utf8(q)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, AcceptParam::Q(q)))
}

fn accept_param_extension(input: &[u8]) -> Result<&[u8], AcceptParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, AcceptParam::Extension(param)))
}

fn accept_param(input: &[u8]) -> Result<&[u8], AcceptParam> {
    alt((
        accept_param_q,
        accept_param_extension,
    ))(input)
}

fn accept_range(input: &[u8]) -> Result<&[u8], Accept> {
    let (input, (media, params)) = pair(
        media_range,
        many0(preceded(semicolon, accept_param))
    )(input)?;

    Ok((input, Accept {
        media,
        params,
    }))
}

pub fn accept(input: &[u8]) -> Result<&[u8], Header> {
    let (input, medias) = preceded(
        pair(
            tag_no_case("Accept"),
            header_colon,
        ),
        separated_list(comma, accept_range),
    )(input)?;

    Ok((input, Header::Accept(medias)))
}

fn codings_any(input: &[u8]) -> Result<&[u8], ContentCoding> {
    let (input, _) = tag("*")(input)?;

    Ok((input, ContentCoding::Any))
}

fn codings_other(input: &[u8]) -> Result<&[u8], ContentCoding> {
    let (input, value) = token_str(input)?;

    Ok((input, ContentCoding::Other(value)))
}

fn codings(input: &[u8]) -> Result<&[u8], ContentCoding> {
    alt((
        codings_any,
        codings_other,
    ))(input)
}

fn encoding(input: &[u8]) -> Result<&[u8], Encoding> {
    let (input, (coding, params)) = pair(
        codings,
        many0(preceded(semicolon, accept_param))
    )(input)?;

    Ok((input, Encoding {
        coding,
        params,
    }))
}

pub fn accept_encoding(input: &[u8]) -> Result<&[u8], Header> {
    let (input, encodings) = preceded(
        pair(
            tag_no_case("Accept-Encoding"),
            header_colon,
        ),
        separated_list(comma, encoding)
    )(input)?;

    Ok((input, Header::AcceptEncoding(encodings)))
}

fn language_range_any(input: &[u8]) -> Result<&[u8], LanguageRange> {
    let (input, _) = tag("*")(input)?;

    Ok((input, LanguageRange::Any))
}

fn language_range_other(input: &[u8]) -> Result<&[u8], LanguageRange> {
    let (input, value) = recognize(pair(
        take_while_m_n(1, 8, is_alphabetic),
        many0(pair(tag("-"), take_while_m_n(1, 8, is_alphabetic)))
    ))(input)?;

    let value = std::str::from_utf8(value)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, LanguageRange::Other(value)))
}

fn language_range(input: &[u8]) -> Result<&[u8], LanguageRange> {
    alt((
        language_range_any,
        language_range_other,
    ))(input)
}

fn language(input: &[u8]) -> Result<&[u8], Language> {
    let (input, (range, params)) = pair(
        language_range,
        many0(preceded(semicolon, accept_param))
    )(input)?;

    Ok((input, Language {
        range,
        params,
    }))
}

pub fn accept_language(input: &[u8]) -> Result<&[u8], Header> {
    let (input, languages) = preceded(
        pair(
            tag_no_case("Accept-Language"),
            header_colon,
        ),
        separated_list(comma, language)
    )(input)?;

    Ok((input, Header::AcceptLanguage(languages)))
}

fn media_type(input: &[u8]) -> Result<&[u8], Media> {
    let (input, (r#type, subtype, params)) = tuple((
        m_type,
        preceded(slash, m_subtype),
        many0(preceded(semicolon, m_parameter))
    ))(input)?;

    // TODO: Validate that type and subtype are not `Any`

    Ok((input, Media {
        r#type,
        subtype,
        params,
    }))
}

pub fn content_type(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, media)) = tuple((
        alt((
            tag_no_case("Content-Type"),
            tag_no_case("c"),
        )),
        header_colon,
        media_type,
    ))(input)?;

    Ok((input, Header::ContentType(media)))
}

pub fn content_length(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, length)) = tuple((
        alt((
            tag_no_case("Content-Length"),
            tag_no_case("l"),
        )),
        header_colon,
        integer,
    ))(input)?;

    Ok((input, Header::ContentLength(length)))
}

pub fn content_encoding(input: &[u8]) -> Result<&[u8], Header> {
    let (input, encodings) = preceded(
        pair(
            alt((
                tag_no_case("Content-Encoding"),
                tag_no_case("e"),
            )),
            header_colon,
        ),
        separated_nonempty_list(comma, token_str)
    )(input)?;

    Ok((input, Header::ContentEncoding(encodings)))
}

fn disposition_param_handling_optional(input: &[u8]) -> Result<&[u8], DispositionParam> {
    let (input, _) = tuple((
        tag_no_case("handling"),
        equal,
        tag_no_case("optional"),
    ))(input)?;

    Ok((input, DispositionParam::HandlingOptional))
}

fn disposition_param_handling_required(input: &[u8]) -> Result<&[u8], DispositionParam> {
    let (input, _) = tuple((
        tag_no_case("handling"),
        equal,
        tag_no_case("required"),
    ))(input)?;

    Ok((input, DispositionParam::HandlingRequired))
}

fn disposition_param_handling_other(input: &[u8]) -> Result<&[u8], DispositionParam> {
    let (input, (_, _, value)) = tuple((
        tag_no_case("handling"),
        equal,
        token_str,
    ))(input)?;

    Ok((input, DispositionParam::OtherHandling(value)))
}

fn disposition_param_extension(input: &[u8]) -> Result<&[u8], DispositionParam> {
    let (input, param) = generic_param(input)?;

    Ok((input, DispositionParam::Extension(param)))
}


fn disposition_param(input: &[u8]) -> Result<&[u8], DispositionParam> {
    alt((
        disposition_param_handling_optional,
        disposition_param_handling_required,
        disposition_param_handling_other,
        disposition_param_extension,
    ))(input)
}

fn disp_type_render(input: &[u8]) -> Result<&[u8], DispositionType> {
    let (input, _) = tag_no_case("render")(input)?;

    Ok((input, DispositionType::Render))
}

fn disp_type_session(input: &[u8]) -> Result<&[u8], DispositionType> {
    let (input, _) = tag_no_case("session")(input)?;

    Ok((input, DispositionType::Session))
}

fn disp_type_icon(input: &[u8]) -> Result<&[u8], DispositionType> {
    let (input, _) = tag_no_case("icon")(input)?;

    Ok((input, DispositionType::Icon))
}

fn disp_type_alert(input: &[u8]) -> Result<&[u8], DispositionType> {
    let (input, _) = tag_no_case("alert")(input)?;

    Ok((input, DispositionType::Alert))
}

fn disp_type_extension(input: &[u8]) -> Result<&[u8], DispositionType> {
    let (input, value) = token_str(input)?;

    Ok((input, DispositionType::Extension(value)))
}

fn disp_type(input: &[u8]) -> Result<&[u8], DispositionType> {
    alt((
        disp_type_render,
        disp_type_session,
        disp_type_icon,
        disp_type_alert,
        disp_type_extension,
    ))(input)
}

pub fn content_disposition(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (disposition, params)) = preceded(
        pair(
            tag_no_case("Content-Disposition"),
            header_colon,
        ),
        pair(
            disp_type,
            many0(preceded(semicolon, disposition_param))
        )
    )(input)?;

    Ok((input, Header::ContentDisposition(ContentDisposition {
        disposition,
        params,
    })))
}

fn language_tag(input: &[u8]) -> Result<&[u8], &str> {
    let (input, tag) = recognize(
        pair(
            take_while_m_n(1, 8, is_alphabetic),
            many0(pair(tag("-"), take_while_m_n(1, 8, is_alphabetic)))
        )
    )(input)?;

    let tag = std::str::from_utf8(tag)
        .map_err(|err| nom::Err::Failure(err.into()))?;

    Ok((input, tag))
}

pub fn content_language(input: &[u8]) -> Result<&[u8], Header> {
    let (input, (_, _, tags)) = tuple((
        tag_no_case("Content-Language"),
        header_colon,
        separated_nonempty_list(comma, language_tag)
    ))(input)?;

    Ok((input, Header::ContentLanguage(tags)))
}
