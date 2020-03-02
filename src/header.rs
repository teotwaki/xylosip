use super::sip::*;

/// Representation of an HTTP Language Range
///
/// **Note**: This may be renamed to `LanguageTag` in the future to be clearer and more in line
/// with RFC2616.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum LanguageRange<'a> {
    /// This variant indicates that the language in question was equal to `*`. This means that the
    /// user accepts any language equally.
    Any,

    /// Any other value (more restrictive than `*`) will be stored in this variant. The value of
    /// this string will be composed of a primary tag and zero or more subtags, separated by
    /// dashes.
    ///
    /// # ABNF
    /// ```ignore
    /// language-tag  = primary-tag *( "-" subtag )
    /// primary-tag   = 1*8ALPHA
    /// subtag        = 1*8ALPHA
    /// ```
    ///
    /// # Examples
    ///
    /// - `en`
    /// - `en-US`
    /// - `en-cockney`
    /// - `i-cherokee`
    /// - `x-pig-latin`
    Other(&'a str),
}

/// Language description, used in the Accept-Language header
///
/// The serialized version of this could be for example `en-US;q=0.8`, or simply `en`.
///
/// **Note**: This might be refactored into an ordered list by preference.
#[derive(PartialEq, Debug, Clone)]
pub struct Language<'a> {
    /// The language tag for this specific language definition
    pub range: LanguageRange<'a>,

    /// Optional parameters. Usually this will only have a Q param set, indicating the preference
    /// (or lack thereof) over other languages. A missing Q param indicates a default value of 1.0
    /// (highest possible value).
    pub params: Vec<AcceptParam<'a>>
}

/// Representation of a content-coding.
///
/// A content-coding is used to indicate how the body of a message has been transformed. For
/// example, `gzip` indicates that the body has been GNU zipped before being sent over the wire.
/// For the recipient to make sense of the data, they will first need to apply the correct decoding
/// in order to obtain the message's actual media type. As per [RFC3261][1]:
///
/// > Clients MAY apply content encodings to the body in requests. A server MAY apply content
/// > encodings to the bodies in responses. The server MUST only use encodings listed in the
/// > Accept-Encoding header field in the request.
///
/// [1]: https://tools.ietf.org/html/rfc3261#section-20.12
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ContentCoding<'a> {
    /// This value indicates, when used in the Content-Encoding header, that the client accepts any
    /// kind of permissible encoding.
    Any,

    /// This variant allows storing of any other (more specific) encoding types
    Other(&'a str),
}

/// Content-coding description, used in the Accept-Encoding header
///
/// The serialized version of this could be for example `gzip;q=0.1`.
///
/// **Note**: This might be refactored into an ordered list by preference.
#[derive(PartialEq, Debug, Clone)]
pub struct Encoding<'a> {
    /// The descriptor of an encoding format
    pub coding: ContentCoding<'a>,

    /// Optional parameters. Usually this will only have a Q param set, indicating the preference
    /// (or lack thereof) over other languages. A missing Q param indicates a default value of 1.0
    /// (highest possible value).
    pub params: Vec<AcceptParam<'a>>
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum MediaSubType<'a> {
    Any,
    IETFExtension(&'a str),
    IANAExtension(&'a str),
    XExtension(&'a str),
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum MediaType<'a> {
    Any,
    Text,
    Image,
    Audio,
    Video,
    Application,
    Message,
    Multipart,
    IETFExtension(&'a str),
    XExtension(&'a str),
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct MediaParam<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Media<'a> {
    pub r#type: MediaType<'a>,
    pub subtype: MediaSubType<'a>,
    pub params: Vec<MediaParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum AcceptParam<'a> {
    Q(&'a str),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Accept<'a> {
    pub media: Media<'a>,
    pub params: Vec<AcceptParam<'a>>
}

#[derive(PartialEq, Debug, Clone)]
pub struct AlertInfo<'a> {
    pub uri: &'a str,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum URIParam<'a> {
    Transport(Transport<'a>),
    User(User<'a>),
    Method(Method<'a>),
    TTL(i32),
    MAddr(&'a str),
    LR,
    Other(&'a str, Option<&'a str>),
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct URIHeader<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ViaParam<'a> {
    Ttl(i32),
    MAddr(&'a str),
    Received(&'a str),
    Branch(&'a str),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Via<'a> {
    pub protocol: &'a str,
    pub sent_by: &'a str,
    pub params: Vec<ViaParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum InfoParamPurpose<'a> {
    Icon,
    Info,
    Card,
    Other(&'a str),
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum InfoParam<'a> {
    Purpose(InfoParamPurpose<'a>),
    Extension(GenericParam<'a>)
}

#[derive(PartialEq, Debug, Clone)]
pub struct Info<'a> {
    pub uri: &'a str,
    pub params: Vec<InfoParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum AlgorithmKind<'a> {
    MD5,
    MD5Sess,
    Extension(&'a str)
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum QOPValue<'a> {
    Auth,
    AuthInt,
    Extension(&'a str)
}

#[derive(PartialEq, Debug, Clone)]
pub enum DigestParam<'a> {
    Realm(&'a str),
    Domain(Vec<&'a str>),
    Nonce(&'a str),
    Opaque(&'a str),
    Stale(bool),
    Algorithm(AlgorithmKind<'a>),
    QOPOptions(Vec<QOPValue<'a>>),
    Extension(&'a str, &'a str),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Challenge<'a> {
    Digest(Vec<DigestParam<'a>>),
    Other(&'a str, Vec<(&'a str, &'a str)>)
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum DigestResponseParam<'a> {
    Username(&'a str),
    Realm(&'a str),
    Nonce(&'a str),
    URI(&'a str),
    Response(&'a str),
    Algorithm(AlgorithmKind<'a>),
    CNonce(&'a str),
    Opaque(&'a str),
    QOP(QOPValue<'a>),
    NonceCount(&'a str),
    Extension(&'a str, &'a str),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Credentials<'a> {
    DigestResponse(Vec<DigestResponseParam<'a>>),
    OtherResponse(&'a str, Vec<(&'a str, &'a str)>)
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum AuthenticationInfo<'a> {
    NextNonce(&'a str),
    QOP(QOPValue<'a>),
    ResponseAuth(&'a str),
    CNonce(&'a str),
    NonceCount(&'a str)
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Priority<'a> {
    Emergency,
    Urgent,
    Normal,
    NonUrgent,
    Extension(&'a str),
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ToParam<'a> {
    Tag(&'a str),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct To<'a> {
    pub addr: &'a str,
    pub name: Option<&'a str>,
    pub params: Vec<ToParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct GenericParam<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Route<'a> {
    pub addr: &'a str,
    pub name: Option<&'a str>,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReplyTo<'a> {
    pub addr: &'a str,
    pub name: Option<&'a str>,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct RecordRoute<'a> {
    pub addr: &'a str,
    pub name: Option<&'a str>,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FromParam<'a> {
    Tag(&'a str),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct From<'a> {
    pub addr: &'a str,
    pub name: Option<&'a str>,
    pub params: Vec<FromParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ContactParam<'a> {
    Q(&'a str),
    Expires(i32),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Contact<'a> {
    pub addr: &'a str,
    pub name: Option<&'a str>,
    pub params: Vec<ContactParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ContactValue<'a> {
    Any,
    Specific(Vec<Contact<'a>>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct ErrorInfo<'a> {
    pub uri: &'a str,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum WarningAgent<'a> {
    HostPort(&'a str, Option<i32>),
    Pseudonym(&'a str),
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Warning<'a> {
    pub code: &'a str,
    pub agent: WarningAgent<'a>,
    pub text: &'a str,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum DispositionType<'a> {
    Render,
    Session,
    Icon,
    Alert,
    Extension(&'a str),
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum DispositionParam<'a> {
    HandlingOptional,
    HandlingRequired,
    OtherHandling(&'a str),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct ContentDisposition<'a> {
    pub disposition: DispositionType<'a>,
    pub params: Vec<DispositionParam<'a>>
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum RetryParam<'a> {
    AvailabilityDuration(i32),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct RetryAfter<'a> {
    pub duration: i32,
    pub comment: Option<&'a str>,
    pub params: Vec<RetryParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Header<'a> {
    Accept(Vec<Accept<'a>>),
    AcceptEncoding(Vec<Encoding<'a>>),
    AcceptLanguage(Vec<Language<'a>>),
    AlertInfo(Vec<AlertInfo<'a>>),
    Allow(Vec<Method<'a>>),
    AuthenticationInfo(Vec<AuthenticationInfo<'a>>),
    Authorization(Credentials<'a>),
    CallID(&'a str),
    CallInfo(Vec<Info<'a>>),
    Contact(ContactValue<'a>),
    ContentDisposition(ContentDisposition<'a>),
    ContentEncoding(Vec<&'a str>),
    ContentLanguage(Vec<&'a str>),
    ContentLength(i32),
    ContentType(Media<'a>),
    CSeq(i32, Method<'a>),
    Date(&'a str),
    ErrorInfo(Vec<ErrorInfo<'a>>),
    Expires(i32),
    From(From<'a>),
    Via(Vec<Via<'a>>),
    InReplyTo(Vec<&'a str>),
    MaxForwards(i32),
    MIMEVersion(&'a str),
    MinExpires(i32),
    Organization(Option<&'a str>),
    Priority(Priority<'a>),
    ProxyAuthenticate(Challenge<'a>),
    ProxyAuthorization(Credentials<'a>),
    ProxyRequire(Vec<&'a str>),
    RecordRoute(Vec<RecordRoute<'a>>),
    ReplyTo(ReplyTo<'a>),
    Require(Vec<&'a str>),
    RetryAfter(RetryAfter<'a>),
    Route(Vec<Route<'a>>),
    Server(&'a str),
    Subject(Option<&'a str>),
    Supported(Vec<&'a str>),
    Timestamp(&'a str, Option<&'a str>),
    To(To<'a>),
    Unsupported(Vec<&'a str>),
    UserAgent(&'a str),
    Warning(Vec<Warning<'a>>),
    WWWAuthenticate(Challenge<'a>),
    Extension(&'a str, &'a str),
}
