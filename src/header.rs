use super::sip::*;

/// Representation of an HTTP Language Range
///
/// **Note**: This may be renamed to `LanguageTag` in the future to be clearer and more in line
/// with RFC2616.
#[derive(PartialEq, Debug, Clone)]
pub enum LanguageRange {
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
    Other(String),
}

/// Language description, used in the Accept-Language header
///
/// The serialized version of this could be for example `en-US;q=0.8`, or simply `en`.
///
/// **Note**: This might be refactored into an ordered list by preference.
#[derive(PartialEq, Debug, Clone)]
pub struct Language {
    /// The language tag for this specific language definition
    pub range: LanguageRange,

    /// Optional parameters. Usually this will only have a Q param set, indicating the preference
    /// (or lack thereof) over other languages. A missing Q param indicates a default value of 1.0
    /// (highest possible value).
    pub params: Vec<AcceptParam>
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
#[derive(PartialEq, Debug, Clone)]
pub enum ContentCoding {
    /// This value indicates, when used in the Content-Encoding header, that the client accepts any
    /// kind of permissible encoding.
    Any,

    /// This variant allows storing of any other (more specific) encoding types
    Other(String),
}

/// Content-coding description, used in the Accept-Encoding header
///
/// The serialized version of this could be for example `gzip;q=0.1`.
///
/// **Note**: This might be refactored into an ordered list by preference.
#[derive(PartialEq, Debug, Clone)]
pub struct Encoding {
    /// The descriptor of an encoding format
    pub coding: ContentCoding,

    /// Optional parameters. Usually this will only have a Q param set, indicating the preference
    /// (or lack thereof) over other languages. A missing Q param indicates a default value of 1.0
    /// (highest possible value).
    pub params: Vec<AcceptParam>
}

#[derive(PartialEq, Debug, Clone)]
pub enum MediaSubType {
    Any,
    IETFExtension(String),
    IANAExtension(String),
    XExtension(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum MediaType {
    Any,
    Text,
    Image,
    Audio,
    Video,
    Application,
    Message,
    Multipart,
    IETFExtension(String),
    XExtension(String),
}

#[derive(PartialEq, Debug, Clone)]
pub struct MediaParam {
    pub name: String,
    pub value: String,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Media {
    pub r#type: MediaType,
    pub subtype: MediaSubType,
    pub params: Vec<MediaParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum AcceptParam {
    Q(String),
    Extension(GenericParam),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Accept {
    pub media: Media,
    pub params: Vec<AcceptParam>
}

#[derive(PartialEq, Debug, Clone)]
pub struct AlertInfo {
    pub uri: String,
    pub params: Vec<GenericParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum URIParam {
    Transport(Transport),
    User(User),
    Method(Method),
    TTL(i32),
    MAddr(String),
    LR,
    Other(String, Option<String>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct URIHeader {
    pub name: String,
    pub value: String,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ViaParam {
    Ttl(i32),
    MAddr(String),
    Received(String),
    Branch(String),
    Extension(GenericParam),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Via {
    pub protocol: String,
    pub sent_by: String,
    pub params: Vec<ViaParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum InfoParamPurpose {
    Icon,
    Info,
    Card,
    Other(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum InfoParam {
    Purpose(InfoParamPurpose),
    Extension(GenericParam)
}

#[derive(PartialEq, Debug, Clone)]
pub struct Info {
    pub uri: String,
    pub params: Vec<InfoParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum AlgorithmKind {
    MD5,
    MD5Sess,
    Extension(String)
}

#[derive(PartialEq, Debug, Clone)]
pub enum QOPValue {
    Auth,
    AuthInt,
    Extension(String)
}

#[derive(PartialEq, Debug, Clone)]
pub enum DigestParam {
    Realm(String),
    Domain(Vec<String>),
    Nonce(String),
    Opaque(String),
    Stale(bool),
    Algorithm(AlgorithmKind),
    QOPOptions(Vec<QOPValue>),
    Extension(String, String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Challenge {
    Digest(Vec<DigestParam>),
    Other(String, Vec<(String, String)>)
}

#[derive(PartialEq, Debug, Clone)]
pub enum DigestResponseParam {
    Username(String),
    Realm(String),
    Nonce(String),
    URI(String),
    Response(String),
    Algorithm(AlgorithmKind),
    CNonce(String),
    Opaque(String),
    QOP(QOPValue),
    NonceCount(String),
    Extension(String, String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Credentials {
    DigestResponse(Vec<DigestResponseParam>),
    OtherResponse(String, Vec<(String, String)>)
}

#[derive(PartialEq, Debug, Clone)]
pub enum AuthenticationInfo {
    NextNonce(String),
    QOP(QOPValue),
    ResponseAuth(String),
    CNonce(String),
    NonceCount(String)
}

#[derive(PartialEq, Debug, Clone)]
pub enum Priority {
    Emergency,
    Urgent,
    Normal,
    NonUrgent,
    Extension(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum ToParam {
    Tag(String),
    Extension(GenericParam),
}

#[derive(PartialEq, Debug, Clone)]
pub struct To {
    pub addr: String,
    pub name: Option<String>,
    pub params: Vec<ToParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct GenericParam {
    pub name: String,
    pub value: Option<String>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Route {
    pub addr: String,
    pub name: Option<String>,
    pub params: Vec<GenericParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReplyTo {
    pub addr: String,
    pub name: Option<String>,
    pub params: Vec<GenericParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct RecordRoute {
    pub addr: String,
    pub name: Option<String>,
    pub params: Vec<GenericParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum FromParam {
    Tag(String),
    Extension(GenericParam),
}

#[derive(PartialEq, Debug, Clone)]
pub struct From {
    pub addr: String,
    pub name: Option<String>,
    pub params: Vec<FromParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ContactParam {
    Q(String),
    Expires(i32),
    Extension(GenericParam),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Contact {
    pub addr: String,
    pub name: Option<String>,
    pub params: Vec<ContactParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ContactValue {
    Any,
    Specific(Vec<Contact>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct ErrorInfo {
    pub uri: String,
    pub params: Vec<GenericParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum WarningAgent {
    HostPort(String, Option<i32>),
    Pseudonym(String),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Warning {
    pub code: String,
    pub agent: WarningAgent,
    pub text: String,
}

#[derive(PartialEq, Debug, Clone)]
pub enum DispositionType {
    Render,
    Session,
    Icon,
    Alert,
    Extension(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum DispositionParam {
    HandlingOptional,
    HandlingRequired,
    OtherHandling(String),
    Extension(GenericParam),
}

#[derive(PartialEq, Debug, Clone)]
pub struct ContentDisposition {
    pub disposition: DispositionType,
    pub params: Vec<DispositionParam>
}

#[derive(PartialEq, Debug, Clone)]
pub enum RetryParam {
    AvailabilityDuration(i32),
    Extension(GenericParam),
}

#[derive(PartialEq, Debug, Clone)]
pub struct RetryAfter {
    pub duration: i32,
    pub comment: Option<String>,
    pub params: Vec<RetryParam>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum Header {
    Accept(Vec<Accept>),
    AcceptEncoding(Vec<Encoding>),
    AcceptLanguage(Vec<Language>),
    AlertInfo(Vec<AlertInfo>),
    Allow(Vec<Method>),
    AuthenticationInfo(Vec<AuthenticationInfo>),
    Authorization(Credentials),
    CallID(String),
    CallInfo(Vec<Info>),
    Contact(ContactValue),
    ContentDisposition(ContentDisposition),
    ContentEncoding(Vec<String>),
    ContentLanguage(Vec<String>),
    ContentLength(i32),
    ContentType(Media),
    CSeq(i32, Method),
    Date(String),
    ErrorInfo(Vec<ErrorInfo>),
    Expires(i32),
    From(From),
    Via(Vec<Via>),
    InReplyTo(Vec<String>),
    MaxForwards(i32),
    MIMEVersion(String),
    MinExpires(i32),
    Organization(Option<String>),
    Priority(Priority),
    ProxyAuthenticate(Challenge),
    ProxyAuthorization(Credentials),
    ProxyRequire(Vec<String>),
    RecordRoute(Vec<RecordRoute>),
    ReplyTo(ReplyTo),
    Require(Vec<String>),
    RetryAfter(RetryAfter),
    Route(Vec<Route>),
    Server(String),
    Subject(Option<String>),
    Supported(Vec<String>),
    Timestamp(String, Option<String>),
    To(To),
    Unsupported(Vec<String>),
    UserAgent(String),
    Warning(Vec<Warning>),
    WWWAuthenticate(Challenge),
    Extension(String, String),
}
