#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Method<'a> {
    Invite,
    Ack,
    Options,
    Bye,
    Cancel,
    Register,
    Extension(&'a [u8])
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Version<'a> {
    Two,
    Other(&'a [u8], &'a [u8]),
}

#[derive(Debug, Copy, Clone)]
pub struct RequestLine<'a> {
    pub method: Method<'a>,
    pub uri: &'a [u8],
    pub version: Version<'a>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ViaParam<'a> {
    Ttl(i32),
    MAddr(&'a [u8]),
    Received(&'a [u8]),
    Branch(&'a [u8]),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Via<'a> {
    pub protocol: &'a [u8],
    pub sent_by: &'a [u8],
    pub params: Vec<ViaParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum InfoParamPurpose<'a> {
    Icon,
    Info,
    Card,
    Other(&'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub enum InfoParam<'a> {
    Purpose(InfoParamPurpose<'a>),
    Extension(GenericParam<'a>)
}

#[derive(PartialEq, Debug, Clone)]
pub struct Info<'a> {
    pub uri: &'a [u8],
    pub params: Vec<InfoParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum AlgorithmKind<'a> {
    MD5,
    MD5Sess,
    Extension(&'a [u8])
}

#[derive(PartialEq, Debug, Clone)]
pub enum QOPValue<'a> {
    Auth,
    AuthInt,
    Extension(&'a [u8])
}

#[derive(PartialEq, Debug, Clone)]
pub enum DigestParam<'a> {
    Realm(&'a [u8]),
    Domain(Vec<&'a [u8]>),
    Nonce(&'a [u8]),
    Opaque(&'a [u8]),
    Stale(bool),
    Algorithm(AlgorithmKind<'a>),
    QOPOptions(Vec<QOPValue<'a>>),
    Extension(&'a [u8], &'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Challenge<'a> {
    Digest(Vec<DigestParam<'a>>),
    Other(&'a [u8], Vec<(&'a [u8], &'a [u8])>)
}

#[derive(PartialEq, Debug, Clone)]
pub enum DigestResponseParam<'a> {
    Username(&'a [u8]),
    Realm(&'a [u8]),
    Nonce(&'a [u8]),
    URI(&'a [u8]),
    Response(&'a [u8]),
    Algorithm(AlgorithmKind<'a>),
    CNonce(&'a [u8]),
    Opaque(&'a [u8]),
    QOP(QOPValue<'a>),
    NonceCount(&'a [u8]),
    Extension(&'a [u8], &'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Credentials<'a> {
    DigestResponse(Vec<DigestResponseParam<'a>>),
    OtherResponse(&'a [u8], Vec<(&'a [u8], &'a [u8])>)
}

#[derive(PartialEq, Debug, Clone)]
pub enum AuthenticationInfo<'a> {
    NextNonce(&'a [u8]),
    QOP(QOPValue<'a>),
    ResponseAuth(&'a [u8]),
    CNonce(&'a [u8]),
    NonceCount(&'a [u8])
}

#[derive(PartialEq, Debug, Clone)]
pub enum Priority<'a> {
    Emergency,
    Urgent,
    Normal,
    NonUrgent,
    Extension(&'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub enum ToParam<'a> {
    Tag(&'a [u8]),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct To<'a> {
    pub addr: &'a [u8],
    pub name: Option<&'a [u8]>,
    pub params: Vec<ToParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct GenericParam<'a> {
    pub name: &'a [u8],
    pub value: Option<&'a [u8]>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Route<'a> {
    pub addr: &'a [u8],
    pub name: Option<&'a [u8]>,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ReplyTo<'a> {
    pub addr: &'a [u8],
    pub name: Option<&'a [u8]>,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct RecordRoute<'a> {
    pub addr: &'a [u8],
    pub name: Option<&'a [u8]>,
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum FromParam<'a> {
    Tag(&'a [u8]),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct From<'a> {
    pub addr: &'a [u8],
    pub name: Option<&'a [u8]>,
    pub params: Vec<FromParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ContactParam<'a> {
    Q(&'a [u8]),
    Expires(i32),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Contact<'a> {
    pub addr: &'a [u8],
    pub name: Option<&'a [u8]>,
    pub params: Vec<ContactParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ContactValue<'a> {
    Any,
    Specific(Vec<Contact<'a>>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct AlertInfo<'a> {
    pub uri: &'a [u8],
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ErrorInfo<'a> {
    pub uri: &'a [u8],
    pub params: Vec<GenericParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Warning<'a> {
    pub code: &'a [u8],
    pub agent: &'a [u8],
    pub text: &'a [u8],
}

#[derive(PartialEq, Debug, Clone)]
pub enum MediaSubType<'a> {
    Any,
    IETFExtension(&'a [u8]),
    IANAExtension(&'a [u8]),
    XExtension(&'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub enum MediaType<'a> {
    Any,
    Text,
    Image,
    Audio,
    Video,
    Application,
    Message,
    Multipart,
    IETFExtension(&'a [u8]),
    XExtension(&'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub struct MediaParam<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

#[derive(PartialEq, Debug, Clone)]
pub struct Media<'a> {
    pub r#type: MediaType<'a>,
    pub subtype: MediaSubType<'a>,
    pub params: Vec<MediaParam<'a>>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum AcceptParam<'a> {
    Q(&'a [u8]),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Accept<'a> {
    pub media: Media<'a>,
    pub params: Vec<AcceptParam<'a>>
}

#[derive(PartialEq, Debug, Clone)]
pub enum ContentCoding<'a> {
    Any,
    Other(&'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Encoding<'a> {
    pub coding: ContentCoding<'a>,
    pub params: Vec<AcceptParam<'a>>
}

#[derive(PartialEq, Debug, Clone)]
pub enum LanguageRange<'a> {
    Any,
    Other(&'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub struct Language<'a> {
    pub range: LanguageRange<'a>,
    pub params: Vec<AcceptParam<'a>>
}

#[derive(PartialEq, Debug, Clone)]
pub enum DispositionType<'a> {
    Render,
    Session,
    Icon,
    Alert,
    Extension(&'a [u8]),
}

#[derive(PartialEq, Debug, Clone)]
pub enum DispositionParam<'a> {
    HandlingOptional,
    HandlingRequired,
    OtherHandling(&'a [u8]),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct ContentDisposition<'a> {
    pub disposition: DispositionType<'a>,
    pub params: Vec<DispositionParam<'a>>
}

#[derive(PartialEq, Debug, Clone)]
pub enum RetryParam<'a> {
    AvailabilityDuration(i32),
    Extension(GenericParam<'a>),
}

#[derive(PartialEq, Debug, Clone)]
pub struct RetryAfter<'a> {
    pub duration: i32,
    pub comment: Option<&'a [u8]>,
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
    CallID(&'a [u8]),
    CallInfo(Vec<Info<'a>>),
    Contact(ContactValue<'a>),
    ContentDisposition(ContentDisposition<'a>),
    ContentEncoding(Vec<&'a [u8]>),
    ContentLanguage(Vec<&'a [u8]>),
    ContentLength(&'a [u8]),
    ContentType(Media<'a>),
    CSeq(i32, Method<'a>),
    Date(&'a [u8]),
    ErrorInfo(Vec<ErrorInfo<'a>>),
    Expires(i32),
    From(From<'a>),
    Via(Vec<Via<'a>>),
    InReplyTo(Vec<&'a [u8]>),
    MaxForwards(i32),
    MIMEVersion(&'a [u8]),
    MinExpires(i32),
    Organization(Option<&'a [u8]>),
    Priority(Priority<'a>),
    ProxyAuthenticate(Challenge<'a>),
    ProxyAuthorization(Credentials<'a>),
    ProxyRequire(Vec<&'a [u8]>),
    RecordRoute(Vec<RecordRoute<'a>>),
    ReplyTo(ReplyTo<'a>),
    Require(Vec<&'a [u8]>),
    RetryAfter(RetryAfter<'a>),
    Route(Vec<Route<'a>>),
    Server(&'a [u8]),
    Subject(Option<&'a [u8]>),
    Supported(Vec<&'a [u8]>),
    Timestamp(&'a [u8], Option<&'a [u8]>),
    To(To<'a>),
    Unsupported(Vec<&'a [u8]>),
    UserAgent(&'a [u8]),
    Warning(Vec<Warning<'a>>),
    WWWAuthenticate(Challenge<'a>),
    Extension(&'a [u8], &'a [u8]),
}

#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub request_line: RequestLine<'a>,
    pub headers: Vec<Header<'a>>,
    pub body: Option<&'a [u8]>,
}

#[derive(Debug, Copy, Clone)]
pub struct Response<'a> {
    pub content: &'a [u8],
}

#[derive(Debug, Clone)]
pub enum Message<'a> {
    Request(Request<'a>),
    Response(Response<'a>),
}
