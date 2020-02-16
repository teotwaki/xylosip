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

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Header<'a> {
    Accept,
    AcceptEncoding,
    AcceptLanguage,
    AlertInfo,
    AuthenticationInfo,
    Authorization,
    CallID,
    CallInfo,
    Contact,
    ContentDisposition,
    ContentEncoding,
    ContentLanguage,
    ContentLength,
    ContentType,
    CSeq,
    Date,
    ErrorInfo,
    Expires,
    From,
    Via,
    InReplyTo,
    MaxForwards,
    MIMEVersion,
    MinExpires,
    Organization,
    Priority,
    ProxyAuthenticate,
    ProxyAuthorization,
    ProxyRequire,
    RecordRoute,
    ReplyTo,
    Require,
    RetryAfter,
    Route,
    Server,
    Subject,
    Supported,
    Timestamp,
    To,
    Unsupported,
    UserAgent,
    Warning,
    WWWAuthenticate,
    Extension(&'a [u8], &'a [u8]),
}

#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub request_line: RequestLine<'a>,
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
