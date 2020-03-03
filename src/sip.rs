#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Version {
    Two,
    Other(i32, i32),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Transport {
    UDP,
    TCP,
    SCTP,
    TLS,
    Extension(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum User {
    Phone,
    IP,
    Other(String),
}

/// Representation of a SIP method
///
/// A SIP method informs on the request type (when it is part of a Request-Line), or what a
/// response refers to (when part of a CSeq header), or what kind of methods a server can handle
/// (when part of accept headers).
///
/// **Note**: `INFO` is not supported, but can be if there is a use for it. Patches welcome!
#[derive(PartialEq, Debug, Clone)]
pub enum Method {
    /// used to setup sessions
    Invite,

    /// used to confirm reception of a previous message
    Ack,

    /// used to query servers about their capabilities
    Options,

    /// used to tear down sessions
    Bye,

    /// used to abort a transaction, or disavow a previous message
    Cancel,

    /// used to register contact information
    Register,

    /// other extension to the SIP protocol
    Extension(String)
}
