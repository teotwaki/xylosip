//! # Welcome to xylosip, a memory-safe RFC3261 SIP parser
//!
//! xylosip is a SIP parser as described in [RFC3261][1]. Some parts of [RFC2806][2] and
//! [RFC2234][3] are also implemented. This project is in the early stages and should *not* be
//! considered stable.
//!
//! Parsing a SIP message in xylosip is extremely easy, for most cases, simply pass a byte-slice to
//! the `Message::parse` method and you'll get a validated message back.
//!
//! ```
//! # fn handle_sip_message(_: Message) {}
//! use xylosip::Message;
//!
//! // read the data from the network
//! let bytes = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n";
//!
//! Message::parse(bytes)
//!     // let your application handle the message
//!     .map(handle_sip_message);
//! ```
//!
//! [1]: https://tools.ietf.org/html/rfc3261
//! [2]: https://tools.ietf.org/html/rfc2806
//! [3]: https://tools.ietf.org/html/rfc2234

mod parser;
mod message;
/// contains request-related code
pub mod request;
mod response;
/// contains header-related code
pub mod header;
/// Generic data structures related to SIP
pub mod sip;

pub use message::Message;
pub use request::Request;
pub use response::Response;
