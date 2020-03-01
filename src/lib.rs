#![warn(missing_docs)]

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
//! use xylosip::Message;
//!
//! let bytes = b"INVITE sip:bob@biloxi.example.com SIP/2.0\r\n";
//! let msg = Message::parse(bytes)?;
//!
//! // pass the parsed message to your application
//! handle_sip_message(msg)?;
//! ```
//!
//! [1]: https://tools.ietf.org/html/rfc3261
//! [2]: https://tools.ietf.org/html/rfc2806
//! [3]: https://tools.ietf.org/html/rfc2234

mod parser;
mod message;
mod request;
mod response;
pub mod header;
mod method;

pub use message::Message;
pub use request::Request;
pub use response::Response;
pub use method::Method;
