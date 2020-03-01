use crate::request::Request;
use crate::response::Response;

#[derive(PartialEq, Debug, Clone)]
pub enum Message<'a> {
    Request(Request<'a>),
    Response(Response<'a>),
}
