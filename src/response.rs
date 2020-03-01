#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Response<'a> {
    pub content: &'a str,
}
