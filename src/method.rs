#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Method<'a> {
    Invite,
    Ack,
    Options,
    Bye,
    Cancel,
    Register,
    Extension(&'a str)
}
