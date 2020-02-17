mod rfc2806;
mod rfc3261;

pub use rfc3261::{ sip_message };

use nom::error::ParseError;

#[derive(PartialEq, Debug)]
pub struct Error<'a, I> {
    pub kind: ErrorKind<'a, I>,
    backtrace: Vec<Error<'a, I>>
}

#[derive(PartialEq, Debug)]
pub enum ErrorKind<'a, I> {
    Nom(I, nom::error::ErrorKind),
    ParseIntError(std::num::ParseIntError),
    Utf8Error(std::str::Utf8Error),
    InvalidHostname(&'a [u8]),
    InvalidDomainPart(&'a [u8]),
    InvalidIntegerError,
    InvalidTTLValue,
}

impl<'a, I> ParseError<I> for Error<'a, I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self {
            kind: ErrorKind::Nom(input, kind),
            backtrace: Vec::new()
        }
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.backtrace.push(Self::from_error_kind(input, kind));
        other
    }
}

impl<'a, I> From<std::num::ParseIntError> for Error<'a, I> {
    fn from(error: std::num::ParseIntError) -> Self {
        Self {
            kind: ErrorKind::ParseIntError(error),
            backtrace: Vec::new()
        }
    }
}

impl<'a, I> From<std::str::Utf8Error> for Error<'a, I> {
    fn from(error: std::str::Utf8Error) -> Self {
        Self {
            kind: ErrorKind::Utf8Error(error),
            backtrace: Vec::new()
        }
    }
}

type Result<'a, I, T> = nom::IResult<I, T, Error<'a, I>>;

fn integer<T>(input: &[u8]) -> Result<&[u8], T>
   where T: atoi::FromRadix10Checked
{
    let (input, i) = nom::character::complete::digit1(input)?;

    match atoi::atoi(i) {
        Some(i) => Ok((input, i)),
        None => Err(nom::Err::Failure(Error {
            kind: ErrorKind::InvalidIntegerError,
            backtrace: Vec::new(),
        }))
    }
}
