mod rfc2806;
pub mod rfc3261;

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
    UnknownError,
}

impl<'a, I> Error<'a, I> {
    pub fn new(kind: ErrorKind<'a, I>) -> Self {
        Self {
            kind,
            backtrace: vec![],
        }
    }
}

impl<'a, I> ParseError<I> for Error<'a, I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self::new(ErrorKind::Nom(input, kind))
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.backtrace.push(Self::from_error_kind(input, kind));
        other
    }
}

impl<'a, I> From<std::num::ParseIntError> for Error<'a, I> {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::new(ErrorKind::ParseIntError(error))
    }
}

impl<'a, I> From<std::str::Utf8Error> for Error<'a, I> {
    fn from(error: std::str::Utf8Error) -> Self {
        Self::new(ErrorKind::Utf8Error(error))
    }
}

type Result<'a, I, T> = nom::IResult<I, T, Error<'a, I>>;

fn integer<T>(input: &[u8]) -> Result<&[u8], T>
   where T: atoi::FromRadix10Checked
{
    let (input, i) = nom::character::complete::digit1(input)?;

    match atoi::atoi(i) {
        Some(i) => Ok((input, i)),
        None => Err(nom::Err::Failure(
            Error::new(ErrorKind::InvalidIntegerError)
        ))
    }
}
