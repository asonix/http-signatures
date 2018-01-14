// This file is part of HTTP Signatures

// HTTP Signatures is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// HTTP Signatures is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with HTTP Signatures  If not, see <http://www.gnu.org/licenses/>.

//! This module defines the Error types for http_signatures.

use std::error::Error as StdError;
use std::fmt;
use std::io::Error as IoError;
use std::str::Utf8Error;

/// The root Error
#[derive(Debug)]
pub enum Error {
    /// Problems opening files and such
    IO(IoError),
    /// Problems verifying a request
    Verification(VerificationError),
    /// Problems creating a signature
    Creation(CreationError),
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IO(e)
    }
}

impl From<VerificationError> for Error {
    fn from(e: VerificationError) -> Self {
        Error::Verification(e)
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Self {
        VerificationError::Decode(e).into()
    }
}

impl From<CreationError> for Error {
    fn from(e: CreationError) -> Self {
        Error::Creation(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IO(ref ie) => write!(f, "{}", ie),
            Error::Verification(ref ve) => write!(f, "{}", ve),
            Error::Creation(ref ce) => write!(f, "{}", ce),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IO(ref ie) => ie.description(),
            Error::Verification(ref ve) => ve.description(),
            Error::Creation(ref ce) => ce.description(),
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            Error::IO(ref ie) => Some(ie),
            Error::Verification(ref ve) => Some(ve),
            Error::Creation(ref ce) => Some(ce),
        }
    }
}

/// When creating a signature doesn't work
#[derive(Debug)]
pub enum CreationError {
    /// Problems reading keys
    IO(IoError),
    /// Headers must be provided to sign a request
    NoHeaders,
    /// An error occurred when signing the request
    SigningError,
    /// An error occurred when interacting with an RSA key
    BadPrivateKey,
}

impl From<IoError> for CreationError {
    fn from(e: IoError) -> Self {
        CreationError::IO(e)
    }
}

impl fmt::Display for CreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CreationError::IO(ref io) => write!(f, "{}, {}", self.description(), io),
            _ => write!(f, "{}", self.description()),
        }
    }
}

impl StdError for CreationError {
    fn description(&self) -> &str {
        match *self {
            CreationError::IO(_) => "Signature creation: Error reading keys",
            CreationError::NoHeaders => "Signature creation: Must provide at least one header",
            CreationError::SigningError => "Signature creation: Error signing",
            CreationError::BadPrivateKey => "Signature creation: Provided private key is invalid",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            CreationError::IO(ref ie) => Some(ie),
            _ => None,
        }
    }
}

/// When decoding a signature doesn't work
#[derive(Clone, Debug)]
pub enum DecodeError {
    /// A required key is missing
    MissingKey(&'static str),
    /// The signature algorithm is not supported
    InvalidAlgorithm(String),
    /// The key was not properly encoded to base64
    NotBase64,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::MissingKey(ref mk) => write!(f, "Missing key: {}", mk),
            DecodeError::InvalidAlgorithm(ref ia) => write!(f, "Invalid Algorithm: {}", ia),
            _ => write!(f, "{}", self.description()),
        }
    }
}

impl StdError for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::MissingKey(_) => "Decoding: Missing key",
            DecodeError::InvalidAlgorithm(_) => "Decoding: Provided algorithm is not supported",
            DecodeError::NotBase64 => "Decoding: Provided signature is not base64 encoded",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            _ => None,
        }
    }
}

/// When a request cannot be verified
#[derive(Clone, Debug)]
pub enum VerificationError {
    /// Issues decoding a signature
    Decode(DecodeError),
    /// Headers present in the `headers` field are missing from the request
    MissingHeaders(String),
    /// Problems reading headers
    Utf8(Utf8Error),
    /// When the `get_key` method from the `GetKey` type fails
    GetKey,
    /// Problems reading the required keys
    ReadKey,
    /// Problems verifying the signature
    BadSignature,
    /// When the Authorization header is missing
    HeaderNotPresent,
}

impl From<Utf8Error> for VerificationError {
    fn from(e: Utf8Error) -> Self {
        VerificationError::Utf8(e)
    }
}

impl From<DecodeError> for VerificationError {
    fn from(d: DecodeError) -> Self {
        VerificationError::Decode(d)
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VerificationError::Decode(ref de) => write!(f, "Verification: {}", de),
            VerificationError::MissingHeaders(ref mh) => write!(f, "{}, {}", self.description(), mh),
            VerificationError::Utf8(ref ue) => write!(f, "Verification: reading headers: {}", ue),
            _ => write!(f, "{}", self.description()),
        }
    }
}

impl StdError for VerificationError {
    fn description(&self) -> &str {
        match *self {
            VerificationError::Decode(ref de) => de.description(),
            VerificationError::MissingHeaders(_) => "Verification: Headers provided in headers field are not present in the request",
            VerificationError::Utf8(ref ue) => ue.description(),
            VerificationError::GetKey => "Verification: Error getting key",
            VerificationError::ReadKey => "Verification: Error reading key",
            VerificationError::BadSignature => "Verification: Bad signature",
            VerificationError::HeaderNotPresent => "Verification: Header missing",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            VerificationError::Decode(ref de) => Some(de),
            VerificationError::Utf8(ref ue) => Some(ue),
            _ => None,
        }
    }
}
