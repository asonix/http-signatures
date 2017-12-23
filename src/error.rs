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

use std::io::Error as IoError;

/// The root Error
#[derive(Debug)]
pub enum Error {
    /// Problems opening files and such
    IO(IoError),
    /// Problems verifying a request
    Verification(VerificationError),
    /// Problems creating a signature
    Creation(CreationError),
    /// Unknown error occurred
    Unknown,
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

/// When decoding a signature doesn't work
#[derive(Debug)]
pub enum DecodeError {
    /// A required key is missing
    MissingKey(&'static str),
    /// The signature algorithm is not supported
    InvalidAlgorithm(String),
    /// The key was not properly encoded to base64
    NotBase64,
}

/// When a request cannot be verified
#[derive(Debug)]
pub enum VerificationError {
    /// Issues decoding a signature
    Decode(DecodeError),
    /// Headers present in the `headers` field are missing from the request
    MissingHeaders(String),
    /// When the `get_key` method from the `GetKey` type fails
    GetKey,
    /// Problems reading the required keys
    ReadKey,
    /// Problems verifying the signature
    BadSignature,
    /// When the Authorization header is missing
    HeaderNotPresent,
    /// When we're not sure what went wrong
    Unknown,
}

impl From<DecodeError> for VerificationError {
    fn from(d: DecodeError) -> Self {
        VerificationError::Decode(d)
    }
}
