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

use std::io::Error as IoError;

#[derive(Debug)]
pub enum Error {
    IO(IoError),
    NoHeaders,
    SigningError,
    BadPrivateKey,
    Unknown,
}

impl From<IoError> for Error {
    fn from(e: IoError) -> Self {
        Error::IO(e)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    MissingKey(&'static str),
    InvalidAlgorithm(String),
    NotBase64,
    Unknown,
}

#[derive(Debug)]
pub enum VerificationError {
    Decode(DecodeError),
    MissingHeaders(String),
    GetKey,
    ReadKey,
    BadSignature,
    HeaderNotPresent,
    Unknown,
}

impl From<DecodeError> for VerificationError {
    fn from(d: DecodeError) -> Self {
        VerificationError::Decode(d)
    }
}
