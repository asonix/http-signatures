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

//! This module defines useful traits for using HTTP Signatures.

use std::io::Read;

use super::SignatureAlgorithm;
use create::HttpSignature;
use error::{Error, VerificationError};

/// `AsHttpSignature` defines a trait for getting an Authorization or Signature Header string from
/// any type that implements it. It provides three methods: `as_http_signature`, which implementors
/// must define, and `authorization_header` and `signature_header`, which use `as_http_signature`
/// to create the header string.
pub trait AsHttpSignature<T>
where
    T: Read,
{
    /// Gets an `HttpSignature` struct from an immutably borrowed Self
    fn as_http_signature(
        &self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<HttpSignature<T>, Error>;

    /// Generates the Authorization Header from an immutably borrowed Self
    fn authorization_header(
        &self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<String, Error> {
        Ok(self
            .as_http_signature(key_id, key, algorithm)?
            .authorization_header()?)
    }

    /// Generates the Signature Header from an immutably borrowed Self
    fn signature_header(
        &self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<String, Error> {
        Ok(self
            .as_http_signature(key_id, key, algorithm)?
            .signature_header()?)
    }
}

/// `WithHttpSignature` defines a trait for adding Authorization and Signature headers to another
/// library's request or response object.
pub trait WithHttpSignature<T>: AsHttpSignature<T>
where
    T: Read,
{
    fn with_authorization_header(
        &mut self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<&mut Self, Error>;

    fn with_signature_header(
        &mut self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<&mut Self, Error>;
}

/// The `GetKey` trait is used during HTTP Signature verification to access the required decryption
/// key based on a given `key_id`.
///
/// The `key_id` is provided in the Authorization or Signature header of the request as `KeyId`.
///
/// ### Example
/// ```rust
/// # use std::io::Cursor;
/// # use std::collections::HashMap;
/// use http_signatures::prelude::*;
///
/// struct MyKeyGetter {
///     keys: HashMap<String, Vec<u8>>,
/// }
///
/// impl MyKeyGetter {
///     pub fn new() -> Self {
///         MyKeyGetter {
///             keys: HashMap::new(),
///         }
///     }
///
///     pub fn add_key(&mut self, key_id: String, key: Vec<u8>) {
///         self.keys.insert(key_id, key);
///     }
/// }
///
/// impl GetKey for MyKeyGetter {
///     type Key = Cursor<Vec<u8>>;
///     type Error = ();
///
///     fn get_key(self, key_id: &str) -> Result<Self::Key, Self::Error> {
///         self.keys.get(key_id).map(|key| Cursor::new(key.clone())).ok_or(())
///     }
/// }
///
/// # fn run() -> Result<(), ()> {
/// let mut key_getter = MyKeyGetter::new();
/// key_getter.add_key("key-1".into(), vec![1, 2, 3, 4, 5]);
///
/// key_getter.get_key("key-1")?;
/// # Ok(())
/// # }
/// ```
pub trait GetKey {
    type Key: Read;
    type Error;

    fn get_key(self, key_id: &str) -> Result<Self::Key, Self::Error>;
}

/// The `VerifyHeader` trait is meant to be implemented for the request types from
/// http libraries (such as Hyper and Rocket). This trait makes verifying requests much easier,
/// since the `verify_authorization_header()` and `verify_signature_header()` methods can be called
/// directly on a Request type.
///
/// For examples, see the
/// [hyper server](https://github.com/asonix/http-signatures/blob/master/examples/hyper_server.rs)
/// and [rocket](https://github.com/asonix/http-signatures/blob/master/examples/rocket.rs) files.
pub trait VerifyHeader {
    fn verify_signature_header<G: GetKey>(&self, key_getter: G) -> Result<(), VerificationError>;

    fn verify_authorization_header<G: GetKey>(
        &self,
        key_getter: G,
    ) -> Result<(), VerificationError>;
}
