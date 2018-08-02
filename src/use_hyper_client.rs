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

//! Available with the `use_hyper` feature. This modulde defines the `AsHttpSignature` and
//! `WithHttpSignature` traits for `hyper::Request`.
//!
//! This is useful for interacting with HTTP Signatures from Hyper-based applications, since it can
//! automatically generate signatures and add them to requests.
//!
//! # Example generating a signature
//! This example shows getting an `HttpSignature` type from a `hyper::Request`. Typically you
//! wouldn't want to do this directly, you'd use `with_authorization_header` or
//! `with_signature_header` directly, but in the event you want the intermediate state, this is
//! available.
//!
//! ```rust
//! # #![feature(try_from)]
//! # extern crate hyper;
//! # extern crate http_signatures;
//! #
//! # use std::convert::TryInto;
//! # use std::error::Error;
//! # use std::fs::File;
//! #
//! # use http_signatures::prelude::*;
//! # use http_signatures::{ShaSize, SignatureAlgorithm};
//! # use hyper::{Method, Request};
//! #
//! # fn run() -> Result<(), Box<Error>> {
//! let key = File::open("tests/assets/private.der")?;
//! let uri = "https://example.com";
//! let alg = SignatureAlgorithm::RSA(ShaSize::TwoFiftySix);
//!
//! let req = Request::post(uri)
//!     .body(()).unwrap();
//!
//! let http_sig = req.as_http_signature("rsa-key-1".into(), key, alg)?;
//! #     Ok(())
//! # }
//! # fn main() {
//! #     run().unwrap();
//! # }
//! ```
//!
//! # Example adding a signature to a Request type
//!
//! This example adds the HTTP Signature to the request directly as an Authorization header.
//! `with_signature_header` can be used to add the signature as a Signature header instead.
//!
//! ```rust
//! # extern crate hyper;
//! # extern crate http_signatures;
//! #
//! # use std::error::Error;
//! # use std::fs::File;
//! #
//! # use http_signatures::prelude::*;
//! # use http_signatures::{ShaSize, SignatureAlgorithm};
//! # use hyper::{Method, Request};
//! #
//! # fn run() -> Result<(), Box<Error>> {
//! let key = File::open("tests/assets/private.der")?;
//! let uri = "https://example.com";
//! let alg = SignatureAlgorithm::RSA(ShaSize::TwoFiftySix);
//!
//! let mut req: Request<_> = Request::post(uri)
//!     .body(()).unwrap();
//!
//! req.with_authorization_header("rsa-key-1".into(), key, alg)?;
//! #     Ok(())
//! # }
//! # fn main() {
//! #     run().unwrap();
//! # }
//! ```
//!
//! See
//! [this example](https://github.com/asonix/http-signatures/blob/master/examples/hyper_client.rs)
//! for more information.

use std::collections::BTreeMap;
use std::io::Read;

use super::{SignatureAlgorithm, REQUEST_TARGET};
use create::HttpSignature;
use error::{CreationError, Error};
use prelude::*;

use hyper::header::HeaderValue;
use hyper::Request as HyperRequest;

/// An implementation of `AsHttpSignature` for `hyper::Request`.
///
/// This trait is not often used directly, but is required by the `WithHttpSignature` trait defined
/// below.
impl<T, B> AsHttpSignature<T> for HyperRequest<B>
where
    T: Read,
{
    fn as_http_signature(
        &self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<HttpSignature<T>, Error> {
        let mut headers = BTreeMap::new();
        headers.insert(
            REQUEST_TARGET.into(),
            vec![if let Some(query) = self.uri().query() {
                format!(
                    "{} {}?{}",
                    self.method().as_ref().to_lowercase(),
                    self.uri().path(),
                    query
                )
            } else {
                format!(
                    "{} {}",
                    self.method().as_ref().to_lowercase(),
                    self.uri().path()
                )
            }],
        );

        let headers =
            self.headers()
                .iter()
                .fold(headers, |mut acc, (header_name, header_value)| {
                    let _ = header_value.to_str().map(|header_value| {
                        acc.entry(header_name.as_str().to_string())
                            .or_insert_with(Vec::new)
                            .push(header_value.to_string())
                    });
                    acc
                });

        HttpSignature::new(key_id, key, algorithm, headers).map_err(Error::from)
    }
}

/// An implementation of `WithHttpSignature` for `hyper::Request`
///
/// This automatically adds an Authorization header to a given `hyper::Request` struct containing
/// an HTTP Signature.
///
/// See
/// [this example](https://github.com/asonix/http-signatures/blob/master/examples/hyper_client.rs)
/// for usage information.
impl<T, B> WithHttpSignature<T> for HyperRequest<B>
where
    T: Read,
{
    fn with_authorization_header(
        &mut self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<&mut Self, Error> {
        use hyper::header::AUTHORIZATION;

        let auth_header = self.authorization_header(key_id, key, algorithm)?;
        let header = HeaderValue::from_str(&auth_header).or(Err(CreationError::NoHeaders))?;
        self.headers_mut().insert(AUTHORIZATION, header);

        Ok(self)
    }

    fn with_signature_header(
        &mut self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<&mut Self, Error> {
        let sig_header = self.signature_header(key_id, key, algorithm)?;
        let header = HeaderValue::from_str(&sig_header).or(Err(CreationError::NoHeaders))?;
        self.headers_mut().insert("Signature", header);

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::fs::File;

    use hyper::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE, DATE, HOST};
    use hyper::{Request, Uri};

    use create::SigningString;
    use prelude::*;
    use ShaSize;
    use SignatureAlgorithm;

    /* Request used for all tests:
     *
     * POST /foo HTTP/1.1
     * Host: example.org
     * Date: Tue, 07 Jun 2014 20:51:35 GMT
     * Content-Type: application/json
     * Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
     * Content-Length: 18
     *
     * {"hello": "world"}
     */

    const KEY_ID: &'static str = "rsa-key-1";
    const ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::RSA(ShaSize::TwoFiftySix);
    const PRIVATE_KEY_PATH: &'static str = "tests/assets/private.der";

    #[test]
    fn min_test() {
        let uri: Uri = "http://example.org/foo".parse().unwrap();
        let req = Request::post(uri).body(()).unwrap();

        test_request(req, "(request-target): post /foo");
    }

    #[test]
    fn full_test() {
        let uri: Uri = "http://example.org/foo".parse().unwrap();
        let body = r#"{"hello": "world"}"#;
        let mut req = Request::post(uri).body(body).unwrap();

        req.headers_mut()
            .insert(HOST, HeaderValue::from_str("example.org").unwrap());
        req.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str("application/json").unwrap(),
        );
        req.headers_mut().insert(
            "Digest",
            HeaderValue::from_str("SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=").unwrap(),
        );
        req.headers_mut().insert(
            DATE,
            HeaderValue::from_str("Tue, 07 Jun 2014 20:51:35 GMT").unwrap(),
        );
        req.headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_str("18").unwrap());

        test_request(
            req,
            "(request-target): post /foo
content-length: 18
content-type: application/json
date: Tue, 07 Jun 2014 20:51:35 GMT
digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
host: example.org",
        )
    }

    fn test_request<B>(req: Request<B>, s: &str) {
        let key = File::open(PRIVATE_KEY_PATH).unwrap();

        let http_sig = req
            .as_http_signature(KEY_ID.into(), key, ALGORITHM)
            .unwrap();

        let signing_string: SigningString<File> = http_sig.try_into().unwrap();

        assert_eq!(signing_string.signing_string, s);
    }
}
