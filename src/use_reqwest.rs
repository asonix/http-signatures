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

//! Available with the `use_reqwest` feature. This module defines `AsHttpSignature` and
//! `WithHttpSignature` for `reqwest::Request`.
//!
//! # Example adding a signature to a request
//!
//! This example adds the HTTP Signature to the request directly as an Authorization header.
//! `with_signature_header` can be used to add the signature as a Signature header instead.
//!
//! ```rust
//! # extern crate reqwest;
//! # extern crate http_signatures;
//! #
//! # use std::error::Error;
//! # use std::fs::File;
//! #
//! # use http_signatures::prelude::*;
//! # use http_signatures::{ShaSize, SignatureAlgorithm};
//! # use reqwest::Client;
//! #
//! # fn run() -> Result<(), Box<Error>> {
//! let key = File::open("tests/assets/private.der")?;
//! let alg = SignatureAlgorithm::RSA(ShaSize::TwoFiftySix);
//!
//! let client = Client::new();
//! let mut req = client.get("https://example.com").build()?;
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
//! [this example](https://github.com/asonix/http-signatures/blob/master/examples/reqwest.rs)
//! for more usage information.

use std::collections::BTreeMap;
use std::io::Read;

use super::{SignatureAlgorithm, REQUEST_TARGET};
use create::HttpSignature;
use error::Error;
use prelude::*;

use reqwest::Request as ReqwestRequest;

impl<T> AsHttpSignature<T> for ReqwestRequest
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
            vec![if let Some(query) = self.url().query() {
                format!(
                    "{} {}?{}",
                    self.method().as_ref().to_lowercase(),
                    self.url().path(),
                    query
                )
            } else {
                format!(
                    "{} {}",
                    self.method().as_ref().to_lowercase(),
                    self.url().path()
                )
            }],
        );

        let headers = self.headers().iter().fold(headers, |mut acc, header_view| {
            acc.entry(header_view.name().into())
                .or_insert_with(Vec::new)
                .push(header_view.value_string());

            acc
        });

        HttpSignature::new(key_id, key, algorithm, headers).map_err(Error::from)
    }
}

impl<T> WithHttpSignature<T> for ReqwestRequest
where
    T: Read,
{
    fn with_authorization_header(
        &mut self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<&mut Self, Error> {
        use reqwest::header::Authorization;

        let auth_header = self.authorization_header(key_id, key, algorithm)?;
        self.headers_mut().set(Authorization(auth_header));

        Ok(self)
    }

    fn with_signature_header(
        &mut self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<&mut Self, Error> {
        let sig_header = self.signature_header(key_id, key, algorithm)?;
        self.headers_mut().set_raw("Signature", sig_header);

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::fs::File;
    use std::str::FromStr;

    use reqwest::header::{ContentLength, ContentType, Date, Headers, Host, HttpDate};
    use reqwest::{Client, Request};

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
        let uri = "http://example.org/foo";
        let req = Client::new().post(uri).build().unwrap();

        test_request(req, "(request-target): post /foo");
    }

    #[test]
    fn full_test() {
        let uri = "http://example.org/foo";

        let mut headers = Headers::new();

        headers.set(Host::new("example.org", None));
        headers.set(ContentType::json());
        headers.set_raw(
            "Digest",
            "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
        );
        headers.set(Date(
            HttpDate::from_str("Tue, 07 Jun 2014 20:51:35 GMT").unwrap(),
        ));
        headers.set(ContentLength(18));

        let req = Client::new()
            .post(uri)
            .headers(headers)
            .body(r#"{"hello": "world"}"#)
            .build()
            .unwrap();

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

    fn test_request(req: Request, s: &str) {
        let key = File::open(PRIVATE_KEY_PATH).unwrap();

        let http_sig = req
            .as_http_signature(KEY_ID.into(), key, ALGORITHM)
            .unwrap();

        let signing_string: SigningString<File> = http_sig.try_into().unwrap();

        assert_eq!(signing_string.signing_string, s);
    }
}
