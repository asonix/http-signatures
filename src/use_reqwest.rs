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

use std::io::Read;
use std::collections::HashMap;

use error::Error;
use super::{SignatureAlgorithm, REQUEST_TARGET};
use create::{AsHttpSignature, WithHttpSignature, HttpSignature};

use reqwest::Request as ReqwestRequest;

/// An implementation of `AsHttpSignature` for `reqwest::Request`.
///
/// This trait is not often used directly, but is required by the `WithHttpSignature` trait defined
/// below.
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
        let mut headers = HashMap::new();
        headers.insert(
            REQUEST_TARGET.into(),
            vec![
                if let Some(ref query) = self.url().query() {
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
                },
            ],
        );

        let headers = self.headers().iter().fold(headers, |mut acc, header_view| {
            acc.entry(header_view.name().into())
                .or_insert(Vec::new())
                .push(header_view.value_string());

            acc
        });

        HttpSignature::new(key_id, key, algorithm, headers).map_err(Error::from)
    }
}

/// An implementation of `WithHttpSignature` for `reqwest::Request`
///
/// This automatically adds an Authorization header to a given `reqwest::Request` struct containing
/// an HTTP Signature.
///
/// See [https://github.com/asonix/http-signatures/blob/master/examples/reqwest.rs](this
/// example) for usage information.
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
