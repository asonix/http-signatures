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

//! This module defines `VerifyHeader` for `hyper::server::Request`.
//!
//! This allows easy verification of incomming requests in Hyper.
//!
//! See
//! [this example](https://github.com/asonix/http-signatures/blob/master/examples/hyper_server.rs)
//! for usage information.

use std::str::from_utf8;

use hyper::header::Authorization;
use hyper::server::Request;

use verify::{SignedHeader, VerifyHeader, GetKey};
use error::VerificationError;

impl VerifyHeader for Request {
    fn verify_signature_header<G: GetKey>(&self, key_getter: G) -> Result<(), VerificationError> {
        let auth_header = self.headers()
            .get_raw("Signature")
            .ok_or(VerificationError::HeaderNotPresent)?
            .one()
            .ok_or(VerificationError::HeaderNotPresent)?;

        verify_header(self, from_utf8(auth_header)?, key_getter)
    }

    fn verify_authorization_header<G: GetKey>(
        &self,
        key_getter: G,
    ) -> Result<(), VerificationError> {
        let &Authorization(ref auth_header) = self.headers().get::<Authorization<String>>().ok_or(
            VerificationError::HeaderNotPresent,
        )?;

        verify_header(self, auth_header, key_getter)
    }
}

fn verify_header<G>(req: &Request, header: &str, key_getter: G) -> Result<(), VerificationError>
where
    G: GetKey,
{
    let auth_header = SignedHeader::new(header)?;

    let headers: Vec<(&str, String)> = req.headers()
        .iter()
        .map(|header_view| {
            (header_view.name(), header_view.value_string())
        })
        .collect();

    let headers_borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|&(key, ref val)| (key, val.as_ref()))
        .collect();

    auth_header.verify(
        headers_borrowed.as_ref(),
        &req.method().as_ref().to_lowercase(),
        req.path(),
        req.query(),
        key_getter,
    )
}
