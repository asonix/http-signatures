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

//! This module defines `VerifyHeader` for `rocket::Request`.
//!
//! This allows easy verification of incomming requests in Rocket, and can be used with Request
//! guards.
//!
//! See
//! [this example](https://github.com/asonix/http-signatures/blob/master/examples/rocket.rs)
//! for usage information.

use rocket::Request;

use verify::{SignedHeader, VerifyHeader, GetKey};
use error::VerificationError;

impl<'r> VerifyHeader for Request<'r> {
    fn verify_signature_header<G: GetKey>(&self, key_getter: G) -> Result<(), VerificationError> {
        verify_header(self, "Signature", key_getter)
    }

    fn verify_authorization_header<G: GetKey>(
        &self,
        key_getter: G,
    ) -> Result<(), VerificationError> {
        verify_header(self, "Authorization", key_getter)
    }
}

fn verify_header<'r, G>(
    req: &Request<'r>,
    header: &str,
    key_getter: G,
) -> Result<(), VerificationError>
where
    G: GetKey,
{
    let auth_header = req.headers().get_one(header).ok_or(
        VerificationError::HeaderNotPresent,
    )?;

    let auth_header = SignedHeader::new(auth_header)?;

    let headers: Vec<(String, String)> = req.headers()
        .iter()
        .map(|header| (header.name().into(), header.value().into()))
        .collect();

    let headers_borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|&(ref key, ref val)| (key.as_ref(), val.as_ref()))
        .collect();

    auth_header.verify(
        headers_borrowed.as_ref(),
        req.method().as_str(),
        req.uri().path(),
        req.uri().query(),
        key_getter,
    )
}
