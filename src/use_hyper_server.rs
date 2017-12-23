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

use hyper::header::Authorization;
use hyper::server::Request;

use verify::{AuthorizationHeader, VerifyAuthorizationHeader, GetKey};
use error::VerificationError;

impl VerifyAuthorizationHeader for Request {
    fn verify_authorization_header<G: GetKey>(
        &self,
        key_getter: G,
    ) -> Result<(), VerificationError> {
        let &Authorization(ref auth_header) = self.headers().get::<Authorization<String>>().ok_or(
            VerificationError::HeaderNotPresent,
        )?;

        let auth_header = AuthorizationHeader::new(auth_header)?;

        let headers: Vec<(&str, String)> = self.headers()
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
            &self.method().as_ref().to_lowercase(),
            self.path(),
            self.query(),
            key_getter,
        )
    }
}
