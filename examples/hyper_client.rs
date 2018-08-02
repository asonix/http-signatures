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

extern crate futures;
extern crate http_signatures;
extern crate hyper;
extern crate tokio_core;

use std::fs::File;

use futures::{Future, Stream};
use http_signatures::prelude::*;
use http_signatures::{ShaSize, SignatureAlgorithm};
use hyper::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Client, Request};
use tokio_core::reactor::Core;

fn main() {
    let key_id = "some-username-or-something";
    let private_key = File::open("tests/assets/private.der").unwrap();

    let mut core = Core::new().unwrap();
    let client = Client::new();

    let json = r#"{"library":"hyper"}"#;
    let mut req = Request::post("http://localhost:3000")
        .body(Body::from(json))
        .unwrap();
    req.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str("application/json").unwrap(),
    );
    req.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&format!("{}", json.len())).unwrap(),
    );

    // Add the HTTP Signature
    req.with_signature_header(
        key_id.into(),
        private_key,
        SignatureAlgorithm::RSA(ShaSize::FiveTwelve),
    ).unwrap();

    let post = client.request(req).and_then(|res| {
        println!("POST: {}", res.status());

        res.into_body().concat2()
    });

    core.run(post).unwrap();
}
