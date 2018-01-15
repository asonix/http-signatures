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

extern crate hyper;
extern crate futures;
extern crate tokio_core;
extern crate http_signatures;

use std::fs::File;

use tokio_core::reactor::Core;
use hyper::{Client, Method, Request};
use hyper::header::{ContentLength, ContentType};
use futures::{Future, Stream};
use http_signatures::{WithHttpSignature, SignatureAlgorithm, ShaSize};

fn main() {
    let key_id = "some-username-or-something";
    let private_key = File::open("tests/assets/private.der").unwrap();

    let mut core = Core::new().unwrap();
    let client = Client::new(&core.handle());

    let json = r#"{"library":"hyper"}"#;
    let mut req = Request::new(Method::Post, "http://localhost:3000".parse().unwrap());
    req.headers_mut().set(ContentType::json());
    req.headers_mut().set(ContentLength(json.len() as u64));
    req.set_body(json);

    // Add the HTTP Signature
    req.with_signature_header(
        key_id.into(),
        private_key,
        SignatureAlgorithm::RSA(ShaSize::FiveTwelve),
    ).unwrap();

    let post = client.request(req).and_then(|res| {
        println!("POST: {}", res.status());

        res.body().concat2()
    });

    core.run(post).unwrap();
}
