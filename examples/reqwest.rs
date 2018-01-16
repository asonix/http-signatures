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

extern crate http_signatures;
extern crate reqwest;

use std::fs::File;

use reqwest::Client;
use http_signatures::prelude::*;
use http_signatures::{ShaSize, SignatureAlgorithm};

fn main() {
    let key_id = "some-username-or-something".into();
    let private_key = File::open("tests/assets/private.der").unwrap();

    let client = Client::new();
    let mut req = client.get("http://localhost:8000").build().unwrap();

    req.with_authorization_header(
        key_id,
        private_key,
        SignatureAlgorithm::RSA(ShaSize::FiveTwelve),
    ).unwrap();

    let res = client.execute(req).unwrap();
    println!("GET: {}", res.status());
}
