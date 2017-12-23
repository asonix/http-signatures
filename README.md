# HTTP Signatures

This crate is used to create and verify HTTP Signatures, defined [here](https://tools.ietf.org/html/draft-cavage-http-signatures-09). It has support for Hyper and Reqwest types, although currently these adapters have not been tested. In the future, I plan on supporting Rocket's request guards, and possibly an Iron middleware for verification.

### Usage
#### With Hyper
Add this to your `Cargo.toml`
```toml
[dependencies.http-signatures]
version = "0.1"
features = ["use_hyper"]
```
In your code, use it when building a request as follows.

```rust
extern crate hyper;
extern crate tokio_core;
extern crate http_signatures;

use tokio_core::reactor::Core;
use hyper::{Client, Method, Request};
use http_signatures::{WithHttpRequest, SignatureAlgorithm, ShaSize};

let key_id = "some-username-or-something";
let private_key = File.open("some-public-key.der")?;

let mut core = Core::new()?;
let client = Client::new(&core.handle());

let mut req = Request::new(Method::Post, "https://example.com");
req.headers_mut().set(ContentType::json());
req.headers_mut().set(ContentLength(json.len() as u64));

// Add the HTTP Signature
req.with_http_signature(key_id.into(), private_key, SignatureAlgorithm::RSA(ShaSize::FiveTwelve))?;

req.set_body(json);

let post = client.request(req).and_then(|res| {
    println!("POST: {}", res.status());

    res.body().concat2()
});

core.run(post);
```
#### With Reqwest
Add this to your `Cargo.toml`
```toml
[dependencies.http-signatures]
version = "0.1"
features = ["use_reqwest"]
```
In your code, use it when building a request as follows.

```rust
extern crate reqwest;
extern crate http_signatures;

use reqwest::Client;
use http_signatures::{WithHttpRequest, SignatureAlgorithm, ShaSize};

let key_id = "some-username-or-something".into();
let private_key = File.open("some-public-key.der")?;

let client = Client::new();
let req = client.post("https://example.com")
    .body("Some Body")
    .with_http_signature(key_id, private_key, SignatureAlgorithm::RSA(ShaSize::FiveTwelve))?;

client::execute(req)?;
```

### License
HTTP Signatures is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

HTTP Signatures is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. This file is part of HTTP Signatures

You should have received a copy of the GNU General Public License along with HTTP Signatures If not, see http://www.gnu.org/licenses/.
