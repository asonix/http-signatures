# HTTP Signatures

This crate is used to create and verify HTTP Signatures, defined [here](https://tools.ietf.org/html/draft-cavage-http-signatures-09). It has support for Hyper, Rocket, and Reqwest types. In the future, I might also support Iron middleware for verification.

[crates.io](https://crates.io/crates/http-signatures) [documentation](https://asonix.github.io/http-signatures/http_signatures/index.html)

### Running the examples
Since this crate is built to modularly require dependencies, running the examples is not as straightforward as for other projects.  To run `hyper_server` and `hyper_client`, the proper commands are
```bash
cargo run --example hyper_server --features use_hyper
```
and
```bash
cargo run --example hyper_client --features use_hyper
```
The hyper examples are configured to talk to eachother by default. The server runs on port 3000, and the client POSTs on port 3000. They also use the `Signature` header to sign and verify the request.
The rocket server
```bash
cargo run --example rocket --features use_rocket
```
runs on port 8000, and the reqwest client 
```bash
cargo run --example reqwest --features use_reqwest
```
GETs on port 8000. These examples use the `Authorization` header to sign and verify the request.

### Usage
#### With Hyper
Add this to your `Cargo.toml`
```toml
[dependencies.http-signatures]
version = "0.2"
default-features = false
features = ["use_hyper"]
```
##### Client
Use it when building a request as follows.
```rust
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
```
##### Server
This is a very basic example server outline that should give you a general idea of how to set up a Hyper server that verifies HTTP Signatures. This is not meant to be code that actually works.
```rust
#[derive(Debug)]
enum Error {
    FileError,
}

#[derive(Clone)]
struct MyKeyGetter {
    key: Vec<u8>,
}

impl MyKeyGetter {
    fn new(filename: &str) -> Result<Self, Error> {
        let mut key = Vec::new();
        std::fs::File::open(filename)
            .map_err(|_| Error::FileError)?
            .read_to_end(&mut key)
            .map_err(|_| Error::FileError)?;

        Ok(MyKeyGetter { key })
    }
}

impl<'a> GetKey for &'a MyKeyGetter {
    type Key = Cursor<Vec<u8>>;
    type Error = Error;

    fn get_key(self, _key_id: &str) -> Result<Self::Key, Self::Error> {
        Ok(Cursor::new(self.key.clone()))
    }
}

const PHRASE: &str = "Hewwo, Mr. Obama???";

fn main() {
    let key_getter_arc = Arc::new(MyKeyGetter::new("tests/assets/public.der").unwrap());
    let service = move || {
        let key_getter = key_getter_arc.clone();
        service_fn(move |req: Request<Body>| {
            let verified = req.verify_signature_header(&*key_getter);

            verified
                .into_future()
                .map_err(|e| format!("{:?}", e))
                .and_then(|_| {
                    println!("Succesfully verified request!");
                    Response::builder()
                        .header(CONTENT_LENGTH, PHRASE.len() as u64)
                        .body(Body::from(PHRASE))
                        .map_err(|e| format!("{:?}", e))
                })
        })
    };

    let addr = "127.0.0.1:3000".parse().unwrap();
    let server = Server::bind(&addr)
        .serve(service)
        .map_err(|e| eprintln!("server error: {}", e));
    rt::run(server);
}
```
#### With Reqwest
Add this to your `Cargo.toml`
```toml
[dependencies.http-signatures]
version = "0.1"
default-features = false
features = ["use_reqwest"]
```
In your code, use it when building a request as follows.

```rust
let key_id = "some-username-or-something".into();
let private_key = File::open("test/assets/private.der").unwrap();

let client = Client::new();
let mut req = client
    .post("http://localhost:3000")
    .body("Some Body")
    .build()
    .unwrap();

req.with_authorization_header(
    key_id,
    private_key,
    SignatureAlgorithm::RSA(ShaSize::FiveTwelve),
).unwrap();

client.execute(req).unwrap();
```
#### With Rocket
Add this to your `Cargo.toml`
```toml
[dependencies.http-signatures]
version = "0.1"
default-features = false
features = ["use_rocket"]
```
In your code, use it in a route like so
```rust
#[derive(Clone)]
struct MyKeyGetter {
    key: Vec<u8>,
}

impl MyKeyGetter {
    fn new(filename: &str) -> Result<Self, Error> {
        let mut key = Vec::new();
        std::fs::File::open(filename)
            .map_err(|_| ..)?
            .read_to_end(&mut key)
            .map_err(|_| ..)?;

        Ok(MyKeyGetter { key })
    }
}

impl GetKey for MyKeyGetter {
    type Key = Cursor<Vec<u8>>;
    type Error = ..;

    fn get_key(self, _key_id: &str) -> Result<Self::Key, Self::Error> {
        Ok(Cursor::new(self.key.clone()))
    }
}

struct Verified;

impl<'a, 'r> FromRequest<'a, 'r> for Verified {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> Outcome<Verified, ()> {
        let res = request
            .guard::<State<MyKeyGetter>>()
            .succeeded()
            .ok_or(())
            .and_then(|key_getter| {
                request
                    .verify_authorization_header(key_getter.clone())
                    .map_err(|_| ..)?;

                Ok(Verified)
            });

        match res {
            Ok(verified) => Success(verified),
            Err(fail) => Failure((Status::Forbidden, fail)),
        }
    }
}

#[get("/")]
fn index(_verified: Verified) -> &'static str {
    "Successfully verified request"
}

fn main() {
    let key_getter = MyKeyGetter::new("test/assets/public.der").unwrap();

    rocket::ignite()
        .mount("/", routes![index])
        .manage(key_getter)
        .launch();
}
```

### Contributing
Please be aware that all code contributed to this project will be licensed under the GPL version 3.

### License
HTTP Signatures is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

HTTP Signatures is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. This file is part of HTTP Signatures

You should have received a copy of the GNU General Public License along with HTTP Signatures If not, see http://www.gnu.org/licenses/.
