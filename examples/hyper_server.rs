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
extern crate http_signatures;

use std::io::{Cursor, Read};

use futures::{Future, IntoFuture};

use hyper::header::ContentLength;
use hyper::server::{Http, Request, Response, Service};
use http_signatures::{GetKey, VerifyAuthorizationHeader};

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

impl GetKey for MyKeyGetter {
    type Key = Cursor<Vec<u8>>;
    type Error = Error;

    fn get_key(self, _key_id: &str) -> Result<Self::Key, Self::Error> {
        Ok(Cursor::new(self.key.clone()))
    }
}

struct HelloWorld {
    key_getter: MyKeyGetter,
}

impl HelloWorld {
    fn new(filename: &str) -> Result<Self, Error> {
        Ok(HelloWorld { key_getter: MyKeyGetter::new(filename)? })
    }
}

const PHRASE: &'static str = "Hewwo, Mr. Obama???";

impl Service for HelloWorld {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;

    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        let verified = req.verify_authorization_header(self.key_getter.clone())
            .map_err(|_| hyper::Error::Header);

        Box::new(verified.into_future().and_then(|_| {
            println!("Succesfully verified request!");
            Ok(
                Response::new()
                    .with_header(ContentLength(PHRASE.len() as u64))
                    .with_body(PHRASE),
            )
        }))
    }
}

fn main() {
    let addr = "127.0.0.1:3000".parse().unwrap();
    let server = Http::new()
        .bind(&addr, || {
            Ok(HelloWorld::new("test/assets/public.der").unwrap())
        })
        .unwrap();
    server.run().unwrap();
}
