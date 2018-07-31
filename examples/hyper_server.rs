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
extern crate http;
extern crate hyper;

use std::io::{Cursor, Read};
use std::sync::Arc;

use futures::{Future, IntoFuture};

use hyper::rt;
use hyper::header::CONTENT_LENGTH;
use hyper::{Server, Request, Response, Body};
use hyper::service::service_fn;
use http_signatures::prelude::*;

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

// struct HelloWorld {
//     key_getter: MyKeyGetter,
// }

// impl HelloWorld {
//     fn new(filename: &str) -> Result<Self, Error> {
//         Ok(HelloWorld {
//             key_getter: MyKeyGetter::new(filename)?,
//         })
//     }
// }

const PHRASE: &str = "Hewwo, Mr. Obama???";

fn main() {
    let key_getter_arc = Arc::new(MyKeyGetter::new("tests/assets/public.der").unwrap());
    let service = move || {
        let key_getter = key_getter_arc.clone();
        service_fn(move |req: Request<Body>| {
            let verified = req.verify_signature_header(&*key_getter);

            verified.into_future()
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
