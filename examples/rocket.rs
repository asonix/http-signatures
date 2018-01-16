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

#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate http_signatures;
extern crate rocket;

use std::io::{Cursor, Read};

use rocket::State;
use rocket::Outcome::{Failure, Success};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::http::Status;
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

impl GetKey for MyKeyGetter {
    type Key = Cursor<Vec<u8>>;
    type Error = Error;

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
                    .map_err(|e| println!("Error: {:?}", e))?;

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
    let key_getter = MyKeyGetter::new("tests/assets/public.der").unwrap();

    rocket::ignite()
        .mount("/", routes![index])
        .manage(key_getter)
        .launch();
}
