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

//! HTTP Signatures, an implementation of [the http signatures specification](https://tools.ietf.org/html/draft-cavage-http-signatures-09)
//!
//! The base crate provides types for creating and verifying signatures, and the features
//! `use_hyper`, `use_reqwest`, and `use_rocket` provide implementations of required traits for
//! easily using HTTP Signatures with web applications.
//!
//! # Creating an HTTP Signature
//!
//! To get a string that would be the contents of an HTTP Request's Authorization header, a few
//! steps must be taken. The method, path, and query must be known, furthermore, there must be at
//! least one item in the headers hashmap, if there is not, the HTTP Signature creation will fail.
//!
//! ```rust
//! use http_signatures::{HttpSignature, SignatureAlgorithm, ShaSize};
//! use http_signatures::REQUEST_TARGET;
//! # use http_signatures::Error;
//! # use std::fs::File;
//! # use std::collections::BTreeMap;
//! # fn run() -> Result<(), Error> {
//! # let priv_key = File::open("tests/assets/private.der")?;
//!
//! let method = "GET";
//! let path = "/test";
//! let query = "key=value";
//!
//! let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
//! headers.insert("Accept".into(), vec!["application/json".into()]);
//! headers.insert(
//!     REQUEST_TARGET.into(),
//!     vec![format!("{} {}?{}", method.to_lowercase(), path, query)],
//! );
//!
//! let algorithm = SignatureAlgorithm::RSA(ShaSize::FiveTwelve);
//! let key_id = "1".into();
//!
//! let auth_header = HttpSignature::new(key_id, priv_key, algorithm, headers)?
//!     .authorization_header()?;
//!
//! println!("Authorization: {}", auth_header);
//! # Ok(())
//! # }
//! ```
//!
//! # Verifying an HTTP Signature
//!
//! To verify a header, one must implement a type called `GetKey`. This type is imporant because it
//! contains the information required to convert a key id, represented as &str, into a Key. This
//! can be done by accessing some external state, or by storing the required state in the struct
//! that implements GetKey.
//!
//! ```rust
//! # use http_signatures::{HttpSignature, SignatureAlgorithm, ShaSize};
//! # use http_signatures::REQUEST_TARGET;
//! # use http_signatures::Error;
//! use http_signatures::{GetKey, SignedHeader};
//! # use std::fs::File;
//! # use std::collections::BTreeMap;
//! # fn some_auth_header() -> Result<String, Error> {
//! # let priv_key = File::open("tests/assets/private.der")?;
//! # let method = "GET";
//! # let path = "/test";
//! # let query = "key=value";
//! # let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
//! # headers.insert("Accept".into(), vec!["application/json".into()]);
//! # headers.insert(
//! #     REQUEST_TARGET.into(),
//! #     vec![format!("{} {}?{}", method.to_lowercase(), path, query)],
//! # );
//! # let algorithm = SignatureAlgorithm::RSA(ShaSize::FiveTwelve);
//! # let key_id = "1".into();
//! # let auth_header = HttpSignature::new(key_id, priv_key, algorithm, headers)?
//! #   .authorization_header()?;
//! # Ok(auth_header)
//! # }
//!
//! struct MyKeyGetter;
//!
//! impl GetKey for MyKeyGetter {
//!     type Key = File;
//!     type Error = Error;
//!
//!     fn get_key(self, _key_id: &str) -> Result<Self::Key, Self::Error> {
//!         File::open("tests/assets/public.der").map_err(Error::from)
//!     }
//! }
//! # fn run() -> Result<(), Error> {
//! # let auth_header = some_auth_header()?;
//!
//! let mut headers = Vec::new();
//! headers.push(("Accept".into(), "application/json".into()));
//!
//! let method = "GET";
//! let path = "/test";
//! let query = "key=value";
//!
//! let key_getter = MyKeyGetter;
//!
//! let auth_header = SignedHeader::new(&auth_header)?;
//! auth_header
//!     .verify(&headers, method, path, Some(query), key_getter)?;
//!
//! # Ok(())
//! # }
//! ```

#![feature(try_from)]

#[cfg(feature = "use_hyper")]
extern crate hyper;
#[cfg(feature = "use_reqwest")]
extern crate reqwest;
#[cfg(feature = "use_rocket")]
extern crate rocket;
extern crate ring;
extern crate untrusted;
extern crate base64;

use std::convert::TryFrom;

#[cfg(feature = "use_hyper")]
mod use_hyper_client;
#[cfg(feature = "use_hyper")]
mod use_hyper_server;
#[cfg(feature = "use_reqwest")]
mod use_reqwest;
#[cfg(feature = "use_rocket")]
mod use_rocket;

mod create;
mod verify;
mod error;

use error::DecodeError;

pub use create::{AsHttpSignature, WithHttpSignature, HttpSignature};
pub use verify::{SignedHeader, VerifyHeader, GetKey};
pub use error::Error;

pub const REQUEST_TARGET: &'static str = "(request-target)";

/// Variations of the Sha hashing function.
///
/// This stuct is used to tell the RSA and HMAC signature functions how big the sha hash should be.
/// It currently offers three variations.
#[derive(Debug, Clone)]
pub enum ShaSize {
    /// SHA256
    TwoFiftySix,
    /// SHA384
    ThreeEightyFour,
    /// SHA512
    FiveTwelve,
}

/// Which algorithm should be used to create an HTTP header.
///
/// This library uses Ring 0.11.0 for creating and verifying hashes, so this determines whether the
/// library will use Ring's RSA Signatures or Rings's HMAC signatures.
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    /// RSA
    RSA(ShaSize),
    /// HMAC
    HMAC(ShaSize),
}

/// Convert an &str into a SignatureAlgorithm
impl<'a> TryFrom<&'a str> for SignatureAlgorithm {
    type Error = DecodeError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        match s {
            "rsa-sha256" => Ok(SignatureAlgorithm::RSA(ShaSize::TwoFiftySix)),
            "rsa-sha384" => Ok(SignatureAlgorithm::RSA(ShaSize::ThreeEightyFour)),
            "rsa-sha512" => Ok(SignatureAlgorithm::RSA(ShaSize::FiveTwelve)),
            "hmac-sha256" => Ok(SignatureAlgorithm::HMAC(ShaSize::TwoFiftySix)),
            "hmac-sha384" => Ok(SignatureAlgorithm::HMAC(ShaSize::ThreeEightyFour)),
            "hmac-sha512" => Ok(SignatureAlgorithm::HMAC(ShaSize::FiveTwelve)),
            e => Err(DecodeError::InvalidAlgorithm(e.into())),
        }
    }
}

/// Convert a SignatureAlgorithm into an &str
impl From<SignatureAlgorithm> for &'static str {
    fn from(alg: SignatureAlgorithm) -> Self {
        match alg {
            SignatureAlgorithm::RSA(size) => {
                match size {
                    ShaSize::TwoFiftySix => "rsa-sha256",
                    ShaSize::ThreeEightyFour => "rsa-sha384",
                    ShaSize::FiveTwelve => "rsa-sha512",
                }
            }
            SignatureAlgorithm::HMAC(size) => {
                match size {
                    ShaSize::TwoFiftySix => "hmac-sha256",
                    ShaSize::ThreeEightyFour => "hmac-sha384",
                    ShaSize::FiveTwelve => "hmac-sha512",
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::{digest, hmac, rand};

    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::fs::File;

    use super::SignatureAlgorithm;
    use super::ShaSize;
    use super::REQUEST_TARGET;
    use create::HttpSignature;
    use verify::GetKey;
    use verify::SignedHeader;
    use error::VerificationError;

    struct HmacKeyGetter {
        key: Vec<u8>,
    }

    impl GetKey for HmacKeyGetter {
        type Key = Cursor<Vec<u8>>;
        type Error = VerificationError;

        fn get_key(self, _: &str) -> Result<Self::Key, Self::Error> {
            Ok(Cursor::new(self.key))
        }
    }

    struct RsaKeyGetter {
        key: File,
    }

    impl GetKey for RsaKeyGetter {
        type Key = File;
        type Error = VerificationError;

        fn get_key(self, _: &str) -> Result<Self::Key, Self::Error> {
            Ok(self.key)
        }
    }

    #[test]
    fn hmac_256_can_sign_and_verify() {
        hmac_can_sign_and_verify(ShaSize::TwoFiftySix, &digest::SHA256);
    }

    #[test]
    fn hmac_384_can_sign_and_verify() {
        hmac_can_sign_and_verify(ShaSize::ThreeEightyFour, &digest::SHA384);
    }

    #[test]
    fn hmac_512_can_sign_and_verify() {
        hmac_can_sign_and_verify(ShaSize::FiveTwelve, &digest::SHA512);
    }

    #[test]
    fn rsa_256_can_sign_and_verify() {
        rsa_can_sign_and_verify(ShaSize::TwoFiftySix);
    }

    #[test]
    fn rsa_384_can_sign_and_verify() {
        rsa_can_sign_and_verify(ShaSize::ThreeEightyFour);
    }

    #[test]
    fn rsa_512_can_sign_and_verify() {
        rsa_can_sign_and_verify(ShaSize::FiveTwelve);
    }

    fn hmac_can_sign_and_verify(sha_size: ShaSize, digest: &'static digest::Algorithm) {
        let rng = rand::SystemRandom::new();
        let len = hmac::recommended_key_len(digest);
        let mut key_vec: Vec<u8> = Vec::new();
        for _ in 0..len {
            key_vec.push(0);
        }
        let _ = hmac::SigningKey::generate_serializable(digest, &rng, key_vec.as_mut_slice())
            .unwrap();

        let key_getter = HmacKeyGetter { key: key_vec.clone() };

        let method = "GET";
        let path = "/test";
        let query = "key=value";

        let mut headers_one: BTreeMap<String, Vec<String>> = BTreeMap::new();
        headers_one.insert("Accept".into(), vec!["application/json".into()]);
        headers_one.insert(
            REQUEST_TARGET.into(),
            vec![format!("{} {}?{}", method.to_lowercase(), path, query)],
        );

        let mut headers_two = Vec::new();
        headers_two.push(("Accept".into(), "application/json".into()));

        let algorithm = SignatureAlgorithm::HMAC(sha_size);
        let key_id = "1".into();

        let auth_header = HttpSignature::new(key_id, Cursor::new(key_vec), algorithm, headers_one)
            .unwrap()
            .authorization_header()
            .unwrap();

        let auth_header = SignedHeader::new(&auth_header).unwrap();

        auth_header
            .verify(&headers_two, method, path, Some(query), key_getter)
            .unwrap();
    }

    fn rsa_can_sign_and_verify(sha_size: ShaSize) {
        let priv_key = File::open("tests/assets/private.der").unwrap();
        let pub_key = File::open("tests/assets/public.der").unwrap();

        let key_getter = RsaKeyGetter { key: pub_key };

        let method = "GET";
        let path = "/test";
        let query = "key=value";

        let mut headers_one: BTreeMap<String, Vec<String>> = BTreeMap::new();
        headers_one.insert("Accept".into(), vec!["application/json".into()]);
        headers_one.insert(
            REQUEST_TARGET.into(),
            vec![format!("{} {}?{}", method.to_lowercase(), path, query)],
        );

        let mut headers_two = Vec::new();
        headers_two.push(("Accept".into(), "application/json".into()));

        let algorithm = SignatureAlgorithm::RSA(sha_size);
        let key_id = "1".into();

        let auth_header = HttpSignature::new(key_id, priv_key, algorithm, headers_one)
            .unwrap()
            .signature_header()
            .unwrap();

        let auth_header = SignedHeader::new(&auth_header).unwrap();

        auth_header
            .verify(&headers_two, method, path, Some(query), key_getter)
            .unwrap();
    }
}
