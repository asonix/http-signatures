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

#![feature(try_from)]

#[cfg(feature = "use_hyper")]
extern crate hyper;

#[cfg(feature = "use_reqwest")]
extern crate reqwest;

extern crate ring;
extern crate untrusted;
extern crate base64;

use std::convert::TryFrom;

#[cfg(feature = "use_hyper")]
mod use_hyper;
#[cfg(feature = "use_reqwest")]
mod use_reqwest;

mod create;
mod verify;
mod error;

pub use create::{AsHttpSignature, WithHttpSignature, HttpSignature, SigningString};
pub use verify::AuthorizationHeader;
pub use error::{Error, DecodeError, VerificationError};

#[derive(Debug)]
pub enum ShaSize {
    TwoFiftySix,
    ThreeEightyFour,
    FiveTwelve,
}

#[derive(Debug)]
pub enum SignatureAlgorithm {
    RSA(ShaSize),
    HMAC(ShaSize),
}

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

    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::io::Cursor;
    use std::fs::File;

    use super::HttpSignature;
    use super::SignatureAlgorithm;
    use super::Signature;
    use super::SigningString;
    use super::GetKey;
    use super::AuthorizationHeader;
    use super::ShaSize;
    use super::VerificationError;

    struct HmacKeyGetter {
        key: Vec<u8>,
    }

    impl GetKey for HmacKeyGetter {
        type Key = Cursor<Vec<u8>>;
        type Error = VerificationError;

        fn get_key(self, _: String) -> Result<Self::Key, Self::Error> {
            Ok(Cursor::new(self.key))
        }
    }

    struct RsaKeyGetter {
        key: File,
    }

    impl GetKey for RsaKeyGetter {
        type Key = File;
        type Error = VerificationError;

        fn get_key(self, _: String) -> Result<Self::Key, Self::Error> {
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

        let mut headers_one: HashMap<String, Vec<String>> = HashMap::new();
        headers_one.insert("Accept".into(), vec!["application/json".into()]);
        headers_one.insert(
            "(request-target)".into(),
            vec![format!("{} {}?{}", method.to_lowercase(), path, query)],
        );

        let mut headers_two = Vec::new();
        headers_two.push(("Accept".into(), "application/json".into()));

        let algorithm = SignatureAlgorithm::HMAC(sha_size);
        let key_id = "1".into();

        let http_sig = HttpSignature {
            key_id: key_id,
            key: Cursor::new(key_vec),
            algorithm: algorithm,
            headers: headers_one,
        };

        let signing_string: SigningString<_> = http_sig.into();
        let signature: Signature = signing_string.try_into().unwrap();

        let auth_header = signature.authorization();
        let auth_header = AuthorizationHeader::new(auth_header).unwrap();

        auth_header
            .verify(&headers_two, method, path, query, key_getter)
            .unwrap();
    }

    fn rsa_can_sign_and_verify(sha_size: ShaSize) {
        let priv_key = File::open("test/assets/private.der").unwrap();
        let pub_key = File::open("test/assets/public.der").unwrap();

        let key_getter = RsaKeyGetter { key: pub_key };

        let method = "GET";
        let path = "/test";
        let query = "key=value";

        let mut headers_one: HashMap<String, Vec<String>> = HashMap::new();
        headers_one.insert("Accept".into(), vec!["application/json".into()]);
        headers_one.insert(
            "(request-target)".into(),
            vec![format!("{} {}?{}", method.to_lowercase(), path, query)],
        );

        let mut headers_two = Vec::new();
        headers_two.push(("Accept".into(), "application/json".into()));

        let algorithm = SignatureAlgorithm::RSA(sha_size);
        let key_id = "1".into();

        let http_sig = HttpSignature {
            key_id: key_id,
            key: priv_key,
            algorithm: algorithm,
            headers: headers_one,
        };

        let signing_string: SigningString<_> = http_sig.into();
        let signature: Signature = signing_string.try_into().unwrap();

        let auth_header = signature.authorization();
        let auth_header = AuthorizationHeader::new(auth_header).unwrap();

        auth_header
            .verify(&headers_two, method, path, query, key_getter)
            .unwrap();
    }
}
