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

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::io::Read;
use std::sync::Arc;

use ring::{rand, signature, digest, hmac};
use base64::{encode, decode};

#[cfg(feature = "use_hyper")]
mod use_hyper;

#[cfg(feature = "use_reqwest")]
mod use_reqwest;

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

pub trait AsHttpSignature<T>
where
    T: Read,
{
    fn as_http_signature(
        &self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> HttpSignature<T>;

    fn authorization_header(
        &self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<String, Error> {
        let signing_string: SigningString<T> = self.as_http_signature(key_id, key, algorithm)
            .into();
        let signature: Signature = signing_string.try_into()?;

        Ok(signature.authorization())
    }
}

pub trait WithHttpSignature<T>: AsHttpSignature<T>
where
    T: Read,
{
    fn with_http_signature(
        &mut self,
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
    ) -> Result<&mut Self, Error>;
}

pub struct HttpSignature<T> {
    key_id: String,
    key: T,
    algorithm: SignatureAlgorithm,
    headers: HashMap<String, Vec<String>>,
}

pub struct SigningString<T> {
    key_id: String,
    key: T,
    headers: Vec<String>,
    algorithm: SignatureAlgorithm,
    signing_string: String,
}

impl<T> From<HttpSignature<T>> for SigningString<T> {
    fn from(http_signature: HttpSignature<T>) -> Self {
        let (header_keys, signing_vec): (Vec<_>, Vec<_>) = http_signature
            .headers
            .iter()
            .map(|(header, values)| {
                (
                    header.to_lowercase(),
                    format!("{}: {}", header.to_lowercase(), values.join(", ")),
                )
            })
            .unzip();

        SigningString {
            key_id: http_signature.key_id,
            key: http_signature.key,
            headers: header_keys,
            algorithm: http_signature.algorithm,
            signing_string: signing_vec.join("\n"),
        }
    }
}

pub trait GetKey {
    type Key: Read;
    type Error;

    fn get_key(self, key_id: String) -> Result<Self::Key, Self::Error>;
}

pub struct AuthorizationHeader {
    key_id: String,
    header_keys: Vec<String>,
    algorithm: SignatureAlgorithm,
    signature: Vec<u8>,
}

impl AuthorizationHeader {
    pub fn new(s: String) -> Result<Self, DecodeError> {
        s.try_into()
    }

    pub fn verify<G>(
        self,
        headers: &[(String, String)],
        method: &str,
        path: &str,
        query: &str,
        key_getter: G,
    ) -> Result<(), VerificationError>
    where
        G: GetKey,
    {
        let vah: VerifyAuthorizationHeader = VerifyAuthorizationHeader {
            auth_header: self,
            headers: headers,
            method: method,
            path: path,
            query: query,
        };

        vah.verify(key_getter)
    }
}

pub struct VerifyAuthorizationHeader<'a> {
    auth_header: AuthorizationHeader,
    headers: &'a [(String, String)],
    method: &'a str,
    path: &'a str,
    query: &'a str,
}

impl<'a> VerifyAuthorizationHeader<'a> {
    pub fn verify<G>(self, key_getter: G) -> Result<(), VerificationError>
    where
        G: GetKey,
    {
        let key: G::Key = key_getter.get_key(self.auth_header.key_id).map_err(|_| {
            VerificationError::GetKey
        })?;

        let headers: HashMap<String, Vec<String>> =
            self.headers.iter().fold(HashMap::new(), |mut acc,
             &(ref key, ref value)| {
                acc.entry(key.clone().to_lowercase())
                    .or_insert(Vec::new())
                    .push(value.clone());

                acc
            });

        let mut headers: HashMap<String, String> = headers
            .iter()
            .map(|(key, value)| (key.clone(), value.join(", ")))
            .collect();

        headers.insert(
            "(request-target)".into(),
            format!(
                "{} {}?{}",
                self.method.to_lowercase(),
                self.path,
                self.query
            ),
        );

        let signing_string = self.auth_header
            .header_keys
            .iter()
            .filter_map(|header_key| {
                let header = headers.get(header_key)?;
                Some(format!("{}: {}", header_key, header))
            })
            .collect::<Vec<_>>()
            .join("\n");

        match self.auth_header.algorithm {
            SignatureAlgorithm::RSA(sha_size) => {
                Self::verify_rsa(
                    key,
                    sha_size,
                    signing_string,
                    self.auth_header.signature.as_ref(),
                )
            }
            SignatureAlgorithm::HMAC(sha_size) => {
                Self::verify_hmac(
                    key,
                    sha_size,
                    signing_string,
                    self.auth_header.signature.as_ref(),
                )
            }
        }
    }

    fn verify_rsa<T>(
        mut key: T,
        sha_size: ShaSize,
        signing_string: String,
        sig: &[u8],
    ) -> Result<(), VerificationError>
    where
        T: Read,
    {
        // Verify the signature.
        let mut public_key_der = Vec::new();
        key.read_to_end(&mut public_key_der).map_err(|_| {
            VerificationError::ReadKey
        })?;
        let public_key_der = untrusted::Input::from(&public_key_der);
        let message = untrusted::Input::from(signing_string.as_ref());
        let signature = untrusted::Input::from(sig);

        match sha_size {
            ShaSize::TwoFiftySix => {
                signature::verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    public_key_der,
                    message,
                    signature,
                ).map_err(|ring::error::Unspecified| VerificationError::BadSignature)?;
            }
            ShaSize::ThreeEightyFour => {
                signature::verify(
                    &signature::RSA_PKCS1_2048_8192_SHA384,
                    public_key_der,
                    message,
                    signature,
                ).map_err(|ring::error::Unspecified| VerificationError::BadSignature)?;
            }
            ShaSize::FiveTwelve => {
                signature::verify(
                    &signature::RSA_PKCS1_2048_8192_SHA512,
                    public_key_der,
                    message,
                    signature,
                ).map_err(|ring::error::Unspecified| VerificationError::BadSignature)?;
            }
        }

        Ok(())
    }

    fn verify_hmac<T>(
        mut key: T,
        sha_size: ShaSize,
        signing_string: String,
        sig: &[u8],
    ) -> Result<(), VerificationError>
    where
        T: Read,
    {
        let mut hmac_key = Vec::new();
        key.read_to_end(&mut hmac_key).map_err(
            |_| VerificationError::ReadKey,
        )?;
        let hmac_key = hmac::SigningKey::new(
            match sha_size {
                ShaSize::TwoFiftySix => &digest::SHA256,
                ShaSize::ThreeEightyFour => &digest::SHA384,
                ShaSize::FiveTwelve => &digest::SHA512,
            },
            &hmac_key,
        );

        hmac::verify_with_own_key(&hmac_key, signing_string.as_ref(), sig)
            .map_err(|_| VerificationError::BadSignature)?;

        Ok(())
    }
}

impl TryFrom<String> for AuthorizationHeader {
    type Error = DecodeError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let s = s.trim_left_matches("Signature: ");
        let key_value = s.split(',')
            .filter_map(|item| {
                let key_value_slice: Vec<_> = item.split('=').collect();

                if key_value_slice.len() >= 2 {
                    Some((key_value_slice[0], key_value_slice[1..].join("=")))
                } else {
                    None
                }
            })
            .collect::<HashMap<_, _>>();

        let key_id = (*key_value
                          .get("keyId")
                          .ok_or(DecodeError::MissingKey("keyId"))?
                          .trim_left_matches("\"")
                          .trim_right_matches("\""))
            .into();

        let header_keys = key_value
            .get("headers")
            .ok_or(DecodeError::MissingKey("headers"))?
            .trim_left_matches("\"")
            .trim_right_matches("\"")
            .split(' ')
            .map(|header| header.into())
            .collect();

        let algorithm = (*key_value
                             .get("algorithm")
                             .ok_or(DecodeError::MissingKey("algorithm"))?
                             .trim_left_matches("\"")
                             .trim_right_matches("\""))
            .try_into()?;

        let signature = decode(
            key_value
                .get("signature")
                .ok_or(DecodeError::MissingKey("signature"))?
                .trim_left_matches("\"")
                .trim_right_matches("\"")
                .into(),
        ).map_err(|_| DecodeError::NotBase64)?;

        Ok(AuthorizationHeader {
            key_id,
            header_keys,
            algorithm,
            signature,
        })
    }
}

#[derive(Debug)]
pub enum DecodeError {
    MissingKey(&'static str),
    InvalidAlgorithm(String),
    NotBase64,
    Unknown,
}

#[derive(Debug)]
pub enum VerificationError {
    Decode(DecodeError),
    GetKey,
    ReadKey,
    BadSignature,
    Unknown,
}

impl From<DecodeError> for VerificationError {
    fn from(d: DecodeError) -> Self {
        VerificationError::Decode(d)
    }
}

pub struct Signature {
    sig: String,
    key_id: String,
    headers: Vec<String>,
    algorithm: SignatureAlgorithm,
}

impl Signature {
    pub fn authorization(self) -> String {
        let alg: &str = self.algorithm.into();

        format!("Signature: keyId=\"{}\",algorithm=\"{}\",headers=\"{}\",signature=\"{}\"",
                self.key_id,
                alg,
                self.headers.join(" "),
                self.sig,
        )
    }

    fn rsa<T>(mut key: T, size: &ShaSize, signing_string: &[u8]) -> Result<String, Error>
    where
        T: Read,
    {
        let mut private_key_der = Vec::new();
        key.read_to_end(&mut private_key_der)?;
        let private_key_der = untrusted::Input::from(&private_key_der);

        let key_pair = signature::RSAKeyPair::from_der(private_key_der).map_err(
            |_| {
                Error::BadPrivateKey
            },
        )?;
        let key_pair = Arc::new(key_pair);

        let mut signing_state = signature::RSASigningState::new(key_pair).map_err(
            |_| Error::Unknown,
        )?;

        let rng = rand::SystemRandom::new();
        let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
        signing_state
            .sign(
                match *size {
                    ShaSize::TwoFiftySix => &signature::RSA_PKCS1_SHA256,
                    ShaSize::ThreeEightyFour => &signature::RSA_PKCS1_SHA384,
                    ShaSize::FiveTwelve => &signature::RSA_PKCS1_SHA512,
                },
                &rng,
                signing_string,
                signature.as_mut_slice(),
            )
            .map_err(|_| Error::SigningError)?;

        Ok(encode(signature.as_slice()))
    }

    fn hmac<T>(mut key: T, size: &ShaSize, signing_string: &[u8]) -> Result<String, Error>
    where
        T: Read,
    {
        let mut hmac_key = Vec::new();
        key.read_to_end(&mut hmac_key)?;
        let hmac_key = hmac::SigningKey::new(
            match *size {
                ShaSize::TwoFiftySix => &digest::SHA256,
                ShaSize::ThreeEightyFour => &digest::SHA384,
                ShaSize::FiveTwelve => &digest::SHA512,
            },
            &hmac_key,
        );
        let signature = hmac::sign(&hmac_key, signing_string);

        Ok(encode(signature.as_ref()))
    }
}

impl<T> TryFrom<SigningString<T>> for Signature
where
    T: Read,
{
    type Error = Error;

    fn try_from(signing_string: SigningString<T>) -> Result<Self, Self::Error> {
        Ok(match signing_string.algorithm {
            SignatureAlgorithm::RSA(size) => {
                Signature {
                    sig: Signature::rsa(
                        signing_string.key,
                        &size,
                        signing_string.signing_string.as_ref(),
                    )?,
                    key_id: signing_string.key_id,
                    headers: signing_string.headers,
                    algorithm: SignatureAlgorithm::RSA(size),
                }
            }
            SignatureAlgorithm::HMAC(size) => {
                Signature {
                    sig: Signature::hmac(
                        signing_string.key,
                        &size,
                        signing_string.signing_string.as_ref(),
                    )?,
                    key_id: signing_string.key_id,
                    headers: signing_string.headers,
                    algorithm: SignatureAlgorithm::HMAC(size),
                }
            }
        })
    }
}

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    SigningError,
    BadPrivateKey,
    Unknown,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IO(e)
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
