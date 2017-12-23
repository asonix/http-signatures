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

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use std::io::Read;

use ring::{rand, signature, digest, hmac};
use base64::encode;
use untrusted::Input;

use super::{SignatureAlgorithm, ShaSize};
use error::Error;

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

impl<T> HttpSignature<T> {
    pub fn new(
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
        headers: HashMap<String, Vec<String>>,
    ) -> Self {
        HttpSignature {
            key_id,
            key,
            algorithm,
            headers,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn algorithm(&self) -> &SignatureAlgorithm {
        &self.algorithm
    }

    pub fn headers(&self) -> &HashMap<String, Vec<String>> {
        &self.headers
    }
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
        let private_key_der = Input::from(&private_key_der);

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
