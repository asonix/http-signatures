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

//! This module defines types for creating HTTP Signatures.

use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use std::io::Read;

use ring::{digest, hmac, rand, signature};
use base64::encode;
use untrusted::Input;

use error::{CreationError, Error};
use super::{ShaSize, SignatureAlgorithm};
use prelude::*;

/// The `HttpSignature` struct, this is the entry point for creating Authorization or Signature
/// headers. It contains all the values required for generation.
#[derive(Clone, Debug)]
pub struct HttpSignature<T>
where
    T: Read,
{
    /// The keyId field in the header
    key_id: String,
    /// The key (implementing `Read`) used to sign the request
    key: T,
    /// The algorithm used to sign the request
    algorithm: SignatureAlgorithm,
    /// The headers that will be included in the signature
    headers: BTreeMap<String, Vec<String>>,
}

impl<T> HttpSignature<T>
where
    T: Read,
{
    /// Create a new HttpSignature from its components.
    ///
    /// This method will Error if `headers` is empty.
    ///
    /// ### Example
    /// ```rust
    /// # use std::fs::File;
    /// # use std::collections::BTreeMap;
    /// # use http_signatures::Error;
    /// use http_signatures::{HttpSignature, SignatureAlgorithm, ShaSize, REQUEST_TARGET};
    ///
    /// # fn run() -> Result<(), Error> {
    /// let key_id = "tests/assets/public.der".into();
    /// let priv_key = File::open("tests/assets/private.der")?;
    ///
    /// let alg = SignatureAlgorithm::RSA(ShaSize::FiveTwelve);
    ///
    /// let mut headers = BTreeMap::new();
    /// headers.insert(REQUEST_TARGET.into(), vec!["get /".into()]);
    ///
    /// let http_sig = HttpSignature::new(key_id, priv_key, alg, headers)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        key_id: String,
        key: T,
        algorithm: SignatureAlgorithm,
        headers: BTreeMap<String, Vec<String>>,
    ) -> Result<Self, CreationError> {
        if headers.is_empty() {
            return Err(CreationError::NoHeaders);
        }

        Ok(HttpSignature {
            key_id,
            key,
            algorithm,
            headers,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn algorithm(&self) -> &SignatureAlgorithm {
        &self.algorithm
    }

    pub fn headers(&self) -> &BTreeMap<String, Vec<String>> {
        &self.headers
    }

    /// Generate the Authorization Header from the `HttpSignature`
    ///
    /// This method errors if signing the signing-string fails.
    ///
    /// ### Example
    /// ```rust
    /// # use std::fs::File;
    /// # use std::collections::BTreeMap;
    /// # use http_signatures::{Error, SignatureAlgorithm, ShaSize, REQUEST_TARGET};
    /// use http_signatures::HttpSignature;
    /// # fn run() -> Result<(), Error> {
    /// # let key_id = "tests/assets/public.der".into();
    /// # let priv_key = File::open("tests/assets/private.der")?;
    /// # let alg = SignatureAlgorithm::RSA(ShaSize::FiveTwelve);
    /// # let mut headers = BTreeMap::new();
    /// # headers.insert(REQUEST_TARGET.into(), vec!["get /".into()]);
    /// # let http_signature = HttpSignature::new(key_id, priv_key, alg, headers)?;
    ///
    /// let auth_header = http_signature.authorization_header()?;
    /// println!("Authorization: {}", auth_header);
    /// # Ok(())
    /// # }
    /// ```
    pub fn authorization_header(self) -> Result<String, CreationError> {
        Ok(self.signature()?.authorization())
    }

    /// Generate the Signature Header from the `HttpSignature`
    ///
    /// This method errors if signing the signing-string fails.
    ///
    /// ### Example
    /// ```rust
    /// # use std::fs::File;
    /// # use std::collections::BTreeMap;
    /// # use http_signatures::{Error, SignatureAlgorithm, ShaSize, REQUEST_TARGET};
    /// use http_signatures::HttpSignature;
    /// # fn run() -> Result<(), Error> {
    /// # let key_id = "tests/assets/public.der".into();
    /// # let priv_key = File::open("tests/assets/private.der")?;
    /// # let alg = SignatureAlgorithm::RSA(ShaSize::FiveTwelve);
    /// # let mut headers = BTreeMap::new();
    /// # headers.insert(REQUEST_TARGET.into(), vec!["get /".into()]);
    /// # let http_signature = HttpSignature::new(key_id, priv_key, alg, headers)?;
    ///
    /// let sig_header = http_signature.signature_header()?;
    /// println!("Signature: {}", sig_header);
    /// # Ok(())
    /// # }
    /// ```
    pub fn signature_header(self) -> Result<String, CreationError> {
        Ok(self.signature()?.signature())
    }

    pub fn signature(self) -> Result<Signature, CreationError> {
        let signing_string: SigningString<T> = self.into();
        signing_string.try_into()
    }
}

/// A default implementation of `AsHttpSignature` for `HttpSignature`.
///
/// This only works if type `T` is `Clone` in addition to `Read`, which is normally required. This
/// implementation doesn't serve much of a purpose.
impl<T> AsHttpSignature<T> for HttpSignature<T>
where
    T: Read + Clone,
{
    fn as_http_signature(&self, _: String, _: T, _: SignatureAlgorithm) -> Result<Self, Error> {
        Ok(HttpSignature {
            key_id: self.key_id.clone(),
            key: self.key.clone(),
            algorithm: self.algorithm.clone(),
            headers: self.headers.clone(),
        })
    }
}

/// The `SigningString<T>` struct uses what was given in the `HttpSignature` struct, but also has a
/// plaintext field called `signing_string` which holds the string used to sign the request.
///
/// Since `From<HttpSignature<T>>` was implemented for `SigningString<T>`, the transition is as
/// simple as calling `http_signature.into()`.
///
/// This struct does not have public fields, and does not have a constructor since it should only
/// be used as an intermediate point from `HttpSignature<T>` to the signed string.
#[derive(Clone, Debug)]
pub struct SigningString<T> {
    key_id: String,
    key: T,
    headers: Vec<String>,
    algorithm: SignatureAlgorithm,
    // The plaintext string used to sign the request
    pub signing_string: String,
}

impl<T> From<HttpSignature<T>> for SigningString<T>
where
    T: Read,
{
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

/// `Signature` is the result of using the `key: T` of `SigningString<T>` to sign the
/// `signing_string`.
///
/// To get the Authorization or Signature Header String from the Signature, the `authorization`
/// and `signature` methods are provided.
#[derive(Clone, Debug)]
pub struct Signature {
    sig: String,
    key_id: String,
    headers: Vec<String>,
    algorithm: SignatureAlgorithm,
}

impl Signature {
    /// Get the Authorization Header String.
    pub fn authorization(self) -> String {
        format!("Signature {}", self.header())
    }

    /// Get the Signature Header String.
    pub fn signature(self) -> String {
        self.header()
    }

    fn header(self) -> String {
        let alg: &str = self.algorithm.into();

        format!(
            "Signature keyId=\"{}\",algorithm=\"{}\",headers=\"{}\",signature=\"{}\"",
            self.key_id,
            alg,
            self.headers.join(" "),
            self.sig,
        )
    }

    fn rsa<T>(mut key: T, size: &ShaSize, signing_string: &[u8]) -> Result<String, CreationError>
    where
        T: Read,
    {
        let mut private_key_der = Vec::new();
        key.read_to_end(&mut private_key_der)?;
        let private_key_der = Input::from(&private_key_der);

        let key_pair = signature::RSAKeyPair::from_der(private_key_der)
            .map_err(|_| CreationError::BadPrivateKey)?;
        let key_pair = Arc::new(key_pair);

        let mut signing_state =
            signature::RSASigningState::new(key_pair).map_err(|_| CreationError::SigningError)?;

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
            .map_err(|_| CreationError::SigningError)?;

        Ok(encode(signature.as_slice()))
    }

    fn hmac<T>(mut key: T, size: &ShaSize, signing_string: &[u8]) -> Result<String, CreationError>
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
    type Error = CreationError;

    /// Attempt to sign the signing_string. If signing fails, a `Signature` will not be created and
    /// an `Error` will be returned.
    fn try_from(signing_string: SigningString<T>) -> Result<Self, Self::Error> {
        Ok(match signing_string.algorithm {
            SignatureAlgorithm::RSA(size) => Signature {
                sig: Signature::rsa(
                    signing_string.key,
                    &size,
                    signing_string.signing_string.as_ref(),
                )?,
                key_id: signing_string.key_id,
                headers: signing_string.headers,
                algorithm: SignatureAlgorithm::RSA(size),
            },
            SignatureAlgorithm::HMAC(size) => Signature {
                sig: Signature::hmac(
                    signing_string.key,
                    &size,
                    signing_string.signing_string.as_ref(),
                )?,
                key_id: signing_string.key_id,
                headers: signing_string.headers,
                algorithm: SignatureAlgorithm::HMAC(size),
            },
        })
    }
}
