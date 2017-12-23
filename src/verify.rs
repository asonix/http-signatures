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

use std::io::Read;
use std::convert::{TryFrom, TryInto};
use std::collections::HashMap;

use ring::{signature, digest, hmac};
use ring::error::Unspecified;
use base64::decode;
use untrusted::Input;

use super::{SignatureAlgorithm, ShaSize};
use error::{DecodeError, VerificationError};

pub trait GetKey {
    type Key: Read;
    type Error;

    fn get_key(self, key_id: String) -> Result<Self::Key, Self::Error>;
}

pub trait VerifyAuthorizationHeader {
    fn verify_authorization_header<G: GetKey>(
        &self,
        key_getter: G,
    ) -> Result<(), VerificationError>;
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
        query: Option<&str>,
        key_getter: G,
    ) -> Result<(), VerificationError>
    where
        G: GetKey,
    {
        let vah: CheckAuthorizationHeader = CheckAuthorizationHeader {
            auth_header: self,
            headers: headers,
            method: method,
            path: path,
            query: query,
        };

        vah.verify(key_getter)
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
            .unwrap_or(&"date".into())
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

        let sig_string: String = key_value
            .get("signature")
            .ok_or(DecodeError::MissingKey("signature"))?
            .trim_left_matches("\"")
            .trim_right_matches("\"")
            .into();

        let signature = decode(&sig_string).map_err(|_| DecodeError::NotBase64)?;

        Ok(AuthorizationHeader {
            key_id,
            header_keys,
            algorithm,
            signature,
        })
    }
}

pub struct CheckAuthorizationHeader<'a> {
    auth_header: AuthorizationHeader,
    headers: &'a [(String, String)],
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
}

impl<'a> CheckAuthorizationHeader<'a> {
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
            if let Some(ref query) = self.query {
                format!(
                    "{} {}?{}",
                    self.method.to_lowercase(),
                    self.path,
                    query,
                )
            } else {
                format!(
                    "{} {}",
                    self.method.to_lowercase(),
                    self.path,
                )
            },
        );

        let signing_vec = self.auth_header.header_keys.iter().fold(
            (Vec::new(), Vec::new()),
            |mut acc, header_key| {
                if let Some(ref header) = headers.get(header_key) {
                    acc.0.push(format!("{}: {}", header_key, header));
                } else {
                    acc.1.push(header_key.clone());
                }

                acc
            },
        );

        if signing_vec.1.len() > 0 {
            return Err(VerificationError::MissingHeaders(signing_vec.1.join(", ")));
        }

        let signing_string = signing_vec.0.join("\n");

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
        let public_key_der = Input::from(&public_key_der);
        let message = Input::from(signing_string.as_ref());
        let signature = Input::from(sig);

        match sha_size {
            ShaSize::TwoFiftySix => {
                signature::verify(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    public_key_der,
                    message,
                    signature,
                ).map_err(|Unspecified| VerificationError::BadSignature)?;
            }
            ShaSize::ThreeEightyFour => {
                signature::verify(
                    &signature::RSA_PKCS1_2048_8192_SHA384,
                    public_key_der,
                    message,
                    signature,
                ).map_err(|Unspecified| VerificationError::BadSignature)?;
            }
            ShaSize::FiveTwelve => {
                signature::verify(
                    &signature::RSA_PKCS1_2048_8192_SHA512,
                    public_key_der,
                    message,
                    signature,
                ).map_err(|Unspecified| VerificationError::BadSignature)?;
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
