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

use ring::{digest, hmac, signature};
use ring::error::Unspecified;
use base64::decode;
use untrusted::Input;

use prelude::*;
use super::{ShaSize, SignatureAlgorithm, REQUEST_TARGET};
use error::{DecodeError, VerificationError};

const KEY_ID: &str = "keyId";
const HEADERS: &str = "headers";
const ALGORITHM: &str = "algorithm";
const DATE: &str = "date";
const SIGNATURE: &str = "signature";

/// The `SignedHeader` struct is the direct reasult of reading in the Authorization or Signature
/// header from a given request.
///
/// It contains the keys to the request's headers in the correct order for recreating the signing
/// string, the algorithm used to create the signature, and the signature itself.
///
/// It also contains the `key_id`, which will be handled by a type implementing `GetKey`.
#[derive(Debug)]
pub struct SignedHeader<'a> {
    key_id: &'a str,
    header_keys: Vec<&'a str>,
    algorithm: SignatureAlgorithm,
    signature: Vec<u8>,
}

impl<'a> SignedHeader<'a> {
    /// Try to create an `SignedHeader` from a given String.
    pub fn new(s: &'a str) -> Result<Self, DecodeError> {
        s.try_into()
    }

    /// Try to verify the current `SignedHeader`.
    pub fn verify<G>(
        self,
        headers: &[(&str, &str)],
        method: &str,
        path: &str,
        query: Option<&str>,
        key_getter: G,
    ) -> Result<(), VerificationError>
    where
        G: GetKey,
    {
        let vah = CheckSignedHeader {
            auth_header: self,
            headers: headers,
            method: method,
            path: path,
            query: query,
        };

        vah.verify(key_getter)
    }
}

impl<'a> TryFrom<&'a str> for SignedHeader<'a> {
    type Error = DecodeError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let s = s.trim_left_matches("Signature ");
        let key_value = s.split(',')
            .filter_map(|item| {
                let eq_index = item.find('=')?;
                let tup = item.split_at(eq_index);
                let val = tup.1.get(1..)?;
                Some((tup.0, val))
            })
            .collect::<HashMap<&str, &str>>();

        let key_id = key_value
            .get(KEY_ID)
            .ok_or(DecodeError::MissingKey(KEY_ID))?
            .trim_left_matches('"')
            .trim_right_matches('"');

        let header_keys = key_value
            .get(HEADERS)
            .unwrap_or(&DATE)
            .trim_left_matches('"')
            .trim_right_matches('"')
            .split(' ')
            .collect();

        let algorithm = (*key_value
            .get(ALGORITHM)
            .ok_or(DecodeError::MissingKey(ALGORITHM))?
            .trim_left_matches('"')
            .trim_right_matches('"'))
            .parse()?;

        let sig_string: String = key_value
            .get(SIGNATURE)
            .ok_or(DecodeError::MissingKey(SIGNATURE))?
            .trim_left_matches('"')
            .trim_right_matches('"')
            .into();

        let signature = decode(&sig_string).map_err(|_| DecodeError::NotBase64)?;

        Ok(SignedHeader {
            key_id,
            header_keys,
            algorithm,
            signature,
        })
    }
}

#[derive(Debug)]
struct CheckSignedHeader<'a> {
    auth_header: SignedHeader<'a>,
    headers: &'a [(&'a str, &'a str)],
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
}

impl<'a> CheckSignedHeader<'a> {
    pub fn verify<G>(&self, key_getter: G) -> Result<(), VerificationError>
    where
        G: GetKey,
    {
        let key: G::Key = key_getter
            .get_key(self.auth_header.key_id)
            .map_err(|_| VerificationError::GetKey)?;

        let headers: HashMap<String, Vec<&str>> = self.headers.iter().fold(
            HashMap::new(),
            |mut acc, &(key, value)| {
                acc.entry(key.to_lowercase())
                    .or_insert_with(Vec::new)
                    .push(value);

                acc
            },
        );

        let mut headers: HashMap<&str, String> = headers
            .iter()
            .map(|(key, value)| (key.as_ref(), value.join(", ")))
            .collect();

        headers.insert(
            REQUEST_TARGET,
            if let Some(query) = self.query {
                format!("{} {}?{}", self.method.to_lowercase(), self.path, query,)
            } else {
                format!("{} {}", self.method.to_lowercase(), self.path,)
            },
        );

        let signing_vec = self.auth_header.header_keys.iter().fold(
            (Vec::new(), Vec::new()),
            |mut acc, header_key| {
                if let Some(header) = headers.get(header_key) {
                    acc.0.push(format!("{}: {}", header_key, header));
                } else {
                    acc.1.push(header_key.to_owned());
                }

                acc
            },
        );

        if !signing_vec.1.is_empty() {
            return Err(VerificationError::MissingHeaders(signing_vec.1.join(", ")));
        }

        let signing_string = signing_vec.0.join("\n");

        match self.auth_header.algorithm {
            SignatureAlgorithm::RSA(ref sha_size) => Self::verify_rsa(
                key,
                sha_size,
                signing_string.as_bytes(),
                &self.auth_header.signature,
            ),
            SignatureAlgorithm::HMAC(ref sha_size) => Self::verify_hmac(
                key,
                sha_size,
                signing_string.as_bytes(),
                &self.auth_header.signature,
            ),
        }
    }

    fn verify_rsa<T>(
        mut key: T,
        sha_size: &ShaSize,
        signing_string: &[u8],
        sig: &[u8],
    ) -> Result<(), VerificationError>
    where
        T: Read,
    {
        // Verify the signature.
        let mut public_key_der = Vec::new();
        key.read_to_end(&mut public_key_der)
            .map_err(|_| VerificationError::ReadKey)?;
        let public_key_der = Input::from(&public_key_der);
        let message = Input::from(signing_string);
        let signature = Input::from(sig);

        match *sha_size {
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
        sha_size: &ShaSize,
        signing_string: &[u8],
        sig: &[u8],
    ) -> Result<(), VerificationError>
    where
        T: Read,
    {
        let mut hmac_key = Vec::new();
        key.read_to_end(&mut hmac_key)
            .map_err(|_| VerificationError::ReadKey)?;
        let hmac_key = hmac::SigningKey::new(
            match *sha_size {
                ShaSize::TwoFiftySix => &digest::SHA256,
                ShaSize::ThreeEightyFour => &digest::SHA384,
                ShaSize::FiveTwelve => &digest::SHA512,
            },
            &hmac_key,
        );

        hmac::verify_with_own_key(&hmac_key, signing_string, sig)
            .map_err(|_| VerificationError::BadSignature)?;

        Ok(())
    }
}
