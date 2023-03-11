use std::{marker::PhantomData, time::Duration};

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error as ErrorTrait;
use time::OffsetDateTime;

#[derive(Debug, ErrorTrait)]
pub enum Error {
    #[error(transparent)]
    Jsonwebtoken(#[from] jsonwebtoken::errors::Error),
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

pub type ClaimsEncoded<T> = Claims<T, Encoded>;
pub type ClaimsDecoded<T> = Claims<T, Decoded<T>>;

pub trait ClaimsSubTrait: Serialize {
    const DURATION: u64;

    fn secret<'a>() -> &'a [u8];
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Encoded(String);

#[derive(Debug, Serialize, Deserialize)]
pub struct Decoded<T: ClaimsSubTrait> {
    #[serde(flatten)]
    pub(crate) sub: T,
    exp: i64,
    iat: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Claims<T: ClaimsSubTrait, State = Decoded<T>> {
    claims: State,
    #[serde(skip)]
    _type: PhantomData<T>,
}

impl<T: ClaimsSubTrait> Claims<T> {
    pub fn new(claims: T) -> Result<Claims<T, Encoded>> {
        let iat = OffsetDateTime::now_utc();
        let exp = iat + Duration::from_secs(T::DURATION);

        let claim = Self {
            claims: Decoded {
                sub: claims,
                exp: exp.unix_timestamp(),
                iat: iat.unix_timestamp(),
            },
            _type: PhantomData,
        };

        claim.encode()
    }
}

impl<T: ClaimsSubTrait> Claims<T, Encoded> {
    pub fn token(self) -> String {
        self.claims.0
    }
}

impl<T: ClaimsSubTrait> Claims<T, Decoded<T>> {
    fn encode(self) -> Result<Claims<T, Encoded>> {
        let header = Header::default();
        let claims = self.claims;
        let key = EncodingKey::from_secret(T::secret());

        let encoded_claim = jsonwebtoken::encode(&header, &claims, &key)?;

        Ok(Claims {
            claims: Encoded(encoded_claim),
            _type: PhantomData,
        })
    }

    pub fn claims(self) -> Decoded<T> {
        self.claims
    }

    pub fn sub(self) -> T {
        self.claims.sub
    }
}

impl<T: ClaimsSubTrait> Claims<T, Encoded> {
    pub fn decode(self) -> Result<Claims<T, Decoded<T>>>
    where
        Decoded<T>: DeserializeOwned,
    {
        let token = self.claims.0;
        let key = DecodingKey::from_secret(T::secret());
        let validation = Validation::default();

        let decoded_claims = jsonwebtoken::decode(token.as_str(), &key, &validation)?.claims;

        Ok(Claims {
            claims: decoded_claims,
            _type: PhantomData,
        })
    }
}

impl<T: ClaimsSubTrait> From<String> for Claims<T, Encoded> {
    fn from(value: String) -> Self {
        Self {
            claims: Encoded(value),
            _type: PhantomData,
        }
    }
}

impl<T> TryFrom<String> for ClaimsDecoded<T>
where
    T: ClaimsSubTrait,
    Decoded<T>: for<'a> Deserialize<'a>,
{
    type Error = Error;

    fn try_from(token: String) -> std::result::Result<Self, Self::Error> {
        let claims: ClaimsEncoded<T> = From::from(token);
        let claims = claims.decode()?;

        Ok(claims)
    }
}
