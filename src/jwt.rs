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
    /// The time before expiry from now in seconds
    const DURATION: u64;

    /// The secret key used for encoding and decoding the Subject.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    const DEFAULT: u32 = 0;
    const EXPIRED_TOKEN: u32 = 1;
    const DIFFRENT_SECRETS: u32 = 2;

    // A struct for testing purposes
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    pub struct GenericTestSub<const TEST: u32> {
        id: String,
        name: String,
    }

    impl ClaimsSubTrait for GenericTestSub<DEFAULT> {
        const DURATION: u64 = 60 * 60; // 1 hour

        fn secret<'a>() -> &'a [u8] {
            b"test_secret"
        }
    }

    impl ClaimsSubTrait for GenericTestSub<EXPIRED_TOKEN> {
        const DURATION: u64 = 1; // 1 second

        fn secret<'a>() -> &'a [u8] {
            b"test_secret"
        }
    }
    impl ClaimsSubTrait for GenericTestSub<DIFFRENT_SECRETS> {
        const DURATION: u64 = 60 * 60; // 1 hour

        fn secret<'a>() -> &'a [u8] {
            b"different_test_secret"
        }
    }

    #[test]
    fn test_encode_decode() {
        type TestSub = GenericTestSub<DEFAULT>;

        let claims: TestSub = TestSub {
            id: "123".to_string(),
            name: "John".to_string(),
        };

        let encoded_claims = Claims::new(claims).unwrap();
        let decoded_claims: ClaimsDecoded<TestSub> = encoded_claims.token().try_into().unwrap();

        let sub = decoded_claims.sub();

        assert_eq!(sub.id, "123");
        assert_eq!(sub.name, "John");
    }

    #[test]
    fn test_claims() {
        type TestSub = GenericTestSub<DEFAULT>;

        let claims: TestSub = TestSub {
            id: "123".to_string(),
            name: "John".to_string(),
        };

        let iat_min = OffsetDateTime::now_utc().unix_timestamp();
        let encoded_claims = Claims::new(claims).unwrap();
        let iat_max = OffsetDateTime::now_utc().unix_timestamp();
        let decoded_claims: ClaimsDecoded<TestSub> = encoded_claims.token().try_into().unwrap();

        let claims = decoded_claims.claims();

        assert!(claims.iat >= iat_min);
        assert!(claims.iat <= iat_max);

        assert_eq!(claims.iat + TestSub::DURATION as i64, claims.exp);
    }

    // TODO: Find a better way to test this than waiting 62 seconds
    #[test]
    fn test_expired_token() {
        type TestSub = GenericTestSub<EXPIRED_TOKEN>;
        let claims = TestSub {
            id: "123".to_string(),
            name: "John".to_string(),
        };

        let encoded_claims = Claims::new(claims).unwrap();

        std::thread::sleep(Duration::from_secs(2)); // Wait for token to expire
        std::thread::sleep(Duration::from_secs(60)); // Wait for the leeway in validation to pass

        let result: Result<ClaimsDecoded<TestSub>> = encoded_claims.token().try_into();

        assert!(result.is_err());
    }

    #[test]
    fn test_diffrent_secrets() {
        type TestSub1 = GenericTestSub<DEFAULT>;
        type TestSub2 = GenericTestSub<DIFFRENT_SECRETS>;

        let sub1 = TestSub1 {
            id: "123".to_string(),
            name: "John".to_string(),
        };
        let sub2 = TestSub2 {
            id: "123".to_string(),
            name: "John".to_string(),
        };

        let encoded_claims1_0 = Claims::new(sub1.clone()).unwrap();
        let encoded_claims1_1 = Claims::new(sub1.clone()).unwrap();
        let encoded_claims2_0 = Claims::new(sub2.clone()).unwrap();
        let encoded_claims2_1 = Claims::new(sub2.clone()).unwrap();

        let result: Result<ClaimsDecoded<TestSub1>> = encoded_claims1_0.token().try_into();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub(), sub1);

        let result: Result<ClaimsDecoded<TestSub2>> = encoded_claims1_1.token().try_into();
        assert!(result.is_err());

        let result: Result<ClaimsDecoded<TestSub2>> = encoded_claims2_0.token().try_into();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub(), sub2);

        let result: std::result::Result<ClaimsDecoded<TestSub1>, Error> =
            encoded_claims2_1.token().try_into();
        assert!(result.is_err());
    }
}
