use std::{fmt::Debug, marker::PhantomData};

#[derive(Debug)]
struct Encoded(String);
#[derive(Debug)]
struct Decoded<T: Debug>(T);

#[derive(Debug)]
struct Secret<T: SecretTrait, State = Decoded<T>> {
    content: State,
    _type: PhantomData<T>,
}

/// Placeholder for `serde::Serialize`
trait Serialize {
    fn serialize(self) -> String;
}

/// Placeholder for `serde::Deserialize`
trait Deserialize {
    fn deserialize(value: String) -> Self;
}

trait SecretTrait: Serialize + Deserialize + Debug + Clone {}

impl<T: SecretTrait> Secret<T> {
    fn new(secret: T) -> Secret<T, Decoded<T>> {
        Secret {
            content: Decoded(secret),
            _type: PhantomData,
        }
    }
}

impl<T: SecretTrait> Secret<T, Encoded> {
    fn decode(self) -> Secret<T, Decoded<T>> {
        let string = self.content.0;

        // Decrypt/verify string/jwt token/secret

        Secret {
            content: Decoded(T::deserialize(string)),
            _type: PhantomData,
        }
    }

    fn encoded_secret(&self) -> String {
        // Clone for demonstration
        self.content.0.clone()
    }
}

impl<T: SecretTrait> Secret<T, Decoded<T>> {
    fn encode(self) -> Secret<T, Encoded> {
        let serialized = T::serialize(self.content.0);

        // Encrypt/sign `serialized`

        Secret {
            content: Encoded(serialized),
            _type: PhantomData,
        }
    }

    fn secret(&self) -> T {
        // Clone for demonstration
        self.content.0.clone()
    }
}

#[derive(Debug, Clone)]
struct Secret1(String);
#[derive(Debug, Clone)]
struct Secret2(usize);

impl SecretTrait for Secret1 {}
impl SecretTrait for Secret2 {}

impl Deserialize for Secret1 {
    fn deserialize(value: String) -> Self {
        Self(value)
    }
}
impl Serialize for Secret1 {
    fn serialize(self) -> String {
        self.0
    }
}

impl Deserialize for Secret2 {
    fn deserialize(value: String) -> Self {
        Self(value.parse().unwrap())
    }
}
impl Serialize for Secret2 {
    fn serialize(self) -> String {
        format!("{}", self.0)
    }
}

pub fn main() {
    let secret_1 = Secret::new(Secret1("secret_1".into()));
    let secret_2 = Secret::new(Secret2(42));

    println!("{:?}, {:?}", secret_1.secret(), secret_2.secret());

    //secret_1.decode(); // no method named `decode`
    //secret_2.decode(); // no method named `decode`

    let secret_1 = secret_1.encode();
    let secret_2 = secret_2.encode();

    println!(
        "{:?}, {:?}",
        secret_1.encoded_secret(),
        secret_2.encoded_secret()
    );

    //secret_1.encode(); // no method named `encode`
    //secret_2.encode(); // no method named `encode`

    let secret_1 = secret_1.decode();
    let secret_2 = secret_2.decode();

    println!("{:?}, {:?}", secret_1.secret(), secret_2.secret());
}