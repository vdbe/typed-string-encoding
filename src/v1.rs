use std::marker::PhantomData;

struct Secret1(String);
struct Secret2(usize);

struct EncodedSecret<T: Secret> {
    content: String,
    _type: PhantomData<T>,
}

trait Secret
where
    Self: Sized,
{
    fn encode(self) -> EncodedSecret<Self>;

    fn decode(secret: EncodedSecret<Self>) -> Self;
}

impl<T: Secret> EncodedSecret<T> {
    fn new(content: String) -> EncodedSecret<T> {
        EncodedSecret {
            content,
            _type: PhantomData,
        }
    }

    fn decode(self) -> T {
        T::decode(self)
    }
}

impl Secret for Secret1 {
    fn encode(self) -> EncodedSecret<Self> {
        EncodedSecret::new(self.0)
    }

    fn decode(secret: EncodedSecret<Self>) -> Self {
        eprintln!("Decoding to Secret1");
        Secret1(secret.content)
    }
}

impl Secret for Secret2 {
    fn encode(self) -> EncodedSecret<Self> {
        let content = format!("{}", self.0);
        EncodedSecret::new(content)
    }

    fn decode(secret: EncodedSecret<Self>) -> Self {
        eprintln!("Decoding to Secret2");
        Secret2(secret.content.parse().unwrap())
    }
}

pub fn main() {
    let secret1 = Secret1("toor123".into());
    let secret2 = Secret2(42);

    println!("{:?}, {:?}", secret1.0, secret2.0);

    let encoded_secret1 = secret1.encode();
    let encoded_secret2 = secret2.encode();

    let decoded_secret1 = encoded_secret1.decode();
    let decoded_secret2 = encoded_secret2.decode();

    println!("{:?}, {:?}", decoded_secret1.0, decoded_secret2.0);
}
