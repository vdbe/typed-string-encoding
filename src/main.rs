use std::time::Duration;

use serde::{Deserialize, Serialize};
use typed_string_encoding::{
    jwt::{Claims, ClaimsDecoded, ClaimsSubTrait},
    v1, v2,
};

#[derive(Debug, Deserialize, Serialize)]
struct Subject1 {
    sub: String,
    name: String,
}

impl Subject1 {
    fn new(sub: String, name: String) -> Self {
        Self { sub, name }
    }
}

impl ClaimsSubTrait for Subject1 {
    const DURATION: u64 = Duration::from_secs(24 * 60 * 60).as_secs();

    fn secret<'a>() -> &'a [u8] {
        "secret".as_bytes()
    }
}

fn main() {
    println!("=== V1 ===");
    v1::main();

    println!("\n=== V2 ===");
    v2::main();

    println!("\n=== V3 ===");
    let subject1 = Subject1::new("1234567890".to_string(), "John Doe".to_string());
    let claim1 = Claims::new(subject1).unwrap();

    let token1 = claim1.token();
    println!("{}", &token1);

    let claim1: ClaimsDecoded<Subject1> = TryFrom::try_from(token1).unwrap();
    dbg!(&claim1);
    let subject1 = claim1.sub();
    dbg!(subject1);
}
