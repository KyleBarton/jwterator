use std::{time::{Duration, UNIX_EPOCH, SystemTime}, ops::Add};
use std::collections::BTreeMap;
use hmac::{Hmac, Mac};
use clap::Parser;
use jwt::{Header, Token, SignWithKey, header::HeaderType};
use sha2::Sha256;


#[derive(Parser, Debug)]
struct Args {
  #[arg(short, long)]
  audience: String,

  #[arg(short, long)]
  issuer: String,

  #[arg(short, long)]
  secret: String,

  #[arg(short, long, default_value_t=1)]
  expiration_hours: u8,

  #[arg(short='u', long)]
  subject: String,

  #[arg(short='c', long="claims", long_help="Any additional claims, comma-separated. Usage: -c claim1=claimvalue1,claim2=claimvalue2")]
  additional_claims: String,
}


fn main() {
  let args = Args::parse();

  let key : Hmac<Sha256> = Hmac::new_from_slice(
    format!("{}", &args.secret).as_bytes()
  ).expect("Must be a valid secret");



  let header = Header {
    algorithm: jwt::AlgorithmType::Hs256,
    type_: Some(HeaderType::JsonWebToken),
    ..Default::default()
  };

  let now_seconds = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();

  let mut claims = BTreeMap::new();

  claims.insert("aud", args.audience.clone());
  claims.insert("iss", args.issuer.clone());
  claims.insert("sub", args.subject.clone());
  claims.insert(
    "iat",
    now_seconds.to_string()
  );
  claims.insert(
    "nbf",
    now_seconds.to_string()
  );
  let exp_time = SystemTime::now()
    .add(Duration::from_secs(
      args.expiration_hours as u64 * 60 * 60)
    );
  claims.insert(
    "exp",
    exp_time
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs()
      .to_string()
  );

  args.additional_claims.split(',')
    .for_each(|claim| {
      let mut split_claim = claim.split('=');
      claims.insert(
	split_claim.next().expect("Must have a claim name"),
	split_claim.next().expect("Must have a claim value").to_string());
    });

  let token = Token::new(header, claims).sign_with_key(&key).expect("Should be able to creat token");

  println!("Token: {}", token.as_str())
}
