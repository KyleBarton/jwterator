use std::{time::{Duration, UNIX_EPOCH, SystemTime}, ops::Add};
use clap::Parser;
use jsonwebtoken::{encode, EncodingKey, Header as Hdr};
use serde_json::{Map, json};

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

  let now_seconds = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();

  let exp_time = SystemTime::now()
    .add(Duration::from_secs(
      args.expiration_hours as u64 * 60 * 60)
    );

  let mut claims = Map::new();

  claims.insert(String::from("aud"), json!(args.audience.clone()));
  claims.insert(String::from("iss"), json!(args.issuer.clone()));
  claims.insert(String::from("sub"), json!(args.subject.clone()));
  claims.insert(String::from("iat"), json!(now_seconds));
  claims.insert(String::from("nbf"), json!(now_seconds));
  claims.insert(String::from("exp"), json!(exp_time.duration_since(UNIX_EPOCH).unwrap().as_secs()));

  args.additional_claims.split(',')
    .for_each(|claim| {
      let mut split_claim = claim.split('=');
      claims.insert(
	split_claim.next().expect("Must have a claim name").to_string(),
	json!(split_claim.next().expect("Must have a claim value").to_string()),
      );
    });
  

  let token = encode(&Hdr::default(), &claims, &EncodingKey::from_secret(&args.secret.as_bytes())).unwrap();

  println!("Token: {}", token.as_str())
}
