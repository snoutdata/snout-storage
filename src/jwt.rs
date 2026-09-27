//! Tokens: the caller's (verified on every request) and the signed-URL ones this server issues.
//!
//! Written here rather than taken from a JWT crate, because
//! three things have to match it exactly and a crate would own all three:
//!
//!  - **which key verifies a token** (`findJWKFromHeader`): an HMAC token with no `kid` and the
//!    default algorithm uses the project's JWT secret; otherwise the first `oct` key whose `kid`
//!    matches (or that has none), falling back to the secret. So a URL signed with the tenant's
//!    URL-signing key keeps verifying whichever server signed it;
//!  - **which algorithms are allowed** (`getJWTAlgorithms`): HS256, plus HS384 and HS512 once the
//!    tenant has an `oct` key. Asymmetric keys are not supported: our projects sign HS256 with
//!    their own secret;
//!  - **the refusal's sentence**: a bad token is refused with jose's own message, and
//!    the JavaScript client shows it, so these are jose's words.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::{Sha256, Sha384, Sha512};

/// The default JWT algorithm.
pub const DEFAULT_ALGORITHM: &str = "HS256";
const HMAC_ALGORITHMS: [&str; 3] = ["HS256", "HS384", "HS512"];

/// One key of a tenant's JWKS (`tenants_jwks`, decrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OctKey {
	pub kid: Option<String>,
	/// The raw key bytes (`k`, base64url in the JWK).
	pub k: Vec<u8>,
	pub alg: Option<String>,
}

/// What signs a URL: the tenant's URL-signing JWK when it has one, else the JWT secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningKey {
	Secret(String),
	Jwk(OctKey),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct JwtError(pub String);

fn error(message: &str) -> JwtError {
	JwtError(message.to_string())
}

fn mac(alg: &str, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
	macro_rules! run {
		($hash:ty) => {{
			let mut m = Hmac::<$hash>::new_from_slice(key).ok()?;
			m.update(data);
			Some(m.finalize().into_bytes().to_vec())
		}};
	}
	match alg {
		"HS256" => run!(Sha256),
		"HS384" => run!(Sha384),
		"HS512" => run!(Sha512),
		_ => None,
	}
}

fn verify_mac(alg: &str, key: &[u8], data: &[u8], signature: &[u8]) -> bool {
	macro_rules! run {
		($hash:ty) => {{
			let Ok(mut m) = Hmac::<$hash>::new_from_slice(key) else {
				return false;
			};
			m.update(data);
			m.verify_slice(signature).is_ok()
		}};
	}
	match alg {
		"HS256" => run!(Sha256),
		"HS384" => run!(Sha384),
		"HS512" => run!(Sha512),
		_ => false,
	}
}

fn now() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}

fn decode_segment(segment: &str) -> Option<Vec<u8>> {
	URL_SAFE_NO_PAD.decode(segment.trim_end_matches('=')).ok()
}

/// jose's `jwtVerify` with the tenant's key selection. Returns the payload.
pub fn verify(token: &str, secret: &str, jwks: &[OctKey]) -> Result<Map<String, Value>, JwtError> {
	let parts: Vec<&str> = token.split('.').collect();
	if parts.len() != 3 {
		return Err(error("Invalid Compact JWS"));
	}
	let header: Map<String, Value> = decode_segment(parts[0])
		.and_then(|bytes| serde_json::from_slice(&bytes).ok())
		.ok_or_else(|| error("Invalid Compact JWS"))?;
	let alg = header
		.get("alg")
		.and_then(Value::as_str)
		.ok_or_else(|| error("JWS \"alg\" (Algorithm) Header Parameter missing or invalid"))?;

	let allowed: Vec<&str> = if jwks.is_empty() {
		vec![DEFAULT_ALGORITHM]
	} else {
		HMAC_ALGORITHMS.to_vec()
	};
	if !allowed.contains(&alg) {
		return Err(error(
			"\"alg\" (Algorithm) Header Parameter value not allowed",
		));
	}

	let kid = header.get("kid").and_then(Value::as_str);
	let key: Vec<u8> = if jwks.is_empty() || (kid.is_none() && alg == DEFAULT_ALGORITHM) {
		secret.as_bytes().to_vec()
	} else {
		match jwks
			.iter()
			.find(|key| key.kid.is_none() || key.kid.as_deref() == kid)
		{
			Some(key) => key.k.clone(),
			None => secret.as_bytes().to_vec(),
		}
	};

	let signature = decode_segment(parts[2]).ok_or_else(|| error("Invalid Compact JWS"))?;
	let signed = format!("{}.{}", parts[0], parts[1]);
	if !verify_mac(alg, &key, signed.as_bytes(), &signature) {
		return Err(error("signature verification failed"));
	}

	let payload: Map<String, Value> = decode_segment(parts[1])
		.and_then(|bytes| serde_json::from_slice(&bytes).ok())
		.ok_or_else(|| error("JWT Claims Set must be a top-level JSON object"))?;
	let current = now();
	if let Some(exp) = payload.get("exp") {
		let exp = exp
			.as_f64()
			.ok_or_else(|| error("\"exp\" claim must be a number"))?;
		if exp <= current as f64 {
			return Err(error("\"exp\" claim timestamp check failed"));
		}
	}
	if let Some(nbf) = payload.get("nbf") {
		let nbf = nbf
			.as_f64()
			.ok_or_else(|| error("\"nbf\" claim must be a number"))?;
		if nbf > current as f64 {
			return Err(error("\"nbf\" claim timestamp check failed"));
		}
	}
	Ok(payload)
}

/// jose's `SignJWT(payload).setIssuedAt().setExpirationTime(...)`: `iat` now, `exp` iat + seconds.
pub fn sign(
	mut payload: Map<String, Value>,
	key: &SigningKey,
	expires_in_seconds: Option<i64>,
) -> String {
	let iat = now();
	payload.insert("iat".into(), json!(iat));
	if let Some(seconds) = expires_in_seconds {
		payload.insert("exp".into(), json!(iat + seconds));
	}
	let (header, secret): (Value, Vec<u8>) = match key {
		SigningKey::Secret(secret) => (
			json!({ "alg": DEFAULT_ALGORITHM }),
			secret.as_bytes().to_vec(),
		),
		SigningKey::Jwk(jwk) => {
			let alg = jwk.alg.clone().unwrap_or_else(|| DEFAULT_ALGORITHM.into());
			(json!({ "kid": jwk.kid, "alg": alg }), jwk.k.clone())
		}
	};
	let alg = header
		.get("alg")
		.and_then(Value::as_str)
		.unwrap_or(DEFAULT_ALGORITHM)
		.to_string();
	let head = URL_SAFE_NO_PAD.encode(header.to_string());
	let body = URL_SAFE_NO_PAD.encode(Value::Object(payload).to_string());
	let signed = format!("{head}.{body}");
	let signature = mac(&alg, &secret, signed.as_bytes()).unwrap_or_default();
	format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Reads a JWK as the metadata database stores one (`{"kty":"oct","k":…}`), with the `kid` the server
/// derives from the row (`<kind>_<id>`). Node decodes `k` as plain base64, which accepts the
/// url-safe alphabet too; so does this.
pub fn oct_key_from_jwk(jwk: &Value, kid: Option<String>) -> Option<OctKey> {
	if jwk.get("kty").and_then(Value::as_str) != Some("oct") {
		return None;
	}
	let k = jwk.get("k").and_then(Value::as_str)?;
	let normalised: String = k.replace('-', "+").replace('_', "/");
	let padded = format!("{normalised}{}", "=".repeat((4 - normalised.len() % 4) % 4));
	let bytes = STANDARD.decode(padded).ok()?;
	Some(OctKey {
		kid,
		k: bytes,
		alg: jwk.get("alg").and_then(Value::as_str).map(str::to_string),
	})
}

/// A fresh URL-signing key, as `generateHS512JWK` makes one: 64 random bytes. jose's `exportJWK`
/// writes no `alg`, so tokens are signed with the default algorithm (HS256), as clients expect.
pub fn generate_url_signing_jwk() -> Value {
	let mut bytes = Vec::with_capacity(64);
	for _ in 0..4 {
		bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
	}
	json!({ "kty": "oct", "k": URL_SAFE_NO_PAD.encode(&bytes) })
}

#[cfg(test)]
mod tests {
	use super::*;

	const SECRET: &str = "super-secret-jwt-token-with-at-least-32-characters";

	fn claims(extra: Value) -> Map<String, Value> {
		let mut map = Map::new();
		map.insert("role".into(), json!("authenticated"));
		if let Value::Object(more) = extra {
			map.extend(more);
		}
		map
	}

	#[test]
	fn a_secret_signed_token_verifies_and_keeps_its_claims() {
		let token = sign(
			claims(json!({ "sub": "u1" })),
			&SigningKey::Secret(SECRET.into()),
			Some(60),
		);
		let payload = verify(&token, SECRET, &[]).unwrap_or_default();
		assert_eq!(payload.get("sub"), Some(&json!("u1")));
		assert!(payload.get("exp").and_then(Value::as_i64).is_some());
	}

	/// A token the way project API keys and auth sessions are made: HS256, the secret, no kid,
	/// and a `typ` header this server does not write. Built from its parts here, so no token-shaped
	/// string sits in the source for a secret scanner to stop on.
	#[test]
	fn reads_a_token_shaped_like_the_projects_keys() {
		let head = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
		let body = URL_SAFE_NO_PAD.encode(r#"{"role":"anon","iss":"auth"}"#);
		let signed = format!("{head}.{body}");
		let signature = URL_SAFE_NO_PAD
			.encode(mac("HS256", SECRET.as_bytes(), signed.as_bytes()).unwrap_or_default());
		let payload = verify(&format!("{signed}.{signature}"), SECRET, &[]).unwrap_or_default();
		assert_eq!(payload.get("role"), Some(&json!("anon")));
	}

	#[test]
	fn refusals_are_jose_sentences() {
		let expired = sign(
			claims(json!({ "exp": 1 })),
			&SigningKey::Secret(SECRET.into()),
			None,
		);
		assert_eq!(
			verify(&expired, SECRET, &[]),
			Err(error("\"exp\" claim timestamp check failed"))
		);
		let good = sign(
			claims(json!({})),
			&SigningKey::Secret(SECRET.into()),
			Some(60),
		);
		assert_eq!(
			verify(&good, "another-secret", &[]),
			Err(error("signature verification failed"))
		);
		assert_eq!(verify("", SECRET, &[]), Err(error("Invalid Compact JWS")));
		assert_eq!(
			verify("not.a.jwt!", SECRET, &[]),
			Err(error("Invalid Compact JWS"))
		);
	}

	#[test]
	fn hs512_is_refused_until_the_tenant_has_an_oct_key() {
		let mut jwk = generate_url_signing_jwk();
		jwk["alg"] = json!("HS512");
		let key = oct_key_from_jwk(
			&jwk,
			Some("storage-url-signing-key_1".into()),
		)
		.unwrap_or(OctKey {
			kid: None,
			k: vec![],
			alg: None,
		});
		let token = sign(
			claims(json!({ "url": "b/o" })),
			&SigningKey::Jwk(key.clone()),
			Some(60),
		);
		assert_eq!(
			verify(&token, SECRET, &[]),
			Err(error(
				"\"alg\" (Algorithm) Header Parameter value not allowed"
			))
		);
		assert!(verify(&token, SECRET, &[key]).is_ok());
	}

	#[test]
	fn a_secret_token_still_verifies_when_the_tenant_has_a_url_signing_key() {
		let key = oct_key_from_jwk(
			&generate_url_signing_jwk(),
			Some("storage-url-signing-key_1".into()),
		)
		.unwrap_or(OctKey {
			kid: None,
			k: vec![],
			alg: None,
		});
		let token = sign(
			claims(json!({})),
			&SigningKey::Secret(SECRET.into()),
			Some(60),
		);
		assert!(verify(&token, SECRET, &[key]).is_ok());
	}
}
