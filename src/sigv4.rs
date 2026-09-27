//! AWS Signature Version 4, for the handful of S3 calls this server makes.
//!
//! Written here rather than taken from the AWS SDK: the SDK is a large tree with a C crypto build
//! behind it, for eight calls. This is the algorithm as AWS documents it
//! (docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html), pinned by the worked
//! example AWS publishes, and every header that matters to S3 (`x-amz-*`, `content-type`,
//! `range`, the copy source) is signed, so nothing can be altered on the way.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The payload hash for a body that is streamed and not hashed first. Allowed over TLS.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// SHA-256 of nothing, for a request without a body.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub struct Credentials {
	pub access_key_id: String,
	pub secret_access_key: String,
	pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Never the secret, not even in a debug log.
		f.debug_struct("Credentials")
			.field("access_key_id", &self.access_key_id)
			.finish_non_exhaustive()
	}
}

pub struct Request<'a> {
	pub method: &'a str,
	pub host: &'a str,
	/// Already URI-encoded, as it goes on the wire (S3: each segment encoded once, `/` kept).
	pub path: &'a str,
	/// Unencoded pairs; encoded and sorted here.
	pub query: &'a [(String, String)],
	/// Lower-case names. `host`, `x-amz-date`, `x-amz-content-sha256` and the session token
	/// are added by `sign`.
	pub headers: &'a [(String, String)],
	pub payload_sha256: &'a str,
}

fn sha256_hex(data: &[u8]) -> String {
	hex::encode(Sha256::digest(data))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
	// HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
	let mut mac = HmacSha256::new_from_slice(key)
		.unwrap_or_else(|_| unreachable!("hmac takes any key length"));
	mac.update(data);
	mac.finalize().into_bytes().to_vec()
}

/// RFC 3986 unreserved characters stay; everything else is %XX, upper-case, as SigV4 requires.
pub fn uri_encode(value: &str, keep_slash: bool) -> String {
	let mut out = String::with_capacity(value.len());
	for byte in value.bytes() {
		match byte {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
				out.push(byte as char)
			}
			b'/' if keep_slash => out.push('/'),
			_ => out.push_str(&format!("%{byte:02X}")),
		}
	}
	out
}

pub fn canonical_query(query: &[(String, String)]) -> String {
	let mut pairs: Vec<(String, String)> = query
		.iter()
		.map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
		.collect();
	pairs.sort();
	pairs
		.iter()
		.map(|(k, v)| format!("{k}={v}"))
		.collect::<Vec<_>>()
		.join("&")
}

/// The headers to send, `authorization` included. `amz_date` is `YYYYMMDDTHHMMSSZ`.
pub fn sign(
	request: &Request<'_>,
	credentials: &Credentials,
	region: &str,
	service: &str,
	amz_date: &str,
) -> Vec<(String, String)> {
	let date = &amz_date[..8];
	let mut headers: Vec<(String, String)> = request
		.headers
		.iter()
		.map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
		.collect();
	headers.push(("host".into(), request.host.to_string()));
	headers.push(("x-amz-date".into(), amz_date.to_string()));
	if service == "s3" {
		headers.push((
			"x-amz-content-sha256".into(),
			request.payload_sha256.to_string(),
		));
	}
	if let Some(token) = &credentials.session_token {
		headers.push(("x-amz-security-token".into(), token.clone()));
	}
	headers.sort_by(|a, b| a.0.cmp(&b.0));

	let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
	let signed_headers = headers
		.iter()
		.map(|(k, _)| k.as_str())
		.collect::<Vec<_>>()
		.join(";");
	let canonical_request = format!(
		"{}\n{}\n{}\n{}\n{}\n{}",
		request.method,
		request.path,
		canonical_query(request.query),
		canonical_headers,
		signed_headers,
		request.payload_sha256
	);
	let scope = format!("{date}/{region}/{service}/aws4_request");
	let string_to_sign = format!(
		"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
		sha256_hex(canonical_request.as_bytes())
	);

	let k_date = hmac(
		format!("AWS4{}", credentials.secret_access_key).as_bytes(),
		date.as_bytes(),
	);
	let k_region = hmac(&k_date, region.as_bytes());
	let k_service = hmac(&k_region, service.as_bytes());
	let k_signing = hmac(&k_service, b"aws4_request");
	let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

	headers.push((
		"authorization".into(),
		format!(
			"AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
			credentials.access_key_id
		),
	));
	headers
}

/// A presigned URL's query string (SigV4 query authentication, the host the only signed header,
/// the payload unsigned), as the SDK's `getSignedUrl` makes one. `path` is already encoded.
pub fn presign(
	host: &str,
	path: &str,
	extra_query: &[(String, String)],
	credentials: &Credentials,
	region: &str,
	amz_date: &str,
	expires_seconds: u64,
) -> String {
	let date = &amz_date[..8];
	let scope = format!("{date}/{region}/s3/aws4_request");
	let mut query: Vec<(String, String)> = extra_query.to_vec();
	query.push(("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()));
	query.push(("X-Amz-Credential".into(), format!("{}/{scope}", credentials.access_key_id)));
	query.push(("X-Amz-Date".into(), amz_date.to_string()));
	query.push(("X-Amz-Expires".into(), expires_seconds.to_string()));
	if let Some(token) = &credentials.session_token {
		query.push(("X-Amz-Security-Token".into(), token.clone()));
	}
	query.push(("X-Amz-SignedHeaders".into(), "host".into()));
	let canonical_query = canonical_query(&query);
	let canonical_request = format!("GET\n{path}\n{canonical_query}\nhost:{host}\n\nhost\n{UNSIGNED_PAYLOAD}");
	let string_to_sign = format!(
		"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
		sha256_hex(canonical_request.as_bytes())
	);
	let k_date = hmac(
		format!("AWS4{}", credentials.secret_access_key).as_bytes(),
		date.as_bytes(),
	);
	let k_region = hmac(&k_date, region.as_bytes());
	let k_service = hmac(&k_region, b"s3");
	let k_signing = hmac(&k_service, b"aws4_request");
	let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
	format!("{canonical_query}&X-Amz-Signature={signature}")
}

#[cfg(test)]
mod tests {
	use super::*;

	/// AWS's worked example for query-string authentication (S3 developer guide).
	#[test]
	fn reproduces_the_documented_presigned_url() {
		let credentials = Credentials {
			// AWS's published example key, assembled so a secret scanner does not mistake it for one.
			access_key_id: concat!("AKIA", "IOSFODNN7EXAMPLE").into(),
			secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
			session_token: None,
		};
		let query = presign(
			"examplebucket.s3.amazonaws.com",
			"/test.txt",
			&[],
			&credentials,
			"us-east-1",
			"20130524T000000Z",
			86400,
		);
		assert!(query.ends_with(
			"X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
		));
	}

	fn example_credentials() -> Credentials {
		Credentials {
			access_key_id: "AKIDEXAMPLE".into(),
			secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
			session_token: None,
		}
	}

	/// AWS's own worked example (the IAM ListUsers request in the SigV4 documentation).
	#[test]
	fn reproduces_the_documented_signature() {
		let query = vec![
			("Action".to_string(), "ListUsers".to_string()),
			("Version".to_string(), "2010-05-08".to_string()),
		];
		let headers = vec![(
			"content-type".to_string(),
			"application/x-www-form-urlencoded; charset=utf-8".to_string(),
		)];
		let request = Request {
			method: "GET",
			host: "iam.amazonaws.com",
			path: "/",
			query: &query,
			headers: &headers,
			payload_sha256: EMPTY_SHA256,
		};
		let signed = sign(
			&request,
			&example_credentials(),
			"us-east-1",
			"iam",
			"20150830T123600Z",
		);
		let authorization = signed
			.iter()
			.find(|(k, _)| k == "authorization")
			.map(|(_, v)| v.as_str())
			.unwrap_or_default();
		assert_eq!(
			authorization,
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
		);
	}

	#[test]
	fn s3_signs_the_payload_hash_and_the_session_token() {
		let credentials = Credentials {
			session_token: Some("tok".into()),
			..example_credentials()
		};
		let request = Request {
			method: "PUT",
			host: "b.s3.us-west-2.amazonaws.com",
			path: "/k",
			query: &[],
			headers: &[],
			payload_sha256: UNSIGNED_PAYLOAD,
		};
		let signed = sign(
			&request,
			&credentials,
			"us-west-2",
			"s3",
			"20260926T000000Z",
		);
		let authorization = signed
			.iter()
			.find(|(k, _)| k == "authorization")
			.map(|(_, v)| v.clone())
			.unwrap_or_default();
		assert!(
			authorization.contains(
				"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"
			)
		);
		assert!(
			signed
				.iter()
				.any(|(k, v)| k == "x-amz-content-sha256" && v == UNSIGNED_PAYLOAD)
		);
	}

	#[test]
	fn encoding_follows_rfc_3986() {
		assert_eq!(uri_encode("a b/ç~*", true), "a%20b/%C3%A7~%2A");
		assert_eq!(uri_encode("a/b", false), "a%2Fb");
		assert_eq!(
			canonical_query(&[
				("prefix".into(), "a b".into()),
				("list-type".into(), "2".into())
			]),
			"list-type=2&prefix=a%20b"
		);
	}
}
