//! snout-storage: file storage for Postgres-backed apps, over S3, with row-level security deciding access.
//!
//! The storage HTTP API that existing JavaScript clients speak. Same routes,
//! same `storage` schema, same S3 key layout (`<tenant>/<bucket>/<name>/<version>`), same tenant
//! rows in the metadata database. It does not serve the S3-protocol endpoint.
//!
//! **The security core:** every object operation runs in the customer's own database AS THE
//! CALLER (`db.rs`: the role and the JWT claims set for the transaction), so their row-level
//! security policies decide. This server never decides access itself.

pub mod app;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod jwt;
pub mod limits;
pub mod migration_files;
pub mod migrations;
pub mod objects;
pub mod render;
pub mod s3;
pub mod sigv4;
pub mod tenants;
pub mod tus;

/// Entry points for the fuzz targets (`packages/stack/fuzz`): each parser of untrusted input,
/// called the way a request calls it. Not an API; nothing here is stable.
#[doc(hidden)]
pub mod fuzz {
	/// What a request carries in its headers, path and body fields.
	pub fn request(input: &str) {
		let _ = crate::tus::parse_metadata(input);
		let _ = crate::tus::UploadId::parse(input);
		let _ = crate::objects::decode_cursor(input);
		let _ = crate::objects::parse_user_metadata(input);
		let _ = crate::objects::content_disposition(input);
		let _ = crate::limits::is_valid_bucket_name(input);
		let _ = crate::limits::is_valid_key(input);
		let _ = crate::limits::parse_file_size(input);
		let _ = crate::limits::mime_allowed(input, &["image/*".into(), "text/plain".into()]);
		let _ = crate::s3::parse_http_date(input);
		let _ = crate::app::decode_unverified(input);
	}

	/// A bearer token, against a secret and no JWKS.
	pub fn token(input: &str) {
		let _ = crate::jwt::verify(input, "a-secret-of-at-least-32-characters!!", &[]);
	}

	/// What S3 (or anything answering as S3) sends back.
	pub fn s3_response(input: &str) {
		let _ = crate::s3::xml_tag(input, "Code");
		let _ = crate::s3::xml_blocks(input, "Part");
		let _ = crate::s3::xml_unescape(input);
	}
}
