//! Every refusal, worded and sent the way existing clients expect.
//!
//! The storage API answers almost every refusal with **HTTP 400** and puts the real status in
//! the body (its `userStatusCode` is 400 unless the status is 500 or a factory overrides it). A 4xx
//! body is `{ statusCode, error, message }`: the routes' error schema drops `code`, and `error` is
//! the factory's legacy name when it has one (`Bucket not found`, `not_found`, `Duplicate`, ...)
//! and the code otherwise. A 5xx body has no schema and keeps `code`. `statusCode` is a STRING.
//! These are the words and shapes existing clients already match on.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageError {
	/// The status in the BODY (`statusCode`): the error's real meaning.
	pub status: u16,
	pub code: &'static str,
	pub message: String,
	/// The backwards-compatible `error` name, where the factory has one.
	pub legacy: Option<Cow<'static, str>>,
	/// The HTTP status when a factory overrides the rule (500 stays 500, else 400).
	pub http: Option<u16>,
	/// Sent with its `code` although it is a 4xx: the few routes with no response
	/// schema (list-v2, resumable uploads) do not strip it.
	pub keep_code: bool,
}

impl StorageError {
	pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
		Self {
			status,
			code,
			message: message.into(),
			legacy: None,
			http: None,
			keep_code: false,
		}
	}

	pub fn with_code(mut self) -> Self {
		self.keep_code = true;
		self
	}

	pub fn with_legacy_name(self, name: &'static str) -> Self {
		self.legacy(name)
	}

	fn legacy(mut self, name: &'static str) -> Self {
		self.legacy = Some(Cow::Borrowed(name));
		self
	}

	/// A legacy `error` known only at run time (an S3 error's own sentence).
	pub fn with_legacy_text(mut self, text: String) -> Self {
		self.legacy = Some(Cow::Owned(text));
		self
	}

	pub fn with_http(mut self, status: u16) -> Self {
		self.http = Some(status);
		self
	}

	/// The HTTP status sent: the override, else 500 for a 500, else 400.
	pub fn http_status(&self) -> u16 {
		self.http
			.unwrap_or(if self.status == 500 { 500 } else { 400 })
	}

	pub fn no_such_bucket() -> Self {
		Self::new(404, "NoSuchBucket", "Bucket not found").legacy("Bucket not found")
	}
	pub fn no_such_key() -> Self {
		Self::new(404, "NoSuchKey", "Object not found").legacy("not_found")
	}
	pub fn no_such_upload() -> Self {
		Self::new(404, "NoSuchUpload", "Upload not found")
	}
	pub fn bucket_not_empty() -> Self {
		Self::new(
			409,
			"ResourceNotEmpty",
			"The bucket you tried to delete is not empty",
		)
	}
	pub fn missing_parameter(parameter: &str) -> Self {
		Self::new(
			400,
			"MissingParameter",
			format!("Missing Required Parameter {parameter}"),
		)
	}
	pub fn invalid_parameter(parameter: &str) -> Self {
		Self::new(
			400,
			"InvalidParameter",
			format!("Invalid Parameter {parameter}"),
		)
	}
	pub fn invalid_request(message: impl Into<String>) -> Self {
		Self::new(400, "InvalidRequest", message)
	}
	pub fn invalid_jwt(message: impl Into<String>) -> Self {
		Self::new(400, "InvalidJWT", message)
	}
	pub fn missing_content_length() -> Self {
		Self::new(
			400,
			"MissingContentLength",
			"You must provide the Content-Length HTTP header.",
		)
	}
	pub fn access_denied(action: impl Into<String>) -> Self {
		Self::new(403, "AccessDenied", action).legacy("Unauthorized")
	}
	pub fn resource_already_exists() -> Self {
		Self::new(409, "ResourceAlreadyExists", "The resource already exists").legacy("Duplicate")
	}
	pub fn expired_signature() -> Self {
		Self::new(400, "ExpiredToken", "The provided token has expired.")
	}
	pub fn invalid_signature(message: impl Into<String>) -> Self {
		Self::new(400, "InvalidSignature", message)
	}
	pub fn invalid_tenant_id() -> Self {
		Self::new(400, "TenantNotFound", "Invalid tenant id")
	}
	pub fn missing_tenant_config(tenant: &str) -> Self {
		Self::new(
			400,
			"TenantNotFound",
			format!("Missing tenant config for tenant {tenant}"),
		)
	}
	pub fn invalid_mime_type(mime: &str) -> Self {
		Self::new(
			415,
			"InvalidMimeType",
			format!("mime type {mime} is not supported"),
		)
		.legacy("invalid_mime_type")
	}
	pub fn invalid_range() -> Self {
		Self::new(400, "InvalidRange", "invalid range provided").legacy("invalid_range")
	}
	pub fn entity_too_large() -> Self {
		Self::new(
			413,
			"EntityTooLarge",
			"The object exceeded the maximum allowed size",
		)
		.legacy("Payload too large")
	}
	pub fn internal() -> Self {
		Self::new(500, "InternalError", "Internal server error")
	}
	pub fn invalid_bucket_name() -> Self {
		Self::new(400, "InvalidBucketName", "Bucket name invalid").legacy("Invalid Input")
	}
	pub fn invalid_file_size_limit() -> Self {
		Self::new(
			400,
			"InvalidRequest",
			"Invalid file size format, hint: use 20GB / 20MB / 30KB / 3B",
		)
	}
	pub fn invalid_upload_signature() -> Self {
		Self::new(400, "InvalidUploadSignature", "Invalid upload Signature")
	}
	pub fn invalid_key(key: &str) -> Self {
		Self::new(400, "InvalidKey", format!("Invalid key: {key}"))
	}
	pub fn key_already_exists() -> Self {
		Self::new(409, "KeyAlreadyExists", "The resource already exists").legacy("Duplicate")
	}
	pub fn bucket_already_exists() -> Self {
		Self::new(409, "BucketAlreadyExists", "The resource already exists").legacy("Duplicate")
	}
	pub fn no_content_provided() -> Self {
		Self::new(400, "InvalidRequest", "No content provided")
	}
	/// No content provided, carrying the cause's message.
	pub fn no_content_provided_because(message: impl Into<String>) -> Self {
		Self::new(400, "InvalidRequest", message)
	}
	pub fn resource_locked() -> Self {
		Self::new(423, "ResourceLocked", "The resource is locked")
	}
	pub fn database_timeout() -> Self {
		Self::new(
			544,
			"DatabaseTimeout",
			"The connection to the database timed out",
		)
		.with_http(544)
	}
	pub fn database(message: impl Into<String>) -> Self {
		Self::new(500, "DatabaseError", message)
	}
	/// `/storage/v1/s3` (the S3-protocol endpoint) is not served.
	pub fn s3_protocol_not_supported() -> Self {
		Self::new(
			404,
			"NotSupported",
			"The S3-compatible endpoint is not available on this server",
		)
		.with_http(404)
	}
}

impl IntoResponse for StorageError {
	fn into_response(self) -> Response {
		let http = self.http_status();
		let status = StatusCode::from_u16(http).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
		let error = self.legacy.unwrap_or(Cow::Borrowed(self.code));
		let validation = self.code == "InternalError" && error == "Error";
		let body = if self.keep_code && validation && http < 500 {
			// Fastify's own refusal, in its own key order.
			json!({ "statusCode": self.status.to_string(), "error": error, "code": self.code, "message": self.message })
		} else if http >= 500 || self.keep_code {
			json!({ "statusCode": self.status.to_string(), "code": self.code, "error": error, "message": self.message })
		} else {
			json!({ "statusCode": self.status.to_string(), "error": error, "message": self.message })
		};
		(
			status,
			[(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
			body.to_string(),
		)
			.into_response()
	}
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[cfg(test)]
mod tests {
	use super::*;

	async fn body(error: StorageError) -> (u16, serde_json::Value) {
		let response = error.into_response();
		let status = response.status().as_u16();
		let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
			.await
			.unwrap_or_default();
		(status, serde_json::from_slice(&bytes).unwrap_or_default())
	}

	/// As recorded from the storage API clients are written against.
	#[tokio::test]
	async fn refusals_are_sent_the_way_clients_expect_them() {
		assert_eq!(
			body(StorageError::no_such_bucket()).await,
			(
				400,
				json!({ "statusCode": "404", "error": "Bucket not found", "message": "Bucket not found" })
			)
		);
		assert_eq!(
			body(StorageError::no_such_key()).await,
			(
				400,
				json!({ "statusCode": "404", "error": "not_found", "message": "Object not found" })
			)
		);
		assert_eq!(
			body(StorageError::entity_too_large()).await,
			(
				400,
				json!({ "statusCode": "413", "error": "Payload too large", "message": "The object exceeded the maximum allowed size" })
			)
		);
		assert_eq!(
			body(StorageError::invalid_key("")).await,
			(
				400,
				json!({ "statusCode": "400", "error": "InvalidKey", "message": "Invalid key: " })
			)
		);
		assert_eq!(
			body(StorageError::new(500, "InternalError", "Internal error")).await,
			(
				500,
				json!({ "statusCode": "500", "code": "InternalError", "error": "InternalError", "message": "Internal error" })
			)
		);
	}
}
