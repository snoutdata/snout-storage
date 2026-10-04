//! The S3 calls this server makes, signed by `sigv4.rs` and sent with reqwest.
//!
//! Keys are `<tenant>/<bucket>/<name>/<version>`, and an upload is
//! what its `@aws-sdk/lib-storage` upload does: a body shorter than one part is a single
//! `PutObject`, anything longer is a multipart upload of `part_size` parts with `queue_size` in
//! flight, then a `HeadObject` whose answer is the metadata recorded on the row.
//!
//! **Credentials, in the AWS SDK's default order**, re-read whenever the cached ones are within five
//! minutes of expiring:
//! 1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` (local, MinIO);
//! 2. the profile in `AWS_CONFIG_FILE` (`AWS_PROFILE`, else `default`): its `credential_process`,
//!    which is how a host hands this container one-hour credentials scoped to its bucket
//!    (SnoutData Cloud's host agent does this), or static keys;
//! 3. the instance metadata service, IMDSv2, for a host deployed before scoped credentials.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::{Stream, StreamExt, stream::FuturesOrdered};
use md5::{Digest as _, Md5};
use sha2::Sha256;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;

use crate::error::StorageError;
use crate::sigv4::{self, Credentials, EMPTY_SHA256, UNSIGNED_PAYLOAD};

const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
const REFRESH_MARGIN: Duration = Duration::from_secs(300);
const IMDS: &str = "http://169.254.169.254";

/// An S3 failure, as the API reports one: the S3 error code
/// as the message, S3's own sentence as the legacy `error`, S3's status.
#[derive(Debug)]
pub struct S3Failure {
	pub status: u16,
	pub code: String,
	pub message: String,
}

impl From<S3Failure> for StorageError {
	fn from(failure: S3Failure) -> Self {
		if failure.status >= 500 || failure.status == 0 {
			tracing::error!(status = failure.status, code = %failure.code, message = %failure.message, "s3");
		}
		let status = if failure.status == 0 {
			500
		} else {
			failure.status
		};
		StorageError::new(status, "S3Error", failure.code).with_legacy_text(failure.message)
	}
}

fn transport(error: impl std::fmt::Display) -> S3Failure {
	S3Failure {
		status: 0,
		code: "InternalError".into(),
		message: error.to_string(),
	}
}

/// One part of a multipart upload, as `ListParts` reports it.
#[derive(Debug, Clone)]
pub struct Part {
	pub number: u32,
	pub size: u64,
	pub etag: String,
}

#[derive(Debug, Clone)]
pub struct Head {
	pub size: u64,
	pub etag: String,
	pub content_type: String,
	pub cache_control: String,
	/// As S3 sent it (an HTTP date).
	pub last_modified: Option<OffsetDateTime>,
}

pub struct S3 {
	http: reqwest::Client,
	bucket: String,
	region: String,
	scheme: String,
	/// `host[:port]` of the endpoint (path style) or of the bucket (virtual-hosted).
	host: String,
	path_style: bool,
	part_size: usize,
	queue_size: usize,
	credentials: RwLock<Option<(Credentials, Option<OffsetDateTime>)>>,
}

#[derive(Debug, Clone)]
pub struct S3Options {
	pub bucket: String,
	pub region: String,
	pub endpoint: Option<String>,
	pub force_path_style: bool,
	pub part_size: usize,
	pub queue_size: usize,
	/// Accept a self-signed endpoint certificate (the local tier's MinIO only).
	pub accept_invalid_certs: bool,
}

impl S3 {
	pub fn new(options: S3Options) -> Result<Self, String> {
		let (scheme, endpoint_host) = match &options.endpoint {
			Some(endpoint) => {
				let (scheme, rest) = endpoint
					.split_once("://")
					.ok_or_else(|| format!("STORAGE_S3_ENDPOINT has no scheme: {endpoint}"))?;
				(scheme.to_string(), rest.trim_end_matches('/').to_string())
			}
			None => (
				"https".to_string(),
				format!("s3.{}.amazonaws.com", options.region),
			),
		};
		// A bucket with a dot cannot be a TLS host name under the wildcard certificate.
		let path_style = options.force_path_style || options.bucket.contains('.');
		let host = if path_style {
			endpoint_host
		} else {
			format!("{}.{endpoint_host}", options.bucket)
		};
		let http = reqwest::Client::builder()
			.connect_timeout(Duration::from_secs(10))
			.pool_idle_timeout(Duration::from_secs(60))
			.danger_accept_invalid_certs(options.accept_invalid_certs)
			.build()
			.map_err(|e| e.to_string())?;
		Ok(Self {
			http,
			bucket: options.bucket,
			region: options.region,
			scheme,
			host,
			path_style,
			part_size: options.part_size.max(MIN_PART_SIZE),
			queue_size: options.queue_size.max(1),
			credentials: RwLock::new(None),
		})
	}

	/// A host with no storage cohort starts with no bucket (config.rs); every S3 call then
	/// refuses with this, which is the log line that says why uploads fail there.
	fn bucket_configured(&self) -> Result<(), S3Failure> {
		if self.bucket.is_empty() {
			return Err(transport(
				"STORAGE_S3_BUCKET is not set: this host has no storage bucket",
			));
		}
		Ok(())
	}

	fn path(&self, key: &str) -> String {
		let key = sigv4::uri_encode(key, true);
		if self.path_style {
			format!("/{}/{key}", sigv4::uri_encode(&self.bucket, false))
		} else {
			format!("/{key}")
		}
	}

	fn bucket_path(&self) -> String {
		if self.path_style {
			format!("/{}", sigv4::uri_encode(&self.bucket, false))
		} else {
			"/".into()
		}
	}

	/// One signed request. `body` is sent with its SHA-256 when it is in memory.
	async fn send(
		&self,
		method: &str,
		path: &str,
		query: &[(String, String)],
		headers: &[(String, String)],
		body: Option<Bytes>,
	) -> Result<reqwest::Response, S3Failure> {
		self.bucket_configured()?;
		let credentials = self.credentials().await?;
		// Every PUT with a body (PutObject, UploadPart) carries its MD5. S3 REQUIRES one on a
		// bucket with Object Lock, which the fleet's cohort buckets have (found by the first
		// upload on a fleet host: "Content-MD5 OR x-amz-checksum- HTTP header is required"), and
		// S3 then checks the bytes against it.
		let mut headers = headers.to_vec();
		let mut md5_sent = false;
		if method == "PUT"
			&& let Some(bytes) = &body
			&& !headers
				.iter()
				.any(|(name, _)| name.eq_ignore_ascii_case("content-md5"))
		{
			// On a blocking thread: a part is 16 MiB, and hashing it on this task stalled reading
			// the next part and sending the ones in flight. Parts in flight now hash in parallel.
			let part = bytes.clone();
			let md5 = tokio::task::spawn_blocking(move || {
				base64::Engine::encode(
					&base64::engine::general_purpose::STANDARD,
					Md5::digest(&part),
				)
			})
			.await
			.map_err(transport)?;
			headers.push(("content-md5".into(), md5));
			md5_sent = true;
		}
		let headers = headers.as_slice();
		let payload_hash = match &body {
			// A PUT carrying Content-MD5 is signed UNSIGNED-PAYLOAD, as S3 allows: S3 checks the bytes
			// against the MD5, so a second full pass for SHA-256 bought nothing but time.
			Some(_) if md5_sent => UNSIGNED_PAYLOAD.into(),
			Some(bytes) => hex::encode(Sha256::digest(bytes)),
			None if method == "PUT" || method == "POST" => UNSIGNED_PAYLOAD.into(),
			None => EMPTY_SHA256.into(),
		};
		let amz_date = amz_date(OffsetDateTime::now_utc());
		let signed = sigv4::sign(
			&sigv4::Request {
				method,
				host: &self.host,
				path,
				query,
				headers,
				payload_sha256: &payload_hash,
			},
			&credentials,
			&self.region,
			"s3",
			&amz_date,
		);
		let query_string = sigv4::canonical_query(query);
		let url = if query_string.is_empty() {
			format!("{}://{}{path}", self.scheme, self.host)
		} else {
			format!("{}://{}{path}?{query_string}", self.scheme, self.host)
		};
		let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(transport)?;
		let mut request = self.http.request(method, url);
		for (name, value) in &signed {
			if name != "host" {
				request = request.header(name.as_str(), value.as_str());
			}
		}
		if let Some(bytes) = body {
			request = request.body(bytes);
		}
		request.send().await.map_err(transport)
	}

	/// The response if it succeeded, else S3's own error.
	async fn check(response: reqwest::Response) -> Result<reqwest::Response, S3Failure> {
		let status = response.status().as_u16();
		if (200..300).contains(&status) || status == 304 || status == 206 {
			return Ok(response);
		}
		let text = response.text().await.unwrap_or_default();
		let code = xml_tag(&text, "Code").unwrap_or_else(|| match status {
			404 => "NotFound".into(),
			403 => "Forbidden".into(),
			_ => "UnknownError".into(),
		});
		let message = xml_tag(&text, "Message").unwrap_or_else(|| code.clone());
		Err(S3Failure {
			status,
			code,
			message,
		})
	}

	/// `GetObject`, the body left streaming. `Range`, `If-None-Match` and `If-Modified-Since`
	/// pass through, as upstream passes them.
	pub async fn get(
		&self,
		key: &str,
		conditional: &[(String, String)],
	) -> Result<reqwest::Response, S3Failure> {
		let response = self
			.send("GET", &self.path(key), &[], conditional, None)
			.await?;
		Self::check(response).await
	}

	pub async fn head(&self, key: &str) -> Result<Head, S3Failure> {
		let response =
			Self::check(self.send("HEAD", &self.path(key), &[], &[], None).await?).await?;
		Ok(head_from(response.headers()))
	}

	pub async fn delete(&self, key: &str) -> Result<(), S3Failure> {
		Self::check(self.send("DELETE", &self.path(key), &[], &[], None).await?).await?;
		Ok(())
	}

	/// `DeleteObjects`, a thousand at a time. A key that is already gone is not an error.
	pub async fn delete_many(&self, keys: &[String]) -> Result<(), S3Failure> {
		for chunk in keys.chunks(1000) {
			let mut xml = String::from("<Delete><Quiet>true</Quiet>");
			for key in chunk {
				xml.push_str(&format!("<Object><Key>{}</Key></Object>", xml_escape(key)));
			}
			xml.push_str("</Delete>");
			let body = Bytes::from(xml);
			let md5 = base64::Engine::encode(
				&base64::engine::general_purpose::STANDARD,
				Md5::digest(&body),
			);
			let headers = [
				("content-md5".to_string(), md5),
				("content-type".to_string(), "application/xml".to_string()),
			];
			let response = Self::check(
				self.send(
					"POST",
					&self.bucket_path(),
					&[("delete".into(), String::new())],
					&headers,
					Some(body),
				)
				.await?,
			)
			.await?;
			let text = response.text().await.unwrap_or_default();
			if let Some(code) = xml_tag(&text, "Code") {
				return Err(S3Failure {
					status: 500,
					code,
					message: xml_tag(&text, "Message").unwrap_or_default(),
				});
			}
		}
		Ok(())
	}

	/// `CopyObject`; with `replace`, the copy gets new content type and cache control.
	pub async fn copy(
		&self,
		from: &str,
		to: &str,
		replace: Option<(&str, &str)>,
	) -> Result<(String, Option<OffsetDateTime>), S3Failure> {
		let mut headers = vec![(
			"x-amz-copy-source".to_string(),
			format!(
				"{}/{}",
				sigv4::uri_encode(&self.bucket, false),
				sigv4::uri_encode(from, true)
			),
		)];
		if let Some((content_type, cache_control)) = replace {
			headers.push(("x-amz-metadata-directive".into(), "REPLACE".into()));
			headers.push(("content-type".into(), content_type.into()));
			headers.push(("cache-control".into(), cache_control.into()));
		}
		let response = Self::check(
			self.send("PUT", &self.path(to), &[], &headers, Some(Bytes::new()))
				.await?,
		)
		.await?;
		let text = response.text().await.unwrap_or_default();
		if let Some(code) = xml_tag(&text, "Code") {
			return Err(S3Failure {
				status: 500,
				code,
				message: xml_tag(&text, "Message").unwrap_or_default(),
			});
		}
		let etag = xml_tag(&text, "ETag").unwrap_or_default();
		let modified =
			xml_tag(&text, "LastModified").and_then(|t| OffsetDateTime::parse(&t, &Rfc3339).ok());
		Ok((etag, modified))
	}

	/// An upload of a stream of unknown length, as lib-storage's `Upload` does it: parts of
	/// exactly `part_size` (so a multipart ETag is the one upstream gets for the same bytes), and
	/// a single `PutObject` when everything fits in the first. Returns the bytes read; stops with
	/// `EntityTooLarge` the moment `limit` is passed, aborting what was started. The caller HEADs
	/// the key for the metadata it records.
	pub async fn upload<S, E>(
		&self,
		key: &str,
		body: S,
		content_type: &str,
		cache_control: &str,
		limit: u64,
	) -> Result<u64, StorageError>
	where
		S: Stream<Item = Result<Bytes, E>> + Unpin,
		E: std::fmt::Display,
	{
		let mut parts = PartReader {
			body,
			pending: BytesMut::new(),
			ended: false,
			total: 0,
			limit,
			size: self.part_size,
		};
		let headers = [
			("content-type".to_string(), content_type.to_string()),
			("cache-control".to_string(), cache_control.to_string()),
		];
		let (first, last) = parts.next_part().await?.unwrap_or((Bytes::new(), true));
		if last {
			let response = self
				.send("PUT", &self.path(key), &[], &headers, Some(first))
				.await?;
			Self::check(response).await?;
			return Ok(parts.total);
		}

		let path = self.path(key);
		let created = Self::check(
			self.send(
				"POST",
				&path,
				&[("uploads".into(), String::new())],
				&headers,
				Some(Bytes::new()),
			)
			.await?,
		)
		.await?;
		let upload_id = xml_tag(&created.text().await.unwrap_or_default(), "UploadId")
			.ok_or_else(StorageError::internal)?;
		let result = self
			.upload_parts(&path, &upload_id, first, &mut parts)
			.await;
		match result {
			Ok(etags) => {
				let mut xml = String::from("<CompleteMultipartUpload>");
				for (number, etag) in etags.iter().enumerate() {
					xml.push_str(&format!(
						"<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
						number + 1,
						xml_escape(etag)
					));
				}
				xml.push_str("</CompleteMultipartUpload>");
				let response = self
					.send(
						"POST",
						&path,
						&[("uploadId".into(), upload_id.clone())],
						&[("content-type".into(), "application/xml".into())],
						Some(Bytes::from(xml)),
					)
					.await?;
				let response = Self::check(response).await?;
				// CompleteMultipartUpload can fail inside a 200.
				let text = response.text().await.unwrap_or_default();
				if let Some(code) = xml_tag(&text, "Code") {
					self.abort(&path, &upload_id).await;
					return Err(S3Failure {
						status: 500,
						code,
						message: xml_tag(&text, "Message").unwrap_or_default(),
					}
					.into());
				}
				Ok(parts.total)
			}
			Err(error) => {
				self.abort(&path, &upload_id).await;
				Err(error)
			}
		}
	}

	async fn upload_parts<S, E>(
		&self,
		path: &str,
		upload_id: &str,
		first: Bytes,
		parts: &mut PartReader<S>,
	) -> Result<Vec<String>, StorageError>
	where
		S: Stream<Item = Result<Bytes, E>> + Unpin,
		E: std::fmt::Display,
	{
		let mut etags = Vec::new();
		let mut in_flight = FuturesOrdered::new();
		let mut number = 1u32;
		in_flight.push_back(self.upload_part(path, upload_id, number, first));
		let mut reading = true;
		// Reading the next part and sending the ones in flight happen AT ONCE. A future in
		// `in_flight` only makes progress while it is polled, so awaiting the body alone left every
		// queued part idle until the queue filled: reading and sending took turns, and a 1 GiB
		// upload took 72 s where the network allowed about 20. Dropping `next_part` when a part
		// finishes first loses nothing: it is only ever waiting on the body stream, which is
		// cancel-safe, and every chunk it took is already in the reader.
		loop {
			if reading && in_flight.len() < self.queue_size {
				tokio::select! {
					next = parts.next_part() => match next? {
						Some((part, _)) => {
							number += 1;
							in_flight.push_back(self.upload_part(path, upload_id, number, part));
						}
						None => reading = false,
					},
					Some(done) = in_flight.next(), if !in_flight.is_empty() => etags.push(done?),
				}
			} else {
				match in_flight.next().await {
					Some(done) => etags.push(done?),
					None if reading => continue,
					None => break,
				}
			}
		}
		Ok(etags)
	}

	/// A presigned GET for `key`, valid `expires` seconds (`privateAssetUrl`: what imgproxy fetches
	/// with, holding no credential of its own). `endpoint` replaces the S3 endpoint when imgproxy
	/// reaches S3 by another address (`STORAGE_S3_PRIVATE_ASSET_ENDPOINT`).
	pub async fn presigned_get(
		&self,
		key: &str,
		expires: u64,
		endpoint: Option<&str>,
	) -> Result<String, S3Failure> {
		self.bucket_configured()?;
		let credentials = self.credentials().await?;
		let (scheme, host) = match endpoint.and_then(|e| e.split_once("://")) {
			Some((scheme, rest)) => {
				let base = rest.trim_end_matches('/').to_string();
				(
					scheme.to_string(),
					if self.path_style {
						base
					} else {
						format!("{}.{base}", self.bucket)
					},
				)
			}
			None => (self.scheme.clone(), self.host.clone()),
		};
		let path = self.path(key);
		let query = sigv4::presign(
			&host,
			&path,
			&[("x-id".into(), "GetObject".into())],
			&credentials,
			&self.region,
			&amz_date(OffsetDateTime::now_utc()),
			expires,
		);
		Ok(format!("{scheme}://{host}{path}?{query}"))
	}

	// ---- the raw calls TUS keeps its state with (@tus/s3-store's layout) --------------------------

	/// `PutObject` of bytes in memory, with extra headers (`x-amz-meta-*`, `x-amz-tagging`, …).
	pub async fn put(
		&self,
		key: &str,
		body: Bytes,
		headers: &[(String, String)],
	) -> Result<(), S3Failure> {
		Self::check(
			self.send("PUT", &self.path(key), &[], headers, Some(body))
				.await?,
		)
		.await?;
		Ok(())
	}

	/// The whole object, in memory, with its response headers.
	pub async fn get_bytes(
		&self,
		key: &str,
	) -> Result<(reqwest::header::HeaderMap, Bytes), S3Failure> {
		let response =
			Self::check(self.send("GET", &self.path(key), &[], &[], None).await?).await?;
		let headers = response.headers().clone();
		Ok((headers, response.bytes().await.map_err(transport)?))
	}

	/// `CreateMultipartUpload`; the upload id.
	pub async fn create_multipart(
		&self,
		key: &str,
		headers: &[(String, String)],
	) -> Result<String, S3Failure> {
		let response = Self::check(
			self.send(
				"POST",
				&self.path(key),
				&[("uploads".into(), String::new())],
				headers,
				Some(Bytes::new()),
			)
			.await?,
		)
		.await?;
		xml_tag(&response.text().await.unwrap_or_default(), "UploadId")
			.ok_or_else(|| transport("CreateMultipartUpload returned no UploadId"))
	}

	/// `UploadPart`; the part's ETag.
	pub async fn put_part(
		&self,
		key: &str,
		upload_id: &str,
		number: u32,
		bytes: Bytes,
	) -> Result<String, StorageError> {
		self.upload_part(&self.path(key), upload_id, number, bytes)
			.await
	}

	/// Every part uploaded so far, following `NextPartNumberMarker`, in part order.
	pub async fn list_parts(&self, key: &str, upload_id: &str) -> Result<Vec<Part>, S3Failure> {
		let mut parts = Vec::new();
		let mut marker: Option<String> = None;
		loop {
			let mut query = vec![("uploadId".to_string(), upload_id.to_string())];
			if let Some(marker) = &marker {
				query.push(("part-number-marker".into(), marker.clone()));
			}
			let response =
				Self::check(self.send("GET", &self.path(key), &query, &[], None).await?).await?;
			let text = response.text().await.unwrap_or_default();
			for block in xml_blocks(&text, "Part") {
				parts.push(Part {
					number: xml_tag(block, "PartNumber")
						.and_then(|n| n.parse().ok())
						.unwrap_or(0),
					size: xml_tag(block, "Size")
						.and_then(|n| n.parse().ok())
						.unwrap_or(0),
					etag: xml_tag(block, "ETag").unwrap_or_default(),
				});
			}
			if xml_tag(&text, "IsTruncated").as_deref() == Some("true") {
				marker = xml_tag(&text, "NextPartNumberMarker");
				if marker.is_some() {
					continue;
				}
			}
			break;
		}
		parts.sort_by_key(|part| part.number);
		Ok(parts)
	}

	/// `CompleteMultipartUpload` with the parts given.
	pub async fn complete_multipart(
		&self,
		key: &str,
		upload_id: &str,
		parts: &[Part],
	) -> Result<(), StorageError> {
		let mut xml = String::from("<CompleteMultipartUpload>");
		for part in parts {
			xml.push_str(&format!(
				"<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
				part.number,
				xml_escape(&part.etag)
			));
		}
		xml.push_str("</CompleteMultipartUpload>");
		let response = self
			.send(
				"POST",
				&self.path(key),
				&[("uploadId".into(), upload_id.to_string())],
				&[("content-type".into(), "application/xml".into())],
				Some(Bytes::from(xml)),
			)
			.await?;
		let text = Self::check(response)
			.await?
			.text()
			.await
			.unwrap_or_default();
		if let Some(code) = xml_tag(&text, "Code") {
			return Err(S3Failure {
				status: 500,
				code,
				message: xml_tag(&text, "Message").unwrap_or_default(),
			}
			.into());
		}
		Ok(())
	}

	pub async fn abort_multipart(&self, key: &str, upload_id: &str) -> Result<(), S3Failure> {
		Self::check(
			self.send(
				"DELETE",
				&self.path(key),
				&[("uploadId".into(), upload_id.to_string())],
				&[],
				None,
			)
			.await?,
		)
		.await?;
		Ok(())
	}

	async fn upload_part(
		&self,
		path: &str,
		upload_id: &str,
		number: u32,
		bytes: Bytes,
	) -> Result<String, StorageError> {
		let query = [
			("partNumber".to_string(), number.to_string()),
			("uploadId".to_string(), upload_id.to_string()),
		];
		let response = Self::check(self.send("PUT", path, &query, &[], Some(bytes)).await?).await?;
		Ok(response
			.headers()
			.get("etag")
			.and_then(|v| v.to_str().ok())
			.unwrap_or_default()
			.to_string())
	}

	async fn abort(&self, path: &str, upload_id: &str) {
		if let Err(error) = self
			.send(
				"DELETE",
				path,
				&[("uploadId".into(), upload_id.into())],
				&[],
				None,
			)
			.await
		{
			tracing::warn!(error = %error.message, "abandoned multipart upload not aborted; the bucket's lifecycle rule collects it");
		}
	}

	// ---- credentials ---------------------------------------------------------------------------

	async fn credentials(&self) -> Result<Credentials, S3Failure> {
		if let Some((credentials, expires)) = self.credentials.read().await.as_ref()
			&& expires.is_none_or(|at| at - OffsetDateTime::now_utc() > REFRESH_MARGIN)
		{
			return Ok(credentials.clone());
		}
		let mut slot = self.credentials.write().await;
		let fresh = self.resolve().await?;
		*slot = Some(fresh.clone());
		Ok(fresh.0)
	}

	async fn resolve(&self) -> Result<(Credentials, Option<OffsetDateTime>), S3Failure> {
		if let (Ok(id), Ok(secret)) = (
			std::env::var("AWS_ACCESS_KEY_ID"),
			std::env::var("AWS_SECRET_ACCESS_KEY"),
		) && !id.is_empty()
		{
			let token = std::env::var("AWS_SESSION_TOKEN")
				.ok()
				.filter(|t| !t.is_empty());
			return Ok((
				Credentials {
					access_key_id: id,
					secret_access_key: secret,
					session_token: token,
				},
				None,
			));
		}
		if let Some(found) = from_config_file().await? {
			return Ok(found);
		}
		self.imds().await
	}

	async fn imds(&self) -> Result<(Credentials, Option<OffsetDateTime>), S3Failure> {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(2))
			.build()
			.map_err(transport)?;
		let token = client
			.put(format!("{IMDS}/latest/api/token"))
			.header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
			.send()
			.await
			.map_err(|e| transport(format!("no AWS credentials: not in the environment, AWS_CONFIG_FILE or the instance metadata service ({e})")))?
			.text()
			.await
			.map_err(transport)?;
		let base = format!("{IMDS}/latest/meta-data/iam/security-credentials/");
		let role = client
			.get(&base)
			.header("x-aws-ec2-metadata-token", &token)
			.send()
			.await
			.map_err(transport)?
			.text()
			.await
			.map_err(transport)?;
		let role = role.lines().next().unwrap_or_default().trim().to_string();
		let document: serde_json::Value = client
			.get(format!("{base}{role}"))
			.header("x-aws-ec2-metadata-token", &token)
			.send()
			.await
			.map_err(transport)?
			.json()
			.await
			.map_err(transport)?;
		credentials_from_json(&document, "Token")
			.ok_or_else(|| transport("the instance metadata service returned no credentials"))
	}
}

/// A body cut into parts of exactly `size` bytes (the last one shorter), counted as it goes.
struct PartReader<S> {
	body: S,
	pending: BytesMut,
	ended: bool,
	total: u64,
	limit: u64,
	size: usize,
}

impl<S, E> PartReader<S>
where
	S: Stream<Item = Result<Bytes, E>> + Unpin,
	E: std::fmt::Display,
{
	async fn fill(&mut self, want: usize) -> Result<(), StorageError> {
		while !self.ended && self.pending.len() < want {
			match self.body.next().await {
				Some(chunk) => {
					let chunk = chunk
						.map_err(|e| StorageError::no_content_provided_because(e.to_string()))?;
					self.total += chunk.len() as u64;
					if self.total > self.limit {
						return Err(StorageError::entity_too_large());
					}
					self.pending.extend_from_slice(&chunk);
				}
				None => self.ended = true,
			}
		}
		Ok(())
	}

	/// The next part and whether it is the last; `None` once everything has been handed out.
	async fn next_part(&mut self) -> Result<Option<(Bytes, bool)>, StorageError> {
		// One byte past the part, to know whether another follows it.
		self.fill(self.size + 1).await?;
		if self.pending.is_empty() {
			return Ok(None);
		}
		// Each part leaves with an allocation of its own, and only the overflow (at most one
		// incoming chunk) is copied into the next buffer. `split_to` would keep the part and the
		// bytes after it in ONE allocation, and growing that shared buffer while earlier parts
		// were still in flight allocated a fresh one of about twice the size each time: a 1 GiB
		// upload peaked at 316 MiB where two 16 MiB parts in flight should need about 50.
		let rest = if self.pending.len() > self.size {
			self.pending.split_off(self.size)
		} else {
			BytesMut::new()
		};
		let mut next = BytesMut::with_capacity(if self.ended {
			rest.len()
		} else {
			self.size + 1024 * 1024
		});
		next.extend_from_slice(&rest);
		let part = std::mem::replace(&mut self.pending, next).freeze();
		Ok(Some((part, self.ended && self.pending.is_empty())))
	}
}

/// The profile in `AWS_CONFIG_FILE`, if the file exists: `credential_process`, else static keys.
async fn from_config_file() -> Result<Option<(Credentials, Option<OffsetDateTime>)>, S3Failure> {
	let Ok(path) = std::env::var("AWS_CONFIG_FILE") else {
		return Ok(None);
	};
	let Ok(text) = tokio::fs::read_to_string(&path).await else {
		return Ok(None);
	};
	let profile = std::env::var("AWS_PROFILE").unwrap_or_else(|_| "default".into());
	let section = ini_section(&text, &profile);
	if let Some(command) = section
		.iter()
		.find(|(k, _)| k == "credential_process")
		.map(|(_, v)| v.clone())
	{
		let output = tokio::process::Command::new("sh")
			.arg("-c")
			.arg(&command)
			.output()
			.await
			.map_err(transport)?;
		if !output.status.success() {
			return Err(transport(format!(
				"credential_process failed: {}",
				String::from_utf8_lossy(&output.stderr).trim()
			)));
		}
		let document: serde_json::Value =
			serde_json::from_slice(&output.stdout).map_err(transport)?;
		return credentials_from_json(&document, "SessionToken")
			.map(Some)
			.ok_or_else(|| transport("credential_process returned no credentials"));
	}
	let get = |name: &str| {
		section
			.iter()
			.find(|(k, _)| k == name)
			.map(|(_, v)| v.clone())
	};
	Ok(
		match (get("aws_access_key_id"), get("aws_secret_access_key")) {
			(Some(id), Some(secret)) => Some((
				Credentials {
					access_key_id: id,
					secret_access_key: secret,
					session_token: get("aws_session_token"),
				},
				None,
			)),
			_ => None,
		},
	)
}

fn credentials_from_json(
	document: &serde_json::Value,
	token_field: &str,
) -> Option<(Credentials, Option<OffsetDateTime>)> {
	let field = |name: &str| {
		document
			.get(name)
			.and_then(serde_json::Value::as_str)
			.map(str::to_string)
	};
	let credentials = Credentials {
		access_key_id: field("AccessKeyId")?,
		secret_access_key: field("SecretAccessKey")?,
		session_token: field(token_field),
	};
	let expires = field("Expiration").and_then(|t| OffsetDateTime::parse(&t, &Rfc3339).ok());
	Some((credentials, expires))
}

/// The `key = value` lines of `[profile name]` (or `[default]`) in an AWS config file.
fn ini_section(text: &str, profile: &str) -> Vec<(String, String)> {
	let wanted = [format!("[profile {profile}]"), format!("[{profile}]")];
	let mut inside = false;
	let mut out = Vec::new();
	for line in text.lines() {
		let line = line.trim();
		if line.starts_with('[') {
			inside = wanted.iter().any(|w| w == line);
			continue;
		}
		if inside && let Some((key, value)) = line.split_once('=') {
			out.push((key.trim().to_string(), value.trim().to_string()));
		}
	}
	out
}

fn head_from(headers: &reqwest::header::HeaderMap) -> Head {
	let text = |name: &str| {
		headers
			.get(name)
			.and_then(|v| v.to_str().ok())
			.map(str::to_string)
	};
	Head {
		size: text("content-length")
			.and_then(|v| v.parse().ok())
			.unwrap_or(0),
		etag: text("etag").unwrap_or_default(),
		content_type: text("content-type").unwrap_or_else(|| "application/octet-stream".into()),
		cache_control: text("cache-control").unwrap_or_else(|| "no-cache".into()),
		last_modified: text("last-modified").and_then(|v| parse_http_date(&v)),
	}
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn parse_http_date(value: &str) -> Option<OffsetDateTime> {
	let format = time::macros::format_description!(
		"[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
	);
	time::PrimitiveDateTime::parse(value, format)
		.ok()
		.map(|t| t.assume_utc())
}

pub fn http_date(at: OffsetDateTime) -> String {
	let format = time::macros::format_description!(
		"[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
	);
	at.to_offset(time::UtcOffset::UTC)
		.format(format)
		.unwrap_or_default()
}

fn amz_date(at: OffsetDateTime) -> String {
	let format = time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");
	at.format(format).unwrap_or_default()
}

/// The text of the first `<name>` element, entities decoded. S3's XML is flat enough for this.
pub fn xml_tag(xml: &str, name: &str) -> Option<String> {
	let open = format!("<{name}>");
	let start = xml.find(&open)? + open.len();
	let end = xml[start..].find(&format!("</{name}>"))? + start;
	Some(xml_unescape(&xml[start..end]))
}

/// The inner text of every `<name>…</name>` element, in order.
pub(crate) fn xml_blocks<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
	let open = format!("<{name}>");
	let close = format!("</{name}>");
	let mut out = Vec::new();
	let mut rest = xml;
	while let Some(start) = rest.find(&open) {
		let after = &rest[start + open.len()..];
		let Some(end) = after.find(&close) else {
			break;
		};
		out.push(&after[..end]);
		rest = &after[end + close.len()..];
	}
	out
}

/// XML's five named entities and numeric references (MinIO writes `&#34;` in an ETag).
pub(crate) fn xml_unescape(text: &str) -> String {
	let mut out = String::with_capacity(text.len());
	let mut rest = text;
	while let Some(at) = rest.find('&') {
		out.push_str(&rest[..at]);
		let tail = &rest[at..];
		let Some(end) = tail.find(';') else {
			out.push_str(tail);
			return out;
		};
		let entity = &tail[1..end];
		let decoded = match entity {
			"quot" => Some('"'),
			"apos" => Some('\''),
			"lt" => Some('<'),
			"gt" => Some('>'),
			"amp" => Some('&'),
			_ => entity
				.strip_prefix("#x")
				.and_then(|hex| u32::from_str_radix(hex, 16).ok())
				.or_else(|| entity.strip_prefix('#').and_then(|dec| dec.parse().ok()))
				.and_then(char::from_u32),
		};
		match decoded {
			Some(c) => {
				out.push(c);
				rest = &tail[end + 1..];
			}
			None => {
				out.push('&');
				rest = &tail[1..];
			}
		}
	}
	out.push_str(rest);
	out
}

fn xml_escape(value: &str) -> String {
	value
		.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reads_the_profile_a_host_writes() {
		let config = "[default]\ncredential_process = cat /tmp/snoutpod-aws/credentials.json\n";
		assert_eq!(
			ini_section(config, "default"),
			vec![(
				"credential_process".to_string(),
				"cat /tmp/snoutpod-aws/credentials.json".to_string()
			)]
		);
		let named = "[default]\na = 1\n[profile x]\nb = 2\n";
		assert_eq!(
			ini_section(named, "x"),
			vec![("b".to_string(), "2".to_string())]
		);
	}

	#[test]
	fn reads_credential_process_output() {
		let document = serde_json::json!({ "Version": 1, "AccessKeyId": "A", "SecretAccessKey": "S", "SessionToken": "T", "Expiration": "2026-09-26T20:00:00Z" });
		let (credentials, expires) =
			credentials_from_json(&document, "SessionToken").unwrap_or_else(|| unreachable!());
		assert_eq!(credentials.session_token.as_deref(), Some("T"));
		assert_eq!(expires.map(|e| e.hour()), Some(20));
	}

	#[test]
	fn dates_round_trip() {
		let at = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap_or_else(|| unreachable!());
		assert_eq!(http_date(at), "Sun, 06 Nov 1994 08:49:37 GMT");
	}

	#[test]
	fn xml() {
		assert_eq!(
			xml_tag("<a><UploadId>x&amp;y</UploadId></a>", "UploadId").as_deref(),
			Some("x&y")
		);
		assert_eq!(
			xml_tag("<ETag>&quot;abc&quot;</ETag>", "ETag").as_deref(),
			Some("\"abc\"")
		);
		assert_eq!(
			xml_tag("<ETag>&#34;abc&#x22;</ETag>", "ETag").as_deref(),
			Some("\"abc\"")
		);
		assert_eq!(xml_unescape("a & b &bogus; &#39;"), "a & b &bogus; '");
		assert_eq!(xml_escape("a<b>&'\""), "a&lt;b&gt;&amp;&apos;&quot;");
	}
}
