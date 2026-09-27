//! Resumable uploads: the tus 1.0.0 protocol, served at `/upload/resumable`
//! (@tus/server 2.2.1), with the upload's state kept in S3 exactly where @tus/s3-store 2.0.3 keeps
//! it, so an upload started against either server can be finished against the other:
//!
//! * the upload id is `<tenant>/<bucket>/<object>/<version>`, and the URL carries it base64url
//!   without the tenant;
//! * `<id>.info` holds the upload as JSON (`id`, `metadata`, `size`, `offset`, `creation_date`,
//!   `storage`), with the S3 multipart upload id in its `x-amz-meta-upload-id`;
//! * the bytes are a multipart upload on `<id>` itself, which is also the object's final key;
//! * a tail shorter than S3's 5 MiB minimum part waits in `<id>.part` for the next PATCH.
//!
//! The authorisation is upstream's too: the caller's insert is tried and rolled back before any
//! byte is accepted, and the row is written as super user once the last byte lands.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use bytes::BytesMut;
use futures_util::{Stream, StreamExt};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::Mutex;

use crate::app::{App, AppState, Ctx, context_jwt, context_public, tenant_of};
use crate::error::StorageError;
use crate::jwt;
use crate::limits;
use crate::objects::{Incoming, complete_upload, find_bucket, header_text, test_insert};
use crate::s3::{Part, S3Failure, http_date};

const TUS_RESUMABLE: &str = "1.0.0";
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
const MAX_PARTS: u64 = 10_000;
const EXTENSIONS: &str = "creation,creation-with-upload,creation-defer-length,termination,expiration";
const HEADERS: [&str; 17] = [
	"Authorization",
	"Content-Type",
	"Location",
	"Tus-Extension",
	"Tus-Max-Size",
	"Tus-Resumable",
	"Tus-Version",
	"Upload-Concat",
	"Upload-Defer-Length",
	"Upload-Length",
	"Upload-Metadata",
	"Upload-Offset",
	"X-HTTP-Method-Override",
	"X-Requested-With",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"Forwarded",
];
const ALLOWED_EXTRA: [&str; 5] = ["Authorization", "X-Upsert", "Upload-Expires", "ApiKey", "x-signature"];

pub fn routes(path: &str) -> Router<AppState> {
	let path = path.trim_end_matches('/').to_string();
	Router::new()
		.route(&path, any(|state, req| handle(state, req, false)))
		.route(&format!("{path}/"), any(|state, req| handle(state, req, false)))
		.route(&format!("{path}/sign"), any(|state, req| handle(state, req, true)))
		.route(&format!("{path}/sign/{{*id}}"), any(|state, req| handle(state, req, true)))
		.route(&format!("{path}/{{*id}}"), any(|state, req| handle(state, req, false)))
}

// ---- the protocol's own refusals -------------------------------------------------------------

/// A tus answer: a status and a plain-text body.
struct TusError {
	status: u16,
	body: String,
}

impl TusError {
	fn new(status: u16, body: &str) -> Self {
		Self { status, body: body.to_string() }
	}
}

/// Storage errors keep their real status and their message.
impl From<StorageError> for TusError {
	fn from(error: StorageError) -> Self {
		Self { status: error.status, body: error.message }
	}
}

impl From<S3Failure> for TusError {
	fn from(failure: S3Failure) -> Self {
		StorageError::from(failure).into()
	}
}

fn file_not_found() -> TusError {
	TusError::new(404, "The file for this url was not found\n")
}
fn invalid_length() -> TusError {
	TusError::new(400, "Upload-Length or Upload-Defer-Length header required\n")
}
fn size_exceeded() -> TusError {
	TusError::new(413, "upload's size exceeded\n")
}
fn max_size_exceeded() -> TusError {
	TusError::new(413, "Maximum size exceeded\n")
}

// ---- ids, metadata, validation ---------------------------------------------------------------

/// `<tenant>/<bucket>/<object>/<version>`, validated as upstream's `UploadId` does.
#[derive(Debug, Clone)]
struct UploadId {
	tenant: String,
	bucket: String,
	object: String,
	version: String,
}

impl UploadId {
	fn new(tenant: &str, bucket: &str, object: &str, version: &str) -> Result<Self, StorageError> {
		limits::must_be_valid_bucket_name(bucket)?;
		limits::must_be_valid_key(object)?;
		if tenant.is_empty() {
			return Err(StorageError::invalid_tenant_id());
		}
		if version.is_empty() {
			return Err(StorageError::new(400, "InvalidUploadId", "Version not provided"));
		}
		Ok(Self { tenant: tenant.into(), bucket: bucket.into(), object: object.into(), version: version.into() })
	}

	fn parse(id: &str) -> Result<Self, StorageError> {
		let parts: Vec<&str> = id.split('/').collect();
		if parts.len() < 3 {
			return Err(StorageError::new(400, "InvalidUploadId", "Invalid upload id"));
		}
		let version = parts[parts.len() - 1];
		Self::new(parts[0], parts[1], &parts[2..parts.len() - 1].join("/"), version)
	}

	fn key(&self) -> String {
		format!("{}/{}/{}/{}", self.tenant, self.bucket, self.object, self.version)
	}
}

/// tus's `Metadata.parse`: `key base64,key base64,key`; keys ASCII without spaces or commas,
/// unique; values padded base64.
fn parse_metadata(header: &str) -> Option<Vec<(String, Option<String>)>> {
	use base64::Engine;
	if header.trim().is_empty() {
		return None;
	}
	let mut out: Vec<(String, Option<String>)> = Vec::new();
	for pair in header.split(',') {
		let tokens: Vec<&str> = pair.split(' ').collect();
		let key = tokens[0];
		let key_ok = !key.is_empty() && key.chars().all(|c| c.is_ascii() && c != ' ' && c != ',');
		let value_ok = |v: &str| v.len().is_multiple_of(4) && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') && v.trim_end_matches('=').len() + 2 >= v.len();
		let valid = key_ok && (tokens.len() == 1 || (tokens.len() == 2 && value_ok(tokens[1]))) && !out.iter().any(|(k, _)| k == key);
		if !valid {
			return None;
		}
		let value = tokens.get(1).map(|v| String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(v).unwrap_or_default()).to_string());
		out.push((key.to_string(), value));
	}
	Some(out)
}

fn stringify_metadata(metadata: &Map<String, Value>) -> String {
	use base64::Engine;
	metadata
		.iter()
		.map(|(key, value)| match value.as_str() {
			None => key.clone(),
			Some(text) => format!("{key} {}", base64::engine::general_purpose::STANDARD.encode(text)),
		})
		.collect::<Vec<_>>()
		.join(",")
}

/// `Number.isInteger(n) && String(n) === value && n >= 0`.
fn is_plain_integer(value: &str) -> bool {
	!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) && (value == "0" || !value.starts_with('0')) && value.len() <= 16
}

/// tus's header validators, over every header of the request.
fn invalid_headers(method: &Method, headers: &HeaderMap) -> Vec<String> {
	let mut invalid = Vec::new();
	for (name, value) in headers {
		let name = name.as_str();
		let value = value.to_str().unwrap_or("\u{fffd}");
		let ok = match name {
			"content-type" if method != Method::PATCH => true,
			"upload-offset" | "upload-length" => is_plain_integer(value),
			"upload-defer-length" => value == "1",
			"upload-metadata" => parse_metadata(value).is_some(),
			"x-forwarded-proto" => value == "http" || value == "https",
			"tus-version" | "tus-resumable" => value == TUS_RESUMABLE,
			"content-type" => value == "application/offset+octet-stream",
			"upload-concat" => value == "partial" || value.starts_with("final;"),
			_ => true,
		};
		if !ok {
			invalid.push(name.to_string());
		}
	}
	invalid
}

// ---- the upload's state in S3 ----------------------------------------------------------------

/// `<id>.info`, as @tus/s3-store reads it back.
struct Info {
	/// The JSON as stored, in its key order.
	file: Map<String, Value>,
	upload_id: String,
}

impl Info {
	fn size(&self) -> Option<u64> {
		self.file.get("size").and_then(Value::as_u64)
	}
	fn metadata(&self) -> Option<Map<String, Value>> {
		self.file.get("metadata").and_then(Value::as_object).cloned()
	}
	fn meta(&self, key: &str) -> Option<String> {
		self.file.get("metadata").and_then(|m| m.get(key)).and_then(Value::as_str).map(str::to_string)
	}
	fn created(&self) -> Option<OffsetDateTime> {
		self.file.get("creation_date").and_then(Value::as_str).and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok())
	}
}

async fn read_info(app: &App, id: &str) -> Result<Info, TusError> {
	let (headers, body) = app.s3.get_bytes(&format!("{id}.info")).await.map_err(|_| file_not_found())?;
	let file: Map<String, Value> = serde_json::from_slice(&body).map_err(|_| file_not_found())?;
	let upload_id = headers.get("x-amz-meta-upload-id").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
	Ok(Info { file, upload_id })
}

async fn save_info(app: &App, id: &str, file: &Map<String, Value>, upload_id: &str, completed: bool) -> Result<(), TusError> {
	let mut headers = vec![("x-amz-meta-upload-id".to_string(), upload_id.to_string()), ("x-amz-meta-tus-version".to_string(), TUS_RESUMABLE.to_string())];
	if app.config.tus_url_expiry_ms > 0 && app.config.tus_allow_s3_tags {
		headers.push(("x-amz-tagging".into(), format!("Tus-Completed={completed}")));
	}
	app.s3.put(&format!("{id}.info"), Bytes::from(Value::Object(file.clone()).to_string()), &headers).await?;
	Ok(())
}

/// `getUpload`: the parts uploaded plus the waiting tail; a finished upload has no parts to
/// list and counts as complete.
async fn current_offset(app: &App, id: &str, info: &Info) -> Result<u64, TusError> {
	match app.s3.list_parts(id, &info.upload_id).await {
		Ok(parts) => {
			let uploaded: u64 = parts.iter().map(|p| p.size).sum();
			let tail = app.s3.head(&format!("{id}.part")).await.map(|h| h.size).unwrap_or(0);
			Ok(uploaded + tail)
		}
		Err(failure) if failure.code == "NoSuchUpload" || failure.code == "NoSuchKey" => Ok(info.size().unwrap_or(0)),
		Err(failure) => Err(failure.into()),
	}
}

fn expired(app: &App, info: &Info) -> bool {
	let expiry = app.config.tus_url_expiry_ms;
	expiry > 0 && info.created().is_some_and(|created| OffsetDateTime::now_utc() > created + Duration::from_millis(expiry))
}

fn expires_header(app: &App, info_created: Option<OffsetDateTime>) -> Option<String> {
	let expiry = app.config.tus_url_expiry_ms;
	(expiry > 0).then_some(())?;
	info_created.map(|created| http_date(created + Duration::from_millis(expiry)))
}

/// `calcOptimalPartSize`. A deferred length would make upstream's parts 524 MiB, held in memory
/// here; those use the preferred size instead (a deliberate difference).
fn part_size(app: &App, size: Option<u64>) -> u64 {
	let preferred = app.config.tus_part_size_mb * 1024 * 1024;
	let optimal = match size {
		None => preferred,
		Some(size) if size <= preferred => size,
		Some(size) if size <= preferred * MAX_PARTS => preferred,
		Some(size) => size.div_ceil(MAX_PARTS),
	};
	optimal.max(MIN_PART_SIZE)
}

/// `S3Store.write`: the waiting tail first, then the body, cut into parts; a short last piece
/// that does not finish the upload waits in `<id>.part`. Returns the new offset.
async fn write<S, E>(app: &App, id: &str, info: &Info, requested_offset: u64, body: S, limit: u64) -> Result<u64, TusError>
where
	S: Stream<Item = Result<Bytes, E>> + Unpin,
	E: std::fmt::Display,
{
	let parts = app.s3.list_parts(id, &info.upload_id).await?;
	let mut number = parts.last().map(|p| p.number).unwrap_or(0) + 1;
	let tail_key = format!("{id}.part");
	let tail = match app.s3.get_bytes(&tail_key).await {
		Ok((_, bytes)) => Some(bytes),
		Err(failure) if failure.status == 404 => None,
		Err(failure) => return Err(failure.into()),
	};
	let tail_size = tail.as_ref().map(|t| t.len() as u64).unwrap_or(0);
	if tail.is_some() {
		app.s3.delete(&tail_key).await?;
	}
	let size = info.size();
	let chunk = part_size(app, size) as usize;
	let mut offset = requested_offset - tail_size;
	let mut pending = BytesMut::new();
	if let Some(tail) = tail {
		pending.extend_from_slice(&tail);
	}
	let mut body = body;
	let mut received: u64 = 0;
	let mut uploaded: u64 = 0;
	let mut ended = false;
	while !ended || !pending.is_empty() {
		while !ended && pending.len() < chunk {
			match body.next().await {
				Some(Ok(bytes)) => {
					received += bytes.len() as u64;
					if received > limit {
						return Err(max_size_exceeded());
					}
					pending.extend_from_slice(&bytes);
				}
				Some(Err(_)) => return Err(TusError::new(500, "Something went wrong receiving the file\n")),
				None => ended = true,
			}
		}
		if pending.is_empty() {
			break;
		}
		let piece = pending.split_to(pending.len().min(chunk)).freeze();
		let piece_size = piece.len() as u64;
		offset += piece_size;
		let is_final = size == Some(offset);
		if piece_size >= MIN_PART_SIZE || is_final {
			app.s3.put_part(id, &info.upload_id, number, piece).await?;
			number += 1;
		} else {
			let mut headers = Vec::new();
			if app.config.tus_url_expiry_ms > 0 && app.config.tus_allow_s3_tags {
				headers.push(("x-amz-tagging".to_string(), "Tus-Completed=false".to_string()));
			}
			app.s3.put(&tail_key, piece, &headers).await?;
		}
		uploaded += piece_size;
	}
	let new_offset = requested_offset + uploaded - tail_size;
	if size == Some(new_offset) {
		let mut parts = app.s3.list_parts(id, &info.upload_id).await?;
		if parts.is_empty() {
			let etag = app.s3.put_part(id, &info.upload_id, 1, Bytes::new()).await?;
			parts.push(Part { number: 1, size: 0, etag });
		}
		app.s3.complete_multipart(id, &info.upload_id, &parts).await?;
		if app.config.tus_url_expiry_ms > 0 && app.config.tus_allow_s3_tags {
			save_info(app, id, &info.file, &info.upload_id, true).await?;
		}
	}
	Ok(new_offset)
}

// ---- locks -----------------------------------------------------------------------------------

/// One request at a time per upload. One server per host has nobody else to exclude, so an
/// in-process lock is enough.
static LOCKS: LazyLock<std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>> = LazyLock::new(Default::default);

async fn lock(id: &str) -> Result<tokio::sync::OwnedMutexGuard<()>, TusError> {
	let entry = {
		let mut locks = LOCKS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		locks.retain(|_, lock| Arc::strong_count(lock) > 1 || lock.try_lock().is_err());
		locks.entry(id.to_string()).or_default().clone()
	};
	tokio::time::timeout(Duration::from_secs(5), entry.lock_owned())
		.await
		.map_err(|_| TusError::from(StorageError::new(503, "LockTimeout", "acquiring lock timeout").with_legacy_name("acquiring_lock_timeout")))
}

// ---- the handler -----------------------------------------------------------------------------

/// Who is uploading, as the route establishes it.
struct Uploader {
	ctx: Ctx,
	owner: Option<String>,
	upsert: bool,
	signed: bool,
}

async fn handle(State(app): State<AppState>, request: Request, signed: bool) -> Response {
	let method = request.method().clone();
	let headers = request.headers().clone();
	let uri = request.uri().clone();
	if method == Method::GET {
		return crate::app::route_not_found(method, uri).await;
	}
	// First the tenant, and the JWT on the authenticated routes.
	// Their refusals are its ordinary JSON ones.
	let ctx = if method == Method::OPTIONS {
		None
	} else if signed {
		match context_public(&app, &method, &uri, &headers, "storage.object.upload_resumable_signed").await {
			Ok(ctx) => Some(ctx),
			Err(error) => return error.with_code().into_response(),
		}
	} else {
		match context_jwt(&app, &method, &uri, &headers, "storage.object.upload_resumable").await {
			Ok(ctx) => Some(ctx),
			Err(error) => return error.with_code().into_response(),
		}
	};

	let mut out = HeaderMap::new();
	out.insert("tus-resumable", HeaderValue::from_static(TUS_RESUMABLE));
	if method != Method::OPTIONS && headers.get("tus-resumable").is_none() {
		return text(412, out, "Tus-Resumable Required\n");
	}
	if method != Method::OPTIONS {
		let invalid = invalid_headers(&method, &headers);
		if !invalid.is_empty() {
			return text(400, out, &format!("Invalid {}\n", invalid.join(" ")));
		}
	}
	let origin = header_text(&headers, "origin").unwrap_or("*");
	insert(&mut out, "access-control-allow-origin", origin);
	// tus joins an empty list of extra headers onto its own, leaving a trailing comma.
	insert(&mut out, "access-control-expose-headers", &format!("{},", HEADERS.join(", ")));

	let result = match (method.as_str(), ctx) {
		("OPTIONS", _) => options(&app, &headers, out.clone()).await,
		("POST", Some(ctx)) => {
			let uploader = Uploader { owner: ctx.caller.sub().map(str::to_string), upsert: header_text(&headers, "x-upsert") == Some("true"), ctx, signed };
			create(&app, uploader, &uri, request, out.clone()).await
		}
		("PATCH", Some(ctx)) => {
			let uploader = Uploader { owner: ctx.caller.sub().map(str::to_string), upsert: header_text(&headers, "x-upsert") == Some("true"), ctx, signed };
			patch(&app, uploader, &uri, request, out.clone()).await
		}
		("HEAD", Some(ctx)) => {
			let uploader = Uploader { owner: ctx.caller.sub().map(str::to_string), upsert: header_text(&headers, "x-upsert") == Some("true"), ctx, signed };
			head(&app, uploader, &uri, &headers, out.clone()).await
		}
		("DELETE", Some(ctx)) => {
			let uploader = Uploader { owner: ctx.caller.sub().map(str::to_string), upsert: header_text(&headers, "x-upsert") == Some("true"), ctx, signed };
			terminate(&app, uploader, &uri, &headers, out.clone()).await
		}
		_ => Err(TusError::new(404, "Not found\n")),
	};
	match result {
		Ok(response) => response,
		Err(error) => text(error.status, out, &error.body),
	}
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) {
	if let Ok(value) = HeaderValue::from_str(value) {
		headers.insert(name, value);
	}
}

/// tus's `write`: a plain-text body (a web `Response` of a string says so) with its length,
/// except on a 204.
fn text(status: u16, mut headers: HeaderMap, body: &str) -> Response {
	let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
	if status == StatusCode::NO_CONTENT {
		let mut response = Response::new(Body::empty());
		*response.status_mut() = status;
		*response.headers_mut() = headers;
		return response;
	}
	insert(&mut headers, "content-type", "text/plain;charset=UTF-8");
	insert(&mut headers, "content-length", &body.len().to_string());
	let mut response = Response::new(Body::from(body.to_string()));
	*response.status_mut() = status;
	*response.headers_mut() = headers;
	response
}

/// The id at the end of the URL: base64url of `<bucket>/<object>/<version>`, the tenant prefixed.
fn id_from(uri: &axum::http::Uri, ctx: &Ctx, tus_path: &str) -> Option<String> {
	let path = uri.path().trim_end_matches('/');
	let last = path.rsplit('/').next()?;
	if last.is_empty() || tus_path.contains(last) {
		return None;
	}
	use base64::Engine;
	let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(last.trim_end_matches('=')).ok()?;
	Some(format!("{}/{}", ctx.tenant.id, String::from_utf8_lossy(&decoded)))
}

/// `generateUrl`: the forwarded scheme, host and port (or `STORAGE_PUBLIC_URL`'s), the path (under
/// `X-Forwarded-Prefix` when allowed), `/sign` kept, the id base64url.
fn location(app: &App, headers: &HeaderMap, uri: &axum::http::Uri, id: &str) -> String {
	use base64::Engine;
	let path = app.config.tus_path.trim_end_matches('/');
	let mut host = String::new();
	let forwarded_proto = header_text(headers, "forwarded")
		.and_then(|f| f.find("proto=").map(|i| f[i + 6..].split([';', ',', ' ']).next().unwrap_or_default().to_string()))
		.filter(|p| p == "http" || p == "https")
		.or_else(|| header_text(headers, "x-forwarded-proto").filter(|p| *p == "http" || *p == "https").map(str::to_string));
	let mut proto = forwarded_proto.unwrap_or_else(|| "http".into());
	let public = app.config.public_url.as_deref().and_then(|u| u.split_once("://")).map(|(p, h)| (p.to_string(), h.trim_end_matches('/').split('/').next().unwrap_or_default().to_string()));
	if let Some((p, h)) = &public {
		proto = p.clone();
		host = h.clone();
	} else {
		if let Some(forwarded) = header_text(headers, "forwarded")
			&& let Some(start) = forwarded.find("host=")
		{
			host = forwarded[start + 5..].trim_start_matches('"').split(['"', ';']).next().unwrap_or_default().to_string();
		}
		if host.is_empty() {
			host = header_text(headers, "x-forwarded-host").or_else(|| header_text(headers, "host")).unwrap_or_default().to_string();
		}
		if headers.get("x-forwarded-host").is_some()
			&& let Some(port) = header_text(headers, "x-forwarded-port")
			&& !port.is_empty()
			&& port != "443"
			&& port != "80"
		{
			if host.contains(':') {
				if let Some((h, _)) = host.rsplit_once(':') {
					host = format!("{h}:{port}");
				}
			} else {
				host = format!("{host}:{port}");
			}
		}
	}
	let mut base = path.to_string();
	if app.config.allow_forwarded_prefix
		&& let Some(prefix) = header_text(headers, "x-forwarded-prefix")
	{
		base = format!("{}{path}", prefix.trim_end_matches('/'));
	}
	if uri.path().trim_end_matches('/').ends_with("/sign") {
		base.push_str("/sign");
	}
	let without_tenant = id.split_once('/').map(|(_, rest)| rest).unwrap_or(id);
	format!("{proto}://{host}{base}/{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(without_tenant))
}

/// The largest upload the bucket allows under the project's own ceiling (`maxSize`).
async fn max_size(app: &App, ctx: &Ctx, bucket: &str) -> Result<u64, TusError> {
	let scope = ctx.super_scope(app).await?;
	let found = find_bucket(&scope, bucket, false).await?;
	scope.commit().await?;
	let (_, limit, _) = found.ok_or_else(StorageError::no_such_bucket)?;
	let global = ctx.tenant.file_size_limit;
	let limit = limit.filter(|l| *l > 0).map(|l| l as u64).unwrap_or(global);
	Ok(limit.min(global))
}

/// What the insert is tried with: the content type, the length and the user's metadata JSON.
struct Declared {
	content_type: Option<String>,
	length: Option<u64>,
	raw_metadata: Option<String>,
}

impl Declared {
	fn stored(info: &Info) -> Self {
		Self { content_type: info.meta("contentType"), length: info.size(), raw_metadata: info.meta("metadata") }
	}
	fn new(metadata: &Map<String, Value>, length: Option<u64>) -> Self {
		let text = |key: &str| metadata.get(key).and_then(Value::as_str).map(str::to_string);
		Self { content_type: text("contentType"), length, raw_metadata: text("metadata") }
	}
}

/// `onIncomingRequest`: a signed upload's token, else the caller's insert tried and rolled
/// back. `None` is a HEAD, which only a signed upload checks.
async fn authorise(app: &App, uploader: &mut Uploader, headers: &HeaderMap, id: &UploadId, declared: Option<Declared>) -> Result<(), TusError> {
	if uploader.signed {
		let signature = header_text(headers, "x-signature").ok_or_else(|| StorageError::invalid_signature("Missing x-signature header"))?;
		let claims = jwt::verify(signature, &uploader.ctx.tenant.jwt_secret, &uploader.ctx.tenant.jwks).map_err(|e| StorageError::invalid_jwt(e.0))?;
		if claims.get("url").and_then(Value::as_str) != Some(format!("{}/{}", id.bucket, id.object).as_str()) {
			return Err(StorageError::invalid_signature("Invalid signature").into());
		}
		if claims.get("exp").and_then(Value::as_i64).is_some_and(|exp| exp < OffsetDateTime::now_utc().unix_timestamp()) {
			return Err(StorageError::expired_signature().into());
		}
		uploader.owner = claims.get("owner").and_then(Value::as_str).map(str::to_string);
		uploader.upsert = claims.get("upsert").and_then(Value::as_bool).unwrap_or(false);
		return Ok(());
	}
	let Some(declared) = declared else {
		return Ok(());
	};
	let user_metadata: Option<Value> = declared.raw_metadata.and_then(|r| serde_json::from_str(&r).ok());
	let row_metadata = json!({ "mimetype": declared.content_type, "contentLength": declared.length });
	test_insert(app, &uploader.ctx, &id.bucket, &id.object, uploader.upsert, &row_metadata, user_metadata.as_ref()).await?;
	Ok(())
}

/// `onUploadFinish`: the row written as super user, pointing at the version just completed.
async fn finish(app: &AppState, uploader: &Uploader, id: &UploadId, info_metadata: Option<&Map<String, Value>>) -> Result<(), TusError> {
	let user_metadata = info_metadata.and_then(|m| m.get("metadata")).and_then(Value::as_str).and_then(|r| serde_json::from_str::<Value>(r).ok());
	let incoming = Incoming {
		mime: String::new(),
		cache_control: String::new(),
		user_metadata,
		robots: None,
		declared_length: None,
		max_size: 0,
	};
	complete_upload(app, &uploader.ctx, &id.bucket, &id.object, &id.version, uploader.owner.as_deref(), &incoming).await?;
	Ok(())
}

async fn options(app: &App, headers: &HeaderMap, mut out: HeaderMap) -> Result<Response, TusError> {
	let tenant = tenant_of(app, headers).await?;
	insert(&mut out, "tus-version", TUS_RESUMABLE);
	insert(&mut out, "tus-extension", EXTENSIONS);
	if tenant.file_size_limit > 0 {
		insert(&mut out, "tus-max-size", &tenant.file_size_limit.to_string());
	}
	insert(&mut out, "access-control-allow-methods", "POST, HEAD, PATCH, OPTIONS, DELETE");
	let allowed: Vec<&str> = HEADERS.iter().chain(ALLOWED_EXTRA.iter()).copied().collect();
	insert(&mut out, "access-control-allow-headers", &allowed.join(", "));
	insert(&mut out, "access-control-max-age", "86400");
	Ok(text(204, out, ""))
}

/// `calculateMaxBodySize`.
fn body_limit(headers: &HeaderMap, offset: u64, size: Option<u64>, configured: u64) -> Result<u64, TusError> {
	let declared = header_text(headers, "content-length").and_then(|v| v.parse::<u64>().ok());
	let length = declared.unwrap_or(0);
	match size {
		None => {
			if declared.is_some() && configured > 0 && offset + length > configured {
				return Err(size_exceeded());
			}
			Ok(if configured > 0 { configured.saturating_sub(offset) } else { u64::MAX })
		}
		Some(size) => {
			if offset + length > size {
				return Err(size_exceeded());
			}
			Ok(if declared.is_some() { length } else { size - offset })
		}
	}
}

async fn create(app: &AppState, mut uploader: Uploader, uri: &axum::http::Uri, request: Request, mut out: HeaderMap) -> Result<Response, TusError> {
	let headers = request.headers().clone();
	if headers.get("upload-concat").is_some() {
		return Err(TusError::new(501, "Concatenation extension is not (yet) supported. Disable parallel uploads in the tus client.\n"));
	}
	let length = header_text(&headers, "upload-length").map(|v| v.parse::<u64>().unwrap_or(0));
	let deferred = headers.get("upload-defer-length").is_some();
	if length.is_none() == !deferred {
		return Err(invalid_length());
	}
	let metadata: Option<Map<String, Value>> = match header_text(&headers, "upload-metadata") {
		Some(raw) => Some(parse_metadata(raw).ok_or_else(|| TusError::new(400, "Upload-Metadata is invalid. It MUST consist of one or more comma-separated key-value pairs. The key and value MUST be separated by a space. The key MUST NOT contain spaces and commas and MUST NOT be empty. The key SHOULD be ASCII encoded and the value MUST be Base64 encoded. All keys MUST be unique"))?.into_iter().map(|(k, v)| (k, v.map(Value::String).unwrap_or(Value::Null))).collect()),
		None => None,
	};
	let Some(mut metadata) = metadata else {
		return Err(StorageError::new(400, "InvalidRequest", "Metadata header is required").into());
	};
	let field = |m: &Map<String, Value>, key: &str| m.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
	let id = UploadId::new(&uploader.ctx.tenant.id, &field(&metadata, "bucketName"), &field(&metadata, "objectName"), &uuid::Uuid::new_v4().to_string())?;
	let limit = max_size(app, &uploader.ctx, &id.bucket).await?;
	if let Some(length) = length
		&& limit > 0
		&& length > limit
	{
		return Err(max_size_exceeded());
	}
	authorise(app, &mut uploader, &headers, &id, Some(Declared::new(&metadata, length))).await?;

	// `onUploadCreate`: the bucket's types checked, the cache time made a header.
	let scope = uploader.ctx.super_scope(app).await?;
	let found = find_bucket(&scope, &id.bucket, false).await?;
	scope.commit().await?;
	let (_, _, allowed) = found.ok_or_else(StorageError::no_such_bucket)?;
	let cache = field(&metadata, "cacheControl");
	let cache_is_number = !cache.is_empty() && cache.trim_start_matches('-').bytes().all(|b| b.is_ascii_digit()) && cache != "-";
	metadata.insert("cacheControl".into(), json!(if cache_is_number { format!("max-age={cache}") } else { "no-cache".to_string() }));
	let content_type = metadata.get("contentType").and_then(Value::as_str).map(str::to_string);
	if let (Some(content_type), Some(allowed)) = (&content_type, &allowed)
		&& !allowed.is_empty()
		&& (!content_type.contains('/') || !limits::mime_allowed(content_type, allowed))
	{
		return Err(StorageError::invalid_mime_type(content_type).into());
	}

	let key = id.key();
	let _guard = lock(&key).await?;
	// `S3Store.create`: the multipart upload, then `<id>.info`.
	let created = OffsetDateTime::now_utc();
	let mut s3_headers = vec![("x-amz-meta-tus-version".to_string(), TUS_RESUMABLE.to_string())];
	if let Some(content_type) = &content_type {
		s3_headers.push(("content-type".into(), content_type.clone()));
	}
	s3_headers.push(("cache-control".into(), field(&metadata, "cacheControl")));
	let upload_id = app.s3.create_multipart(&key, &s3_headers).await?;
	let mut file = Map::new();
	file.insert("id".into(), json!(key));
	file.insert("metadata".into(), Value::Object(metadata.clone()));
	if let Some(length) = length {
		file.insert("size".into(), json!(length));
	}
	file.insert("offset".into(), json!(0));
	file.insert("creation_date".into(), json!(crate::objects::js_iso(created)));
	file.insert("storage".into(), json!({ "type": "s3", "path": key, "bucket": app.config.s3.bucket }));
	save_info(app, &key, &file, &upload_id, false).await?;
	let url = location(app, &headers, uri, &key);

	let mut finished = length == Some(0);
	let mut offset = 0;
	if header_text(&headers, "content-type") == Some("application/offset+octet-stream") {
		let info = Info { file: file.clone(), upload_id: upload_id.clone() };
		let limit = body_limit(&headers, 0, length, limit)?;
		offset = write(app, &key, &info, 0, request.into_body().into_data_stream(), limit).await?;
		insert(&mut out, "upload-offset", &offset.to_string());
		finished = length == Some(offset);
	} else if length == Some(0) {
		// **Deliberately:** an empty upload is complete
		// the moment it is created, so the empty object is made now. Upstream went straight to the
		// row, found no object and answered a bare 404 that clients retry forever.
		let info = Info { file: file.clone(), upload_id: upload_id.clone() };
		write(app, &key, &info, 0, futures_util::stream::empty::<Result<Bytes, std::io::Error>>(), 0).await?;
	}
	drop(_guard);
	if finished {
		finish(app, &uploader, &id, Some(&metadata)).await?;
		insert(&mut out, "tus-complete", "1");
	}
	if length != Some(offset)
		&& let Some(expires) = expires_header(app, Some(created))
	{
		insert(&mut out, "upload-expires", &expires);
	}
	insert(&mut out, "location", &url);
	Ok(text(201, out, ""))
}

async fn patch(app: &AppState, mut uploader: Uploader, uri: &axum::http::Uri, request: Request, mut out: HeaderMap) -> Result<Response, TusError> {
	let headers = request.headers().clone();
	let key = id_from(uri, &uploader.ctx, &app.config.tus_path).ok_or_else(file_not_found)?;
	let requested: u64 = header_text(&headers, "upload-offset").ok_or_else(|| TusError::new(403, "Upload-Offset header required\n"))?.parse().unwrap_or(0);
	if headers.get("content-type").is_none() {
		return Err(TusError::new(403, "Content-Type header required\n"));
	}
	let id = UploadId::parse(&key)?;
	let info = if uploader.signed { None } else { Some(read_info(app, &key).await?) };
	authorise(app, &mut uploader, &headers, &id, info.as_ref().map(Declared::stored)).await?;
	let limit = max_size(app, &uploader.ctx, &id.bucket).await?;
	let guard = lock(&key).await?;
	let mut info = read_info(app, &key).await?;
	if expired(app, &info) {
		return Err(TusError::new(410, "The file for this url no longer exists\n"));
	}
	let offset = current_offset(app, &key, &info).await?;
	if offset != requested {
		return Err(TusError::new(409, "Upload-Offset conflict\n"));
	}
	if let Some(declared) = header_text(&headers, "upload-length") {
		let size: u64 = declared.parse().unwrap_or(0);
		if info.size().is_some() || size < offset {
			return Err(invalid_length());
		}
		if limit > 0 && size > limit {
			return Err(max_size_exceeded());
		}
		info.file.insert("size".into(), json!(size));
		save_info(app, &key, &info.file, &info.upload_id, false).await?;
	}
	let body_max = body_limit(&headers, offset, info.size(), limit)?;
	let new_offset = write(app, &key, &info, offset, request.into_body().into_data_stream(), body_max).await?;
	drop(guard);
	insert(&mut out, "upload-offset", &new_offset.to_string());
	if info.size() == Some(new_offset) {
		finish(app, &uploader, &id, info.metadata().as_ref()).await?;
		insert(&mut out, "tus-complete", "1");
	} else if let Some(expires) = expires_header(app, info.created()) {
		insert(&mut out, "upload-expires", &expires);
	}
	Ok(text(204, out, ""))
}

async fn head(app: &AppState, mut uploader: Uploader, uri: &axum::http::Uri, headers: &HeaderMap, mut out: HeaderMap) -> Result<Response, TusError> {
	let key = id_from(uri, &uploader.ctx, &app.config.tus_path).ok_or_else(file_not_found)?;
	let id = UploadId::parse(&key)?;
	authorise(app, &mut uploader, headers, &id, None).await?;
	let guard = lock(&key).await?;
	let info = read_info(app, &key).await?;
	let offset = current_offset(app, &key, &info).await?;
	drop(guard);
	if expired(app, &info) {
		return Err(TusError::new(410, "The file for this url no longer exists\n"));
	}
	insert(&mut out, "content-type", "text/plain;charset=UTF-8");
	insert(&mut out, "cache-control", "no-store");
	insert(&mut out, "upload-offset", &offset.to_string());
	match info.size() {
		Some(size) => insert(&mut out, "upload-length", &size.to_string()),
		None => insert(&mut out, "upload-defer-length", "1"),
	}
	if let Some(metadata) = info.metadata() {
		insert(&mut out, "upload-metadata", &stringify_metadata(&metadata));
	}
	let mut response = Response::new(Body::empty());
	*response.headers_mut() = out;
	Ok(response)
}

async fn terminate(app: &AppState, mut uploader: Uploader, uri: &axum::http::Uri, headers: &HeaderMap, out: HeaderMap) -> Result<Response, TusError> {
	let key = id_from(uri, &uploader.ctx, &app.config.tus_path).ok_or_else(file_not_found)?;
	let id = UploadId::parse(&key)?;
	let info = if uploader.signed { None } else { Some(read_info(app, &key).await?) };
	authorise(app, &mut uploader, headers, &id, info.as_ref().map(Declared::stored)).await?;
	let _guard = lock(&key).await?;
	let info = read_info(app, &key).await?;
	let offset = current_offset(app, &key, &info).await?;
	if Some(offset) == info.size() {
		return Err(TusError::new(400, "Cannot terminate an already completed upload"));
	}
	if !info.upload_id.is_empty() {
		app.s3.abort_multipart(&key, &info.upload_id).await.map_err(|failure| {
			if ["NotFound", "NoSuchKey", "NoSuchUpload"].contains(&failure.code.as_str()) { file_not_found() } else { failure.into() }
		})?;
	}
	app.s3.delete_many(&[key.clone(), format!("{key}.info")]).await?;
	Ok(text(204, out, ""))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn metadata_parses_as_tus_does() {
		let parsed = parse_metadata("bucketName YnVja2V0,objectName YS90eHQ=,flag").unwrap_or_default();
		assert_eq!(parsed, vec![("bucketName".into(), Some("bucket".into())), ("objectName".into(), Some("a/txt".into())), ("flag".into(), None)]);
		assert!(parse_metadata("a b c").is_none());
		assert!(parse_metadata("a YQ==,a YQ==").is_none());
		assert!(parse_metadata("a YQ=").is_none());
		assert!(parse_metadata("").is_none());
	}

	#[test]
	fn ids_split_as_upstream_does() {
		let id = UploadId::parse("t1/bucket/a/b.png/v1").unwrap_or_else(|_| unreachable!());
		assert_eq!((id.bucket.as_str(), id.object.as_str(), id.version.as_str()), ("bucket", "a/b.png", "v1"));
		assert!(UploadId::parse("t1/bucket").is_err());
	}

	#[test]
	fn integers_are_plain() {
		assert!(is_plain_integer("0"));
		assert!(is_plain_integer("12"));
		assert!(!is_plain_integer("012"));
		assert!(!is_plain_integer("-1"));
		assert!(!is_plain_integer("1.5"));
	}

	#[test]
	fn body_limits() {
		let mut headers = HeaderMap::new();
		headers.insert("content-length", HeaderValue::from_static("10"));
		assert_eq!(body_limit(&headers, 0, Some(100), 0).ok(), Some(10));
		assert!(body_limit(&headers, 95, Some(100), 0).is_err());
		assert_eq!(body_limit(&HeaderMap::new(), 40, Some(100), 0).ok(), Some(60));
	}
}
