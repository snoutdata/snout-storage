//! The object routes: `/object/*` and `POST /bucket/:id/empty`.
//!
//! The order of every check, which role runs each statement, and the words of each refusal are
//! the ones clients are written against, because a
//! customer's policies see exactly the statements it runs. Where something runs "as
//! super user", so does this, on the tenant's service role; everything else runs as the caller.
//!
//! **Bytes** go to S3 under `<tenant>/<bucket>/<name>/<version>`, a fresh version per write, and the
//! version a row no longer names is deleted after the row has moved on (a queue could do that
//! delete; this server runs it in the background as soon as the transaction commits).

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::app::{
	App, AppState, Ctx, context, context_jwt, context_optional, context_public, escape_like, iso,
	json_body, json_response, message, sql_json_response, validation,
};
use crate::db::Scope;
use crate::error::StorageError;
use crate::jwt::{self, SigningKey};
use crate::limits;
use crate::s3::{Head, http_date, parse_http_date};

/// `requestUrlLengthLimit`: how many names go into one `IN (…)`, measured as upstream measures.
const URL_LENGTH_LIMIT: usize = 7_500;
const EMPTY_BUCKET_MAX: i64 = 200_000;

pub fn routes() -> Router<AppState> {
	Router::new()
		.route("/object/move", post(move_object))
		.route("/object/copy", post(copy_object))
		.route("/object/list/{bucket}", post(list_objects))
		.route("/object/list-v2/{bucket}", post(list_objects_v2))
		.route("/object/sign/{bucket}", post(sign_urls))
		.route(
			"/object/sign/{bucket}/{*name}",
			post(sign_url).get(get_signed_object),
		)
		.route(
			"/object/upload/sign/{bucket}/{*name}",
			post(sign_upload_url).put(upload_signed_object),
		)
		.route(
			"/object/public/{bucket}/{*name}",
			get(get_public_object).head(head_public_object),
		)
		.route(
			"/object/authenticated/{bucket}/{*name}",
			get(get_authenticated_object).head(head_authenticated_object),
		)
		.route(
			"/object/info/public/{bucket}/{*name}",
			get(info_public_object),
		)
		.route(
			"/object/info/authenticated/{bucket}/{*name}",
			get(info_authenticated_object),
		)
		.route("/object/info/{bucket}/{*name}", get(info_object))
		.route("/object/{bucket}", delete(delete_objects))
		.route(
			"/object/{bucket}/{*name}",
			post(create_object)
				.put(update_object)
				.delete(delete_object)
				.get(get_object)
				.head(head_object),
		)
		.route("/bucket/{id}/empty", post(empty_bucket))
}

// ---- keys, locks, JSON -----------------------------------------------------------------------

pub(crate) fn s3_key(tenant: &str, bucket: &str, name: &str, version: Option<&str>) -> String {
	match version {
		Some(version) if !version.is_empty() => format!("{tenant}/{bucket}/{name}/{version}"),
		_ => format!("{tenant}/{bucket}/{name}"),
	}
}

/// djb2 over UTF-16 units with JavaScript's 32-bit wrap, so a lock
/// taken by either server is the same lock.
fn lock_key(bucket: &str, name: &str) -> i64 {
	let mut hash: i32 = 5381;
	for unit in format!("{bucket}/{name}").encode_utf16() {
		hash = hash.wrapping_mul(33) ^ i32::from(unit);
	}
	i64::from(hash as u32)
}

/// An object row as the API serializes it: its key order, a null string as `""`.
fn object_json() -> String {
	format!(
		"json_build_object('name', name, 'bucket_id', bucket_id, 'owner', coalesce(owner::text, ''), \
		 'owner_id', coalesce(owner_id, ''), 'version', coalesce(version, ''), 'id', id, \
		 'updated_at', {}, 'created_at', {}, 'last_accessed_at', {}, 'metadata', metadata, 'user_metadata', user_metadata)",
		iso("updated_at"),
		iso("created_at"),
		iso("last_accessed_at")
	)
}

/// JavaScript's `Date#toISOString`.
pub(crate) fn js_iso(at: OffsetDateTime) -> String {
	let at = at.to_offset(time::UtcOffset::UTC);
	format!(
		"{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
		at.year(),
		u8::from(at.month()),
		at.day(),
		at.hour(),
		at.minute(),
		at.second(),
		at.millisecond()
	)
}

/// The metadata recorded on a row after an upload: `headObject`'s answer, as upstream shapes it.
fn head_metadata(head: &Head, robots: Option<&str>) -> Value {
	let mut metadata = json!({
		"eTag": head.etag,
		"size": head.size,
		"mimetype": head.content_type,
		"cacheControl": head.cache_control,
		"lastModified": head.last_modified.map(js_iso),
		"contentLength": head.size,
		"httpStatusCode": 200,
	});
	if let (Some(robots), Some(map)) = (robots, metadata.as_object_mut()) {
		map.insert("xRobotsTag".into(), json!(robots));
	}
	metadata
}

/// `owner` is the caller's `sub` when it is a UUID, `owner_id` is the `sub` whatever it is.
pub(crate) fn owner_columns(owner: Option<&str>) -> (Option<uuid::Uuid>, Option<String>) {
	(
		owner.and_then(|s| uuid::Uuid::parse_str(s).ok()),
		owner.map(str::to_string),
	)
}

/// Deletes S3 versions nobody names any more, after the fact, as upstream's queue does.
pub(crate) fn delete_later(app: &AppState, keys: Vec<String>) {
	if keys.is_empty() {
		return;
	}
	let app = app.clone();
	tokio::spawn(async move {
		if let Err(error) = app.s3.delete_many(&keys).await {
			tracing::warn!(code = %error.code, message = %error.message, count = keys.len(), "stale object versions not deleted");
		}
	});
}

pub(crate) async fn find_bucket(
	scope: &Scope,
	id: &str,
	public_only: bool,
) -> Result<Option<(bool, Option<i64>, Option<Vec<String>>)>, StorageError> {
	let sql = if public_only {
		"SELECT public, file_size_limit, allowed_mime_types FROM buckets WHERE id = $1 AND public = true"
	} else {
		"SELECT public, file_size_limit, allowed_mime_types FROM buckets WHERE id = $1"
	};
	Ok(scope
		.query_opt(sql, &[&id])
		.await?
		.map(|row| (row.get(0), row.get(1), row.get(2))))
}

struct Found {
	version: Option<String>,
	metadata: Option<Value>,
	user_metadata: Option<Value>,
}

async fn find_object(
	scope: &Scope,
	bucket: &str,
	name: &str,
	for_update: bool,
) -> Result<Option<Found>, StorageError> {
	let sql = format!(
		"SELECT id, version, metadata, user_metadata FROM objects WHERE name = $1 AND bucket_id = $2 LIMIT 1{}",
		if for_update { " FOR UPDATE" } else { "" }
	);
	Ok(scope
		.query_opt(&sql, &[&name, &bucket])
		.await?
		.map(|row| Found {
			version: row.get(1),
			metadata: row.get(2),
			user_metadata: row.get(3),
		}))
}

/// `waitObjectLock` with a timeout: upstream's `LockTimeout` when it runs out.
async fn wait_lock(
	scope: &mut Scope,
	bucket: &str,
	name: &str,
	timeout_ms: u32,
) -> Result<(), StorageError> {
	scope
		.execute_batch(&format!("SET LOCAL lock_timeout = '{timeout_ms}ms'"))
		.await?;
	let locked = scope
		.query(
			"SELECT pg_advisory_xact_lock($1)",
			&[&lock_key(bucket, name)],
		)
		.await;
	if let Err(error) = locked {
		return Err(if error.code == "ResourceLocked" {
			StorageError::new(503, "LockTimeout", "acquiring lock timeout")
				.with_legacy_name("acquiring_lock_timeout")
		} else {
			error
		});
	}
	scope.execute_batch("SET LOCAL lock_timeout = 0").await
}

/// `testPermission`: the statement as the caller, then rolled back. What it proves is that the
/// customer's policies allow it; what it refuses is refused in the database's words.
pub(crate) async fn test_insert(
	app: &App,
	ctx: &Ctx,
	bucket: &str,
	name: &str,
	upsert: bool,
	metadata: &Value,
	user_metadata: Option<&Value>,
) -> Result<(), StorageError> {
	let (owner, owner_id) = owner_columns(ctx.caller.sub());
	let scope = ctx.scope(app).await?;
	let sql = if upsert {
		"INSERT INTO objects (bucket_id, name, version, owner, owner_id, metadata, user_metadata) VALUES ($1, $2, '1', $3, $4, $5, $6) \
		 ON CONFLICT (name, bucket_id) DO UPDATE SET metadata = EXCLUDED.metadata, user_metadata = EXCLUDED.user_metadata, \
		 version = EXCLUDED.version, owner = EXCLUDED.owner, owner_id = EXCLUDED.owner_id"
	} else {
		"INSERT INTO objects (bucket_id, name, version, owner, owner_id, metadata, user_metadata) VALUES ($1, $2, '1', $3, $4, $5, $6)"
	};
	let result = scope
		.execute(
			sql,
			&[&bucket, &name, &owner, &owner_id, metadata, &user_metadata],
		)
		.await;
	scope.rollback().await?;
	result.map(|_| ()).map_err(|e| {
		if e.code == "ResourceAlreadyExists" {
			StorageError::key_already_exists()
		} else {
			e
		}
	})
}

// ---- uploads ---------------------------------------------------------------------------------

pub(crate) struct Incoming {
	pub(crate) mime: String,
	pub(crate) cache_control: String,
	pub(crate) user_metadata: Option<Value>,
	pub(crate) robots: Option<String>,
	pub(crate) declared_length: Option<u64>,
	pub(crate) max_size: u64,
}

/// `x-metadata`: base64 JSON, ignored when it does not parse (upstream's `parseUserMetadata`).
pub(crate) fn parse_user_metadata(value: &str) -> Option<Value> {
	use base64::Engine;
	let bytes = base64::engine::general_purpose::STANDARD
		.decode(value.trim())
		.ok()?;
	serde_json::from_slice(&bytes).ok()
}

fn is_empty_folder(name: &str) -> bool {
	name.ends_with(".emptyFolderPlaceholder")
}

pub(crate) fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
	headers.get(name).and_then(|v| v.to_str().ok())
}

/// Whether a verified signed-URL token was issued for UPLOADING. The two kinds are signed with the
/// same key over the same `url`, so the routes tell them apart by what each always carries: an
/// upload token (`sign_upload_url`) always has `upsert`, a download token never does. Upstream's
/// tokens have the same shape, so a token issued before this check still works where it was meant to.
pub(crate) fn is_upload_token(claims: &Map<String, Value>) -> bool {
	claims.contains_key("upsert")
}

/// The policy every response that serves an object's bytes carries when its type could run script
/// in a browser: no script, no plugins, an opaque origin. An image or a PDF is unaffected.
pub(crate) const ACTIVE_CONTENT_CSP: &str =
	"default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox";

/// What an object is served as. An object's type is whatever its uploader said, so HTML is served
/// as plain text (upstream's rule, now matched without regard to case or parameters), and the other
/// types a browser runs script from (SVG, XHTML, XML) keep their type but are served with
/// `ACTIVE_CONTENT_CSP` and `nosniff`. Returns the type, and whether those two headers go with it.
pub(crate) fn served_type(mime: &str) -> (String, bool) {
	let essence = mime
		.split(';')
		.next()
		.unwrap_or("")
		.trim()
		.to_ascii_lowercase();
	if essence == "text/html" || essence == "application/xhtml+xml" {
		return ("text/plain".to_string(), true);
	}
	let active = essence.ends_with("+xml") || essence == "text/xml" || essence == "application/xml";
	(mime.to_string(), active)
}

/// Adds the headers `served_type` asked for.
pub(crate) fn guard_active(headers: &mut HeaderMap, active: bool) {
	if active {
		headers.insert(
			header::CONTENT_SECURITY_POLICY,
			HeaderValue::from_static(ACTIVE_CONTENT_CSP),
		);
		headers.insert(
			header::X_CONTENT_TYPE_OPTIONS,
			HeaderValue::from_static("nosniff"),
		);
	}
}

/// The most a form field other than the file may hold. The file part streams; every other field is
/// held in memory whole, by a process that serves every project on the host, so each is capped.
/// 1 MiB is what the metadata field was already allowed (anything longer was refused after it had
/// been read).
const FORM_FIELD_MAX: usize = 1024 * 1024;
/// How many fields may come before the file. The form uses at most four.
const FORM_FIELDS_MAX: usize = 32;

/// A non-file form field's text, refused as soon as it passes `FORM_FIELD_MAX`.
async fn form_field_text(mut field: multer::Field<'_>) -> Result<String, StorageError> {
	let mut buf: Vec<u8> = Vec::new();
	while let Some(chunk) = field
		.chunk()
		.await
		.map_err(|e| StorageError::no_content_provided_because(e.to_string()))?
	{
		if buf.len() + chunk.len() > FORM_FIELD_MAX {
			return Err(StorageError::new(
				413,
				"EntityTooLarge",
				"A form field exceeded the maximum allowed size",
			)
			.with_legacy_name("Payload too large"));
		}
		buf.extend_from_slice(&chunk);
	}
	Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// `uploadFromRequest` + `uploadNewObject` + `Uploader.upload`: the bucket's limits (as super
/// user), the file's type and size, the key, the caller's permission, the bytes, the row.
async fn upload(
	app: &AppState,
	ctx: &Ctx,
	request: Request,
	bucket: &str,
	name: &str,
	owner: Option<String>,
	upsert: bool,
) -> Result<(u16, String, uuid::Uuid), StorageError> {
	let limits_row = {
		let scope = ctx.super_scope(app).await?;
		let found = find_bucket(&scope, bucket, false).await?;
		scope.commit().await?;
		found.ok_or_else(StorageError::no_such_bucket)?
	};
	let (_, bucket_limit, allowed) = limits_row;
	let allowed = allowed.unwrap_or_default();
	let mut max_size = 0u64;
	if !is_empty_folder(name) {
		max_size = ctx.tenant.file_size_limit;
		if let Some(limit) = bucket_limit {
			max_size = max_size.min(limit.max(0) as u64);
		}
	}
	let headers = request.headers().clone();
	let robots = header_text(&headers, "x-robots-tag").map(str::to_string);
	if let Some(value) = &robots {
		validate_robots(value)?;
	}
	let content_type = header_text(&headers, "content-type")
		.unwrap_or("")
		.to_string();
	let declared_length =
		header_text(&headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
	let check_mime = |mime: &str| -> Result<(), StorageError> {
		if !allowed.is_empty()
			&& !is_empty_folder(name)
			&& (!mime.contains('/') || !limits::mime_allowed(mime, &allowed))
		{
			return Err(StorageError::invalid_mime_type(mime));
		}
		Ok(())
	};

	let version = uuid::Uuid::new_v4().to_string();
	let key = s3_key(&ctx.tenant.id, bucket, name, Some(&version));
	let body = request.into_body().into_data_stream();

	let incoming;
	let written = if content_type.starts_with("multipart/form-data") {
		let boundary = multer::parse_boundary(&content_type)
			.map_err(|e| StorageError::no_content_provided_because(e.to_string()))?;
		let mut form = multer::Multipart::with_constraints(
			body,
			boundary,
			multer::Constraints::new().size_limit(multer::SizeLimit::new()),
		);
		let mut fields: Map<String, Value> = Map::new();
		let mut file = None;
		let mut form_fields_seen = 0usize;
		while let Some(field) = form
			.next_field()
			.await
			.map_err(|e| StorageError::no_content_provided_because(e.to_string()))?
		{
			if field.file_name().is_some() {
				file = Some(field);
				break;
			}
			form_fields_seen += 1;
			if form_fields_seen > FORM_FIELDS_MAX {
				return Err(StorageError::no_content_provided_because(format!(
					"more than {FORM_FIELDS_MAX} form fields before the file"
				)));
			}
			let field_name = field.name().unwrap_or_default().to_string();
			let text = form_field_text(field).await?;
			if fields.len() < 10 {
				fields.insert(field_name, json!(text));
			}
		}
		let field = file.ok_or_else(StorageError::no_content_provided)?;
		let text = |key: &str| fields.get(key).and_then(Value::as_str).map(str::to_string);
		// **Deliberately:** the file part's Content-Type as
		// sent, charset and all; upstream's form parser kept only the media type.
		let mime = text("contentType")
			.filter(|s| !s.is_empty())
			.or_else(|| {
				field
					.headers()
					.get("content-type")
					.and_then(|v| v.to_str().ok())
					.map(str::to_string)
			})
			.unwrap_or_else(|| "text/plain".into());
		let cache_control = text("cacheControl")
			.filter(|s| !s.is_empty())
			.map(|t| format!("max-age={t}"))
			.unwrap_or_else(|| "no-cache".into());
		check_mime(&mime)?;
		let user_metadata = match text("metadata").or_else(|| text("userMetadata")) {
			Some(raw) if raw.len() > 1024 * 1024 => {
				return Err(StorageError::new(
					413,
					"EntityTooLarge",
					"The user_metadata exceeded the maximum allowed size",
				)
				.with_legacy_name("Payload too large"));
			}
			Some(raw) => serde_json::from_str(&raw).ok(),
			None => None,
		};
		incoming = Incoming {
			mime,
			cache_control,
			user_metadata,
			robots,
			declared_length,
			max_size,
		};
		prepare(app, ctx, bucket, name, upsert, &incoming).await?;
		app.s3
			.upload(
				&key,
				field,
				&incoming.mime,
				&incoming.cache_control,
				incoming.max_size,
			)
			.await
	} else {
		let mime = if content_type.is_empty() {
			"application/octet-stream".to_string()
		} else {
			content_type.clone()
		};
		let cache_control = header_text(&headers, "cache-control")
			.unwrap_or("no-cache")
			.to_string();
		check_mime(&mime)?;
		let user_metadata = header_text(&headers, "x-metadata").and_then(parse_user_metadata);
		if declared_length.is_some_and(|length| length > max_size) {
			return Err(StorageError::entity_too_large());
		}
		incoming = Incoming {
			mime,
			cache_control,
			user_metadata,
			robots,
			declared_length,
			max_size,
		};
		prepare(app, ctx, bucket, name, upsert, &incoming).await?;
		app.s3
			.upload(
				&key,
				body,
				&incoming.mime,
				&incoming.cache_control,
				incoming.max_size,
			)
			.await
	};
	if let Err(error) = written {
		delete_later(app, vec![key]);
		return Err(error);
	}
	let incoming = Incoming {
		user_metadata: Some(incoming.user_metadata.clone().unwrap_or_else(|| json!({}))),
		..incoming
	};
	match complete_upload(
		app,
		ctx,
		bucket,
		name,
		&version,
		owner.as_deref(),
		&incoming,
	)
	.await
	{
		Ok(id) => Ok((200, format!("{bucket}/{name}"), id)),
		Err(error) => {
			delete_later(app, vec![key]);
			Err(error)
		}
	}
}

/// The key checked, then the insert tried as the caller and rolled back (`canUpload`).
async fn prepare(
	app: &App,
	ctx: &Ctx,
	bucket: &str,
	name: &str,
	upsert: bool,
	incoming: &Incoming,
) -> Result<(), StorageError> {
	limits::must_be_valid_key(name)?;
	let metadata = json!({ "mimetype": incoming.mime, "contentLength": incoming.declared_length });
	test_insert(
		app,
		ctx,
		bucket,
		name,
		upsert,
		&metadata,
		incoming.user_metadata.as_ref(),
	)
	.await
}

/// `completeUpload`, as super user: the row points at the new version, the old one is deleted.
pub(crate) async fn complete_upload(
	app: &AppState,
	ctx: &Ctx,
	bucket: &str,
	name: &str,
	version: &str,
	owner: Option<&str>,
	incoming: &Incoming,
) -> Result<uuid::Uuid, StorageError> {
	let head = app
		.s3
		.head(&s3_key(&ctx.tenant.id, bucket, name, Some(version)))
		.await?;
	let metadata = head_metadata(&head, incoming.robots.as_deref());
	// A standard upload always records its user metadata (`{}` when none was sent); a resumable one
	// without any records none, and an overwrite keeps what the row had, as knex drops `undefined`.
	let user_metadata = incoming.user_metadata.clone();
	let keep = if user_metadata.is_none() {
		"objects.user_metadata"
	} else {
		"EXCLUDED.user_metadata"
	};
	let (owner, owner_id) = owner_columns(owner);
	let mut scope = ctx.super_scope(app).await?;
	wait_lock(&mut scope, bucket, name, 5000).await?;
	let current = find_object(&scope, bucket, name, true).await?;
	let row = scope
		.query_opt(
			&format!(
				"INSERT INTO objects (name, owner, owner_id, bucket_id, metadata, user_metadata, version) VALUES ($1, $2, $3, $4, $5, $6, $7) \
				 ON CONFLICT (name, bucket_id) DO UPDATE SET metadata = EXCLUDED.metadata, user_metadata = {keep}, \
				 version = EXCLUDED.version, owner = EXCLUDED.owner, owner_id = EXCLUDED.owner_id RETURNING id"
			),
			&[&name, &owner, &owner_id, &bucket, &metadata, &user_metadata, &version],
		)
		.await?
		.ok_or_else(StorageError::internal)?;
	scope.commit().await?;
	if let Some(old) = current
		&& old.version.as_deref() != Some(version)
	{
		delete_later(
			app,
			vec![s3_key(&ctx.tenant.id, bucket, name, old.version.as_deref())],
		);
	}
	Ok(row.get(0))
}

fn upload_response(status: u16, key: &str, id: Option<uuid::Uuid>) -> Response {
	let body = match id {
		Some(id) => json!({ "Key": key, "Id": id.to_string() }),
		None => json!({ "Key": key }),
	};
	let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
	(status, json_response(body.to_string())).into_response()
}

async fn create_object(
	State(app): State<AppState>,
	Path((bucket, name)): Path<(String, String)>,
	request: Request,
) -> Result<Response, StorageError> {
	let ctx = context(
		&app,
		request.method(),
		request.uri(),
		request.headers(),
		"storage.object.upload",
	)
	.await?;
	let upsert = header_text(request.headers(), "x-upsert") == Some("true");
	let owner = ctx.caller.sub().map(str::to_string);
	let (status, key, id) = upload(&app, &ctx, request, &bucket, &name, owner, upsert).await?;
	Ok(upload_response(status, &key, Some(id)))
}

async fn update_object(
	State(app): State<AppState>,
	Path((bucket, name)): Path<(String, String)>,
	request: Request,
) -> Result<Response, StorageError> {
	let ctx = context(
		&app,
		request.method(),
		request.uri(),
		request.headers(),
		"storage.object.upload_update",
	)
	.await?;
	let owner = ctx.caller.sub().map(str::to_string);
	let (status, key, id) = upload(&app, &ctx, request, &bucket, &name, owner, true).await?;
	Ok(upload_response(status, &key, Some(id)))
}

#[derive(Deserialize)]
struct TokenQuery {
	token: Option<String>,
	download: Option<String>,
}

async fn upload_signed_object(
	State(app): State<AppState>,
	Path((bucket, name)): Path<(String, String)>,
	Query(query): Query<TokenQuery>,
	request: Request,
) -> Result<Response, StorageError> {
	let token = query
		.token
		.ok_or_else(|| validation("querystring must have required property 'token'"))?;
	let ctx = context_public(
		&app,
		request.method(),
		request.uri(),
		request.headers(),
		"storage.object.upload_signed",
	)
	.await?;
	let claims = jwt::verify(&token, &ctx.tenant.jwt_secret, &ctx.tenant.jwks)
		.map_err(|e| StorageError::invalid_jwt(e.0))?;
	if claims.get("url").and_then(Value::as_str) != Some(format!("{bucket}/{name}").as_str())
		|| !is_upload_token(&claims)
	{
		return Err(StorageError::invalid_signature("Invalid signature"));
	}
	let owner = claims
		.get("owner")
		.and_then(Value::as_str)
		.map(str::to_string);
	let upsert = claims
		.get("upsert")
		.and_then(Value::as_bool)
		.unwrap_or(false);
	let (status, key, _) = upload(&app, &ctx, request, &bucket, &name, owner, upsert).await?;
	Ok(upload_response(status, &key, None))
}

// ---- downloads -------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
	/// `/object/authenticated/...`: a valid token required.
	Authenticated,
	/// `/object/...`: a bad token is anon; a public bucket is read as super user.
	Optional,
	/// `/object/public/...`: a public bucket only, read as super user.
	Public,
}

async fn access_context(
	app: &App,
	access: Access,
	method: &Method,
	uri: &Uri,
	headers: &HeaderMap,
	operation: &str,
) -> Result<Ctx, StorageError> {
	match access {
		Access::Authenticated => context(app, method, uri, headers, operation).await,
		Access::Optional => context_optional(app, method, uri, headers, operation).await,
		Access::Public => context_public(app, method, uri, headers, operation).await,
	}
}

/// The object a read is about, found the way the route finds it.
async fn readable_object(
	app: &App,
	ctx: &Ctx,
	access: Access,
	bucket: &str,
	name: &str,
	columns: &str,
) -> Result<tokio_postgres::Row, StorageError> {
	let scope = ctx.super_scope(app).await?;
	let found = find_bucket(&scope, bucket, access == Access::Public).await?;
	scope.commit().await?;
	let Some((public, _, _)) = found else {
		return Err(StorageError::no_such_bucket());
	};
	if !ctx.authenticated && !public && access != Access::Public {
		return Err(StorageError::no_such_bucket());
	}
	let scope = if public || access == Access::Public {
		ctx.super_scope(app).await?
	} else {
		ctx.scope(app).await?
	};
	let row = scope
		.query_opt(
			&format!("SELECT {columns} FROM objects WHERE name = $1 AND bucket_id = $2 LIMIT 1"),
			&[&name, &bucket],
		)
		.await?;
	scope.commit().await?;
	row.ok_or_else(StorageError::no_such_key)
}

/// The asset renderer: S3's answer streamed through with the storage headers.
/// What the asset renderer is asked to send.
struct Asset<'a> {
	bucket: &'a str,
	name: &'a str,
	version: Option<&'a str>,
	download: Option<&'a str>,
	expires: Option<String>,
	robots: Option<&'a str>,
}

async fn render_asset(
	app: &App,
	ctx: &Ctx,
	request_headers: &HeaderMap,
	asset: Asset<'_>,
) -> Result<Response, StorageError> {
	let Asset {
		bucket,
		name,
		version,
		download,
		expires,
		robots,
	} = asset;
	let key = s3_key(&ctx.tenant.id, bucket, name, version);
	let mut conditional = Vec::new();
	for name in ["range", "if-none-match", "if-modified-since"] {
		if let Some(value) = header_text(request_headers, name) {
			conditional.push((name.to_string(), value.to_string()));
		}
	}
	let response = match app.s3.get(&key, &conditional).await {
		Ok(response) => response,
		Err(failure) if failure.status == 404 => {
			let body = json!({ "error": "Not found", "message": "The resource was not found", "statusCode": "404" });
			return Ok((
				StatusCode::BAD_REQUEST,
				[(header::CACHE_CONTROL, "no-store")],
				json_response(body.to_string()),
			)
				.into_response());
		}
		Err(failure) => return Err(failure.into()),
	};
	let status = response.status().as_u16();
	if status == 304 {
		return Ok(StatusCode::NOT_MODIFIED.into_response());
	}
	let upstream = response.headers().clone();
	let text = |name: &str| {
		upstream
			.get(name)
			.and_then(|v| v.to_str().ok())
			.map(str::to_string)
	};
	let mime = text("content-type").unwrap_or_else(|| "application/octet-stream".into());
	let (mime, active) = served_type(&mime);
	let etag = text("etag").unwrap_or_default();
	let mut builder = Response::builder()
		.status(status)
		.header("accept-ranges", "bytes")
		.header(header::CONTENT_TYPE, mime)
		.header(header::ETAG, &etag)
		.header("x-robots-tag", robots_header(robots));
	if let Some(headers) = builder.headers_mut() {
		guard_active(headers, active);
	}
	if let Some(modified) = text("last-modified").and_then(|v| parse_http_date(&v)) {
		builder = builder.header(header::LAST_MODIFIED, http_date(modified));
	}
	if let Some(length) = text("content-length") {
		builder = builder.header(header::CONTENT_LENGTH, length);
	}
	match expires {
		Some(expires) => builder = builder.header(header::EXPIRES, expires),
		None => {
			let cache_control = text("cache-control").unwrap_or_else(|| "no-cache".into());
			let mut values = vec![cache_control];
			if let Some(requested) = header_text(request_headers, "if-none-match")
				&& requested != etag
			{
				values.push("stale-while-revalidate=30".into());
			}
			let joined = values
				.into_iter()
				.filter(|v| !v.is_empty())
				.collect::<Vec<_>>()
				.join(", ");
			if !joined.is_empty() {
				builder = builder.header(header::CACHE_CONTROL, joined);
			}
		}
	}
	if let Some(range) = text("content-range") {
		builder = builder.header(header::CONTENT_RANGE, range);
	}
	if let Some(disposition) = download.map(content_disposition) {
		builder = builder.header(header::CONTENT_DISPOSITION, disposition);
	}
	builder
		.body(Body::from_stream(response.bytes_stream()))
		.map_err(|_| StorageError::internal())
}

/// A stored `X-Robots-Tag` that still validates, else `none`.
fn robots_header(robots: Option<&str>) -> String {
	match robots {
		Some(value) if validate_robots(value).is_ok() => value.to_string(),
		_ => "none".into(),
	}
}

/// `encodeURIComponent`.
fn encode_component(value: &str) -> String {
	let mut out = String::new();
	for byte in value.bytes() {
		match byte {
			b'A'..=b'Z'
			| b'a'..=b'z'
			| b'0'..=b'9'
			| b'-'
			| b'_'
			| b'.'
			| b'!'
			| b'~'
			| b'*'
			| b'\''
			| b'('
			| b')' => out.push(byte as char),
			_ => out.push_str(&format!("%{byte:02X}")),
		}
	}
	out
}

/// `?download=`. **Deliberately:** RFC 6266 and
/// 8187 rather than `encodeURIComponent` twice: a quoted ASCII `filename` fallback, and a
/// `filename*` that escapes every character outside RFC 8187's attr-char (upstream left
/// `' ( ) *` bare, which ends the value early in a browser).
pub(crate) fn content_disposition(download: &str) -> String {
	if download.is_empty() {
		return "attachment;".into();
	}
	let fallback: String = download
		.chars()
		.map(|c| {
			if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' {
				c
			} else {
				'_'
			}
		})
		.collect();
	let mut encoded = String::new();
	for byte in download.bytes() {
		match byte {
			b'A'..=b'Z'
			| b'a'..=b'z'
			| b'0'..=b'9'
			| b'!'
			| b'#'
			| b'$'
			| b'&'
			| b'+'
			| b'-'
			| b'.'
			| b'^'
			| b'_'
			| b'`'
			| b'|'
			| b'~' => encoded.push(byte as char),
			_ => encoded.push_str(&format!("%{byte:02X}")),
		}
	}
	format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
}

/// A request's method, URI and headers, as the routes hand them on.
struct Req {
	method: Method,
	uri: Uri,
	headers: HeaderMap,
}

async fn serve_object(
	app: AppState,
	access: Access,
	operation: &str,
	req: Req,
	(bucket, name): (String, String),
	download: Option<String>,
) -> Result<Response, StorageError> {
	if access == Access::Authenticated {
		crate::app::require_authorization(&req.headers)?;
	}
	let ctx = access_context(&app, access, &req.method, &req.uri, &req.headers, operation).await?;
	let row = readable_object(&app, &ctx, access, &bucket, &name, "version, metadata").await?;
	let version: Option<String> = row.get(0);
	let metadata: Option<Value> = row.get(1);
	let robots = metadata
		.as_ref()
		.and_then(|m| m.get("xRobotsTag"))
		.and_then(Value::as_str)
		.map(str::to_string);
	let asset = Asset {
		bucket: &bucket,
		name: &name,
		version: version.as_deref(),
		download: download.as_deref(),
		expires: None,
		robots: robots.as_deref(),
	};
	render_asset(&app, &ctx, &req.headers, asset).await
}

async fn get_object(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path((bucket, name)): Path<(String, String)>,
	Query(query): Query<TokenQuery>,
) -> Result<Response, StorageError> {
	serve_object(
		app,
		Access::Optional,
		"storage.object.get_authenticated",
		Req {
			method,
			uri,
			headers,
		},
		(bucket, name),
		query.download,
	)
	.await
}

async fn get_authenticated_object(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path((bucket, name)): Path<(String, String)>,
	Query(query): Query<TokenQuery>,
) -> Result<Response, StorageError> {
	serve_object(
		app,
		Access::Authenticated,
		"storage.object.get_authenticated",
		Req {
			method,
			uri,
			headers,
		},
		(bucket, name),
		query.download,
	)
	.await
}

async fn get_public_object(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path((bucket, name)): Path<(String, String)>,
	Query(query): Query<TokenQuery>,
) -> Result<Response, StorageError> {
	serve_object(
		app,
		Access::Public,
		"storage.object.get_public",
		Req {
			method,
			uri,
			headers,
		},
		(bucket, name),
		query.download,
	)
	.await
}

async fn get_signed_object(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path((bucket, name)): Path<(String, String)>,
	Query(query): Query<TokenQuery>,
) -> Result<Response, StorageError> {
	let token = query
		.token
		.ok_or_else(|| validation("querystring must have required property 'token'"))?;
	let ctx = context_public(&app, &method, &uri, &headers, "storage.object.get_signed").await?;
	let claims = jwt::verify(&token, &ctx.tenant.jwt_secret, &ctx.tenant.jwks)
		.map_err(|e| StorageError::invalid_jwt(e.0))?;
	let url = claims
		.get("url")
		.and_then(Value::as_str)
		.unwrap_or_default()
		.to_string();
	if url != format!("{bucket}/{name}") || is_upload_token(&claims) {
		return Err(StorageError::invalid_signature("Invalid signature"));
	}
	let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
	let (signed_bucket, signed_name) = url.split_once('/').unwrap_or((url.as_str(), ""));
	let scope = ctx.super_scope(&app).await?;
	let found = scope
		.query_opt(
			"SELECT version, metadata FROM objects WHERE name = $1 AND bucket_id = $2 LIMIT 1",
			&[&signed_name, &signed_bucket],
		)
		.await?;
	scope.commit().await?;
	let row = found.ok_or_else(StorageError::no_such_key)?;
	let version: Option<String> = row.get(0);
	let metadata: Option<Value> = row.get(1);
	let robots = metadata
		.as_ref()
		.and_then(|m| m.get("xRobotsTag"))
		.and_then(Value::as_str)
		.map(str::to_string);
	let expires = OffsetDateTime::from_unix_timestamp(exp).ok().map(http_date);
	let asset = Asset {
		bucket: signed_bucket,
		name: signed_name,
		version: version.as_deref(),
		download: query.download.as_deref(),
		expires,
		robots: robots.as_deref(),
	};
	render_asset(&app, &ctx, &headers, asset).await
}

// ---- head and info ---------------------------------------------------------------------------

const INFO_COLUMNS: &str =
	"id, name, version, bucket_id, metadata, user_metadata, updated_at, created_at";

/// The head and info renderers: everything from the row's recorded metadata, nothing from S3.
async fn describe(
	app: AppState,
	access: Access,
	info: bool,
	operation: &str,
	req: Req,
	(bucket, name): (String, String),
) -> Result<Response, StorageError> {
	let headers = req.headers;
	if access == Access::Authenticated {
		crate::app::require_authorization(&headers)?;
	}
	let ctx = access_context(&app, access, &req.method, &req.uri, &headers, operation).await?;
	let columns = format!(
		"{INFO_COLUMNS}, {} AS updated_iso, {} AS created_iso",
		iso("updated_at"),
		iso("created_at")
	);
	let row = readable_object(&app, &ctx, access, &bucket, &name, &columns).await?;
	let metadata: Option<Value> = row.get("metadata");
	let raw = metadata.unwrap_or(Value::Null);
	let text = |key: &str| raw.get(key).and_then(Value::as_str).map(str::to_string);
	let number = |key: &str| match raw.get(key) {
		Some(Value::Number(n)) => n.as_u64(),
		Some(Value::String(s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
			s.parse().ok()
		}
		_ => None,
	};
	let etag = text("eTag");
	let cache_control = text("cacheControl");
	let mime = text("mimetype");
	let last_modified = text("lastModified")
		.and_then(|v| OffsetDateTime::parse(&v, &Rfc3339).ok())
		.or_else(|| {
			raw.get("lastModified")
				.and_then(Value::as_i64)
				.and_then(|ms| OffsetDateTime::from_unix_timestamp(ms / 1000).ok())
		});
	let status = number("httpStatusCode")
		.and_then(|s| StatusCode::from_u16(s as u16).ok())
		.unwrap_or(StatusCode::OK);

	let mut response = if info {
		let body = json!({
			"id": row.get::<_, uuid::Uuid>("id").to_string(),
			"name": row.get::<_, Option<String>>("name"),
			"version": row.get::<_, Option<String>>("version"),
			"bucket_id": row.get::<_, Option<String>>("bucket_id"),
			"size": number("size"),
			"content_type": mime,
			"cache_control": cache_control,
			"etag": etag,
			"metadata": row.get::<_, Option<Value>>("user_metadata"),
			"last_modified": row.get::<_, Option<String>>("updated_iso"),
			"created_at": row.get::<_, Option<String>>("created_iso"),
		});
		let mut response = json_response(body.to_string());
		*response.status_mut() = status;
		response
	} else {
		let mut response = Response::new(Body::empty());
		*response.status_mut() = status;
		let headers_out = response.headers_mut();
		headers_out.insert("accept-ranges", HeaderValue::from_static("bytes"));
		if let Some(mime) = &mime {
			let (mime, active) = served_type(mime);
			if let Ok(value) = HeaderValue::from_str(&mime) {
				headers_out.insert(header::CONTENT_TYPE, value);
			}
			guard_active(headers_out, active);
		}
		if let Ok(value) = HeaderValue::from_str(&robots_header(text("xRobotsTag").as_deref())) {
			headers_out.insert("x-robots-tag", value);
		}
		if let Some(length) = number("contentLength")
			&& let Ok(value) = HeaderValue::from_str(&length.to_string())
		{
			headers_out.insert(header::CONTENT_LENGTH, value);
		}
		response
	};
	let headers_out = response.headers_mut();
	if let Some(etag) = &etag
		&& let Ok(value) = HeaderValue::from_str(etag)
	{
		headers_out.insert(header::ETAG, value);
	}
	if let Some(at) = last_modified
		&& let Ok(value) = HeaderValue::from_str(&http_date(at))
	{
		headers_out.insert(header::LAST_MODIFIED, value);
	}
	let mut cache = cache_control.clone().into_iter().collect::<Vec<_>>();
	if !info
		&& let Some(requested) = header_text(&headers, "if-none-match")
		&& Some(requested) != etag.as_deref()
	{
		cache.push("must-revalidate".into());
	}
	let cache = cache
		.into_iter()
		.filter(|v| !v.is_empty())
		.collect::<Vec<_>>()
		.join(", ");
	if !cache.is_empty()
		&& let Ok(value) = HeaderValue::from_str(&cache)
	{
		headers_out.insert(header::CACHE_CONTROL, value);
	}
	Ok(response)
}

macro_rules! describe_route {
	($name:ident, $access:expr, $info:expr, $operation:expr) => {
		async fn $name(
			State(app): State<AppState>,
			method: Method,
			uri: Uri,
			headers: HeaderMap,
			Path((bucket, name)): Path<(String, String)>,
		) -> Result<Response, StorageError> {
			describe(
				app,
				$access,
				$info,
				$operation,
				Req {
					method,
					uri,
					headers,
				},
				(bucket, name),
			)
			.await
		}
	};
}

describe_route!(
	head_object,
	Access::Optional,
	false,
	"storage.object.head_authenticated_info"
);
describe_route!(
	head_authenticated_object,
	Access::Authenticated,
	false,
	"storage.object.head_authenticated_info"
);
describe_route!(
	head_public_object,
	Access::Public,
	false,
	"storage.object.info_public"
);
describe_route!(
	info_object,
	Access::Optional,
	true,
	"storage.object.get_authenticated_info"
);
describe_route!(
	info_authenticated_object,
	Access::Authenticated,
	true,
	"storage.object.get_authenticated_info"
);
describe_route!(
	info_public_object,
	Access::Public,
	true,
	"storage.object.info_public"
);

// ---- signing ---------------------------------------------------------------------------------

/// `assertValidNumericJWTExpiration`: a positive whole number of seconds that keeps `exp` a
/// safe integer.
fn expires_in(body: &Map<String, Value>) -> Result<i64, StorageError> {
	let value = body
		.get("expiresIn")
		.ok_or_else(|| validation("body must have required property 'expiresIn'"))?;
	let seconds = match value {
		Value::Number(n) => n
			.as_i64()
			.or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64))
			.ok_or_else(|| validation("body/expiresIn must be integer"))?,
		Value::String(s) => s
			.trim()
			.parse::<i64>()
			.map_err(|_| validation("body/expiresIn must be integer"))?,
		_ => return Err(validation("body/expiresIn must be integer")),
	};
	if seconds < 1 {
		return Err(validation("body/expiresIn must be >= 1"));
	}
	let now = OffsetDateTime::now_utc().unix_timestamp();
	if seconds > 9_007_199_254_740_991 - now {
		return Err(StorageError::invalid_parameter("expiresIn"));
	}
	Ok(seconds)
}

async fn sign_url(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path((bucket, name)): Path<(String, String)>,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let seconds = expires_in(&body)?;
	let transform = match body.get("transform") {
		None | Some(Value::Null) => None,
		Some(Value::Object(fields)) => Some(transform_body(fields)?),
		Some(_) => return Err(validation("body/transform must be object")),
	};
	let ctx = context(&app, &method, &uri, &headers, "storage.object.sign").await?;
	let scope = ctx.scope(&app).await?;
	let found = find_object(&scope, &bucket, &name, false).await?;
	scope.commit().await?;
	found.ok_or_else(StorageError::no_such_key)?;
	// The signed path is the request's own, after `/object/sign/`, URI-decoded as `decodeURI` does.
	let path = uri.path();
	let signed_part = path.split('/').skip(3).collect::<Vec<_>>().join("/");
	let url = percent_encoding::percent_decode_str(&signed_part)
		.decode_utf8_lossy()
		.to_string();
	let mut payload = Map::new();
	payload.insert("url".into(), json!(url));
	// With image transformation on, the transform rides in the token (empty values dropped) and the
	// URL points at the renderer instead.
	let mut route = "object";
	if ctx.tenant.image_transformation {
		let transform = transform.unwrap_or_default();
		let transformations = crate::render::segments(
			&transform,
			true,
			app.config.image_size_min,
			app.config.image_size_max,
		)
		.join(",");
		if !transformations.is_empty() {
			payload.insert("transformations".into(), json!(transformations));
			route = "render/image";
		}
		if let Some(format) = transform.format.filter(|f| !f.is_empty()) {
			payload.insert("format".into(), json!(format));
		}
	}
	let token = jwt::sign(payload, &ctx.tenant.signing_key(), Some(seconds));
	Ok(json_response(
		json!({ "signedURL": format!("/{route}/sign/{url}?token={token}") }).to_string(),
	))
}

/// `body.transform`, as the sign route's schema admits it.
fn transform_body(fields: &Map<String, Value>) -> Result<crate::render::Transform, StorageError> {
	let integer = |key: &str,
	               minimum: i64,
	               maximum: Option<i64>|
	 -> Result<Option<i64>, StorageError> {
		let value = match fields.get(key) {
			None | Some(Value::Null) => return Ok(None),
			Some(Value::Number(n)) => n
				.as_i64()
				.ok_or_else(|| validation(&format!("body/transform/{key} must be integer")))?,
			Some(Value::String(s)) => s
				.trim()
				.parse::<i64>()
				.map_err(|_| validation(&format!("body/transform/{key} must be integer")))?,
			Some(_) => return Err(validation(&format!("body/transform/{key} must be integer"))),
		};
		if value < minimum {
			return Err(validation(&format!(
				"body/transform/{key} must be >= {minimum}"
			)));
		}
		if let Some(maximum) = maximum
			&& value > maximum
		{
			return Err(validation(&format!(
				"body/transform/{key} must be <= {maximum}"
			)));
		}
		Ok(Some(value))
	};
	let choice = |key: &str, allowed: &[&str]| -> Result<Option<String>, StorageError> {
		match fields.get(key) {
			None | Some(Value::Null) => Ok(None),
			Some(Value::String(s)) if allowed.contains(&s.as_str()) => Ok(Some(s.clone())),
			Some(_) => Err(validation(&format!(
				"body/transform/{key} must be equal to one of the allowed values"
			))),
		}
	};
	Ok(crate::render::Transform {
		height: integer("height", 0, None)?,
		width: integer("width", 0, None)?,
		resize: choice("resize", &["cover", "contain", "fill"])?,
		format: choice("format", &["origin", "avif", "webp"])?,
		quality: integer("quality", 20, Some(100))?,
	})
}

async fn sign_urls(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(bucket): Path<String>,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let seconds = expires_in(&body)?;
	let paths: Vec<String> = match body.get("paths") {
		None => return Err(validation("body must have required property 'paths'")),
		Some(Value::Array(items)) if items.is_empty() => {
			return Err(validation("body/paths must NOT have fewer than 1 items"));
		}
		Some(Value::Array(items)) => items
			.iter()
			.map(|v| {
				v.as_str()
					.map(str::to_string)
					.unwrap_or_else(|| v.to_string())
			})
			.collect(),
		Some(_) => return Err(validation("body/paths must be array")),
	};
	let ctx = context(&app, &method, &uri, &headers, "storage.object.sign_many").await?;
	let scope = ctx.scope(&app).await?;
	let mut found = std::collections::HashSet::new();
	for chunk in by_url_length(&paths) {
		for row in scope
			.query(
				"SELECT name FROM objects WHERE bucket_id = $1 AND name = ANY($2)",
				&[&bucket, &chunk],
			)
			.await?
		{
			found.insert(row.get::<_, String>(0));
		}
	}
	scope.commit().await?;
	let key: SigningKey = ctx.tenant.signing_key();
	let results: Vec<Value> = paths
		.iter()
		.map(|path| {
			if found.contains(path) {
				let url = format!("{bucket}/{path}");
				let mut payload = Map::new();
				payload.insert("url".into(), json!(url));
				let token = jwt::sign(payload, &key, Some(seconds));
				json!({ "error": null, "path": path, "signedURL": format!("/object/sign/{url}?token={token}") })
			} else {
				json!({ "error": "Either the object does not exist or you do not have access to it", "path": path, "signedURL": null })
			}
		})
		.collect();
	Ok(json_response(Value::Array(results).to_string()))
}

/// Names batched so an `IN` list stays under upstream's URL-length budget.
fn by_url_length(names: &[String]) -> Vec<Vec<String>> {
	let mut batches = Vec::new();
	let mut current = Vec::new();
	let mut length = 0;
	for name in names {
		current.push(name.clone());
		length += encode_component(name).len() + 9;
		if length >= URL_LENGTH_LIMIT {
			batches.push(std::mem::take(&mut current));
			length = 0;
		}
	}
	if !current.is_empty() {
		batches.push(current);
	}
	batches
}

async fn sign_upload_url(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path((bucket, name)): Path<(String, String)>,
) -> Result<Response, StorageError> {
	let ctx = context(&app, &method, &uri, &headers, "storage.object.upload_sign").await?;
	let upsert = header_text(&headers, "x-upsert") == Some("true");
	let user_metadata = header_text(&headers, "x-metadata").and_then(parse_user_metadata);
	let content_length =
		header_text(&headers, "content-length").and_then(|v| v.trim().parse::<f64>().ok());
	let metadata = json!({ "mimetype": header_text(&headers, "content-type"), "contentLength": content_length });
	test_insert(
		&app,
		&ctx,
		&bucket,
		&name,
		upsert,
		&metadata,
		user_metadata.as_ref(),
	)
	.await?;
	let url = format!("{bucket}/{name}");
	let mut payload = Map::new();
	if let Some(owner) = ctx.caller.sub() {
		payload.insert("owner".into(), json!(owner));
	}
	payload.insert("url".into(), json!(url));
	payload.insert("upsert".into(), json!(upsert));
	let token = jwt::sign(
		payload,
		&ctx.tenant.signing_key(),
		Some(app.config.signed_upload_url_expires),
	);
	Ok(json_response(
		json!({ "url": format!("/object/upload/sign/{url}?token={token}"), "token": token })
			.to_string(),
	))
}

// ---- delete ----------------------------------------------------------------------------------

async fn delete_object(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path((bucket, name)): Path<(String, String)>,
) -> Result<Response, StorageError> {
	let ctx = context(&app, &method, &uri, &headers, "storage.object.delete").await?;
	let scope = ctx.scope(&app).await?;
	// As super user inside the caller's transaction, as upstream's `db.asSuperUser()` there does.
	scope
		.become_caller(&ctx.service_caller(), &ctx.facts)
		.await?;
	let found = find_object(&scope, &bucket, &name, true)
		.await?
		.ok_or_else(StorageError::no_such_key)?;
	scope.become_caller(&ctx.caller, &ctx.facts).await?;
	let deleted = scope
		.query_opt(
			"DELETE FROM objects WHERE name = $1 AND bucket_id = $2 RETURNING id",
			&[&name, &bucket],
		)
		.await?;
	if deleted.is_none() {
		return Err(StorageError::access_denied("Access denied"));
	}
	app.s3
		.delete(&s3_key(
			&ctx.tenant.id,
			&bucket,
			&name,
			found.version.as_deref(),
		))
		.await?;
	scope.commit().await?;
	Ok(message("Successfully deleted"))
}

async fn delete_objects(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(bucket): Path<String>,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let prefixes: Vec<String> = match body.get("prefixes") {
		None => return Err(validation("body must have required property 'prefixes'")),
		Some(Value::Array(items)) if items.is_empty() => {
			return Err(validation("body/prefixes must NOT have fewer than 1 items"));
		}
		Some(Value::Array(items)) => items
			.iter()
			.map(|v| {
				v.as_str()
					.map(str::to_string)
					.unwrap_or_else(|| v.to_string())
			})
			.collect(),
		Some(_) => return Err(validation("body/prefixes must be array")),
	};
	let ctx = context(&app, &method, &uri, &headers, "storage.object.delete_many").await?;
	let mut results: Vec<Value> = Vec::new();
	for chunk in by_url_length(&prefixes) {
		let scope = ctx.scope(&app).await?;
		let sql = format!(
			"WITH gone AS (DELETE FROM objects WHERE bucket_id = $1 AND name = ANY($2) RETURNING *) \
			 SELECT {}::text, name, version FROM gone",
			object_json()
		);
		let rows = scope.query(&sql, &[&bucket, &chunk]).await?;
		let mut keys = Vec::new();
		for row in &rows {
			let name: String = row.get(1);
			let version: Option<String> = row.get(2);
			let key = s3_key(&ctx.tenant.id, &bucket, &name, version.as_deref());
			if version.is_some() {
				keys.push(format!("{key}.info"));
			}
			keys.push(key);
			results.push(serde_json::from_str(row.get::<_, &str>(0)).unwrap_or(Value::Null));
		}
		if !keys.is_empty() {
			app.s3.delete_many(&keys).await?;
		}
		scope.commit().await?;
	}
	Ok(json_response(Value::Array(results).to_string()))
}

// ---- move and copy ---------------------------------------------------------------------------

fn body_string(body: &Map<String, Value>, key: &str) -> Result<Option<String>, StorageError> {
	match body.get(key) {
		None | Some(Value::Null) => Ok(None),
		Some(Value::String(s)) => Ok(Some(s.clone())),
		Some(Value::Number(n)) => Ok(Some(n.to_string())),
		Some(Value::Bool(b)) => Ok(Some(b.to_string())),
		Some(_) => Err(validation(&format!("body/{key} must be string"))),
	}
}

fn required_strings(body: &Map<String, Value>, keys: &[&str]) -> Result<Vec<String>, StorageError> {
	for key in keys {
		if !body.contains_key(*key) {
			return Err(validation(&format!(
				"body must have required property '{key}'"
			)));
		}
	}
	keys.iter()
		.map(|key| body_string(body, key).map(Option::unwrap_or_default))
		.collect()
}

async fn move_object(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let fields = required_strings(&body, &["bucketId", "sourceKey", "destinationKey"])?;
	let (bucket, source, destination) = (fields[0].clone(), fields[1].clone(), fields[2].clone());
	let destination_bucket = body_string(&body, "destinationBucket")?
		.filter(|s| !s.is_empty())
		.unwrap_or_else(|| bucket.clone());
	let ctx = context(&app, &method, &uri, &headers, "storage.object.move").await?;
	limits::must_be_valid_key(&destination)?;
	let version = uuid::Uuid::new_v4().to_string();
	let (owner, owner_id) = owner_columns(ctx.caller.sub());

	// Whether the caller may read the source and rename it there, tried and rolled back.
	{
		let scope = ctx.scope(&app).await?;
		let checked = async {
			find_object(&scope, &bucket, &source, false).await?.ok_or_else(StorageError::no_such_key)?;
			let updated = scope
				.query_opt(
					"UPDATE objects SET name = $3, version = $4, bucket_id = $5, owner = $6, owner_id = $7 WHERE bucket_id = $1 AND name = $2 RETURNING id",
					&[&bucket, &source, &destination, &version, &destination_bucket, &owner, &owner_id],
				)
				.await?;
			updated.ok_or_else(StorageError::no_such_key).map(|_| ())
		}
		.await;
		scope.rollback().await?;
		checked?;
	}

	let scope = ctx.super_scope(&app).await?;
	let source_row = find_object(&scope, &bucket, &source, false)
		.await?
		.ok_or_else(StorageError::no_such_key)?;
	scope.commit().await?;
	let from = s3_key(&ctx.tenant.id, &bucket, &source, None);
	let to = s3_key(&ctx.tenant.id, &destination_bucket, &destination, None);
	if from == to {
		return Ok(message("Successfully moved"));
	}
	let from_versioned = s3_key(
		&ctx.tenant.id,
		&bucket,
		&source,
		source_row.version.as_deref(),
	);
	let to_versioned = s3_key(
		&ctx.tenant.id,
		&destination_bucket,
		&destination,
		Some(&version),
	);
	let result = async {
		app.s3.copy(&from_versioned, &to_versioned, None).await?;
		let head = app.s3.head(&to_versioned).await?;
		let metadata = head_metadata(&head, None);
		let mut scope = ctx.super_scope(&app).await?;
		wait_lock(&mut scope, &bucket, &destination, 5000).await?;
		let locked = find_object(&scope, &bucket, &source, true).await?.ok_or_else(StorageError::no_such_key)?;
		scope
			.execute(
				"UPDATE objects SET name = $3, bucket_id = $4, version = $5, owner = $6, owner_id = $7, metadata = $8, user_metadata = $9 WHERE bucket_id = $1 AND name = $2",
				&[&bucket, &source, &destination, &destination_bucket, &version, &owner, &owner_id, &metadata, &source_row.user_metadata],
			)
			.await?;
		scope.commit().await?;
		Ok::<_, StorageError>(locked)
	}
	.await;
	match result {
		Ok(locked) => {
			delete_later(
				&app,
				vec![s3_key(
					&ctx.tenant.id,
					&bucket,
					&source,
					locked.version.as_deref(),
				)],
			);
			Ok(message("Successfully moved"))
		}
		Err(error) => {
			delete_later(&app, vec![to_versioned]);
			Err(error)
		}
	}
}

async fn copy_object(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let fields = required_strings(&body, &["sourceKey", "bucketId", "destinationKey"])?;
	let (source, bucket, destination) = (fields[0].clone(), fields[1].clone(), fields[2].clone());
	let destination_bucket = body_string(&body, "destinationBucket")?
		.filter(|s| !s.is_empty())
		.unwrap_or_else(|| bucket.clone());
	let copy_metadata = match body.get("copyMetadata") {
		None | Some(Value::Null) => true,
		Some(Value::Bool(b)) => *b,
		Some(_) => return Err(validation("body/copyMetadata must be boolean")),
	};
	let given_metadata = match body.get("metadata") {
		None | Some(Value::Null) => None,
		Some(Value::Object(map)) => Some(map.clone()),
		Some(_) => return Err(validation("body/metadata must be object")),
	};
	let ctx = context(&app, &method, &uri, &headers, "storage.object.copy").await?;
	let upsert = header_text(&headers, "x-upsert") == Some("true");
	let header_user_metadata = header_text(&headers, "x-metadata").and_then(parse_user_metadata);
	limits::must_be_valid_key(&destination)?;
	let version = uuid::Uuid::new_v4().to_string();

	let scope = ctx.scope(&app).await?;
	let origin = find_object(&scope, &bucket, &source, false).await?;
	scope.commit().await?;
	let origin = origin.ok_or_else(StorageError::no_such_key)?;
	let mut destination_metadata = origin.metadata.clone().unwrap_or_else(|| json!({}));
	if !copy_metadata
		&& let (Some(given), Some(map)) = (&given_metadata, destination_metadata.as_object_mut())
	{
		for (key, value) in given {
			map.insert(key.clone(), value.clone());
		}
	}
	let destination_user_metadata = if copy_metadata {
		origin.user_metadata.clone()
	} else {
		header_user_metadata
	};
	test_insert(
		&app,
		&ctx,
		&destination_bucket,
		&destination,
		upsert,
		&destination_metadata,
		destination_user_metadata.as_ref(),
	)
	.await?;
	// The copy's type is held to the destination bucket's allowed types, as an upload to it is:
	// otherwise a copy with a new `metadata.mimetype` serves any type from any bucket.
	{
		let scope = ctx.super_scope(&app).await?;
		let found = find_bucket(&scope, &destination_bucket, false).await?;
		scope.commit().await?;
		let (_, _, allowed) = found.ok_or_else(StorageError::no_such_bucket)?;
		let allowed = allowed.unwrap_or_default();
		let mime = destination_metadata
			.get("mimetype")
			.and_then(Value::as_str)
			.unwrap_or_default();
		if !allowed.is_empty()
			&& !is_empty_folder(&destination)
			&& (!mime.contains('/') || !limits::mime_allowed(mime, &allowed))
		{
			return Err(StorageError::invalid_mime_type(mime));
		}
	}

	let from = s3_key(&ctx.tenant.id, &bucket, &source, origin.version.as_deref());
	let to = s3_key(
		&ctx.tenant.id,
		&destination_bucket,
		&destination,
		Some(&version),
	);
	let (owner, owner_id) = owner_columns(ctx.caller.sub());
	let result = async {
		// **Deliberately:** new metadata asked for is
		// written to the copy itself, so it is served; upstream recorded it on the row only.
		let replace = (!copy_metadata && given_metadata.is_some()).then(|| {
			let text = |key: &str| destination_metadata.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
			(text("mimetype"), text("cacheControl"))
		});
		let (etag, modified) = app.s3.copy(&from, &to, replace.as_ref().map(|(m, c)| (m.as_str(), c.as_str()))).await?;
		if let Some(map) = destination_metadata.as_object_mut() {
			map.insert("lastModified".into(), json!(modified.map(js_iso)));
			map.insert("eTag".into(), json!(etag));
		}
		let mut scope = ctx.super_scope(&app).await?;
		wait_lock(&mut scope, &destination_bucket, &destination, 3000).await?;
		let existing = find_object(&scope, &destination_bucket, &destination, true).await?;
		let sql = format!(
			"WITH up AS (INSERT INTO objects (bucket_id, name, owner, owner_id, metadata, user_metadata, version) VALUES ($1, $2, $3, $4, $5, $6, $7) \
			 ON CONFLICT (name, bucket_id) DO UPDATE SET metadata = EXCLUDED.metadata, user_metadata = EXCLUDED.user_metadata, \
			 version = EXCLUDED.version, owner = EXCLUDED.owner, owner_id = EXCLUDED.owner_id RETURNING *) \
			 SELECT {}::text, id FROM up",
			object_json()
		);
		let row = scope
			.query_opt(&sql, &[&destination_bucket, &destination, &owner, &owner_id, &destination_metadata, &destination_user_metadata, &version])
			.await?
			.ok_or_else(StorageError::internal)?;
		scope.commit().await?;
		Ok::<_, StorageError>((row, existing))
	}
	.await;
	match result {
		Ok((row, existing)) => {
			if let Some(old) = existing {
				delete_later(
					&app,
					vec![s3_key(
						&ctx.tenant.id,
						&destination_bucket,
						&destination,
						old.version.as_deref(),
					)],
				);
			}
			let object: Value = serde_json::from_str(row.get::<_, &str>(0)).unwrap_or(Value::Null);
			let id: uuid::Uuid = row.get(1);
			let mut out = Map::new();
			out.insert(
				"Key".into(),
				json!(format!("{destination_bucket}/{destination}")),
			);
			out.insert("Id".into(), json!(id.to_string()));
			if let Value::Object(fields) = object {
				out.extend(fields);
			}
			Ok(json_response(Value::Object(out).to_string()))
		}
		Err(error) => {
			delete_later(&app, vec![to]);
			Err(error)
		}
	}
}

// ---- list ------------------------------------------------------------------------------------

fn sort_by(
	body: &Map<String, Value>,
	columns: &[&str],
) -> Result<(Option<String>, Option<String>), StorageError> {
	match body.get("sortBy") {
		None => Ok((None, None)),
		Some(Value::Object(sort)) => {
			let column = match sort.get("column") {
				None => {
					return Err(validation(
						"body/sortBy must have required property 'column'",
					));
				}
				Some(Value::String(c)) if columns.contains(&c.as_str()) => c.clone(),
				Some(_) => {
					return Err(validation(
						"body/sortBy/column must be equal to one of the allowed values",
					));
				}
			};
			let order = match sort.get("order") {
				None => None,
				Some(Value::String(o)) if o == "asc" || o == "desc" => Some(o.clone()),
				Some(_) => {
					return Err(validation(
						"body/sortBy/order must be equal to one of the allowed values",
					));
				}
			};
			Ok((Some(column), order))
		}
		Some(_) => Err(validation("body/sortBy must be object")),
	}
}

fn body_integer(
	body: &Map<String, Value>,
	key: &str,
	minimum: i64,
) -> Result<Option<i64>, StorageError> {
	let value = match body.get(key) {
		None | Some(Value::Null) => return Ok(None),
		Some(Value::Number(n)) => n
			.as_i64()
			.ok_or_else(|| validation(&format!("body/{key} must be integer")))?,
		Some(Value::String(s)) => s
			.trim()
			.parse::<i64>()
			.map_err(|_| validation(&format!("body/{key} must be integer")))?,
		Some(_) => return Err(validation(&format!("body/{key} must be integer"))),
	};
	if value < minimum {
		return Err(validation(&format!("body/{key} must be >= {minimum}")));
	}
	Ok(Some(value))
}

async fn list_objects(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(bucket): Path<String>,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let limit = body_integer(&body, "limit", 1)?;
	let offset = body_integer(&body, "offset", 0)?;
	let (column, order) = sort_by(
		&body,
		&["name", "updated_at", "created_at", "last_accessed_at"],
	)?;
	let search = body_string(&body, "search")?;
	if !body.contains_key("prefix") {
		return Err(validation("body must have required property 'prefix'"));
	}
	let mut prefix = body_string(&body, "prefix")?.unwrap_or_default();
	let ctx = context(&app, &method, &uri, &headers, "storage.object.list").await?;
	if !prefix.is_empty() && !prefix.ends_with('/') {
		prefix.push('/');
	}
	let column = column.unwrap_or_else(|| "name".into());
	let escape = column != "name";
	let safe_prefix = if escape { escape_like(&prefix) } else { prefix };
	let search = search.unwrap_or_default();
	let safe_search = if escape { escape_like(&search) } else { search };
	let levels = safe_prefix.split('/').count() as i32;
	let direction = if order.as_deref() == Some("desc") {
		"DESC"
	} else {
		"ASC"
	};
	let sql = list_v1_sql(&column, direction);
	let target = format!("{safe_prefix}{safe_search}");
	let limit = limit.unwrap_or(100).min(1500);
	let offset = offset.unwrap_or(0);
	let scope = ctx.scope(&app).await?;
	let row = scope
		.query_opt(&sql, &[&bucket, &target, &levels, &offset, &limit])
		.await?;
	scope.commit().await?;
	Ok(sql_json_response(
		row.map(|r| r.get::<_, String>(0))
			.unwrap_or_else(|| "[]".into()),
	))
}

/// One level of a bucket under a prefix: the folders there (a folder is a common prefix, never a
/// row) and the objects directly in it, as `name`, `id`, the three dates and `metadata`, a folder
/// with everything but its name null. Parameters: `$1` bucket, `$2` the prefix with the search
/// text appended, `$3` which `/`-separated segment is the entry's name, `$4` offset, `$5` limit.
///
/// Sorted by name, the match is case-insensitive and folders and objects interleave in byte order
/// of the lower-cased key. Sorted by a date, folders come first (by name), then the objects, and
/// `$2` is an ILIKE pattern (escaped by the caller).
fn list_v1_sql(column: &str, direction: &str) -> String {
	let entry = format!(
		"json_build_object('name', name, 'id', id, 'updated_at', {}, 'created_at', {}, 'last_accessed_at', {}, 'metadata', metadata)",
		iso("updated_at"),
		iso("created_at"),
		iso("last_accessed_at")
	);
	if column == "name" {
		format!(
			"WITH m AS ( \
			   SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata, lower(o.name) AS lname, \
			          strpos(substr(lower(o.name), length(lower($2::text)) + 1), '/') AS cut \
			   FROM storage.objects o WHERE o.bucket_id = $1 AND starts_with(lower(o.name), lower($2::text)) \
			 ), listed AS ( \
			   (SELECT DISTINCT ON (left(lname, length(lower($2::text)) + cut)) \
			           left(lname, length(lower($2::text)) + cut) AS sort_key, \
			           split_part(rtrim(left(name, length(lower($2::text)) + cut), '/'), '/', $3) AS name, \
			           NULL::uuid AS id, NULL::timestamptz AS updated_at, NULL::timestamptz AS created_at, \
			           NULL::timestamptz AS last_accessed_at, NULL::jsonb AS metadata \
			    FROM m WHERE cut > 0 ORDER BY left(lname, length(lower($2::text)) + cut), lname COLLATE \"C\" {direction}) \
			   UNION ALL \
			   (SELECT lname, split_part(name, '/', $3), id, updated_at, created_at, last_accessed_at, metadata FROM m WHERE cut = 0) \
			 ), page AS ( \
			   SELECT * FROM listed ORDER BY sort_key COLLATE \"C\" {direction} OFFSET $4 LIMIT $5 \
			 ) \
			 SELECT coalesce(json_agg({entry} ORDER BY sort_key COLLATE \"C\" {direction}), '[]'::json)::text FROM page"
		)
	} else {
		format!(
			"WITH listed AS ( \
			   (SELECT 0 AS branch, folder AS folder_name, NULL::timestamptz AS sort_value, folder AS name, NULL::uuid AS id, \
			           NULL::timestamptz AS updated_at, NULL::timestamptz AS created_at, NULL::timestamptz AS last_accessed_at, NULL::jsonb AS metadata \
			    FROM (SELECT path_tokens[$3] AS folder FROM storage.objects \
			          WHERE name ILIKE $2::text || '%' AND bucket_id = $1 AND array_length(path_tokens, 1) <> $3 GROUP BY 1) f) \
			   UNION ALL \
			   (SELECT 1, NULL, {column}, path_tokens[$3], id, updated_at, created_at, last_accessed_at, metadata FROM storage.objects \
			    WHERE name ILIKE $2::text || '%' AND bucket_id = $1 AND array_length(path_tokens, 1) = $3) \
			 ), page AS ( \
			   SELECT * FROM listed ORDER BY branch, folder_name {direction}, sort_value {direction} OFFSET $4 LIMIT $5 \
			 ) \
			 SELECT coalesce(json_agg({entry} ORDER BY branch, folder_name {direction}, sort_value {direction}), '[]'::json)::text FROM page"
		)
	}
}

/// One level of a bucket under a prefix, delimited by `/`: rows of `key` (the entry's segment),
/// `name` (its full path, a folder's without the trailing slash), `id`, the three dates and
/// `metadata`. Parameters: `$1` bucket, `$2` prefix, `$3` which segment is the key, `$4` page size,
/// `$5` the cursor (the last name of the previous page, `''` for none), `$6` the previous page's
/// last date when sorted by one.
///
/// By name: keys in byte order, case-sensitive. A cursor that is a folder resumes after
/// everything in it; a cursor that is an object resumes after its own subtree.
///
/// By a date: each folder dated by its oldest object's creation, then by name to break ties, and
/// the cursor is the (date, name) pair.
fn list_v2_delimited_sql(by_date: Option<&str>, direction: &str) -> String {
	let asc = direction == "ASC";
	let entry = "json_build_object('key', split_part(name, '/', $3), 'name', name, 'id', id, 'updated_at', updated_at, \
	             'created_at', created_at, 'last_accessed_at', last_accessed_at, 'metadata', metadata)::text";
	match by_date {
		None => {
			let (folder_seek, object_seek, compare) = if asc {
				("$5 || '0'", "$5 || '/'", ">=")
			} else {
				("$5 || '/'", "$5", "<")
			};
			format!(
				"WITH cursor AS ( \
				   SELECT CASE WHEN $5::text = '' THEN NULL \
				               WHEN EXISTS (SELECT FROM storage.objects WHERE bucket_id = $1 AND name COLLATE \"C\" LIKE $5::text || '/%') \
				               THEN {folder_seek} ELSE {object_seek} END AS seek \
				 ), m AS ( \
				   SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata, \
				          strpos(substr(o.name, length($2::text) + 1), '/') AS cut \
				   FROM storage.objects o, cursor c \
				   WHERE o.bucket_id = $1 AND starts_with(o.name, $2::text) \
				     AND (c.seek IS NULL OR o.name COLLATE \"C\" {compare} c.seek COLLATE \"C\") \
				 ), listed AS ( \
				   (SELECT DISTINCT ON (left(name, length($2::text) + cut)) left(name, length($2::text) + cut) AS sort_key, \
				           rtrim(left(name, length($2::text) + cut), '/') AS name, NULL::uuid AS id, NULL::timestamptz AS updated_at, \
				           NULL::timestamptz AS created_at, NULL::timestamptz AS last_accessed_at, NULL::jsonb AS metadata \
				    FROM m WHERE cut > 0 ORDER BY 1) \
				   UNION ALL \
				   (SELECT name, name, id, updated_at, created_at, last_accessed_at, metadata FROM m WHERE cut = 0) \
				 ) \
				 SELECT {entry} FROM listed ORDER BY sort_key COLLATE \"C\" {direction} LIMIT $4"
			)
		}
		Some(column) => {
			let compare = if asc { ">" } else { "<" };
			format!(
				"WITH raw AS ( \
				   SELECT o.name, o.id, o.updated_at, o.created_at, o.last_accessed_at, o.metadata, \
				          CASE WHEN strpos(substr(o.name, length($2::text) + 1), '/') > 0 \
				               THEN left(o.name, length($2::text) + strpos(substr(o.name, length($2::text) + 1), '/')) END AS folder \
				   FROM storage.objects o WHERE o.bucket_id = $1 AND o.name COLLATE \"C\" LIKE $2::text || '%' \
				 ), listed AS ( \
				   SELECT rtrim(folder, '/') AS name, NULL::uuid AS id, min(created_at) AS updated_at, min(created_at) AS created_at, \
				          NULL::timestamptz AS last_accessed_at, NULL::jsonb AS metadata \
				   FROM raw WHERE folder IS NOT NULL GROUP BY folder \
				   UNION ALL \
				   SELECT name, id, updated_at, created_at, last_accessed_at, metadata FROM raw WHERE folder IS NULL \
				 ) \
				 SELECT {entry} FROM listed \
				 WHERE $5::text = '' OR ROW(date_trunc('milliseconds', {column}), name COLLATE \"C\") {compare} \
				       ROW(coalesce(nullif($6::text, '')::timestamptz, 'epoch'::timestamptz), $5::text) \
				 ORDER BY coalesce(date_trunc('milliseconds', {column}), 'epoch'::timestamptz) {direction}, name COLLATE \"C\" {direction} \
				 LIMIT $4"
			)
		}
	}
}

/// The list-v2 continuation token: `k:value` lines, base64.
fn encode_cursor(
	start_after: &str,
	order: Option<&str>,
	column: Option<&str>,
	column_after: Option<&str>,
) -> String {
	use base64::Engine;
	let mut text = String::new();
	for (key, value) in [
		("l", Some(start_after)),
		("o", order),
		("c", column),
		("a", column_after),
	] {
		if let Some(value) = value.filter(|v| !v.is_empty()) {
			text.push_str(&format!("{key}:{value}\n"));
		}
	}
	text.pop();
	base64::engine::general_purpose::STANDARD.encode(text)
}

#[derive(Default)]
pub(crate) struct Cursor {
	start_after: Option<String>,
	order: Option<String>,
	column: Option<String>,
	column_after: Option<String>,
}

/// `decodeContinuationToken`: every line `k:value` with a known `k`, the order `asc` unless the
/// token says otherwise, anything else refused.
pub(crate) fn decode_cursor(token: &str) -> Result<Cursor, StorageError> {
	use base64::Engine;
	let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
		.decode(token.trim_end_matches('='))
		.unwrap_or_default();
	let text = String::from_utf8_lossy(&bytes).to_string();
	let mut cursor = Cursor {
		order: Some("asc".into()),
		..Cursor::default()
	};
	for line in text.split('\n') {
		let mut chars = line.chars();
		let (Some(key), Some(':')) = (chars.next(), chars.next()) else {
			return Err(StorageError::invalid_parameter("continuation token"));
		};
		let value = Some(chars.as_str().to_string()).filter(|v| !v.is_empty());
		match key {
			'l' => cursor.start_after = value,
			'o' => cursor.order = value,
			'c' => cursor.column = value,
			'a' => cursor.column_after = value,
			_ => return Err(StorageError::invalid_parameter("continuation token")),
		}
	}
	Ok(cursor)
}

/// list-v2 has no response schema upstream, so its refusals keep their `code`.
async fn list_objects_v2(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(bucket): Path<String>,
	body: Bytes,
) -> Result<Response, StorageError> {
	list_v2(app, method, uri, headers, bucket, body)
		.await
		.map_err(StorageError::with_code)
}

async fn list_v2(
	app: AppState,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	bucket: String,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let cursor_text = body_string(&body, "cursor")?;
	let with_delimiter = match body.get("with_delimiter") {
		None | Some(Value::Null) => false,
		Some(Value::Bool(b)) => *b,
		Some(_) => return Err(validation("body/with_delimiter must be boolean")),
	};
	let (column, order) = sort_by(&body, &["name", "updated_at", "created_at"])?;
	let ctx = context_jwt(&app, &method, &uri, &headers, "storage.object.list_v2").await?;
	let limit = body_integer(&body, "limit", i64::MIN)?
		.filter(|n| *n != 0)
		.unwrap_or(1000)
		.min(1000);
	let prefix = body_string(&body, "prefix")?.unwrap_or_default();
	let cursor = cursor_text
		.as_deref()
		.filter(|t| !t.is_empty())
		.map(decode_cursor)
		.transpose()?;
	let start_after_option = body_string(&body, "startAfter")?;
	let order = cursor.as_ref().and_then(|c| c.order.clone()).or(order);
	let column = cursor.as_ref().and_then(|c| c.column.clone()).or(column);
	let column_after = cursor.as_ref().and_then(|c| c.column_after.clone());
	let next_token = cursor.as_ref().and_then(|c| c.start_after.clone());
	let start_after = next_token.clone().or(start_after_option);

	let scope = ctx.scope(&app).await?;
	let mut rows: Vec<Map<String, Value>> = if !with_delimiter {
		let sort_column = column
			.as_deref()
			.filter(|c| *c == "updated_at" || *c == "created_at");
		let sort_order = order
			.as_deref()
			.filter(|o| *o == "asc" || *o == "desc")
			.unwrap_or("asc");
		let mut sql = format!(
			"SELECT json_build_object('id', id, 'name', name, 'metadata', metadata, 'updated_at', {}, 'created_at', {}, 'last_accessed_at', {})::text \
			 FROM objects WHERE bucket_id = $1",
			iso("updated_at"),
			iso("created_at"),
			iso("last_accessed_at")
		);
		let mut params: Vec<String> = vec![bucket.clone()];
		if !prefix.is_empty() {
			params.push(format!("{}%", escape_like(&prefix)));
			sql.push_str(&format!(" AND name LIKE ${}", params.len()));
		}
		if let (Some(after), None) = (&start_after, &next_token) {
			params.push(after.clone());
			sql.push_str(&format!(" AND name COLLATE \"C\" > ${}", params.len()));
		}
		if let Some(token) = &next_token {
			let op = if sort_order == "asc" { ">" } else { "<" };
			match (sort_column, &column_after) {
				(Some(sort), Some(after)) => {
					params.push(after.clone());
					let a = params.len();
					params.push(token.clone());
					sql.push_str(&format!(
						" AND ROW(date_trunc('milliseconds', {sort}), name COLLATE \"C\") {op} ROW(COALESCE(NULLIF(${a}, '')::timestamptz, 'epoch'::timestamptz), ${})",
						params.len()
					));
				}
				_ => {
					params.push(token.clone());
					sql.push_str(&format!(" AND name COLLATE \"C\" {op} ${}", params.len()));
				}
			}
		}
		if let Some(sort) = sort_column {
			sql.push_str(&format!(
				" ORDER BY {sort} {sort_order}, name COLLATE \"C\" {sort_order}"
			));
		} else {
			sql.push_str(&format!(" ORDER BY name COLLATE \"C\" {sort_order}"));
		}
		sql.push_str(&format!(" LIMIT {}", limit + 1));
		let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
			.iter()
			.map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
			.collect();
		scope
			.query(&sql, &refs)
			.await?
			.iter()
			.filter_map(|row| {
				serde_json::from_str::<Map<String, Value>>(row.get::<_, &str>(0)).ok()
			})
			.collect()
	} else {
		let levels = if prefix.is_empty() {
			1
		} else {
			prefix.split('/').count() as i32
		};
		let direction = if order.as_deref() == Some("desc") {
			"DESC"
		} else {
			"ASC"
		};
		let by_date = column
			.as_deref()
			.filter(|c| *c == "updated_at" || *c == "created_at");
		let sql = list_v2_delimited_sql(by_date, direction);
		let start = start_after.clone().unwrap_or_default();
		let page = (limit + 1).min(1500);
		let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
			vec![&bucket, &prefix, &levels, &page, &start];
		if by_date.is_some() {
			params.push(&column_after);
		}
		scope
			.query(&sql, &params)
			.await?
			.iter()
			.filter_map(|row| {
				serde_json::from_str::<Map<String, Value>>(row.get::<_, &str>(0)).ok()
			})
			.map(normalize_row_dates)
			.collect()
	};
	scope.commit().await?;

	if with_delimiter {
		let mut delimited = Vec::new();
		let mut previous = String::new();
		for row in rows {
			let name = row
				.get("name")
				.and_then(Value::as_str)
				.unwrap_or_default()
				.to_string();
			let rest = name.replacen(&prefix, "", 1);
			if let Some(index) = rest.find('/') {
				let cut = prefix.len() + index + 1;
				let folder = name.get(..cut).unwrap_or(&name).to_string();
				if folder == previous {
					continue;
				}
				previous = folder.clone();
				let mut entry = Map::new();
				entry.insert("id".into(), Value::Null);
				entry.insert("name".into(), json!(folder));
				entry.insert(
					"bucket_id".into(),
					row.get("bucket_id").cloned().unwrap_or(Value::Null),
				);
				delimited.push(entry);
				continue;
			}
			delimited.push(row);
		}
		rows = delimited;
	}
	let truncated = rows.len() as i64 > limit;
	rows.truncate(limit.max(0) as usize);
	let mut folders = Vec::new();
	let mut objects = Vec::new();
	for mut row in rows.iter().cloned() {
		let is_folder = row.get("id").is_none_or(Value::is_null);
		if is_folder
			&& let Some(Value::String(name)) = row.get_mut("name")
			&& !name.ends_with('/')
		{
			name.push('/');
		}
		if is_folder {
			folders.push(Value::Object(row))
		} else {
			objects.push(Value::Object(row))
		}
	}
	let mut out = Map::new();
	out.insert("hasNext".into(), json!(truncated));
	if truncated && let Some(last) = rows.last() {
		let last_name = last.get("name").and_then(Value::as_str).unwrap_or_default();
		let sort = column.as_deref();
		let after = sort
			.filter(|c| *c != "name")
			.and_then(|c| last.get(c))
			.and_then(Value::as_str);
		out.insert(
			"nextCursor".into(),
			json!(encode_cursor(last_name, order.as_deref(), sort, after)),
		);
		out.insert("nextCursorKey".into(), json!(last_name));
	}
	out.insert("folders".into(), Value::Array(folders));
	out.insert("objects".into(), Value::Array(objects));
	Ok(json_response(Value::Object(out).to_string()))
}

/// `row_to_json` writes a timestamp as Postgres does; clients expect JavaScript's Date format.
fn normalize_row_dates(mut row: Map<String, Value>) -> Map<String, Value> {
	for key in ["updated_at", "created_at", "last_accessed_at"] {
		if let Some(Value::String(text)) = row.get(key)
			&& let Some(at) = parse_pg_timestamp(text)
		{
			row.insert(key.into(), json!(js_iso(at)));
		}
	}
	row
}

fn parse_pg_timestamp(text: &str) -> Option<OffsetDateTime> {
	OffsetDateTime::parse(text, &Rfc3339).ok().or_else(|| {
		let fixed = if text.len() > 3 && (text.ends_with("+00") || text.ends_with("-00")) {
			format!("{text}:00")
		} else {
			text.to_string()
		};
		OffsetDateTime::parse(&fixed.replace(' ', "T"), &Rfc3339).ok()
	})
}

// ---- empty bucket ----------------------------------------------------------------------------

async fn empty_bucket(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(id): Path<String>,
) -> Result<Response, StorageError> {
	let ctx = context(&app, &method, &uri, &headers, "storage.bucket.empty").await?;
	let before = OffsetDateTime::now_utc();
	let scope = ctx.scope(&app).await?;
	if scope
		.query_opt("SELECT name FROM buckets WHERE id = $1", &[&id])
		.await?
		.is_none()
	{
		return Err(StorageError::no_such_bucket());
	}
	let count: i64 = scope
		.query_opt(
			"SELECT count(*) FROM (SELECT 1 FROM objects WHERE bucket_id = $1 LIMIT $2) c",
			&[&id, &(EMPTY_BUCKET_MAX + 1)],
		)
		.await?
		.map(|r| r.get(0))
		.unwrap_or(0);
	if count > EMPTY_BUCKET_MAX {
		return Err(StorageError::new(
			409,
			"UnableToEmptyBucket",
			"Unable to empty the bucket because it contains too many objects",
		));
	}
	let first = scope
		.query_opt(
			"SELECT name FROM objects WHERE bucket_id = $1 AND created_at < $2 ORDER BY name LIMIT 1",
			&[&id, &before],
		)
		.await?;
	scope.commit().await?;
	let Some(first) = first else {
		return Ok(message(
			"Empty bucket has been queued. Completion may take up to an hour.",
		));
	};
	let first: String = first.get(0);
	// The caller must be allowed to delete at least the first object, tried and rolled back.
	{
		let scope = ctx.scope(&app).await?;
		let deleted = scope
			.query_opt(
				"DELETE FROM objects WHERE bucket_id = $1 AND name = $2 RETURNING id",
				&[&id, &first],
			)
			.await;
		scope.rollback().await?;
		if deleted?.is_none() {
			return Err(StorageError::no_such_key());
		}
	}
	// **Deliberately, and the one place this differs from upstream on who may do what:** the
	// objects are deleted AS THE CALLER, so the project's delete policy decides every row. Upstream
	// checked the first object only and then deleted everything as the service role, which let a
	// user allowed to delete one file of their own empty the whole bucket (diff/authz.js, "B
	// empties the bucket"). The batches walk the ids the caller can see, so rows it may see but not
	// delete are stepped over rather than ending the job.
	let app_bg = app.clone();
	let tenant = ctx.tenant.clone();
	let caller = ctx.caller.clone();
	let facts = ctx.facts.clone();
	tokio::spawn(async move {
		let mut after: Option<uuid::Uuid> = None;
		loop {
			let batch = async {
				let scope = app_bg.pools.begin(&tenant.id, &tenant.database_url, &caller, &facts).await?;
				let ids: Vec<uuid::Uuid> = scope
					.query(
						"SELECT id FROM objects WHERE bucket_id = $1 AND created_at < $2 AND ($3::uuid IS NULL OR id > $3) ORDER BY id LIMIT 1000",
						&[&id, &before, &after],
					)
					.await?
					.iter()
					.map(|r| r.get(0))
					.collect();
				let Some(last) = ids.last().copied() else {
					scope.commit().await?;
					return Ok::<Option<uuid::Uuid>, StorageError>(None);
				};
				let rows = scope.query("DELETE FROM objects WHERE id = ANY($1) RETURNING name, version", &[&ids]).await?;
				let keys: Vec<String> = rows.iter().map(|r| s3_key(&tenant.id, &id, r.get::<_, &str>(0), r.get::<_, Option<&str>>(1))).collect();
				if !keys.is_empty() {
					app_bg.s3.delete_many(&keys).await?;
				}
				scope.commit().await?;
				Ok(Some(last))
			}
			.await;
			match batch {
				Ok(None) => break,
				Ok(Some(last)) => after = Some(last),
				Err(error) => {
					tracing::error!(bucket = %id, error = %error.message, "empty bucket stopped");
					break;
				}
			}
		}
	});
	Ok(message(
		"Empty bucket has been queued. Completion may take up to an hour.",
	))
}

// ---- X-Robots-Tag ----------------------------------------------------------------------------

const ROBOTS_SIMPLE: [&str; 8] = [
	"all",
	"noindex",
	"nofollow",
	"none",
	"nosnippet",
	"indexifembedded",
	"notranslate",
	"noimageindex",
];
const ROBOTS_PARAMETRIC: [&str; 4] = [
	"max-snippet",
	"max-image-preview",
	"max-video-preview",
	"unavailable_after",
];

fn robots_error(message: &str) -> StorageError {
	StorageError::new(400, "InvalidXRobotsTag", message)
}

/// `validateXRobotsTag`: comma-separated rules, each simple, parametric, or scoped to a bot.
fn validate_robots(value: &str) -> Result<(), StorageError> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		return Err(robots_error(
			"X-Robots-Tag header value must be a non-empty string",
		));
	}
	for part in trimmed.split(',').map(str::trim) {
		if part.is_empty() {
			return Err(robots_error("X-Robots-Tag header contains empty rule"));
		}
		if rule_ok(part) {
			continue;
		}
		match part.split_once(':') {
			Some((_bot, rule)) if rule_ok(rule.trim()) => {}
			_ => return Err(robots_error(&format!("Invalid X-Robots-Tag rule: {part}"))),
		}
	}
	Ok(())
}

fn rule_ok(rule: &str) -> bool {
	if ROBOTS_SIMPLE.contains(&rule) {
		return true;
	}
	match rule.split_once(':') {
		Some((name, value)) if ROBOTS_PARAMETRIC.contains(&name.trim()) => {
			let value = value.trim();
			match name.trim() {
				"max-image-preview" => ["none", "standard", "large"].contains(&value),
				"unavailable_after" => !value.is_empty(),
				_ => value.parse::<i64>().is_ok_and(|n| n >= -1),
			}
		}
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn locks_hash_as_upstream_does() {
		// hashStringToInt in Node: 2857233763 and 176865772.
		assert_eq!(lock_key("bucket", "name"), 2_857_233_763);
		assert_eq!(lock_key("b", "望舌诊病.pdf"), 176_865_772);
	}

	#[test]
	fn keys_carry_the_version() {
		assert_eq!(s3_key("t", "b", "a/b.png", Some("v1")), "t/b/a/b.png/v1");
		assert_eq!(s3_key("t", "b", "a.png", None), "t/b/a.png");
	}

	#[test]
	fn cursors_round_trip() {
		let token = encode_cursor(
			"a/b",
			Some("desc"),
			Some("created_at"),
			Some("2026-01-01T00:00:00.000Z"),
		);
		let cursor = decode_cursor(&token).unwrap_or_default();
		assert_eq!(cursor.start_after.as_deref(), Some("a/b"));
		assert_eq!(
			cursor.column_after.as_deref(),
			Some("2026-01-01T00:00:00.000Z")
		);
	}

	#[test]
	fn robots() {
		assert!(validate_robots("noindex, nofollow").is_ok());
		assert!(validate_robots("max-image-preview: large").is_ok());
		assert!(validate_robots("googlebot: noindex").is_ok());
		assert!(validate_robots("bogus").is_err());
	}

	#[test]
	fn dispositions() {
		assert_eq!(content_disposition(""), "attachment;");
		assert_eq!(
			content_disposition("a b.png"),
			"attachment; filename=\"a b.png\"; filename*=UTF-8''a%20b.png"
		);
		assert_eq!(
			content_disposition("Bob's (1).png"),
			"attachment; filename=\"Bob's (1).png\"; filename*=UTF-8''Bob%27s%20%281%29.png"
		);
		assert_eq!(
			content_disposition("résumé \"x\".pdf"),
			"attachment; filename=\"r_sum_ _x_.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9%20%22x%22.pdf"
		);
	}

	#[test]
	fn active_types_are_never_served_as_they_were_uploaded() {
		for html in [
			"text/html",
			"Text/HTML",
			"TEXT/HTML; charset=utf-8",
			" text/html ",
			"application/xhtml+xml",
		] {
			assert_eq!(
				served_type(html),
				("text/plain".to_string(), true),
				"{html}"
			);
		}
		for active in [
			"image/svg+xml",
			"IMAGE/SVG+XML",
			"application/xml",
			"text/xml",
			"application/rss+xml",
		] {
			assert_eq!(served_type(active), (active.to_string(), true), "{active}");
		}
		for inert in [
			"image/png",
			"application/pdf",
			"text/plain; charset=utf-8",
			"application/json",
			"video/mp4",
		] {
			assert_eq!(served_type(inert), (inert.to_string(), false), "{inert}");
		}
		let mut headers = HeaderMap::new();
		guard_active(&mut headers, true);
		assert!(
			headers[header::CONTENT_SECURITY_POLICY]
				.to_str()
				.unwrap()
				.contains("sandbox")
		);
		assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
		let mut headers = HeaderMap::new();
		guard_active(&mut headers, false);
		assert!(headers.is_empty());
	}

	#[test]
	fn upload_and_download_tokens_are_told_apart() {
		let claims = |v: Value| v.as_object().unwrap().clone();
		assert!(is_upload_token(&claims(
			json!({ "url": "b/o", "upsert": false, "owner": "u" })
		)));
		assert!(is_upload_token(&claims(
			json!({ "url": "b/o", "upsert": true })
		)));
		assert!(!is_upload_token(&claims(json!({ "url": "b/o" }))));
		assert!(!is_upload_token(&claims(
			json!({ "url": "b/o", "transformations": "width:10" })
		)));
	}

	#[tokio::test]
	async fn a_form_field_is_refused_past_its_cap() {
		async fn field_of(len: usize) -> Result<String, StorageError> {
			let body = format!(
				"--X\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n--X--\r\n",
				"a".repeat(len)
			);
			let stream =
				futures_util::stream::once(
					async move { Ok::<_, std::io::Error>(Bytes::from(body)) },
				);
			let mut form = multer::Multipart::new(stream, "X");
			let field = form.next_field().await.unwrap().unwrap();
			form_field_text(field).await
		}
		assert_eq!(field_of(10).await.unwrap().len(), 10);
		assert_eq!(
			field_of(FORM_FIELD_MAX).await.unwrap().len(),
			FORM_FIELD_MAX
		);
		let refused = field_of(FORM_FIELD_MAX + 1).await.unwrap_err();
		assert_eq!(refused.status, 413);
	}
}
