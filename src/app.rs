//! The two HTTP servers: the public one (`/bucket`, `/object`, …, reached through the front door
//! at `/storage/v1`) and the admin one (`/tenants`, the host agent's), on separate ports as
//! the storage API runs them.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::config::Config;
use crate::db::{Caller, Pools, RequestFacts, Scope};
use crate::error::StorageError;
use crate::jwt;
use crate::limits;
use crate::s3::S3;
use crate::tenants::{Registry, Tenant, TenantBody};

pub struct App {
	pub config: Config,
	pub registry: Registry,
	pub pools: Pools,
	pub s3: S3,
}

pub type AppState = Arc<App>;

/// The storage API version whose HTTP contract this server serves, as clients read it.
pub const UPSTREAM_VERSION: &str = "1.60.4";

/// One request's tenant, caller and the facts policies can read.
pub struct Ctx {
	pub tenant: Arc<Tenant>,
	pub caller: Caller,
	pub facts: RequestFacts,
	/// Whether the request is authenticated: false on the routes that allow a missing or bad
	/// token (`allowInvalidJwt`), where the caller is then `anon`.
	pub authenticated: bool,
}

impl Ctx {
	/// A transaction as the tenant's service role.
	pub async fn super_scope(&self, app: &App) -> Result<Scope, StorageError> {
		let caller = self.service_caller();
		app.pools
			.begin(
				&self.tenant.id,
				&self.tenant.database_url,
				&caller,
				&self.facts,
			)
			.await
	}

	pub async fn scope(&self, app: &App) -> Result<Scope, StorageError> {
		app.pools
			.begin(
				&self.tenant.id,
				&self.tenant.database_url,
				&self.caller,
				&self.facts,
			)
			.await
	}

	/// The "super user": the tenant's service_role, for the few checks it makes above
	/// the caller (a bucket's emptiness before a delete, its limits before an upload).
	pub fn service_caller(&self) -> Caller {
		let mut claims = decode_unverified(&self.tenant.service_key);
		claims.insert("role".into(), json!("service_role"));
		Caller::from_claims(self.tenant.service_key.clone(), claims)
	}
}

/// A key this server minted is trusted for its claims without re-verifying the signature.
fn decode_unverified(token: &str) -> Map<String, Value> {
	use base64::Engine;
	token
		.split('.')
		.nth(1)
		.and_then(|body| {
			base64::engine::general_purpose::URL_SAFE_NO_PAD
				.decode(body.trim_end_matches('='))
				.ok()
		})
		.and_then(|bytes| serde_json::from_slice::<Map<String, Value>>(&bytes).ok())
		.unwrap_or_default()
}

fn header_map_json(headers: &HeaderMap) -> Map<String, Value> {
	let mut map = Map::new();
	for (name, value) in headers {
		if let Ok(value) = value.to_str() {
			map.insert(name.as_str().to_string(), json!(value));
		}
	}
	map
}

/// The tenant from `X-Forwarded-Host`, the caller from `Authorization`, as the storage API's
/// `tenant-id` and `jwt` plugins do. A bad token is a refusal (403, sent as 400), never `anon`.
///
/// Called after the route's own body and query checks, since Fastify validates those, then the
/// headers, and only then runs the JWT hook.
pub async fn context(
	app: &App,
	method: &Method,
	uri: &Uri,
	headers: &HeaderMap,
	operation: &str,
) -> Result<Ctx, StorageError> {
	require_authorization(headers)?;
	caller_context(app, method, uri, headers, operation, false).await
}

/// The JWT hook without the header schema (routes whose schema is their own, e.g. TUS and
/// list-v2): a missing token is the verifier's refusal, not a validation one.
pub async fn context_jwt(
	app: &App,
	method: &Method,
	uri: &Uri,
	headers: &HeaderMap,
	operation: &str,
) -> Result<Ctx, StorageError> {
	caller_context(app, method, uri, headers, operation, false).await
}

/// The same for a route with `allowInvalidJwt`: no header required, and a missing or bad token
/// makes the caller `anon` rather than a refusal.
pub async fn context_optional(
	app: &App,
	method: &Method,
	uri: &Uri,
	headers: &HeaderMap,
	operation: &str,
) -> Result<Ctx, StorageError> {
	caller_context(app, method, uri, headers, operation, true).await
}

/// A route served as the super user (public objects, signed URLs): no JWT is read and
/// the database is reached as the tenant's service role.
pub async fn context_public(
	app: &App,
	method: &Method,
	uri: &Uri,
	headers: &HeaderMap,
	operation: &str,
) -> Result<Ctx, StorageError> {
	let tenant = tenant_of(app, headers).await?;
	let facts = request_facts(method, uri, headers, operation);
	let mut ctx = Ctx {
		tenant,
		caller: Caller::from_claims(String::new(), Map::new()),
		facts,
		authenticated: false,
	};
	ctx.caller = ctx.service_caller();
	Ok(ctx)
}

pub(crate) async fn tenant_of(app: &App, headers: &HeaderMap) -> Result<Arc<Tenant>, StorageError> {
	let host = headers
		.get("x-forwarded-host")
		.and_then(|v| v.to_str().ok())
		.unwrap_or("");
	let tenant_id = app.config.tenant_from_host(host).unwrap_or_default();
	if tenant_id.is_empty() {
		return Err(StorageError::missing_tenant_config(""));
	}
	app.registry.get(&tenant_id).await
}

fn request_facts(method: &Method, uri: &Uri, headers: &HeaderMap, operation: &str) -> RequestFacts {
	RequestFacts {
		method: method.as_str().to_string(),
		path: uri
			.path_and_query()
			.map(|p| p.as_str().to_string())
			.unwrap_or_default(),
		headers: header_map_json(headers),
		operation: operation.to_string(),
	}
}

async fn caller_context(
	app: &App,
	method: &Method,
	uri: &Uri,
	headers: &HeaderMap,
	operation: &str,
	allow_invalid: bool,
) -> Result<Ctx, StorageError> {
	let tenant = tenant_of(app, headers).await?;
	let raw = headers
		.get("authorization")
		.and_then(|v| v.to_str().ok())
		.unwrap_or("");
	let token = strip_bearer(raw).to_string();
	let facts = request_facts(method, uri, headers, operation);
	let verified = if token.is_empty() && allow_invalid {
		Err(jwt::JwtError(String::new()))
	} else {
		jwt::verify(&token, &tenant.jwt_secret, &tenant.jwks)
	};
	match verified {
		Ok(claims) => Ok(Ctx {
			tenant,
			caller: Caller::from_claims(token, claims),
			facts,
			authenticated: true,
		}),
		Err(_) if allow_invalid => {
			let mut claims = Map::new();
			claims.insert("role".into(), json!("anon"));
			Ok(Ctx {
				tenant,
				caller: Caller::from_claims(token, claims),
				facts,
				authenticated: false,
			})
		}
		Err(e) => Err(StorageError::access_denied(e.0)),
	}
}

/// `Bearer ` followed by the token, case-insensitive.
fn strip_bearer(value: &str) -> &str {
	let trimmed = value.trim_start();
	if trimmed.len() >= 6
		&& trimmed[..6].eq_ignore_ascii_case("bearer")
		&& trimmed[6..].starts_with(char::is_whitespace)
	{
		trimmed[6..].trim_start()
	} else {
		value
	}
}

/// Fastify's schema-validation refusal, which is sent as a 400 named for the error's
/// class (`Error`), since Fastify's errors carry no legacy name.
pub(crate) fn validation(message: &str) -> StorageError {
	StorageError::new(400, "InternalError", message)
		.with_http(400)
		.with_legacy_name("Error")
}

/// Every public route's header schema (`authSchema`), checked where Fastify checks it: after the
/// body and the query string, before the JWT is read.
pub(crate) fn require_authorization(headers: &HeaderMap) -> Result<(), StorageError> {
	if headers.get("authorization").is_some() {
		Ok(())
	} else {
		Err(validation(
			"headers must have required property 'authorization'",
		))
	}
}

/// Fastify's 404 for a route it does not have: not the storage error shape, and a number.
pub(crate) async fn route_not_found(method: Method, uri: Uri) -> Response {
	let body = json!({ "message": format!("Route {}:{} not found", method, uri.path()), "error": "Not Found", "statusCode": 404 });
	(StatusCode::NOT_FOUND, json_response(body.to_string())).into_response()
}

pub fn public_router(state: AppState) -> Router {
	Router::new()
		.route("/status", get(|| async { StatusCode::OK }))
		// The storage API version whose HTTP surface this serves, which is what a client asking
		// `/version` is asking about. Our own build is in the `version` subcommand and the logs.
		.route("/version", get(|| async { UPSTREAM_VERSION }))
		.route("/bucket", get(list_buckets).post(create_bucket))
		.route(
			"/bucket/{id}",
			get(get_bucket).put(update_bucket).delete(delete_bucket),
		)
		.route(
			"/s3",
			any(|| async { StorageError::s3_protocol_not_supported() }),
		)
		.route(
			"/s3/{*rest}",
			any(|| async { StorageError::s3_protocol_not_supported() }),
		)
		.merge(if state.config.image_transformation { crate::render::routes() } else { Router::new() })
		.merge(crate::tus::routes(&state.config.tus_path))
		.merge(crate::objects::routes())
		.fallback(route_not_found)
		.with_state(state)
}

pub fn admin_router(state: AppState) -> Router {
	Router::new()
		.route("/status", get(|| async { StatusCode::OK }))
		.route("/tenants", get(admin_list))
		.route(
			"/tenants/{id}",
			get(admin_get)
				.put(admin_put)
				.post(admin_put)
				.delete(admin_delete),
		)
		.with_state(state)
}

// ---- JSON built in SQL -------------------------------------------------------------------------

/// A timestamp as JavaScript's `Date#toISOString` writes one (milliseconds, `Z`), which is what
/// clients expect for every date returned.
pub fn iso(column: &str) -> String {
	format!("to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')")
}

/// A bucket as the API's response schema serializes it: the schema's key order, a missing
/// owner as `""` (the schema says string), `type` only where the route selects it.
fn bucket_json(with_type: bool) -> String {
	format!(
		"json_build_object('id', id, 'name', name, 'owner', coalesce(owner::text, ''), 'public', public{}, \
		 'file_size_limit', file_size_limit, 'allowed_mime_types', allowed_mime_types, \
		 'created_at', coalesce({}, ''), 'updated_at', coalesce({}, ''))",
		if with_type {
			", 'type', 'STANDARD'"
		} else {
			""
		},
		iso("created_at"),
		iso("updated_at")
	)
}

/// JSON Postgres built (`json_build_object` writes `"key" : value`), re-emitted compactly with its
/// key order kept, as clients receive it.
pub(crate) fn sql_json_response(text: String) -> Response {
	match serde_json::from_str::<Value>(&text) {
		Ok(value) => json_response(value.to_string()),
		Err(_) => json_response(text),
	}
}

pub(crate) fn json_response(text: String) -> Response {
	(
		[(
			axum::http::header::CONTENT_TYPE,
			"application/json; charset=utf-8",
		)],
		text,
	)
		.into_response()
}

pub(crate) fn message(text: &str) -> Response {
	json_response(json!({ "message": text }).to_string())
}

// ---- buckets -----------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListQuery {
	limit: Option<String>,
	offset: Option<String>,
	sort_column: Option<String>,
	sort_order: Option<String>,
	search: Option<String>,
}

async fn list_buckets(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Query(query): Query<ListQuery>,
) -> Result<Response, StorageError> {
	let limit = match query.limit.as_deref() {
		None => None,
		Some(raw) => Some(query_integer(raw, "limit", 1)?),
	};
	let offset = match query.offset.as_deref() {
		None => None,
		Some(raw) => Some(query_integer(raw, "offset", 0)?),
	};
	let sort = match query.sort_column.as_deref() {
		None => None,
		Some(column @ ("id" | "name" | "created_at" | "updated_at")) => Some(column),
		Some(_) => {
			return Err(validation(
				"querystring/sortColumn must be equal to one of the allowed values",
			));
		}
	};
	let order = match query.sort_order.as_deref() {
		None | Some("asc") => "asc",
		Some("desc") => "desc",
		Some(_) => {
			return Err(validation(
				"querystring/sortOrder must be equal to one of the allowed values",
			));
		}
	};
	let ctx = context(&app, &method, &uri, &headers, "storage.bucket.list").await?;
	let mut sql = format!(
		"SELECT coalesce(json_agg(b ORDER BY ord), '[]'::json)::text FROM (SELECT {} AS b, row_number() OVER () AS ord FROM (SELECT * FROM buckets",
		bucket_json(true)
	);
	let search = query
		.search
		.filter(|s| !s.is_empty())
		.map(|s| format!("%{}%", escape_like(&s)));
	if search.is_some() {
		sql.push_str(" WHERE name ILIKE $1");
	}
	if let Some(column) = sort {
		sql.push_str(&format!(" ORDER BY {column} {order}"));
	}
	if let Some(n) = limit {
		sql.push_str(&format!(" LIMIT {n}"));
	}
	if let Some(n) = offset {
		sql.push_str(&format!(" OFFSET {n}"));
	}
	sql.push_str(") buckets) listed");
	let scope = ctx.scope(&app).await?;
	let row = match &search {
		Some(pattern) => scope.query_opt(&sql, &[pattern]).await?,
		None => scope.query_opt(&sql, &[]).await?,
	};
	scope.commit().await?;
	Ok(sql_json_response(
		row.map(|r| r.get::<_, String>(0))
			.unwrap_or_else(|| "[]".into()),
	))
}

/// A query-string integer as Ajv coerces and checks it.
fn query_integer(raw: &str, name: &str, minimum: i64) -> Result<i64, StorageError> {
	let n = raw
		.trim()
		.parse::<i64>()
		.map_err(|_| validation(&format!("querystring/{name} must be integer")))?;
	if n < minimum {
		return Err(validation(&format!(
			"querystring/{name} must be >= {minimum}"
		)));
	}
	Ok(n)
}

/// knex's `escapeLike`: `\`, `%` and `_` are literal in a search.
pub(crate) fn escape_like(value: &str) -> String {
	value
		.replace('\\', "\\\\")
		.replace('%', "\\%")
		.replace('_', "\\_")
}

async fn get_bucket(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(id): Path<String>,
) -> Result<Response, StorageError> {
	let ctx = context(&app, &method, &uri, &headers, "storage.bucket.get").await?;
	let scope = ctx.scope(&app).await?;
	let row = scope
		.query_opt(
			&format!(
				"SELECT {}::text FROM buckets WHERE id = $1",
				bucket_json(false)
			),
			&[&id],
		)
		.await?;
	scope.commit().await?;
	row.map(|r| sql_json_response(r.get(0)))
		.ok_or_else(StorageError::no_such_bucket)
}

/// The bucket fields as the route schemas admit them, before anyone is authenticated.
/// `None` = absent, `Some(None)` = explicitly null.
struct BucketFields {
	public: Option<bool>,
	size: Option<Option<SizeInput>>,
	mimes: Option<Option<Vec<String>>>,
}

enum SizeInput {
	Bytes(u64),
	Text(String),
}

/// `file_size_limit: anyOf [integer >= 0, string]`, both nullable.
fn size_field(value: &Value) -> Result<Option<SizeInput>, StorageError> {
	match value {
		Value::Null => Ok(None),
		Value::Number(n) => match n.as_u64() {
			Some(bytes) => Ok(Some(SizeInput::Bytes(bytes))),
			// Not a valid integer branch; the string branch coerces it, as Ajv does.
			None => Ok(Some(SizeInput::Text(n.to_string()))),
		},
		Value::String(s) => Ok(Some(SizeInput::Text(s.clone()))),
		Value::Bool(b) => Ok(Some(SizeInput::Text(b.to_string()))),
		// `coerceTypes: 'array'` unwraps a one-item array; what comes out is never a valid size.
		Value::Array(items)
			if items.len() == 1 && !items[0].is_array() && !items[0].is_object() =>
		{
			Ok(Some(SizeInput::Text(value.to_string())))
		}
		_ => Err(validation(
			"body/file_size_limit must be integer, body/file_size_limit must be string, body/file_size_limit must match a schema in anyOf",
		)),
	}
}

fn bucket_fields(body: &Map<String, Value>) -> Result<BucketFields, StorageError> {
	let public = match body.get("public") {
		None => None,
		Some(Value::Bool(b)) => Some(*b),
		Some(Value::String(s)) if s == "true" || s == "false" => Some(s == "true"),
		Some(_) => return Err(validation("body/public must be boolean")),
	};
	let size = body.get("file_size_limit").map(size_field).transpose()?;
	let mimes = match body.get("allowed_mime_types") {
		None => None,
		Some(Value::Null) => Some(None),
		Some(Value::Array(items)) => {
			let mut list = Vec::with_capacity(items.len());
			for (i, item) in items.iter().enumerate() {
				match item {
					Value::String(s) => list.push(s.clone()),
					Value::Number(n) => list.push(n.to_string()),
					Value::Bool(b) => list.push(b.to_string()),
					_ => {
						return Err(validation(&format!(
							"body/allowed_mime_types/{i} must be string"
						)));
					}
				}
			}
			Some(Some(list))
		}
		// Ajv's `coerceTypes: 'array'` wraps a scalar.
		Some(Value::String(s)) => Some(Some(vec![s.clone()])),
		Some(Value::Number(n)) => Some(Some(vec![n.to_string()])),
		Some(Value::Bool(b)) => Some(Some(vec![b.to_string()])),
		Some(_) => return Err(validation("body/allowed_mime_types must be array")),
	};
	Ok(BucketFields {
		public,
		size,
		mimes,
	})
}

/// A limit given as bytes or as `'20MB'`, checked against the tenant's own ceiling.
fn resolve_size(size: Option<SizeInput>, tenant: &Tenant) -> Result<Option<i64>, StorageError> {
	let bytes = match size {
		None => return Ok(None),
		Some(SizeInput::Bytes(bytes)) => bytes,
		Some(SizeInput::Text(text)) => limits::parse_file_size(&text)?,
	};
	if bytes > tenant.file_size_limit {
		return Err(StorageError::entity_too_large());
	}
	Ok(Some(bytes as i64))
}

/// Empty strings dropped (the route does it), then each one checked.
fn resolve_mimes(mimes: Option<Vec<String>>) -> Result<Option<Vec<String>>, StorageError> {
	match mimes {
		None => Ok(None),
		Some(list) => {
			let list: Vec<String> = list.into_iter().filter(|s| !s.is_empty()).collect();
			limits::validate_mime_types(&list)?;
			Ok(Some(list))
		}
	}
}

pub(crate) fn json_body(bytes: &Bytes) -> Result<Map<String, Value>, StorageError> {
	serde_json::from_slice::<Map<String, Value>>(bytes)
		.map_err(|_| validation("body must be object"))
}

async fn create_bucket(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	let name = match body.get("name") {
		None => return Err(validation("body must have required property 'name'")),
		Some(Value::String(s)) => s.clone(),
		Some(Value::Number(n)) => n.to_string(),
		Some(Value::Bool(b)) => b.to_string(),
		Some(_) => return Err(validation("body/name must be string")),
	};
	let id = match body.get("id") {
		None | Some(Value::Null) => None,
		Some(Value::String(s)) => Some(s.clone()),
		Some(Value::Number(n)) => Some(n.to_string()),
		Some(_) => return Err(validation("body/id must be string")),
	}
	.filter(|s| !s.is_empty())
	.unwrap_or_else(|| name.clone());
	match body.get("type") {
		None => {}
		Some(Value::String(t)) if t == "STANDARD" || t == "ANALYTICS" => {}
		Some(_) => {
			return Err(validation(
				"body/type must be equal to one of the allowed values",
			));
		}
	}
	let fields = bucket_fields(&body)?;
	let ctx = context(&app, &method, &uri, &headers, "storage.bucket.create").await?;
	limits::must_be_valid_new_bucket_name(&name)?;
	let public = fields.public.unwrap_or(false);
	let size = resolve_size(fields.size.flatten(), &ctx.tenant)?;
	let mimes = resolve_mimes(fields.mimes.flatten())?;
	let owner_id = ctx.caller.sub().map(str::to_string);
	let owner = owner_id
		.as_deref()
		.and_then(|s| uuid::Uuid::parse_str(s).ok());
	let scope = ctx.scope(&app).await?;
	let inserted = scope
		.execute(
			"INSERT INTO buckets (id, name, owner, owner_id, public, allowed_mime_types, file_size_limit, type) VALUES ($1, $2, $3, $4, $5, $6, $7, 'STANDARD')",
			&[&id, &name, &owner, &owner_id, &public, &mimes, &size],
		)
		.await
		.map_err(|e| if e.code == "ResourceAlreadyExists" { StorageError::bucket_already_exists() } else { e })?;
	if inserted == 0 {
		return Err(StorageError::no_such_bucket());
	}
	scope.commit().await?;
	Ok(json_response(json!({ "name": name }).to_string()))
}

async fn update_bucket(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(id): Path<String>,
	body: Bytes,
) -> Result<Response, StorageError> {
	let body = json_body(&body)?;
	// Ajv reaches the schema's `anyOf` before `minProperties`, and reports every branch.
	if !["public", "file_size_limit", "allowed_mime_types"]
		.iter()
		.any(|key| body.contains_key(*key))
	{
		return Err(validation(
			"body must have required property 'public', body must have required property 'file_size_limit', \
			 body must have required property 'allowed_mime_types', body must match a schema in anyOf",
		));
	}
	let fields = bucket_fields(&body)?;
	let ctx = context(&app, &method, &uri, &headers, "storage.bucket.update").await?;
	limits::must_be_valid_bucket_name(&id)?;
	let public = fields.public;
	let size = fields
		.size
		.map(|size| resolve_size(size, &ctx.tenant))
		.transpose()?;
	let mimes = fields.mimes.map(resolve_mimes).transpose()?;
	// knex leaves an `undefined` field out of the UPDATE; so do these CASEs.
	let scope = ctx.scope(&app).await?;
	let updated = scope
		.execute(
			"UPDATE buckets SET public = CASE WHEN $2 THEN $3 ELSE public END, \
			 file_size_limit = CASE WHEN $4 THEN $5 ELSE file_size_limit END, \
			 allowed_mime_types = CASE WHEN $6 THEN $7 ELSE allowed_mime_types END WHERE id = $1",
			&[
				&id,
				&public.is_some(),
				&public.unwrap_or(false),
				&size.is_some(),
				&size.flatten(),
				&mimes.is_some(),
				&mimes.clone().flatten(),
			],
		)
		.await?;
	if updated == 0 {
		return Err(StorageError::no_such_bucket());
	}
	scope.commit().await?;
	Ok(message("Successfully updated"))
}

async fn delete_bucket(
	State(app): State<AppState>,
	method: Method,
	uri: Uri,
	headers: HeaderMap,
	Path(id): Path<String>,
) -> Result<Response, StorageError> {
	let ctx = context(&app, &method, &uri, &headers, "storage.bucket.delete").await?;
	let scope = ctx.scope(&app).await?;
	// As the service role, inside the same transaction: the bucket locked and counted, so an
	// upload cannot land between the count and the delete. Then the delete itself as the caller.
	scope
		.become_caller(&ctx.service_caller(), &ctx.facts)
		.await?;
	if scope
		.query_opt("SELECT id FROM buckets WHERE id = $1 FOR UPDATE", &[&id])
		.await?
		.is_none()
	{
		return Err(StorageError::no_such_bucket());
	}
	if scope
		.query_opt("SELECT 1 FROM objects WHERE bucket_id = $1 LIMIT 1", &[&id])
		.await?
		.is_some()
	{
		return Err(StorageError::bucket_not_empty());
	}
	scope.become_caller(&ctx.caller, &ctx.facts).await?;
	if scope
		.execute("DELETE FROM buckets WHERE id = $1", &[&id])
		.await?
		== 0
	{
		return Err(StorageError::no_such_bucket());
	}
	scope.commit().await?;
	Ok(message("Successfully deleted"))
}

// ---- admin -------------------------------------------------------------------------------------

fn admin_allowed(app: &App, headers: &HeaderMap) -> Result<(), StorageError> {
	let given = headers
		.get("apikey")
		.and_then(|v| v.to_str().ok())
		.unwrap_or("");
	if !given.is_empty() && app.config.admin_api_keys.iter().any(|key| key == given) {
		Ok(())
	} else {
		Err(StorageError::new(401, "AccessDenied", "Unauthorized").with_http(401))
	}
}

async fn admin_list(
	State(app): State<AppState>,
	headers: HeaderMap,
) -> Result<Response, StorageError> {
	admin_allowed(&app, &headers)?;
	Ok(json_response(
		Value::Array(app.registry.list().await?).to_string(),
	))
}

async fn admin_get(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(id): Path<String>,
) -> Result<Response, StorageError> {
	admin_allowed(&app, &headers)?;
	let listed = app.registry.list().await?;
	listed
		.into_iter()
		.find(|t| t.get("id").and_then(Value::as_str) == Some(id.as_str()))
		.map(|t| json_response(t.to_string()))
		.ok_or_else(|| StorageError::new(404, "TenantNotFound", "Tenant not found").with_http(404))
}

async fn admin_put(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(id): Path<String>,
	body: Bytes,
) -> Result<Response, StorageError> {
	admin_allowed(&app, &headers)?;
	let body: TenantBody =
		serde_json::from_slice(&body).map_err(|e| validation(&format!("body {e}")))?;
	app.registry.put(&id, &body).await?;
	app.pools.forget(&id).await;
	Ok(StatusCode::NO_CONTENT.into_response())
}

async fn admin_delete(
	State(app): State<AppState>,
	headers: HeaderMap,
	Path(id): Path<String>,
) -> Result<Response, StorageError> {
	admin_allowed(&app, &headers)?;
	app.registry.delete(&id).await?;
	app.pools.forget(&id).await;
	Ok(StatusCode::NO_CONTENT.into_response())
}
