//! `/render/image/*`: an object resized or re-encoded by imgproxy, as the storage API serves it.
//!
//! imgproxy is handed a presigned S3 URL (ten minutes) and never holds a credential; this server
//! decides who may read the object, exactly as a download does, and only then asks for pixels. The
//! transformation segments, their clamping and the response headers are the ones
//! clients are written against.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::app::{App, AppState, Ctx, context_jwt, context_public, json_response, tenant_of, validation};
use crate::error::StorageError;
use crate::jwt;
use crate::objects::{header_text, s3_key};
use crate::s3::{http_date, parse_http_date};

pub fn routes() -> Router<AppState> {
	Router::new()
		.route("/render/image/authenticated/{bucket}/{*name}", get(render_authenticated))
		.route("/render/image/public/{bucket}/{*name}", get(render_public))
		.route("/render/image/sign/{bucket}/{*name}", get(render_signed))
}

/// What a caller may ask of an image.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Transform {
	pub width: Option<i64>,
	pub height: Option<i64>,
	pub resize: Option<String>,
	pub format: Option<String>,
	pub quality: Option<i64>,
}

#[derive(Deserialize)]
pub struct RenderQuery {
	width: Option<String>,
	height: Option<String>,
	resize: Option<String>,
	format: Option<String>,
	quality: Option<String>,
	download: Option<String>,
	token: Option<String>,
}

fn integer(raw: Option<&str>, name: &str, minimum: i64, maximum: Option<i64>) -> Result<Option<i64>, StorageError> {
	let Some(raw) = raw else {
		return Ok(None);
	};
	let n = raw.trim().parse::<i64>().map_err(|_| validation(&format!("querystring/{name} must be integer")))?;
	if n < minimum {
		return Err(validation(&format!("querystring/{name} must be >= {minimum}")));
	}
	if let Some(maximum) = maximum
		&& n > maximum
	{
		return Err(validation(&format!("querystring/{name} must be <= {maximum}")));
	}
	Ok(Some(n))
}

/// `transformationOptionsSchema`, in Ajv's order (properties as declared).
fn transform_from(query: &RenderQuery) -> Result<Transform, StorageError> {
	let height = integer(query.height.as_deref(), "height", 0, None)?;
	let width = integer(query.width.as_deref(), "width", 0, None)?;
	let resize = match query.resize.as_deref() {
		None => None,
		Some(r @ ("cover" | "contain" | "fill")) => Some(r.to_string()),
		Some(_) => return Err(validation("querystring/resize must be equal to one of the allowed values")),
	};
	let format = match query.format.as_deref() {
		None => None,
		Some(f @ ("origin" | "avif" | "webp")) => Some(f.to_string()),
		Some(_) => return Err(validation("querystring/format must be equal to one of the allowed values")),
	};
	let quality = integer(query.quality.as_deref(), "quality", 20, Some(100))?;
	Ok(Transform { width, height, resize, format, quality })
}

/// `setTransformationsFromString`: a signed token's `transformations` claim.
pub fn transform_from_string(text: &str) -> Transform {
	let mut transform = Transform::default();
	for param in text.split(',') {
		let mut parts = param.splitn(2, ':');
		let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
			continue;
		};
		if value.is_empty() {
			continue;
		}
		let number = || leading_integer(value);
		match name {
			"height" => transform.height = number(),
			"width" => transform.width = number(),
			"resize" => transform.resize = Some(value.to_string()),
			"format" => transform.format = Some(value.to_string()),
			"quality" => transform.quality = number(),
			_ => {}
		}
	}
	transform
}

/// `parseInt(value, 10)`: the leading digits, or nothing.
fn leading_integer(value: &str) -> Option<i64> {
	let digits: String = value.trim_start().chars().enumerate().take_while(|(i, c)| c.is_ascii_digit() || (*i == 0 && *c == '-')).map(|(_, c)| c).collect();
	digits.parse().ok()
}

/// `ImageRenderer.applyTransformation`. With `keep_original` (a signed URL's claim) the resize
/// is written as given, including JavaScript's `undefined` when none was.
pub fn segments(transform: &Transform, keep_original: bool, min: i64, max: i64) -> Vec<String> {
	let clamp = |n: i64| n.clamp(min, max);
	let mut out = Vec::new();
	if let Some(height) = transform.height.filter(|h| *h != 0) {
		out.push(format!("height:{}", clamp(height)));
	}
	if let Some(width) = transform.width.filter(|w| *w != 0) {
		out.push(format!("width:{}", clamp(width)));
	}
	if transform.width.is_some_and(|w| w != 0) || transform.height.is_some_and(|h| h != 0) {
		if keep_original {
			out.push(format!("resize:{}", transform.resize.as_deref().unwrap_or("undefined")));
		} else {
			let resizing = match transform.resize.as_deref() {
				Some("contain") => "fit",
				Some("fill") => "force",
				_ => "fill",
			};
			out.push(format!("resizing_type:{resizing}"));
		}
	}
	if let Some(quality) = transform.quality.filter(|q| *q != 0) {
		out.push(format!("quality:{quality}"));
	}
	if let Some(format) = transform.format.as_deref().filter(|f| *f != "origin" && !f.is_empty()) {
		out.push(format!("format:{format}"));
	}
	out
}

/// The tenant's image-transformation switch, which answers before anything else.
fn feature_disabled() -> Response {
	let body = json!({ "statusCode": "403", "error": "FeatureNotEnabled", "message": "feature not enabled for this tenant" });
	(StatusCode::FORBIDDEN, json_response(body.to_string())).into_response()
}

async fn feature_enabled(app: &App, headers: &HeaderMap) -> Result<bool, StorageError> {
	Ok(tenant_of(app, headers).await?.image_transformation)
}

/// `encodeURIComponent`.
fn encode_component(value: &str) -> String {
	let mut out = String::new();
	for byte in value.bytes() {
		match byte {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => out.push(byte as char),
			_ => out.push_str(&format!("%{byte:02X}")),
		}
	}
	out
}

struct Target<'a> {
	bucket: &'a str,
	name: &'a str,
	version: Option<String>,
	robots: Option<String>,
	download: Option<String>,
	expires: Option<String>,
}

/// `ImageRenderer.getAsset` and `render`: the object's head and a presigned URL, imgproxy asked,
/// its answer streamed back with the object's ETag and cache control.
async fn render(app: &App, ctx: &Ctx, request_headers: &HeaderMap, transform: &Transform, target: Target<'_>) -> Result<Response, StorageError> {
	let key = s3_key(&ctx.tenant.id, target.bucket, target.name, target.version.as_deref());
	let head = app.s3.head(&key).await?;
	let signed = app.s3.presigned_get(&key, 600, app.config.private_asset_endpoint.as_deref()).await?;
	let transformations = segments(transform, false, app.config.image_size_min, app.config.image_size_max);
	let mut path = vec!["/public".to_string()];
	path.extend(transformations.iter().cloned());
	if let Some(max) = ctx.tenant.image_max_resolution {
		path.push(format!("max_src_resolution:{max}"));
	}
	path.push("plain".into());
	path.push(encode_component(&signed));
	let base = app.config.imgproxy_url.as_deref().unwrap_or("").trim_end_matches('/');
	let url = format!("{base}/{}", path.join("/").trim_start_matches('/'));

	let client = reqwest::Client::builder().timeout(Duration::from_secs(app.config.imgproxy_timeout_s.max(1))).build().map_err(|_| StorageError::internal())?;
	let mut request = client.get(&url);
	if transform.format.as_deref() != Some("origin")
		&& let Some(accept) = header_text(request_headers, "accept")
	{
		request = request.header("accept", accept);
	}
	let response = match request.send().await {
		Ok(response) => response,
		Err(error) => {
			tracing::error!(%error, "imgproxy");
			return Err(StorageError::new(500, "InternalError", "Internal error"));
		}
	};
	let status = response.status().as_u16();
	if !response.status().is_success() {
		let text = response.text().await.unwrap_or_default();
		let code = if status > 499 { "InternalError" } else { "InvalidRequest" };
		return Err(StorageError::new(status, code, if text.is_empty() { format!("Request failed with status code {status}") } else { text }));
	}
	let upstream = response.headers().clone();
	let text = |name: &str| upstream.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
	let mime = text("content-type").map(|m| if m.contains("text/html") { "text/plain".to_string() } else { m });
	let mut builder = Response::builder().status(status).header("accept-ranges", "bytes");
	if let Some(mime) = mime {
		builder = builder.header(header::CONTENT_TYPE, mime);
	}
	builder = builder.header(header::ETAG, &head.etag).header("x-robots-tag", target.robots.unwrap_or_else(|| "none".into()));
	if let Some(modified) = text("last-modified").and_then(|v| parse_http_date(&v)) {
		builder = builder.header(header::LAST_MODIFIED, http_date(modified));
	}
	if let Some(length) = text("content-length").filter(|l| l.bytes().all(|b| b.is_ascii_digit())) {
		builder = builder.header(header::CONTENT_LENGTH, length);
	}
	match target.expires {
		Some(expires) => builder = builder.header(header::EXPIRES, expires),
		None => {
			let mut values = vec![head.cache_control.clone()];
			if let Some(requested) = header_text(request_headers, "if-none-match")
				&& requested != head.etag
			{
				values.push("stale-while-revalidate=30".into());
			}
			let joined = values.into_iter().filter(|v| !v.is_empty()).collect::<Vec<_>>().join(", ");
			if !joined.is_empty() {
				builder = builder.header(header::CACHE_CONTROL, joined);
			}
		}
	}
	if !transformations.is_empty() {
		builder = builder.header("x-transformations", transformations.join(","));
	}
	if let Some(download) = target.download {
		builder = builder.header(header::CONTENT_DISPOSITION, crate::objects::content_disposition(&download));
	}
	builder.body(Body::from_stream(response.bytes_stream())).map_err(|_| StorageError::internal())
}

fn robots_of(metadata: Option<Value>) -> Option<String> {
	metadata.and_then(|m| m.get("xRobotsTag").and_then(Value::as_str).map(str::to_string))
}

fn finish(result: Result<Response, StorageError>) -> Response {
	result.unwrap_or_else(IntoResponse::into_response)
}

async fn render_authenticated(State(app): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, Path((bucket, name)): Path<(String, String)>, Query(query): Query<RenderQuery>) -> Response {
	match feature_enabled(&app, &headers).await {
		Ok(false) => return feature_disabled(),
		Err(error) => return error.into_response(),
		Ok(true) => {}
	}
	finish(
		async {
			let transform = transform_from(&query)?;
			let ctx = context_jwt(&app, &method, &uri, &headers, "storage.render.image_authenticated").await?;
			let scope = ctx.scope(&app).await?;
			let row = scope.query_opt("SELECT version, metadata FROM objects WHERE name = $1 AND bucket_id = $2 LIMIT 1", &[&name, &bucket]).await?;
			scope.commit().await?;
			let row = row.ok_or_else(StorageError::no_such_key)?;
			let target = Target { bucket: &bucket, name: &name, version: row.get(0), robots: robots_of(row.get(1)), download: query.download.clone(), expires: None };
			render(&app, &ctx, &headers, &transform, target).await
		}
		.await,
	)
}

async fn render_public(State(app): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, Path((bucket, name)): Path<(String, String)>, Query(query): Query<RenderQuery>) -> Response {
	match feature_enabled(&app, &headers).await {
		Ok(false) => return feature_disabled(),
		Err(error) => return error.into_response(),
		Ok(true) => {}
	}
	finish(
		async {
			let transform = transform_from(&query)?;
			let ctx = context_public(&app, &method, &uri, &headers, "storage.render.image_public").await?;
			let scope = ctx.super_scope(&app).await?;
			let public = scope.query_opt("SELECT id FROM buckets WHERE id = $1 AND public = true", &[&bucket]).await?;
			let row = scope.query_opt("SELECT version, metadata FROM objects WHERE name = $1 AND bucket_id = $2 LIMIT 1", &[&name, &bucket]).await?;
			scope.commit().await?;
			public.ok_or_else(StorageError::no_such_bucket)?;
			let row = row.ok_or_else(StorageError::no_such_key)?;
			let target = Target { bucket: &bucket, name: &name, version: row.get(0), robots: robots_of(row.get(1)), download: query.download.clone(), expires: None };
			render(&app, &ctx, &headers, &transform, target).await
		}
		.await,
	)
}

async fn render_signed(State(app): State<AppState>, method: Method, uri: Uri, headers: HeaderMap, Path((bucket, name)): Path<(String, String)>, Query(query): Query<RenderQuery>) -> Response {
	match feature_enabled(&app, &headers).await {
		Ok(false) => return feature_disabled(),
		Err(error) => return error.into_response(),
		Ok(true) => {}
	}
	finish(
		async {
			let token = query.token.clone().ok_or_else(|| validation("querystring must have required property 'token'"))?;
			let ctx = context_public(&app, &method, &uri, &headers, "storage.render.image_sign").await?;
			let claims = jwt::verify(&token, &ctx.tenant.jwt_secret, &ctx.tenant.jwks).map_err(|e| StorageError::invalid_jwt(e.0))?;
			let url = claims.get("url").and_then(Value::as_str).unwrap_or_default().to_string();
			if url != format!("{bucket}/{name}") {
				return Err(StorageError::invalid_signature("Invalid signature"));
			}
			let transform = transform_from_string(claims.get("transformations").and_then(Value::as_str).unwrap_or(""));
			let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
			let (signed_bucket, signed_name) = url.split_once('/').unwrap_or((url.as_str(), ""));
			let scope = ctx.super_scope(&app).await?;
			let row = scope.query_opt("SELECT version, metadata FROM objects WHERE name = $1 AND bucket_id = $2 LIMIT 1", &[&signed_name, &signed_bucket]).await?;
			scope.commit().await?;
			let row = row.ok_or_else(StorageError::no_such_key)?;
			let expires = OffsetDateTime::from_unix_timestamp(exp).ok().map(http_date);
			let target = Target { bucket: signed_bucket, name: signed_name, version: row.get(0), robots: robots_of(row.get(1)), download: query.download.clone(), expires };
			render(&app, &ctx, &headers, &transform, target).await
		}
		.await,
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn segments_as_upstream_writes_them() {
		let t = Transform { width: Some(5000), height: Some(100), resize: Some("contain".into()), format: Some("webp".into()), quality: Some(80) };
		assert_eq!(segments(&t, false, 1, 2000), vec!["height:100", "width:2000", "resizing_type:fit", "quality:80", "format:webp"]);
		let only_width = Transform { width: Some(10), ..Transform::default() };
		assert_eq!(segments(&only_width, true, 1, 2000), vec!["width:10", "resize:undefined"]);
		assert!(segments(&Transform { format: Some("origin".into()), ..Transform::default() }, false, 1, 2000).is_empty());
	}

	#[test]
	fn signed_transformations_parse_back() {
		let t = transform_from_string("height:100,width:200,resize:cover,quality:80,format:avif");
		assert_eq!(t, Transform { width: Some(200), height: Some(100), resize: Some("cover".into()), format: Some("avif".into()), quality: Some(80) });
		assert_eq!(transform_from_string("width:,resize:undefined").resize.as_deref(), Some("undefined"));
	}
}
