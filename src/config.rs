//! Configuration, read from the environment, under the names existing deployments already use.
//!
//! A drop-in has to start from the environment the host agent already composes
//! (on SnoutData Cloud, the host agent and its service catalogue), so a
//! swap is an image change and nothing else. Where two names are in use, both are read.
//! Settings this server does not act on (tracing, queues, iceberg, S3 protocol credentials) are
//! simply not read.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Config {
	pub host: String,
	pub port: u16,
	pub admin_port: u16,
	/// `DATABASE_MULTITENANT_URL`: the metadata database holding the tenants.
	pub metadata_url: String,
	/// `SERVER_ADMIN_API_KEYS`, comma-separated: an admin request's `apikey` must be one.
	pub admin_api_keys: Vec<String>,
	/// `AUTH_ENCRYPTION_KEY`: the passphrase the tenant rows are encrypted with (crypto.rs).
	pub encryption_key: String,
	/// `REQUEST_X_FORWARDED_HOST_REGEXP`: its first group is the tenant id.
	pub tenant_host_pattern: Option<regex::Regex>,
	pub s3: S3Config,
	/// `DB_INSTALL_ROLES`: false on our fleet, where the pod creates the roles itself.
	pub install_roles: bool,
	pub anon_role: String,
	pub authenticated_role: String,
	pub service_role: String,
	pub super_user: String,
	/// `DATABASE_STATEMENT_TIMEOUT`, milliseconds.
	pub statement_timeout_ms: u64,
	/// `DATABASE_MAX_CONNECTIONS`: per tenant.
	pub max_connections: usize,
	/// `UPLOAD_FILE_SIZE_LIMIT` / `FILE_SIZE_LIMIT`: the server's own ceiling, in bytes.
	pub file_size_limit: u64,
	/// `UPLOAD_SIGNED_URL_EXPIRATION_TIME`, seconds.
	pub signed_upload_url_expires: i64,
	pub image_transformation: bool,
	pub imgproxy_url: Option<String>,
	/// `IMAGE_TRANSFORMATION_LIMIT_MIN_SIZE` / `_MAX_SIZE`: a width or height is clamped to these.
	pub image_size_min: i64,
	pub image_size_max: i64,
	/// `IMGPROXY_REQUEST_TIMEOUT`, seconds.
	pub imgproxy_timeout_s: u64,
	/// `STORAGE_S3_PRIVATE_ASSET_ENDPOINT`: where imgproxy reaches S3, when not where we do.
	pub private_asset_endpoint: Option<String>,
	pub tus_path: String,
	pub tus_part_size_mb: u64,
	/// `TUS_URL_EXPIRY_MS`: how long an unfinished resumable upload may be resumed.
	pub tus_url_expiry_ms: u64,
	/// `TUS_ALLOW_S3_TAGS`: tag the `.info` object with `Tus-Completed`, for a lifecycle rule.
	pub tus_allow_s3_tags: bool,
	/// `REQUEST_ALLOW_X_FORWARDED_PATH`: build a resumable upload's URL under `X-Forwarded-Prefix`.
	pub allow_forwarded_prefix: bool,
	/// `STORAGE_PUBLIC_URL`: the scheme and host a resumable upload's URL is built with.
	pub public_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct S3Config {
	pub bucket: String,
	pub region: String,
	/// Absent for AWS; set for anything S3-compatible (MinIO, R2, ...).
	pub endpoint: Option<String>,
	pub force_path_style: bool,
	/// `STORAGE_S3_UPLOAD_PART_SIZE` (bytes, at least 5 MiB) and `STORAGE_S3_UPLOAD_QUEUE_SIZE`.
	pub part_size: usize,
	pub queue_size: usize,
	/// `NODE_TLS_REJECT_UNAUTHORIZED=0`: Node's switch, honoured here for the S3
	/// client, and which the local tier sets for MinIO's self-signed certificate. Same name, same
	/// effect, so the catalogue's env is a drop-in. Never set on the fleet.
	pub accept_invalid_certs: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
	#[error("{0} is required")]
	Missing(&'static str),
	#[error("{0} is not valid: {1}")]
	Invalid(&'static str, String),
}

fn first(env: &HashMap<String, String>, names: &[&str]) -> Option<String> {
	names
		.iter()
		.find_map(|name| env.get(*name).filter(|value| !value.is_empty()).cloned())
}

fn number<T: std::str::FromStr>(
	env: &HashMap<String, String>,
	names: &[&'static str],
	default: T,
) -> Result<T, ConfigError> {
	match first(env, names) {
		None => Ok(default),
		Some(raw) => raw
			.trim()
			.parse()
			.map_err(|_| ConfigError::Invalid(names[0], raw)),
	}
}

impl Config {
	pub fn from_env() -> Result<Self, ConfigError> {
		Self::from_map(&std::env::vars().collect())
	}

	pub fn from_map(env: &HashMap<String, String>) -> Result<Self, ConfigError> {
		let required = |name: &'static str| first(env, &[name]).ok_or(ConfigError::Missing(name));
		let pattern = match first(env, &["REQUEST_X_FORWARDED_HOST_REGEXP"]) {
			None => None,
			Some(raw) => Some(regex::Regex::new(&raw).map_err(|e| {
				ConfigError::Invalid("REQUEST_X_FORWARDED_HOST_REGEXP", e.to_string())
			})?),
		};
		Ok(Self {
			host: first(env, &["SERVER_HOST", "HOST"]).unwrap_or_else(|| "0.0.0.0".into()),
			port: number(env, &["SERVER_PORT", "PORT"], 5000)?,
			admin_port: number(env, &["SERVER_ADMIN_PORT", "ADMIN_PORT"], 5001)?,
			metadata_url: required("DATABASE_MULTITENANT_URL")?,
			admin_api_keys: required("SERVER_ADMIN_API_KEYS")?
				.split(',')
				.map(|key| key.trim().to_string())
				.filter(|key| !key.is_empty())
				.collect(),
			encryption_key: required("AUTH_ENCRYPTION_KEY")?,
			tenant_host_pattern: pattern,
			s3: S3Config {
				// Optional: a host with no storage bucket assigned leaves it unset
				// with no storage cohort (or more than one), and the service must still START
				// there and refuse uploads, not crash-loop. Empty means none (`S3::send`).
				bucket: first(env, &["STORAGE_S3_BUCKET", "GLOBAL_S3_BUCKET"]).unwrap_or_default(),
				// With no bucket nothing is signed, so the default is never used for a request.
				region: first(env, &["STORAGE_S3_REGION", "REGION", "AWS_REGION", "AWS_DEFAULT_REGION"])
					.unwrap_or_else(|| "us-east-1".into()),
				endpoint: first(env, &["STORAGE_S3_ENDPOINT", "GLOBAL_S3_ENDPOINT"]),
				force_path_style: first(
					env,
					&["STORAGE_S3_FORCE_PATH_STYLE", "GLOBAL_S3_FORCE_PATH_STYLE"],
				)
				.as_deref() == Some("true"),
				part_size: number(env, &["STORAGE_S3_UPLOAD_PART_SIZE"], 16 * 1024 * 1024)?,
				queue_size: number(env, &["STORAGE_S3_UPLOAD_QUEUE_SIZE"], 2)?,
				accept_invalid_certs: first(env, &["NODE_TLS_REJECT_UNAUTHORIZED"]).as_deref() == Some("0"),
			},
			install_roles: first(env, &["DB_INSTALL_ROLES"]).as_deref() == Some("true"),
			anon_role: first(env, &["DB_ANON_ROLE"]).unwrap_or_else(|| "anon".into()),
			authenticated_role: first(env, &["DB_AUTHENTICATED_ROLE"])
				.unwrap_or_else(|| "authenticated".into()),
			service_role: first(env, &["DB_SERVICE_ROLE"]).unwrap_or_else(|| "service_role".into()),
			super_user: first(env, &["DB_SUPER_USER"]).unwrap_or_else(|| "postgres".into()),
			statement_timeout_ms: number(env, &["DATABASE_STATEMENT_TIMEOUT"], 30_000)?,
			max_connections: number(env, &["DATABASE_MAX_CONNECTIONS"], 20)?,
			file_size_limit: number(
				env,
				&["UPLOAD_FILE_SIZE_LIMIT", "FILE_SIZE_LIMIT"],
				52_428_800,
			)?,
			signed_upload_url_expires: number(
				env,
				&[
					"UPLOAD_SIGNED_URL_EXPIRATION_TIME",
					"SIGNED_UPLOAD_URL_EXPIRATION_TIME",
				],
				60,
			)?,
			image_transformation: first(
				env,
				&[
					"IMAGE_TRANSFORMATION_ENABLED",
					"ENABLE_IMAGE_TRANSFORMATION",
				],
			)
			.as_deref() == Some("true"),
			imgproxy_url: first(env, &["IMGPROXY_URL"]),
			image_size_min: number(env, &["IMAGE_TRANSFORMATION_LIMIT_MIN_SIZE", "IMG_LIMITS_MIN_SIZE"], 1)?,
			image_size_max: number(env, &["IMAGE_TRANSFORMATION_LIMIT_MAX_SIZE", "IMG_LIMITS_MAX_SIZE"], 2000)?,
			imgproxy_timeout_s: number(env, &["IMGPROXY_REQUEST_TIMEOUT"], 15)?,
			private_asset_endpoint: first(env, &["STORAGE_S3_PRIVATE_ASSET_ENDPOINT", "GLOBAL_S3_PRIVATE_ASSET_ENDPOINT"]),
			tus_path: first(env, &["TUS_URL_PATH"]).unwrap_or_else(|| "/upload/resumable".into()),
			tus_part_size_mb: number(env, &["TUS_PART_SIZE"], 50)?,
			tus_url_expiry_ms: number(env, &["TUS_URL_EXPIRY_MS"], 3_600_000)?,
			tus_allow_s3_tags: first(env, &["TUS_ALLOW_S3_TAGS"]).as_deref() != Some("false"),
			allow_forwarded_prefix: first(env, &["REQUEST_ALLOW_X_FORWARDED_PATH"]).as_deref() == Some("true"),
			public_url: first(env, &["STORAGE_PUBLIC_URL"]),
		})
	}

	/// The tenant a request is for, from `X-Forwarded-Host`, its first group the tenant id.
	pub fn tenant_from_host(&self, forwarded_host: &str) -> Option<String> {
		let pattern = self.tenant_host_pattern.as_ref()?;
		pattern
			.captures(forwarded_host)
			.and_then(|c| c.get(1))
			.map(|m| m.as_str().to_string())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// What a SnoutData Cloud host gives this server.
	fn fleet() -> HashMap<String, String> {
		[
			("MULTI_TENANT", "true"),
			("STORAGE_BACKEND", "s3"),
			("ENABLE_IMAGE_TRANSFORMATION", "true"),
			(
				"DATABASE_MULTITENANT_URL",
				"postgres://storage_admin:pw@metadata-db:5432/storage_meta",
			),
			("SERVER_ADMIN_API_KEYS", "admin-key"),
			("SERVER_ADMIN_PORT", "5002"),
			("AUTH_ENCRYPTION_KEY", "enc"),
			(
				"REQUEST_X_FORWARDED_HOST_REGEXP",
				r"^([a-z0-9]{13})\.api\.snoutdata\.com$",
			),
			("DB_INSTALL_ROLES", "false"),
			("IMGPROXY_URL", "http://imgproxy:8080"),
			("STORAGE_S3_BUCKET", "sd-db-uw2-01"),
			("STORAGE_S3_REGION", "us-west-2"),
			("STORAGE_S3_FORCE_PATH_STYLE", "false"),
		]
		.into_iter()
		.map(|(k, v)| (k.to_string(), v.to_string()))
		.collect()
	}

	#[test]
	fn reads_the_fleet_s_environment_as_it_is() {
		let config = Config::from_map(&fleet()).unwrap_or_else(|e| panic!("{e}"));
		assert_eq!(config.port, 5000);
		assert_eq!(config.admin_port, 5002);
		assert_eq!(config.s3.bucket, "sd-db-uw2-01");
		assert_eq!(config.s3.endpoint, None);
		assert!(!config.install_roles);
		assert!(config.image_transformation);
		assert_eq!(
			config
				.tenant_from_host("abcdefghijklm.api.snoutdata.com")
				.as_deref(),
			Some("abcdefghijklm")
		);
		assert_eq!(config.tenant_from_host("evil.example.com"), None);
	}

	#[test]
	fn a_host_with_no_storage_cohort_still_starts() {
		// What a fleet host with no storage bucket assigned sends.
		let mut env = fleet();
		env.remove("STORAGE_S3_BUCKET");
		env.remove("STORAGE_S3_REGION");
		env.remove("STORAGE_S3_FORCE_PATH_STYLE");
		let config = Config::from_map(&env).unwrap_or_else(|e| panic!("{e}"));
		assert_eq!(config.s3.bucket, "");
	}

	#[test]
	fn a_missing_requirement_is_named() {
		let mut env = fleet();
		env.remove("AUTH_ENCRYPTION_KEY");
		assert_eq!(
			Config::from_map(&env).err(),
			Some(ConfigError::Missing("AUTH_ENCRYPTION_KEY"))
		);
	}
}
