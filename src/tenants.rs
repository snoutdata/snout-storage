//! The tenants: one row per project in the metadata database (`tenants`, and `tenants_jwks` for
//! the URL-signing key), the secrets encrypted with `AUTH_ENCRYPTION_KEY` (crypto.rs).
//!
//! A tenant is cached for a minute: every request needs one, and a row changes only through the
//! admin API, which drops its own cache entry on the spot. One server per host has nobody else to
//! tell.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use deadpool_postgres::{Pool, Runtime};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tokio_postgres::NoTls;

use crate::crypto;
use crate::error::StorageError;
use crate::jwt::{OctKey, SigningKey, generate_url_signing_jwk, oct_key_from_jwk};
use crate::migration_files::TENANT;
use crate::migrations::{Roles, Target, migrate};

/// The kind of the one active URL-signing key per tenant, and its kid separator.
const URL_SIGNING_KIND: &str = "storage-url-signing-key";
const CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Tenant {
	pub id: String,
	pub anon_key: String,
	pub service_key: String,
	pub jwt_secret: String,
	pub database_url: String,
	pub file_size_limit: u64,
	pub image_transformation: bool,
	/// `image_transformation_max_resolution`: the largest source imgproxy may decode, if limited.
	pub image_max_resolution: Option<i32>,
	/// Every active key, for verifying (jwt.rs).
	pub jwks: Vec<OctKey>,
	/// The first active URL-signing `oct` key, for signing; none means sign with the secret.
	pub url_signing_key: Option<OctKey>,
}

impl Tenant {
	pub fn signing_key(&self) -> SigningKey {
		match &self.url_signing_key {
			Some(key) => SigningKey::Jwk(key.clone()),
			None => SigningKey::Secret(self.jwt_secret.clone()),
		}
	}
}

/// The `PUT /tenants/:id` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantBody {
	pub anon_key: String,
	pub service_key: String,
	pub jwt_secret: String,
	pub database_url: String,
	pub file_size_limit: Option<u64>,
	pub features: Option<Features>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
	pub image_transformation: Option<Toggle>,
}

#[derive(Debug, Deserialize)]
pub struct Toggle {
	pub enabled: Option<bool>,
}

pub struct Registry {
	pool: Pool,
	key: String,
	roles: Roles,
	cache: RwLock<HashMap<String, (Arc<Tenant>, Instant)>>,
}

fn db_error(error: impl std::fmt::Display) -> StorageError {
	tracing::error!(%error, "metadata database");
	StorageError::internal()
}

impl Registry {
	pub fn new(
		metadata_url: &str,
		encryption_key: &str,
		roles: Roles,
	) -> Result<Self, StorageError> {
		let config = deadpool_postgres::Config {
			url: Some(metadata_url.to_string()),
			..Default::default()
		};
		let pool = config
			.create_pool(Some(Runtime::Tokio1), NoTls)
			.map_err(db_error)?;
		Ok(Self {
			pool,
			key: encryption_key.to_string(),
			roles,
			cache: RwLock::new(HashMap::new()),
		})
	}

	/// The metadata database's own schema, migrated at start.
	pub async fn migrate_metadata(&self) -> Result<(), StorageError> {
		let mut client = self.pool.get().await.map_err(db_error)?;
		let client: &mut tokio_postgres::Client = &mut client;
		migrate(
			client,
			crate::migration_files::METADATA,
			Target::Metadata,
			&self.roles,
		)
		.await
		.map_err(db_error)?;
		Ok(())
	}

	fn decrypt(&self, value: &str) -> Result<String, StorageError> {
		crypto::decrypt(&self.key, value).map_err(|error| {
			tracing::error!(%error, "a tenant row does not decrypt with AUTH_ENCRYPTION_KEY");
			StorageError::internal()
		})
	}

	pub async fn get(&self, id: &str) -> Result<Arc<Tenant>, StorageError> {
		if let Some((tenant, at)) = self.cache.read().await.get(id)
			&& at.elapsed() < CACHE_TTL
		{
			return Ok(tenant.clone());
		}
		let client = self.pool.get().await.map_err(db_error)?;
		let row = client
			.query_opt(
				"SELECT anon_key, service_key, jwt_secret, database_url, file_size_limit, feature_image_transformation, image_transformation_max_resolution FROM tenants WHERE id = $1",
				&[&id],
			)
			.await
			.map_err(db_error)?
			.ok_or_else(|| StorageError::missing_tenant_config(id))?;
		let mut jwks = Vec::new();
		let mut url_signing_key = None;
		for key_row in client
			.query("SELECT id::text, kind, content FROM tenants_jwks WHERE tenant_id = $1 AND active = true ORDER BY created_at", &[&id])
			.await
			.map_err(db_error)?
		{
			let (key_id, kind, content): (String, String, String) = (key_row.get(0), key_row.get(1), key_row.get(2));
			let jwk: Value = serde_json::from_str(&self.decrypt(&content)?).unwrap_or(Value::Null);
			if let Some(key) = oct_key_from_jwk(&jwk, Some(format!("{kind}_{key_id}"))) {
				if kind == URL_SIGNING_KIND && url_signing_key.is_none() {
					url_signing_key = Some(key.clone());
				}
				jwks.push(key);
			}
		}
		let tenant = Arc::new(Tenant {
			id: id.to_string(),
			anon_key: self.decrypt(row.get(0))?,
			service_key: self.decrypt(row.get(1))?,
			jwt_secret: self.decrypt(row.get(2))?,
			database_url: self.decrypt(row.get(3))?,
			file_size_limit: row.get::<_, i64>(4).max(0) as u64,
			image_transformation: row.get(5),
			image_max_resolution: row.get(6),
			jwks,
			url_signing_key,
		});
		self.cache
			.write()
			.await
			.insert(id.to_string(), (tenant.clone(), Instant::now()));
		Ok(tenant)
	}

	/// `PUT /tenants/:id`: the row upserted, a URL-signing key made if there is none, the
	/// tenant's database migrated and the row marked. Safe to repeat.
	pub async fn put(&self, id: &str, body: &TenantBody) -> Result<(), StorageError> {
		let mut client = self.pool.get().await.map_err(db_error)?;
		let transaction = client.transaction().await.map_err(db_error)?;
		let image = body
			.features
			.as_ref()
			.and_then(|f| f.image_transformation.as_ref())
			.and_then(|t| t.enabled);
		transaction
			.execute(
				"INSERT INTO tenants (id, anon_key, database_url, jwt_secret, service_key, file_size_limit, feature_image_transformation) \
				 VALUES ($1, $2, $3, $4, $5, COALESCE($6::bigint, 52428800), COALESCE($7::boolean, false)) \
				 ON CONFLICT (id) DO UPDATE SET anon_key = EXCLUDED.anon_key, database_url = EXCLUDED.database_url, \
				 jwt_secret = EXCLUDED.jwt_secret, service_key = EXCLUDED.service_key, \
				 file_size_limit = COALESCE($6::bigint, tenants.file_size_limit), \
				 feature_image_transformation = COALESCE($7::boolean, tenants.feature_image_transformation)",
				&[
					&id,
					&crypto::encrypt(&self.key, &body.anon_key),
					&crypto::encrypt(&self.key, &body.database_url),
					&crypto::encrypt(&self.key, &body.jwt_secret),
					&crypto::encrypt(&self.key, &body.service_key),
					&body.file_size_limit.map(|limit| limit as i64),
					&image,
				],
			)
			.await
			.map_err(db_error)?;
		// One active signing key per tenant, enforced by a partial unique index; a second PUT
		// leaves the first key in place, so URLs already handed out stay valid.
		let jwk = crypto::encrypt(&self.key, &generate_url_signing_jwk().to_string());
		transaction
			.execute(
				"INSERT INTO tenants_jwks (tenant_id, content, kind, active) VALUES ($1, $2, $3, true) ON CONFLICT DO NOTHING",
				&[&id, &jwk, &URL_SIGNING_KIND],
			)
			.await
			.map_err(db_error)?;
		transaction.commit().await.map_err(db_error)?;
		self.cache.write().await.remove(id);

		// Migrations after the row; a failure is logged and the tenant stays
		// registered, and the next PUT (the host agent reconciles) tries again.
		match self.migrate_tenant(&body.database_url).await {
			Ok(()) => {
				let last = TENANT.last().map(|file| file.name).unwrap_or_default();
				client
					.execute(
						"UPDATE tenants SET migrations_version = $2, migrations_status = 'COMPLETED' WHERE id = $1",
						&[&id, &last],
					)
					.await
					.map_err(db_error)?;
			}
			Err(error) => {
				tracing::error!(tenant = id, %error, "tenant migrations failed; the next registration retries")
			}
		}
		Ok(())
	}

	async fn migrate_tenant(&self, database_url: &str) -> Result<(), String> {
		let (mut client, connection) = tokio_postgres::connect(database_url, NoTls)
			.await
			.map_err(|e| e.to_string())?;
		let driver = tokio::spawn(connection);
		let result = migrate(&mut client, TENANT, Target::Tenant, &self.roles)
			.await
			.map(|_| ())
			.map_err(|e| e.to_string());
		drop(client);
		let _ = driver.await;
		result
	}

	pub async fn delete(&self, id: &str) -> Result<(), StorageError> {
		let client = self.pool.get().await.map_err(db_error)?;
		client
			.execute("DELETE FROM tenants WHERE id = $1", &[&id])
			.await
			.map_err(db_error)?;
		self.cache.write().await.remove(id);
		Ok(())
	}

	/// `GET /tenants`, without the sensitive fields.
	pub async fn list(&self) -> Result<Vec<Value>, StorageError> {
		let client = self.pool.get().await.map_err(db_error)?;
		let rows = client
			.query("SELECT id, file_size_limit, feature_image_transformation, migrations_version, migrations_status FROM tenants ORDER BY id", &[])
			.await
			.map_err(db_error)?;
		Ok(rows
			.iter()
			.map(|row| {
				json!({
					"id": row.get::<_, String>(0),
					"fileSizeLimit": row.get::<_, i64>(1),
					"migrationVersion": row.get::<_, Option<String>>(3),
					"migrationStatus": row.get::<_, Option<String>>(4),
					"features": { "imageTransformation": { "enabled": row.get::<_, bool>(2) } },
				})
			})
			.collect())
	}
}
